# GCP/GKE Penetration Testing Patterns

## Kubernetes Service Discovery via 302 Redirects

When a gateway (Envoy, Istio, nginx-ingress) returns 302 with internal service URLs, it leaks the cluster topology.

**Detection:**
```bash
# Test path prefixes against the gateway
for prefix in /payment /customer /document /notification /agency /master /onboarding /edoc /branch /product /insurance /agreement; do
  LOC=$(curl -skI --max-time 4 "https://${GATEWAY}${prefix}" 2>/dev/null | grep -i 'location:.*cluster.local')
  [ -n "$LOC" ] && echo "  $prefix -> $LOC"
done
```

**What it reveals:**
- Internal service naming convention: `{env}-ms-{service}.{namespace}.svc.cluster.local`
- Namespace structure (prod, staging, etc.)
- Internal protocol (HTTP = no mTLS between services)
- Full service inventory for targeted SSRF

**Severity:** Low (info disclosure), but escalates to Medium/High if SSRF is found (attacker knows exact internal URLs).

## GCS-Hosted SPA JS Bundle Analysis

When `x-goog-generation` or `x-guploader-uploadid` headers appear, the frontend is served from Google Cloud Storage.

**Extraction pattern:**
```bash
# Find JS bundle
JS=$(curl -sk "https://${TARGET}/" | grep -oE 'src=[^> ]+' | grep -i 'assets.*js' | head -1 | sed 's/src="//;s/"//')

# Extract all internal URLs
curl -sk "https://${TARGET}${JS}" | grep -oE 'https://[a-zA-Z0-9._/-]+bfi\.co\.id[a-zA-Z0-9._/:-]*' | sort -u

# Extract Keycloak config
curl -sk "https://${TARGET}${JS}" | grep -oE '(KEYCLOAK_CLIENT_ID|KEYCLOAK_REALM|KEYCLOAK_URL|API_KEY|BASE_URL)[^,;}{)]*' | sort -u
```

**What to look for:**
- `KEYCLOAK_CLIENT_ID` — public OAuth client names (try password grant, client_credentials)
- `KEYCLOAK_REALM` — realm names for enumeration
- `KEYCLOAK_USE_NONCE: "false"` — nonce disabled = potential token replay
- `BASE_URL` — backend API endpoints (test without auth)
- `API_KEY` — Google/Firebase keys (test for missing referer restrictions)
- GitHub repo names — private repos leaked = info disclosure
- Sentry DSN — potential event injection

**Key insight:** Multiple SPAs on the same org often share the same backend gateway. Cross-reference findings across ALL bundles to build complete API map.

## Keycloak Enumeration on GKE

GKE deployments often expose Keycloak at multiple paths:
- `sso.domain.com` (dedicated SSO subdomain)
- `auth.domain.com` (dedicated auth subdomain)  
- `microservices.domain.com/keycloak` (behind API gateway)

**Enumeration checklist:**
```bash
# Realm discovery
for realm in master bravo bfi internal employee customer partner app; do
  CODE=$(curl -sk -o /dev/null -w '%{http_code}' "https://${KC_URL}/realms/${realm}")
  [ "$CODE" = "200" ] && echo "  $realm -> FOUND"
done

# Admin console check
curl -sk -o /dev/null -w '%{http_code}' "https://${KC_URL}/admin/master/console/"
# 200 = publicly accessible (finding!)
# 403 = IP-restricted (good)
# 302 = redirects to login (normal)

# Client registration endpoint
curl -sk "https://${KC_URL}/realms/${REALM}/clients-registrations/default/${CLIENT_ID}"

# Password grant test
curl -sk -X POST "https://${KC_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=${CLIENT_ID}&username=${USER}&password=${PASS}"

# Client credentials grant
curl -sk -X POST "https://${KC_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -d "grant_type=client_credentials&client_id=${CLIENT_ID}"

# Forgot password (user enumeration check)
# If response differs for valid vs invalid users = user enumeration finding
```

**Common findings:**
- Admin console publicly accessible (Medium)
- Password grant enabled on public clients (enables brute-force)
- Open registration on realm (enables self-signup for internal apps)
- OIDC config exposes public keys (enables JWT forgery if weak algorithm)

## Microservices Auth Pattern Assessment

After discovering services, categorize by auth status:
- **200 (no auth)** — immediate finding, test for sensitive data
- **401 (JWT required)** — need token, try all discovered client_ids
- **403 (blocked)** — IP/network restricted, note for internal testing
- **500 (broken)** — may be auth-less but broken (CORS bug, missing param)
- **302 to internal** — info leak, document service name
- **404** — service not routed at this path

**The "500 but no auth" pattern:** When an endpoint returns 500 with an application error (not "unauthorized"), it means the request passed auth checks but failed on business logic. This confirms the endpoint has NO authentication. Document as a finding even if you can't extract data.
