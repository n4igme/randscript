# Bulk Actuator & Admin Endpoint Scanning

Mandatory technique for Phase 3 (Enumeration). Catches systemic misconfigurations that per-target testing misses.

## Why This Is Mandatory

In the BFI engagement, we dismissed `*.mock.bravo.bfi.co.id` as "all behind Basic Auth" based on testing a few API endpoints. This missed **11 microservices with fully exposed actuators** that revealed:
- Complete backend architecture (PostgreSQL, RabbitMQ, Redis, Elasticsearch, Camunda)
- 100+ API endpoint paths
- Internal K8s service names
- 419KB Prometheus metrics per service
- Heapdump endpoints (potential credential extraction)

The root cause: application-level auth (401 on `/v1/*`) does NOT protect framework endpoints (`/actuator`). These are independent security configurations.

## Scanning Script

```bash
#!/bin/bash
# bulk-actuator-scan.sh
# Run against ALL live subdomains, not just priority targets

INPUT="${1:-live-subs.txt}"  # File with one subdomain per line
OUTPUT="actuator-scan-results.txt"
TOTAL=$(wc -l < "$INPUT" | tr -d ' ')
COUNT=0

echo "[*] Scanning ${TOTAL} hosts for actuator/admin endpoints..."
echo "" > "$OUTPUT"

while IFS='|' read -r sub rest; do
  COUNT=$((COUNT + 1))
  [ $((COUNT % 25)) -eq 0 ] && echo "[*] Progress: ${COUNT}/${TOTAL} hosts checked"
  
  # Test actuator
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://${sub}/actuator" --max-time 8 2>/dev/null)
  [ "$code" = "200" ] && echo "[200] https://${sub}/actuator" | tee -a "$OUTPUT"
  
  # Test actuator/health (sometimes /actuator is 404 but /actuator/health works)
  if [ "$code" = "404" ]; then
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://${sub}/actuator/health" --max-time 8 2>/dev/null)
    [ "$code" = "200" ] && echo "[200] https://${sub}/actuator/health" | tee -a "$OUTPUT"
  fi
  
done < "$INPUT"

FOUND=$(wc -l < "$OUTPUT" | tr -d ' ')
echo ""
echo "[*] Done. ${FOUND} exposed actuator endpoints found across ${TOTAL} hosts."
```

## SPA False-Positive Detection (MANDATORY PRE-CHECK)

Modern SPAs (React/Vue/Angular with client-side routing) return HTTP 200 with the same HTML shell for ALL paths — including /actuator, /swagger, /.git/HEAD, /admin, etc. This makes naive status-code-based scanning useless.

**Detection method:** Before scanning, establish a baseline response size for a known-nonexistent path:

```bash
BASELINE=$(curl -sk --max-time 3 "https://${target}/nonexistent-xyz-baseline-12345" 2>/dev/null | wc -c)
echo "Baseline for ${target}: ${BASELINE} bytes"
```

**Then filter results:** Only flag responses whose size DIFFERS from the baseline:

```bash
for path in /actuator /actuator/health /actuator/env /.git/HEAD /swagger-ui /admin; do
  size=$(curl -sk --max-time 3 "https://${target}${path}" 2>/dev/null | wc -c)
  if [ "$size" != "$BASELINE" ] && [ "$size" != "0" ] && [ "$size" -gt 5 ]; then
    echo "[DIFF] ${target}${path} -> ${size} bytes (baseline: ${BASELINE})"
  fi
done
```

**Additional verification for .git:** Check if response contains `ref: refs/` (actual git HEAD content), not just HTML.

**Real-world examples of SPA baseline sizes (TikTok, May 2026):**
- scm-us.tiktok.com: 89,145 bytes (Garfish micro-frontend shell)
- notes.tiktok.com: 35,588 bytes (Goofy Deploy shell)
- seller-us.tiktok.com: varies by region (34K-90K) due to embedded gfdatav1 config

**Indicators of REAL endpoints behind an SPA:**
- Different response size from baseline
- Different Content-Type (application/json vs text/html)
- Specific error messages ("Not Found" in 9 bytes vs 35K HTML shell)
- HTTP 403/401 with 0 bytes (server blocked before SPA routing)

---

## Additional Paths to Check

After actuator, also scan for:

```bash
# Framework admin endpoints
PATHS=(
  "/actuator"
  "/actuator/health"
  "/actuator/env"
  "/actuator/heapdump"
  "/actuator/prometheus"
  "/swagger-ui.html"
  "/swagger-ui/"
  "/v2/api-docs"
  "/v3/api-docs"
  "/api-docs"
  "/console"
  "/h2-console"
  "/admin"
  "/admin/"
  "/camunda/app/welcome/"
  "/graphql"
  "/graphiql"
  "/_debug"
  "/debug/vars"
  "/metrics"
  "/health"
)
```

## Interpreting Results

### Actuator Endpoint Severity

| Endpoint | Severity if Exposed | Why |
|----------|-------------------|-----|
| /actuator/env | CRITICAL | Contains DB passwords, API keys, JWT secrets in plaintext |
| /actuator/heapdump | CRITICAL | JVM memory dump — extract any in-memory secret |
| /actuator/configprops | HIGH | All Spring configuration including credentials |
| /actuator/mappings | HIGH | Complete URL mapping — full API surface |
| /actuator/prometheus | HIGH | Metrics with endpoint paths, connection details |
| /actuator/health | MEDIUM | Backend component versions, connectivity status |
| /actuator/metrics | MEDIUM | Performance data, endpoint enumeration |
| /actuator/info | LOW | Build info, git commit |
| /actuator/loggers | MEDIUM | Can POST to change log levels (enable DEBUG remotely) |

### When Multiple Services Are Exposed

If 5+ services have exposed actuators on the same subdomain pattern:
- Upgrade to **Critical** — this is a systemic misconfiguration, not a one-off
- Document as a single finding with "N services affected"
- The combined data from all services reveals the complete application architecture
- Recommend infrastructure-level fix (ingress rule, not per-service config)

## Common Patterns

### "Mock" / "Test" / "Dev" environments
- Often have actuator enabled for debugging
- Route to real backends (SIT/UAT) — data is not fake
- Share the same K8s cluster as production
- Internal service names follow same convention as prod

### Shared IP with different security per path
- API endpoints: 401 (auth required) ✓
- Actuator endpoints: 200 (no auth) ✗
- This happens because Spring Security config protects `/v1/**` but not `/actuator/**`
- The ingress/WAF may not have path-specific rules for actuator

### Heapdump availability
- If `/actuator/heapdump` returns 200 or starts downloading → CRITICAL
- If it returns 504 (timeout) → the endpoint EXISTS but the dump is too large for the timeout
- Try with `curl --max-time 120` or download in background
- A successful heapdump contains: DB passwords, JWT signing keys, API tokens, session data

## Reporting

When documenting bulk actuator exposure:

```markdown
## [FINDING-N] Systemic Spring Boot Actuator Exposure ({count} services)

**Severity:** Critical
**CVSS 3.1:** 8.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)
**Affected Assets:** {list all services}
**Environment:** {mock/dev/sit/uat/prod}

### Services Affected
| Service | Health | Prometheus | Heapdump | Key Components |
|---------|--------|-----------|----------|----------------|
| service-1 | ✅ | ✅ | ❌ | PostgreSQL, RabbitMQ |
| service-2 | ✅ | ✅ | ✅ | PostgreSQL, Redis |
...

### Architecture Revealed
{Diagram showing how services connect based on health/metrics data}

### Remediation
1. **Immediate:** Block `/actuator*` at ingress/WAF level for all non-internal traffic
2. **Short-term:** Set `management.endpoints.web.exposure.include=health` in all services
3. **Medium-term:** Place all non-production environments behind VPN/IAP
```

## WAF-Specific Bypass Patterns

### Alibaba Cloud WAF (Tengine) — Confirmed May 2026

On `api.findaya.co.id` (GoTo Financial):
- **Blocked:** `/actuator/prometheus` → 405 (Alibaba WAF block page with Chinese/English error)
- **Allowed:** `/actuator`, `/actuator/health`, `/actuator/info`, `/actuator/metrics`, `/actuator/metrics/{name}` → 200

The WAF has a rule for `/prometheus` (likely matching the path keyword) but does NOT block the actuator index or individual metrics endpoints. This means:
- `/actuator/metrics/http.server.requests` returns the SAME data as Prometheus (all URI tags, status codes, etc.)
- You can enumerate every metric name via `/actuator/metrics` then query each individually
- The WAF rule is path-keyword-based, not endpoint-function-based

**Workaround when /actuator/prometheus is blocked:**
```bash
# 1. Get all metric names
curl -sk "https://$TARGET/actuator/metrics" | jq '.names[]'

# 2. Query each individually (same data as prometheus, just JSON not text)
curl -sk "https://$TARGET/actuator/metrics/http.server.requests" | jq '.availableTags[] | select(.tag=="uri") | .values[]'

# 3. The URI tag values ARE the complete API route map
```

**Detection:** Alibaba WAF block page has `<title>405</title>`, references `errors.aliyun.com`, contains `traceid` in a hidden textarea, and server header is `Tengine`.

### Tencent Cloud WAF — Confirmed May 2026

On GoTo/Gojek targets:
- Blocks dotfile access (`.git`, `.env`) → 403 with WAF block page
- Blocks `/actuator/env` → 403
- Does NOT consistently block `/actuator/health` or `/actuator/info`
- Server header: `stgw`, has `eo-log-uuid` header

## Actuator Metrics as API Route Enumeration (Phase 1/3 Technique)

When `/actuator/metrics/http.server.requests` is accessible, the `uri` tag contains the **complete API route map** — every endpoint the application has ever served. This is often MORE valuable than `/actuator/mappings` because it shows ACTUALLY-USED routes (not just registered ones).

### Extraction Technique

```bash
# 1. Get the full route map from URI tags
curl -sk "https://$TARGET/actuator/metrics/http.server.requests" | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
for tag in d.get('availableTags', []):
    if tag['tag'] == 'uri':
        for uri in sorted(tag['values']):
            print(uri)
"

# 2. Also extract other useful tags
# - 'env' tag → confirms production/staging
# - 'host' tag → internal hostname
# - 'team' tag → owning team (org structure intel)
# - 'status' tag → which HTTP codes are returned (429 = rate limiting exists)
# - 'exception' tag → exception classes (reveals framework internals)
# - 'method' tag → which HTTP methods are used (PATCH/DELETE = write operations)
```

### What to Do With Discovered Routes

1. **Test each route for auth bypass** — callback/integration routes often lack auth
2. **Look for path parameters** (`{id}`, `{gopay_account_id}`) — these accept user input
3. **Identify pre-auth endpoints** — `/login`, `/otp`, `/register`, `/callback` paths
4. **Map internal services** — routes like `/integration/gopay/kyc/v1/{id}/callback` reveal service-to-service communication
5. **Check custom business metrics** — `findaya.login.failed`, `findaya.otp.*` reveal auth flow details

### Real-World Example: Findaya (May 2026)

`/actuator/metrics/http.server.requests` on `api.findaya.co.id` revealed:
- 15+ API routes including `/v1/otp`, `/v2/login`, `/legalEntityKYC/v1/onboarding-doc`
- Team: `gofin-loan-platform`, Host: `findaya-api`, Env: `production`
- Testing the discovered `/legalEntityKYC/v1/onboarding-doc` endpoint → **Critical finding** (unauthenticated KYC document access)
- Testing `/integration/gopay/kyc/v1/{id}/callback` → unauthenticated, leaked internal service names via 500 error

---

## Unauthenticated Callback/Integration Endpoints (MANDATORY Check)

**Pattern:** APIs that receive webhooks from partner services (payment callbacks, KYC callbacks, notification webhooks) are often left WITHOUT authentication because the developers assume "only the partner will call this."

### Detection

Look for these path patterns in actuator metrics, swagger docs, or JS bundles:
```
/integration/*
/callback/*
/webhook/*
/v1/*/callback
/notify/*
/ipn/*
```

### Testing

```bash
# 1. Try POST with empty body (reveals required fields)
curl -sk -X POST "https://$TARGET/integration/partner/v1/callback" \
  -H "Content-Type: application/json" -d '{}'

# 2. Interpret responses:
# - 400 with field validation → endpoint processes requests WITHOUT auth
# - 401 → auth required (safe)
# - 405 → wrong method, try GET/PUT
# - 500 with stack trace → unauthenticated AND leaks internals
# - 200 with data → CRITICAL (unauthenticated data access)

# 3. If 500 with DNS/connection error → the endpoint is unauthenticated
#    but the backend service is down. Still a finding (auth bypass + info disclosure)
```

### Why This Matters

Callback endpoints often:
- Return signed URLs to stored documents (KYC docs, invoices, contracts)
- Accept status updates that change application state (approve/reject flows)
- Leak internal service names and architecture in error messages
- Have no rate limiting (designed for machine-to-machine calls)

### Severity

| Scenario | Severity |
|----------|----------|
| Callback returns production PII/documents | Critical |
| Callback accepts state-changing input (approve/reject) | Critical |
| Callback leaks internal service names via errors | Medium |
| Callback exists but backend is unreachable | Low-Medium |

---

## Lessons Learned

> "Testing a few API endpoints and seeing 401 does NOT mean the host is secure.
> Framework endpoints (actuator, swagger, console) operate independently of
> application auth. ALWAYS test them separately, on EVERY host."

> "When a WAF blocks /actuator/prometheus, try /actuator/metrics instead.
> WAF rules are often keyword-based ('/prometheus') not function-based.
> The metrics endpoint returns the same data in JSON format."

> "After discovering API routes via actuator metrics, ALWAYS test /integration/*
> and /callback/* paths — these are the most commonly unauthenticated endpoints
> on otherwise-hardened APIs. The Findaya Critical (KYC doc leak) was found this way."
