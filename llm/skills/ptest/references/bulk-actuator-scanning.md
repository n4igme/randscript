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

## Lesson Learned

> "Testing a few API endpoints and seeing 401 does NOT mean the host is secure.
> Framework endpoints (actuator, swagger, console) operate independently of
> application auth. ALWAYS test them separately, on EVERY host."

> "When a WAF blocks /actuator/prometheus, try /actuator/metrics instead.
> WAF rules are often keyword-based ('/prometheus') not function-based.
> The metrics endpoint returns the same data in JSON format."
