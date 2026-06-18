# Webhook Signature Bypass — Exploitation & Proof Pattern

## Trigger
- Third-party webhook callbacks (Sumsub, Stripe, AppsFlyer, Twilio, SendGrid)
- Endpoint returns 200 on POST with JSON body
- `X-Payload-Digest` / `X-Hub-Signature` / `Stripe-Signature` header present but not verified

## Proving Real Processing (Not Just 200 Response)

A 200 response alone does NOT prove impact. Triagers will reject with "endpoint might discard invalid events."

### Strategy: Prometheus Counter Observation

When the target exposes `/actuator/prometheus` (even on a test environment):

```bash
# 1. Get baseline counter
curl -sk "https://test-target.com/actuator/prometheus" | grep "webhook_received_total.*event_type"
# Example: counter = 98

# 2. Send forged webhook
curl -sk -X POST "https://test-target.com/callback/vendor/event" \
  -H "Content-Type: application/json" \
  -H "X-Payload-Digest: FORGED_INVALID" \
  -d '{"type":"eventType","id":"proof-001","result":"success"}'

# 3. Wait 3-5 seconds for async processing
sleep 5

# 4. Check counter AFTER
curl -sk "https://test-target.com/actuator/prometheus" | grep "webhook_received_total.*event_type"
# Example: counter = 99 → PROCESSED

# 5. Check Kafka/queue produce counter (proves downstream delivery)
curl -sk "https://test-target.com/actuator/prometheus" | grep "produce_success_total"
# If this also incremented → event reached downstream consumers
```

### Evidence Chain (strongest to weakest)
1. **Counter increment on produce_success** → event entered downstream pipeline (strongest)
2. **Counter increment on webhook_received** → event was parsed and classified
3. **HTTP 200 + input validation differential** → endpoint processes JSON (not catch-all)
4. **HTTP 200 alone** → weakest, triager may reject

### Input Validation Differential (Proving Not Catch-All)

Always demonstrate the endpoint validates input:
- `Content-Type: text/plain` → 415 (validates content type)
- Empty body → 400 (validates body presence)
- Nonexistent sub-path → 500 (route-specific)
- Valid JSON + invalid signature → 200 (signature NOT checked)

If all 4 behaviors match → real processing, not a catch-all 200.

## Common Webhook Signature Headers

| Vendor | Header | Algorithm |
|--------|--------|-----------|
| Sumsub | X-Payload-Digest | HMAC-SHA1 |
| Stripe | Stripe-Signature | HMAC-SHA256 (t=timestamp,v1=hash) |
| GitHub | X-Hub-Signature-256 | HMAC-SHA256 |
| Twilio | X-Twilio-Signature | HMAC-SHA1 (full URL + params) |
| SendGrid | X-Twilio-Email-Event-Webhook-Signature | ECDSA |
| AppsFlyer | (none standard) | Varies by config |

## Severity Assessment

| Evidence Level | Severity |
|---------------|----------|
| State change proven (account status changed) | Critical/High |
| Kafka produce counter incremented | High |
| Webhook received counter incremented | High (with context) |
| 200 + input validation proof only | Medium |
| 200 response only | Low (likely rejected) |

## Capital.com Example (June 2026)

- Target: callback.backend-capital.com (PROD)
- Vendor: Sumsub (KYC)
- Header: X-Payload-Digest (not verified)
- Proof: test-callback Prometheus counters (98→99 received, 633→634 produced)
- Kafka topic: ums.docValidation.callback.v2
- Impact: Forged KYC events reach downstream consumer on regulated financial platform

## Pitfall: Prod vs Test Prometheus

Production endpoints often have Prometheus disabled (500). Test environments may expose it. The proof is still valid — same codebase, same processing logic. Document that both PROD and TEST accept forged events identically (same status codes, same behavior), then show the counter proof on TEST where Prometheus is accessible.
