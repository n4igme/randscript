# OTP/Verification Code Brute-Force via Authenticated Oracle

## Pattern Summary

When an endpoint validates verification codes (OTP, 2FA, email bind, recovery), test for:
1. **Oracle** — does correct vs incorrect code return distinguishable responses?
2. **Rate limiting** — does the endpoint block after N attempts?
3. **Auth context** — does the oracle only appear when authenticated?

## The TikTok Pattern (Proven 2026-05-29)

### Discovery Flow
1. Compare sibling endpoints: `/passport/email/bind/` vs `/passport/email/verify/`
2. `/verify/` returned `error_code=1` (session required) — properly gated
3. `/bind/` returned `error_code=1703` (code validation) — skipped auth check
4. Key insight: the endpoint that skips auth is the vulnerable one

### Oracle Proof Methodology
1. **Unauthenticated test:** Send correct + wrong code → both return same response (no oracle)
2. **Authenticated test:** Send correct + wrong code with session cookie → DIFFERENT responses
   - Correct code: `error_code=7` (code accepted, secondary constraint hit)
   - Wrong code: `error_code=1703` (generic "incorrect" message)
3. The oracle exists only in authenticated context — attacker uses their OWN session

### Rate Limit Comparison
- Vulnerable endpoint: 19/20 attempts processed without blocking
- Sibling endpoint: blocks after 1 attempt (`error_code=7` "Maximum attempts reached")
- This differential proves the vulnerable endpoint is missing rate limiting

### Attack Chain
```
Attacker (own account, no email bound)
  → POST /send_code/ (no auth) → triggers code to victim's email
  → POST /bind/ (with attacker's session) → brute-force codes
  → Oracle: error_code changes from 1703 when correct code found
  → Email binds to attacker's account → password reset → ATO
```

## Generalized Checklist

For any code verification endpoint:

| Test | What to check | Signal |
|------|--------------|--------|
| Auth requirement | Does it process without session? | error_code for "code wrong" vs "session expired" |
| Oracle (unauth) | Correct vs wrong code same response? | If same → no unauth oracle |
| Oracle (auth) | Correct vs wrong code with session? | If different → exploitable |
| Rate limit | Send 20+ wrong codes consecutively | All processed = no rate limit |
| Rate limit comparison | Test sibling/equivalent endpoint | If sibling rate-limits but target doesn't = finding |
| Code trigger | Can attacker trigger code to victim? | send_code without auth = critical enabler |

## PoC Quality Rules (User Feedback)

When writing PoC scripts for OTP brute-force findings:

1. **Include real tested values** — actual codes, error codes, tickets, timestamps
2. **Show the oracle clearly** — print both correct and wrong code responses side by side
3. **Print the found code explicitly** — `[+] The verification code is: {code}` not just "CORRECT code found"
4. **Narrow the demo range** — set start/end range so the PoC hits the correct code within seconds (e.g., if code is 938450, use range 938050-938550)
5. **Self-contained execution** — use Playwright/browser login for session, don't require manual cookie extraction
6. **Usage: single argument** — `python3 poc.py --run <victim_email>` (handle auth internally)

## Applicable Targets

- Any `/bind/`, `/verify/`, `/confirm/` endpoint pair
- 2FA login endpoints (`/two_factor_login/`)
- Recovery code verification (`/account_recovery_code_verify/`)
- Email/phone change confirmation
- OAuth device code flows

## Instagram-Specific Notes (2026-05-29)

### Confirmed Rate Limit Gaps (Phase 3 Enumeration)
| Endpoint | Requests Tested | Blocked | Verdict |
|----------|----------------|---------|---------|
| `/api/v1/accounts/two_factor_login/` | 100 | 0 | **NO RATE LIMIT** |
| `/api/v1/accounts/send_two_factor_login_sms/` | 50 | 0 | **NO RATE LIMIT** |
| `/api/v1/accounts/check_confirmation_code/` | 15 | 0 | Soft limit only |
| `/api/v1/accounts/account_recovery_code_verify/` | 10 | 0 | No limit observed |

### Oracle Status
- Two different error messages on `check_confirmation_code`: "code wrong/expired" vs "please wait" (potential oracle)
- `two_factor_login` — needs valid `two_factor_identifier` from real 2FA challenge to confirm oracle
- `send_two_factor_login_sms` — with `device_id` returns `invalid_identifier` (processes request without auth)

### Next Step to Prove Exploitability
Trigger a real 2FA login flow (requires 2FA-enabled account) to obtain a valid `two_factor_identifier`. Then:
1. Send correct vs wrong verification_code with the identifier
2. Compare responses for oracle (different error_code = exploitable)
3. If oracle confirmed → $20K-$130K finding (2FA bypass → ATO)

### Parameters Required for `two_factor_login`
- `verification_code` (6-digit)
- `two_factor_identifier` (from login challenge response)
- `username`
- `trust_this_device` (0/1)

### Instagram Private API Login Format (Tested 2026-05-29)

```python
import time, hashlib, uuid, urllib.parse, requests

device_id = 'android-' + hashlib.md5(b'<username>').hexdigest()[:16]
uuid_val = str(uuid.uuid4())
phone_id = str(uuid.uuid4())
timestamp = str(int(time.time()))

headers = {
    'User-Agent': 'Instagram 275.0.0.27.98 Android (26/8.0.0; 480dpi; 1080x1920; Xiaomi; MI 6; sagit; qcom; en_US; 458229258)',
    'Content-Type': 'application/x-www-form-urlencoded',
    'X-IG-App-ID': '567067343352427',
}

data = {
    'username': '<username>',
    'enc_password': f'#PWD_INSTAGRAM:0:{timestamp}:<plaintext_password>',
    'device_id': device_id,
    'phone_id': phone_id,
    'guid': uuid_val,
    'login_attempt_count': '0',
    '_csrftoken': 'missing',  # works without valid CSRF
}

form_data = '&'.join(f'{k}={urllib.parse.quote(str(v))}' for k,v in data.items())
r = requests.post('https://i.instagram.com/api/v1/accounts/login/',
                  headers=headers, data=form_data, verify=False)
```

**Key details:**
- `enc_password` format: `#PWD_INSTAGRAM:0:<unix_timestamp>:<plaintext>` (type 0 = plaintext, type 4 = encrypted)
- `X-IG-App-ID: 567067343352427` is the Android app ID (required)
- `_csrftoken: missing` — endpoint processes request without valid CSRF
- On successful login with 2FA enabled, response contains `two_factor_identifier` in JSON body
- On bad password: `{"error_type": "bad_password", "invalid_credentials": true}`
- On 2FA challenge: `{"two_factor_required": true, "two_factor_info": {"two_factor_identifier": "..."}}`

**Test account status (2026-05-29):**
- `nitrospection` — exists, password unknown (tried `#asdF123;` and `#asdf123;`, both bad_password)
- Need a 2FA-enabled account with known credentials to capture `two_factor_identifier`

### Blockers
- `AuthPlatformAntiScriptingException` on `/accounts/login/` — bot detection may trigger after repeated attempts from same IP
- Need a 2FA-enabled account with KNOWN password to trigger the challenge and capture `two_factor_identifier`
- Alternative: use Playwright to drive the Instagram app/web login flow manually

### Payout Estimate
- 2FA bypass with no rate limit: $20K (2FA bypass) to $130K (full ATO chain)
- Comparable to TikTok `/passport/email/bind/` pattern but higher value target
