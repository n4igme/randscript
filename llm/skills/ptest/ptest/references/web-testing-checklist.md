# Web Testing Checklist (Cross-Reference)

Comprehensive checklist for web application testing. Use as a cross-check during Phase 5 (Vuln Assessment) and Phase 6 (Exploitation) to ensure no common test case is missed.

Source: Adapted from six2dez/pentest-book web-checklist + field experience.

---

## 1. User Management

### Registration

| # | Test Case | Technique | Severity if Found |
|---|-----------|-----------|-------------------|
| 1 | Duplicate registration (uppercase, +1@, dots) | Register `User@mail.com` then `user@mail.com` | Medium |
| 2 | Existing user overwrite (account takeover) | Register with existing email, check if original is overwritten | High |
| 3 | Weak password policy | Try `user=password`, `123456`, `qwerty12`, spaces-only | Low-Medium |
| 4 | Null byte in email (`my%00email@mail.com`) | Account takeover via email verification bypass | High |
| 5 | Disposable email allowed | Register with `temp@guerrillamail.com` | Info |
| 6 | Long password DoS (>200 chars) | Submit 5000-char password, measure response time | Low |
| 7 | JSON comma injection | `{"email":"victim@mail.com","hacker@mail.com"}` | Medium |
| 8 | Register with company/internal email | Try `admin@target.com` if no domain restriction | Medium |
| 9 | OAuth state parameter on social registration | Check if state is validated, replay old state | Medium-High |
| 10 | XSS in name/email fields | `<script>alert(1)</script>` in display name | Medium |
| 11 | Rate limit on account creation | Create 100 accounts rapidly | Low |
| 12 | Post-registration directory creation | Fuzz for `/users/{username}/` after signup | Medium |

### Authentication

| # | Test Case | Technique | Severity if Found |
|---|-----------|-----------|-------------------|
| 1 | Username enumeration | Different error for valid vs invalid user | Low-Medium |
| 2 | Account lockout mechanism | Brute-force 20 attempts, check lockout | Medium |
| 3 | Default credentials | `admin:admin`, `admin:password`, service-specific defaults | Critical |
| 4 | Fail-open conditions | Remove auth parameter entirely, check response | Critical |
| 5 | Multi-stage auth bypass | Skip step 2 of 2FA, call final endpoint directly | High |
| 6 | Response tampering (OTP) | Change `{"success":false}` to `{"success":true}` in response | High |
| 7 | OTP brute-force | 4-digit = 10K attempts, check rate limit | High |
| 8 | OTP race condition | Send 100 parallel OTP verification requests | High |
| 9 | OTP reuse | Use same OTP twice after first success | Medium |
| 10 | JWT common flaws | alg:none, weak secret, expired acceptance | Critical-High |
| 11 | Login over HTTP (mixed content) | Check if login form submits to HTTP | Medium |
| 12 | Browser cache on auth pages | Check Pragma, Expires, Cache-Control headers | Low |
| 13 | OAuth open redirect in login | `/login?next=javascript:alert(1)` or `//evil.com` | Medium |
| 14 | SAML response tampering | Modify assertions, check signature validation | High |

### Session Management

| # | Test Case | Technique | Severity if Found |
|---|-----------|-----------|-------------------|
| 1 | Session token predictability | Collect 100 tokens, analyze entropy | High |
| 2 | Session fixation | Set session cookie before auth, check persistence | High |
| 3 | Session not invalidated on logout | Save token, logout, replay | Medium |
| 4 | Session not invalidated on password change | Change password, check old session | Medium |
| 5 | Concurrent session handling | Login from 2 locations, check if first dies | Info-Low |
| 6 | Cookie without HttpOnly flag | Check Set-Cookie headers | Low |
| 7 | Cookie without Secure flag | Check Set-Cookie headers | Low |
| 8 | Cookie scope too broad | Domain=`.target.com` exposes to all subdomains | Medium |
| 9 | Session token in URL | Check for `?session=` or `?token=` in URLs | Medium |
| 10 | Token in Referer header | Navigate to external link, check Referer leak | Medium |
| 11 | Browser back button after logout | Logout → Alt+Left → check if authenticated content shows | Low |
| 12 | Cross-device session reuse | Copy cookie to different IP/UA, check acceptance | Info |

### Password Reset

| # | Test Case | Technique | Severity if Found |
|---|-----------|-----------|-------------------|
| 1 | Reset token predictability | Request 10 tokens, analyze pattern (timestamp? sequential?) | Critical |
| 2 | Reset token doesn't expire | Use token after 24h+ | Medium |
| 3 | Old reset token still valid after new request | Request 2 tokens, use the first | Medium |
| 4 | Host header injection for token theft | `Host: evil.com` → reset link points to evil.com | High |
| 5 | X-Forwarded-Host token theft | `X-Forwarded-Host: evil.com` in reset request | High |
| 6 | IDOR in reset link | Change user_id/email in reset URL | Critical |
| 7 | Token leak in Referer | Click link in reset page, check Referer header | Medium |
| 8 | Email parameter pollution | `email=victim@mail.com&email=attacker@mail.com` | High |
| 9 | Carbon copy injection | `email=victim@mail.com%0a%0dcc:hacker@mail.com` | High |
| 10 | No rate limit on reset requests | Send 1000 reset emails (email bombing) | Low-Medium |
| 11 | Password reset without current password | Change password endpoint doesn't require old password | Medium |
| 12 | Response manipulation on reset | Change error response to success | Medium |

---

## 2. Application Logic

### Business Logic Flaws

| # | Test Case | Technique | Severity if Found |
|---|-----------|-----------|-------------------|
| 1 | Price/amount tampering | Modify price in request (negative, zero, MAX_INT) | Critical |
| 2 | Quantity manipulation | Order -1 items, 0 items, 999999 items | High |
| 3 | Coupon/promo code reuse | Apply same code twice (sequential + race condition) | Medium-High |
| 4 | Self-referral | Refer yourself with different email | Medium |
| 5 | Workflow step skipping | Call step 3 API without completing step 1-2 | High |
| 6 | Status manipulation | Change order status directly via API | Critical |
| 7 | Currency confusion | Submit in different currency than displayed | High |
| 8 | Test credit card acceptance | `4111 1111 1111 1111` in production | Medium |
| 9 | PDF/print IDOR | Generate PDF for other user's data | Medium-High |
| 10 | Unsubscribe user enumeration | Unsubscribe endpoint reveals valid emails | Low |
| 11 | POST↔GET method swap | Change sensitive POST to GET (may bypass CSRF) | Medium |
| 12 | Client-side validation only | Remove JS validation, submit invalid data | Varies |
| 13 | Transaction replay | Replay successful transaction request | High |
| 14 | Gift card/voucher generation abuse | Predict or brute-force gift card codes | High |

### CAPTCHA Bypass

| # | Test Case | Technique | Severity if Found |
|---|-----------|-----------|-------------------|
| 1 | Reuse old CAPTCHA value | Submit same captcha token twice | Medium |
| 2 | Old CAPTCHA + old session ID | Replay both together | Medium |
| 3 | Remove CAPTCHA parameter | Delete from request entirely | Medium |
| 4 | Request CAPTCHA image directly | Access `/captcha/1.png` path | Low |
| 5 | Change POST to GET | Method swap may skip CAPTCHA check | Medium |
| 6 | Empty CAPTCHA value | Submit `captcha=` (empty string) | Medium |
| 7 | OCR bypass | Use tesseract/easy-ocr on simple CAPTCHAs | Info |

---

## 3. Input Handling (Quick Reference)

### Injection Points (Priority Order)

| Location | Test For | Quick Payload |
|----------|----------|---------------|
| URL parameters | SQLi, XSS, SSRF, LFI | `'`, `{{7*7}}`, `http://burp.collab` |
| POST body (JSON) | SQLi, NoSQL, CMDi | `{"id":"1' OR 1=1--"}`, `{"$gt":""}` |
| HTTP headers | SQLi, XSS, SSTI | User-Agent, Referer, X-Forwarded-For |
| File upload name | Path traversal, XSS | `../../../etc/passwd`, `<img src=x onerror=alert(1)>.png` |
| Cookie values | SQLi, deserialization | `' OR 1=1--`, base64-decode and modify |
| WebSocket messages | SQLi, XSS, IDOR | Same payloads as HTTP parameters |

### Error Handling Probes

```bash
# Generate errors to reveal stack traces / technology
curl -sk "$URL/whatever_fake.php"
curl -sk "$URL/%s%s%s%s%s"
curl -sk "$URL/~randomthing"
curl -sk -X PATCH "$URL"  # Wrong method
curl -sk "$URL" -H "Content-Type: application/xml" -d '<x>'
curl -sk "$URL?id[]=1&id[]=2"  # Array parameter
curl -sk "$URL?id=\x00"  # Null byte
```

---

## 4. Security Headers Checklist

| Header | Expected Value | Impact if Missing |
|--------|---------------|-------------------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | MitM downgrade |
| `Content-Security-Policy` | Restrictive policy (no `unsafe-inline`) | XSS amplification |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | Clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME confusion |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or `no-referrer` | Token leak |
| `Permissions-Policy` | Restrict camera, microphone, geolocation | Privacy |
| `Cache-Control` | `no-store` on sensitive pages | Data exposure |
| `X-XSS-Protection` | `0` (deprecated, CSP preferred) | Info |

```bash
# Quick header audit
curl -sk -D- -o /dev/null "$URL" | grep -iE "strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy|cache-control"
```

---

## 5. Infrastructure Quick Checks

| # | Test Case | Command | Severity |
|---|-----------|---------|----------|
| 1 | DMARC/SPF missing | `dig +short TXT _dmarc.target.com` | Low-Medium |
| 2 | Zone transfer | `dig axfr @ns1.target.com target.com` | Medium |
| 3 | Dangerous HTTP methods | `curl -sk -X OPTIONS "$URL" -D- \| grep Allow` | Low-Medium |
| 4 | Directory listing | Browse `/images/`, `/uploads/`, `/backup/` | Medium |
| 5 | .git exposure | `curl -sk "$URL/.git/HEAD"` | High |
| 6 | .env exposure | `curl -sk "$URL/.env"` | Critical |
| 7 | Backup files | `curl -sk "$URL/web.config.bak"`, `.old`, `~` | Medium-High |
| 8 | Alternative channels | Check `m.target.com`, `api.target.com`, `dev.target.com` | Varies |
| 9 | Internal IP in response | Grep responses for `10.x`, `172.16-31.x`, `192.168.x` | Low |
| 10 | Server version disclosure | Check `Server:` header, `X-Powered-By:` | Info |

---

## Usage in ptest Framework

**Phase 5 (Vuln Assessment):**
- Use sections 1-4 as a cross-check after automated scanning (nuclei, nikto)
- Each test case that reveals a vulnerability → document as finding immediately
- Mark tested items in the phase checklist

**Phase 6 (Exploitation):**
- Use section 2 (Application Logic) during technique 6.5
- Use section 1 (User Management) during technique 6.2 and 6.6
- Race condition tests from section 2 → use `references/advanced-web-attacks.md` for scripts

**Phase 3 (Enumeration):**
- Use section 5 (Infrastructure) during directory/file enumeration
- .git, .env, backup files should be caught by gobuster/feroxbuster but verify manually
