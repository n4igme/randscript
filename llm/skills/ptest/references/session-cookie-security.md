# Session & Cookie Security Checklist

Quick-reference for testing session management in web applications (Phase 5/6).

## Cookie Flags Checklist

| Flag | Expected | Test Command | Impact if Missing |
|------|----------|-------------|-------------------|
| `Secure` | ✅ Present | `curl -sk -I <url> \| grep Set-Cookie` | Cookie sent over HTTP (sniffable) |
| `HttpOnly` | ✅ Present | Same — check for `httponly` | XSS can steal via `document.cookie` |
| `SameSite` | `Strict` or `Lax` | Same — check for `samesite` | CSRF attacks possible |
| `Path` | `/` or scoped | Same — check `path=` | Cookie leaks to unintended paths |
| `Domain` | Specific | Same — check `domain=` | Overly broad = shared with subdomains |
| `Expires/Max-Age` | Session or short | Same | Persistent cookies survive browser close |

## Quick Test Commands

```bash
# Get all cookie attributes from login response
curl -sk -D - "https://target.com/login" -X POST \
  -d "user=test&pass=test" 2>&1 | grep -i "set-cookie"

# Check from browser console (only works if HttpOnly is missing!)
# If this returns the session cookie, HttpOnly is NOT set:
document.cookie

# Verify Secure flag (attempt HTTP access)
curl -k "http://target.com/" -I 2>&1 | grep -i "set-cookie"
```

## Session Token Analysis

| Check | How | Finding if True |
|-------|-----|-----------------|
| Predictable? | Register 3+ accounts, compare tokens | CWE-330 |
| Sequential? | Get 5 tokens rapidly, check for increment | CWE-330 |
| Short? | <128 bits entropy = weak | CWE-331 |
| Survives logout? | Logout, replay old token | CWE-613 |
| Fixed on login? | Note pre-auth token, login, check if same | Session fixation (CWE-384) |
| Rotates on privesc? | Change role/elevate, check if new token issued | CWE-384 |

## Common Session Issues

### 1. Missing HttpOnly (CWE-1004)
```
Set-Cookie: PHPSESSID=abc123; path=/; secure
                                        ↑ no httponly
```
**Impact:** XSS → session theft via `document.cookie`
**Remediation:** PHP: `session.cookie_httponly = 1`

### 2. Missing SameSite (CWE-1275)
```
Set-Cookie: PHPSESSID=abc123; path=/; secure; httponly
                                              ↑ no samesite
```
**Impact:** CSRF attacks — browser sends cookie with cross-origin requests
**Remediation:** PHP: `session.cookie_samesite = Strict`

### 3. Missing Secure Flag (CWE-614)
```
Set-Cookie: PHPSESSID=abc123; path=/
                              ↑ no secure
```
**Impact:** Cookie sent over HTTP if user visits http:// URL (MITM)
**Remediation:** PHP: `session.cookie_secure = 1`

### 4. Session Not Invalidated on Logout (CWE-613)
```bash
# Capture session token, logout, then replay:
curl -sk "https://target.com/profile" -b "session=OLD_TOKEN"
# If still returns profile data → session not invalidated
```

### 5. Overly Broad Domain Scope
```
Set-Cookie: session=abc; domain=.example.com
```
**Impact:** Any subdomain (including attacker-controlled) receives the cookie

## Framework-Specific Settings

| Framework | Config for Secure Cookies |
|-----------|--------------------------|
| PHP | `session.cookie_secure=1; session.cookie_httponly=1; session.cookie_samesite=Strict` |
| Express | `app.use(session({cookie: {secure:true, httpOnly:true, sameSite:'strict'}}))` |
| Django | `SESSION_COOKIE_SECURE=True; SESSION_COOKIE_HTTPONLY=True; SESSION_COOKIE_SAMESITE='Strict'` |
| Spring | `server.servlet.session.cookie.secure=true; server.servlet.session.cookie.http-only=true` |
| Laravel | `'secure'=>true, 'http_only'=>true, 'same_site'=>'strict'` in config/session.php |

## Reporting Template

```markdown
## Session Cookie Missing [FLAG] Flag

**Severity:** Low
**CWE:** CWE-[NUMBER]
**Asset:** target.com

### Evidence
Set-Cookie: SESSION_NAME=value; [observed flags]

Missing: [FLAG_NAME]

### Impact
[Specific attack enabled by missing flag]

### Remediation
[Framework-specific fix]
```
