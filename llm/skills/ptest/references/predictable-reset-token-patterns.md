# Predictable Password Reset Token Patterns

## Trigger
- Forgot password functionality with token/hash-based reset
- Change password endpoint accepts a `hash` or `token` parameter
- "Token expired" response confirms hash is validated (not just ignored)

## Common Predictable Token Schemes

| Pattern | Detection | Example |
|---------|-----------|---------|
| MD5(email) | Compute and submit | `ec88280206f8db436475ae83934c7a18` for `secret@secops.group` |
| MD5(user_id) | Enumerate IDs 1-100 | Sequential integers |
| MD5(email+timestamp) | Narrow window brute | Need approximate trigger time |
| SHA1(email) | Compute and submit | 40-char hex |
| Base64(email) | Decode observed tokens | Obvious encoding |
| Sequential/incremental | Observe two tokens | Token2 = Token1 + 1 |
| Timestamp-based | Trigger at known time | Unix epoch seconds as token |

## Exploitation Workflow

### Step 1: Confirm token validation exists
```
POST /reset-password
hash=INVALID&new_password=test&confirm_password=test
→ "Token expired" or "Invalid token" = endpoint validates hash
→ "Password changed" = no validation (direct reset without token!)
```

### Step 2: Test common derivations
```python
import hashlib
email = "victim@target.com"
tests = [
    hashlib.md5(email.encode()).hexdigest(),
    hashlib.sha1(email.encode()).hexdigest(),
    hashlib.sha256(email.encode()).hexdigest(),
    email.encode().hex(),
]
```

### Step 3: If static hash works → ATO any user
No need to trigger forgot password first. The token is deterministic.

## User Enumeration Bonus (Forgot Password Oracle)

### Response content difference
- Existing user: "Check your inbox for the link to reset your password."
- Non-existing: "Check your inbox for the link to reset  your password." (double space)

### Timing difference
- Existing user: ~2.7s (actually sends email or does DB write)
- Non-existing: ~1.1s (returns immediately)

### Both are user enumeration findings (Low severity standalone, enables ATO chain)

## Confirmed (SecOps exam, June 2026)
- Token = MD5(email), no trigger needed, no expiry on static hash
- All /login endpoint: login, forgot, change password share same POST path
- User enum via forgot password double-space oracle + timing

## Severity
- Predictable token alone: Critical (CVSS 9.8) — unauthenticated ATO of any user
- User enumeration alone: Low
- Chain: enum users → compute token → mass ATO = Critical
