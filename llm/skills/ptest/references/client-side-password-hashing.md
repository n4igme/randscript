# Client-Side Password Hashing Detection & Exploitation

## Trigger
- React/Vue/Angular SPA with login form
- JS bundles reference crypto/hashing libraries (CryptoJS, SubtleCrypto, sha256)
- Password field sent as fixed-length hex string (64 chars = SHA-256, 128 = SHA-512)

## Detection (Phase 2-3)

### From Burp/Traffic Capture
```
Look for password values that are hex strings:
- 64 chars = SHA-256: "19b1e4917389aa614b3db9b6bd72c26abd89c8d9a825896bb7a731600158efb3"
- 128 chars = SHA-512
- 32 chars = MD5
```

### From JS Bundle Analysis
```bash
# Search for hashing imports/usage
grep -oE "(sha256|SHA256|CryptoJS|crypto\.subtle|createHash|digest)" main.*.js
grep -oE "(hashPassword|encryptPassword|hash\(|\.digest\()" main.*.js
```

## Security Impact

### Why Client-Side Hashing Is a Finding (Low-Medium)
1. **Hash IS the credential** — if an attacker captures the hash (via MitM, XSS, log leak), they can replay it directly without knowing the plaintext
2. **No server-side salting** — the server likely stores exactly what it receives, or re-hashes it. If the server stores the client hash as-is, database compromise = immediate auth bypass
3. **False sense of security** — developers think "we hash the password" but the hash becomes the new password-equivalent
4. **Offline cracking still viable** — SHA-256 without salt is fast to brute-force (rainbow tables, hashcat)

### Exploitation Chain
1. Capture SHA-256 hash from Burp/traffic
2. Use it directly in login request (no need to crack):
   ```bash
   curl -X POST -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"<captured_sha256_hash>"}' \
     https://target/api/auth/login
   ```
3. If hash was rotated, attempt cracking with hashcat:
   ```bash
   echo "<hash>" > hash.txt
   hashcat -m 1400 hash.txt wordlist.txt  # mode 1400 = SHA-256
   ```

## Differential Field Naming for Auth Endpoint Discovery

### Pattern (AltoCMS, June 2026)
Different auth endpoints use different field names for the same concept:
- `/auth/login` → `username` + `password`
- `/auth/forgot-password` → `username_or_email`
- `/auth/login-otp` → `username` + `otp`
- `/auth/resend-otp` → `username`

### Technique
When you get `Invalid Parameter` (PRC-004 equivalent):
1. Try variants: `username`, `email`, `username_or_email`, `user`, `login`, `account`
2. For password: `password`, `pass`, `pwd`, `secret`, `credential`
3. For OTP: `otp`, `code`, `token`, `verification_code`, `2fa_code`

Response differentiation:
- Wrong field name → parameter validation error (e.g., PRC-004)
- Right field name + wrong value → business logic error (e.g., USR-001)
- This reveals which fields each endpoint expects without documentation

## Reporting
- **Severity**: Low (client-side hashing alone) to Medium (if hash replay proven)
- **CWE**: CWE-328 (Use of Weak Hash), CWE-602 (Client-Side Enforcement of Server-Side Security)
- **Remediation**: Hash server-side with bcrypt/scrypt/argon2 + unique salt. TLS protects in-transit; client-side hashing adds no real security.
