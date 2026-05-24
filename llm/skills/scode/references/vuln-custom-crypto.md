# Custom Cryptography & Validation Scanner

Scanner ID: **3x — custom-crypto**

## Skip Condition

No skip — applies to all codebases. Custom crypto/validation is language-agnostic.

---

## Focus Areas

### 1. Insecure Randomness for Security-Sensitive Values

**Pattern:** Using non-cryptographic PRNG for tokens, keys, session IDs, OTPs.

```bash
# JavaScript/TypeScript
grep -rn "Math\.random\|Math\.floor.*Math\.random" --include="*.js" --include="*.ts" | grep -v node_modules | grep -v test

# Java/Kotlin
grep -rn "java\.util\.Random\|Random()\|nextInt\|nextLong" --include="*.java" --include="*.kt" | grep -v "SecureRandom" | grep -v test

# Python
grep -rn "import random\|random\.randint\|random\.choice\|random\.random" --include="*.py" | grep -v "secrets\|os\.urandom" | grep -v test

# Go
grep -rn "math/rand\|rand\.Int\|rand\.Intn" --include="*.go" | grep -v "crypto/rand"
```

**What to check:**
- Is the random value used for: tokens, session IDs, OTP codes, password reset links, API keys, nonces?
- Is there a seed that's predictable (timestamp, PID, constant)?
- Can an attacker observe outputs and predict future values? (LCG state recovery)

---

### 2. Custom Hash/Checksum Implementations

**Pattern:** Homegrown validation instead of standard HMAC/JWT.

```bash
# XOR-based checksums
grep -rn "\^=\|XOR\|xor" --include="*.js" --include="*.ts" --include="*.java" --include="*.kt" --include="*.py" --include="*.go" | grep -v node_modules | grep -v test | grep -v ".git"

# Custom hash functions
grep -rn "function.*hash\|def.*hash\|func.*hash\|fun.*hash" --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.kt" | grep -v node_modules | grep -v test

# LCG constants (common multipliers)
grep -rn "1103515245\|214013\|1664525\|6364136223846793005\|0x5DEECE66D" --include="*.js" --include="*.ts" --include="*.java" --include="*.kt" --include="*.py" --include="*.go"

# Math.imul (often used in custom JS checksums)
grep -rn "Math\.imul" --include="*.js" --include="*.ts" | grep -v node_modules
```

**What to check:**
- Is the checksum/hash used for authentication or authorization decisions?
- Is the algorithm reversible? (XOR, LCG, simple modular arithmetic = reversible)
- Are all constants visible in client-side code? (attacker can replicate)
- Is there a server-side secret involved? (if not → forgeable)

---

### 3. Weak Password Hashing

```bash
# MD5/SHA1 for passwords (no salt, fast hash)
grep -rn "md5\|MD5\|sha1\|SHA1\|sha-1" --include="*.js" --include="*.ts" --include="*.java" --include="*.kt" --include="*.py" --include="*.go" | grep -i "password\|passwd\|credential\|hash" | grep -v node_modules | grep -v test

# Missing salt
grep -rn "createHash\|MessageDigest\|hashlib" --include="*.js" --include="*.ts" --include="*.java" --include="*.py" | grep -v "salt\|bcrypt\|argon\|scrypt\|pbkdf"

# Proper hashing (these are GOOD — note their absence)
grep -rn "bcrypt\|argon2\|scrypt\|pbkdf2\|PBKDF2" --include="*.js" --include="*.ts" --include="*.java" --include="*.kt" --include="*.py" --include="*.go" | grep -v node_modules | grep -v test
```

**Severity:**
- MD5/SHA1 without salt for passwords → High
- SHA256 without salt → Medium (fast, rainbow-table vulnerable)
- SHA256 with static salt → Medium (shared salt = batch crackable)
- bcrypt/argon2/scrypt with proper work factor → Secure

---

### 4. Hardcoded Encryption Keys / Static IVs

```bash
# Hardcoded keys (hex strings of key-length)
grep -rn "\"[0-9a-fA-F]\{32\}\"\|\"[0-9a-fA-F]\{64\}\"" --include="*.js" --include="*.ts" --include="*.java" --include="*.kt" --include="*.py" | grep -v node_modules | grep -v test

# Key/IV variable assignments
grep -rn "secretKey\s*=\|encryptionKey\s*=\|aesKey\s*=\|iv\s*=\|nonce\s*=" --include="*.js" --include="*.ts" --include="*.java" --include="*.kt" --include="*.py" | grep -v node_modules | grep -v test | grep -v "process\.env\|os\.environ\|System\.getenv\|getProperty"

# Static IV (reuse = breaks confidentiality for CBC/CTR)
grep -rn "IvParameterSpec\|createCipheriv\|AES.*iv\|initialization.vector" --include="*.js" --include="*.ts" --include="*.java" --include="*.kt" | grep -v node_modules | grep -v test
```

**What to check:**
- Is the key derived from environment/KMS or hardcoded in source?
- Is the IV/nonce random per encryption or static/counter?
- Is ECB mode used? (no IV needed but pattern-preserving = broken)
- Can an attacker with source code decrypt stored data?

---

### 5. Custom Token/License Validation

**Pattern:** Proprietary token format with reversible validation logic.

```bash
# Validation functions
grep -rn "function.*validate\|function.*verify\|def.*validate\|def.*verify\|func.*validate" --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.kt" --include="*.java" | grep -i "key\|token\|license\|code\|otp" | grep -v node_modules | grep -v test

# Bitwise operations in validation (common in license keys)
grep -rn ">>>\|<<\|& 0x\|& 0xFF\|\^ 0x" --include="*.js" --include="*.ts" --include="*.java" --include="*.kt" | grep -v node_modules | grep -v test

# Modular arithmetic in validation
grep -rn "% [0-9]\|mod\s" --include="*.js" --include="*.ts" --include="*.java" --include="*.kt" --include="*.py" | grep -i "valid\|check\|verify\|key\|token" | grep -v node_modules | grep -v test
```

**What to check:**
- Is the validation purely algorithmic (no server-side secret)? → forgeable
- Can all constraints be solved independently? (constraint solving)
- Is there a counter/rate limit, or unlimited attempts?
- Is the token checked client-side only? (trivial bypass)

---

### 6. Timing Side Channels

```bash
# String comparison for secrets (vulnerable to timing attack)
grep -rn "===\|==\|equals\|strcmp" --include="*.js" --include="*.ts" --include="*.java" --include="*.kt" --include="*.py" | grep -i "token\|secret\|key\|hash\|signature\|hmac\|password" | grep -v node_modules | grep -v test

# Secure comparison (these are GOOD)
grep -rn "timingSafeEqual\|constantTimeCompare\|hmac\.Equal\|MessageDigest\.isEqual\|compare_digest" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" --include="*.py" | grep -v node_modules
```

**What to check:**
- Is a secret/token/HMAC compared with `===` or `==`? (timing leak)
- Is `crypto.timingSafeEqual()` or equivalent used?
- Is the comparison over a network? (timing amplification possible)

---

### 7. JWT Implementation Flaws

```bash
# Custom JWT handling (not using standard library)
grep -rn "jwt\|jsonwebtoken\|jose\|JWT" --include="*.js" --include="*.ts" --include="*.java" --include="*.kt" --include="*.py" | grep -v node_modules | grep -v test

# Algorithm not enforced
grep -rn "algorithms\|algorithm\|alg" --include="*.js" --include="*.ts" --include="*.java" --include="*.py" | grep -i "jwt\|verify\|decode" | grep -v node_modules

# None algorithm accepted
grep -rn "none\|\"alg\"" --include="*.js" --include="*.ts" | grep -i "jwt\|token" | grep -v node_modules
```

**What to check:**
- Is the algorithm enforced on verification? (alg:none attack)
- Is the secret/key hardcoded or from environment?
- Is RS256→HS256 confusion possible? (public key as HMAC secret)
- Are claims validated? (exp, iss, aud, nbf)

---

### 8. OTP/TOTP Implementation

```bash
# OTP generation
grep -rn "otp\|totp\|hotp\|speakeasy\|otplib\|pyotp" --include="*.js" --include="*.ts" --include="*.py" --include="*.java" --include="*.kt" | grep -v node_modules | grep -v test

# Custom OTP (not using standard library)
grep -rn "Math\.random.*[0-9]\{4,6\}\|random.*pin\|random.*code\|random.*otp" --include="*.js" --include="*.ts" --include="*.py" --include="*.java" | grep -v node_modules | grep -v test
```

**What to check:**
- Is OTP generated with `Math.random()` / `java.util.Random`? (predictable)
- What's the OTP length? (4 digits = 10K possibilities, 6 digits = 1M)
- Is there rate limiting on verification?
- Is the OTP invalidated after use? After timeout?
- Can the same OTP be used across different flows?

---

## Finding Severity Guide

| Pattern | Typical Severity | Condition for Upgrade |
|---------|-----------------|---------------------|
| Math.random() for session token | High | Predictable → session hijack |
| Math.random() for non-security value | Info | No security impact |
| MD5 password hash without salt | High | Bulk crackable |
| Hardcoded AES key in source | High-Critical | Attacker can decrypt all data |
| Static IV with AES-CBC | Medium | Known-plaintext → decrypt |
| Custom license key (reversible) | Medium | Depends on what it protects |
| String comparison for HMAC | Medium | Timing attack (network amplification needed) |
| JWT alg:none accepted | Critical | Complete auth bypass |
| 4-digit OTP with no rate limit | High | Brute-forceable in minutes |
| Client-side-only validation | High | Trivial bypass |

---

## Cross-Reference

- **ptest skill**: `references/proprietary-crypto-reversing.md` — exploitation/solving perspective
- **vuln-authn-session.md**: JWT and session management (broader scope)
- **vuln-injection.md**: If crypto output flows into injection sink
- **vuln-data-exposure.md**: If weak crypto exposes sensitive data
