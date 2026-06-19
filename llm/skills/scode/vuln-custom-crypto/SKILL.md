---
name: vuln-custom-crypto
description: "Scan for custom cryptography vulnerabilities (insecure PRNG, homegrown hashing, hardcoded keys, timing attacks, weak OTP). Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Custom Cryptography & Validation Vulnerabilities

Scan for homegrown crypto, insecure randomness, weak hashing, and custom token validation that bypasses standard security primitives.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Applicability

No skip — applies to all codebases. Custom crypto/validation is language-agnostic.

## Vulnerability Patterns

### Insecure Randomness for Security Values
- `Math.random()` / `java.util.Random` / `import random` for tokens, OTPs, session IDs
- Predictable seeds (timestamp, PID, constant)

**Grep patterns**:
- JS: `Math.random`, `Math.floor.*Math.random`
- Java: `java.util.Random`, `Random()`, `nextInt`
- Python: `import random`, `random.randint`, `random.choice`
- Go: `math/rand`, `rand.Int`, `rand.Intn`

### Custom Hash/Checksum Implementations
- XOR-based checksums for authentication decisions
- LCG constants (1103515245, 214013, 1664525)
- Homegrown validation instead of standard HMAC/JWT

**Grep patterns**: `^=`, `XOR`, `xor`, `function.*hash`, `def.*hash`, `Math.imul`

### Weak Password Hashing
- MD5/SHA1 without salt for passwords
- SHA256 with static salt
- Missing bcrypt/argon2/scrypt

**Grep patterns**: `md5`, `sha1`, `createHash`, `MessageDigest`, `hashlib` near `password`

### Hardcoded Encryption Keys / Static IVs
- Key/IV as hex string constant in source
- Static IV reuse (breaks CBC/CTR confidentiality)
- ECB mode usage

**Grep patterns**: `secretKey =`, `encryptionKey =`, `aesKey =`, `iv =`, `IvParameterSpec`, `createCipheriv`

### Custom Token/License Validation
- Reversible algorithmic validation without server-side secret
- Client-side-only validation (trivial bypass)
- Unlimited verification attempts

**Grep patterns**: `function.*validate`, `def.*verify` near `token`/`license`/`key`

### Timing Side Channels
- `===` / `==` / `equals` for secret comparison (timing leak)
- Missing `timingSafeEqual` / `constantTimeCompare`

**Grep patterns**: `===` near `token`/`secret`/`hmac`, `timingSafeEqual`, `compare_digest`

### JWT Implementation Flaws
- Algorithm not enforced on verification (alg:none attack)
- RS256→HS256 confusion
- Claims not validated (exp, iss, aud)

**Grep patterns**: `jwt`, `jsonwebtoken`, `jose`, `algorithms`, `alg`

### OTP/TOTP Issues
- OTP generated with non-crypto PRNG
- No rate limiting on verification
- OTP not invalidated after use/timeout

**Grep patterns**: `otp`, `totp`, `hotp`, `speakeasy`, `otplib`, `pyotp`

## Process

1. **Find all randomness usage** — is crypto-grade PRNG used for security values?
2. **Find custom hash/validation** — is there homegrown crypto instead of standard libraries?
3. **Check key management** — are keys from env/KMS or hardcoded?
4. **Check comparisons** — are secrets compared with constant-time functions?
5. **Check JWT handling** — algorithm enforced? Claims validated?
6. **Assess impact** — token forgery, session prediction, data decryption

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Custom Cryptography

**Date**: {date}
**Scanner**: vuln-custom-crypto

## Findings

### VULN-CRYPTO-C-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Insecure Random / Weak Hash / Hardcoded Key / Custom Validation / Timing / JWT / OTP}
**Location**: `{file}:{line}`
**CWE**: CWE-{330|328|321|208|347}

**Description**:
{What the vulnerability is}

**Vulnerable Code**:
```{lang}
{code snippet}
`` `

**Attack Scenario**:
1. {How attacker exploits the weakness}

**Impact**:
{Token forgery, session hijack, data decryption, auth bypass}

**Remediation**:
```{lang}
{fixed code using proper crypto primitives}
`` `

---
```

## Positive Observations

While scanning, note strong patterns. Add to `# Positive Security Observations` at end of `vulnerabilities.md`:

```markdown
- vuln-custom-crypto: {what the codebase does well}
```

## Rules

- **Math.random() is only a finding when used for security-sensitive values** — UI randomization is fine.
- **Context matters for severity** — MD5 for cache keys is fine; MD5 for passwords is High.
- **Check if standard library is available** — report if homegrown crypto replaces a standard option.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — Custom Cryptography` section, replace it entirely.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
