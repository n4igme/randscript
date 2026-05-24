# Bug Bounty — Step 3i: Cryptographic Failures

Scan for weak or misused cryptography that could lead to data exposure or integrity bypass.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Vulnerability Patterns

### Weak Algorithms
- MD5/SHA1 used for integrity or password hashing
- DES/3DES/RC4 for encryption
- RSA with key < 2048 bits
- ECB mode usage

**Grep patterns**: `md5`, `sha1`, `DES`, `3DES`, `RC4`, `ECB`, `createHash`, `createCipher`, `crypto.subtle`

### Improper Key Management
- Hardcoded encryption keys/IVs
- Static or predictable IVs/nonces
- Keys derived from weak sources (timestamps, sequential)
- Keys stored alongside encrypted data
- Missing key rotation

**Grep patterns**: `key =`, `iv =`, `nonce =`, `SECRET_KEY`, `ENCRYPTION_KEY`, `AES_KEY`, `Buffer.from(`, `createCipheriv`

### TLS/Transport Issues
- TLS verification disabled (`rejectUnauthorized: false`, `verify=False`)
- Allowing outdated TLS versions (TLS 1.0/1.1)
- Self-signed certificate acceptance in production
- Mixed content (HTTP resources on HTTPS pages)

**Grep patterns**: `rejectUnauthorized`, `verify=False`, `CERT_NONE`, `InsecureRequestWarning`, `ssl`, `tls`, `https`, `NODE_TLS_REJECT_UNAUTHORIZED`

### Random Number Generation
- `Math.random()` for security-sensitive values (tokens, IDs)
- Predictable seed values
- Non-CSPRNG for cryptographic operations

**Grep patterns**: `Math.random`, `random.random`, `rand()`, `srand`, `crypto.randomBytes`, `secrets.`, `os.urandom`

### Encryption Misuse
- Encryption without authentication (no HMAC/GCM)
- Padding oracle potential (CBC without MAC-then-encrypt)
- Reused nonces in stream ciphers/GCM
- Custom crypto implementations

**Grep patterns**: `encrypt(`, `decrypt(`, `AES`, `GCM`, `CBC`, `CTR`, `HMAC`, `createSign`, `createVerify`

## Process

For each priority target from threat-model.md:

1. **Identify crypto usage** — find all encryption, hashing, signing, and random generation calls
2. **Assess algorithm strength** — are algorithms current and appropriate for their use case?
3. **Check key handling** — are keys properly generated, stored, and rotated?
4. **Verify transport security** — is TLS properly enforced and validated?
5. **Assess impact** — data decryption, forgery, integrity bypass

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Cryptographic Failures

**Date**: {date}
**Scanner**: vuln-crypto

## Findings

### VULN-CRYPTO-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Weak Algorithm / Key Management / TLS Issue / Weak RNG / Encryption Misuse}
**Location**: `{file}:{line}`
**CWE**: CWE-{327|321|326|330|328}

**Description**:
{What the vulnerability is}

**Vulnerable Code**:
```{lang}
{code snippet}
`` `

**Attack Scenario**:
1. {Step-by-step exploitation}

**Impact**:
{What attacker gains — data decryption, token forgery, MITM}

**Remediation**:
```{lang}
{fixed code}
`` `

---
```

## Rules

- **Only report crypto weaknesses with real impact** — MD5 for cache keys is not a vuln; MD5 for passwords is.
- **Context matters** — assess whether the crypto protects sensitive data or security-critical operations.
- **Include what the correct algorithm/approach should be.**
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — Cryptographic Failures` section, replace it entirely. See `sc3-vuln-scan` idempotency rule.
- **Save to `./assessment/vulnerabilities.md`** and confirm.