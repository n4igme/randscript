# OWASP Mobile Top 10 (2024) Mapping

## M1: Improper Credential Usage

**What:** Hardcoded credentials, insecure credential storage, improper use of biometrics.

**Test in mtest phases:**
- Phase 2: Hardcoded secrets in source code
- Phase 5: Token storage analysis (SharedPrefs vs Keystore)
- Phase 5: Biometric bypass (client-side only auth)

**Finding examples:**
- API key hardcoded in source → Critical
- JWT stored in SharedPreferences (plaintext) → High
- Biometric auth is client-side only (no CryptoObject) → High
- Password stored in NSUserDefaults → High

---

## M2: Inadequate Supply Chain Security

**What:** Third-party libraries with known vulnerabilities, malicious SDKs.

**Test in mtest phases:**
- Phase 2: Identify all third-party SDKs/frameworks
- Phase 2: Check library versions against CVE databases

**Finding examples:**
- Outdated OkHttp with known CVE → Medium
- Analytics SDK sending PII without consent → Medium
- Vulnerable WebView library → varies by CVE

**Tools:**
```bash
# Android: check dependencies
grep -rn "implementation\|compile" build.gradle 2>/dev/null
# Or from APK: check lib/ folder and class names

# iOS: check frameworks
ls ipa_out/Payload/*.app/Frameworks/
# Check Podfile.lock if available

# Vulnerability check
# https://ossindex.sonatype.org/
# https://snyk.io/vuln/
```

---

## M3: Insecure Authentication/Authorization

**What:** Weak auth mechanisms, missing server-side validation, bypassable client controls.

**Test in mtest phases:**
- Phase 4: Auth flow documentation
- Phase 5: Biometric/PIN bypass
- Phase 6: BOLA/IDOR, JWT attacks, OTP bypass

**Finding examples:**
- No rate limiting on OTP verification → High
- JWT none algorithm accepted → Critical
- IDOR on user profile endpoint → High
- Session not invalidated on logout → Medium
- Missing re-authentication for sensitive operations → Medium

---

## M4: Insufficient Input/Output Validation

**What:** SQL injection, XSS in WebViews, path traversal, command injection.

**Test in mtest phases:**
- Phase 5: Deep link injection, WebView attacks
- Phase 6: SQL/NoSQL injection, GraphQL attacks

**Finding examples:**
- SQL injection in search API → Critical
- XSS via deep link → WebView → High
- Path traversal in content provider → High
- NoSQL injection in login → Critical

---

## M5: Insecure Communication

**What:** Missing SSL/TLS, weak cipher suites, no certificate pinning.

**Test in mtest phases:**
- Phase 2: Network security config analysis, ATS exceptions
- Phase 3: SSL pinning bypass (how easy was it?)
- Phase 4: Check for HTTP endpoints, weak TLS

**Finding examples:**
- No certificate pinning on banking API → High
- cleartext HTTP allowed (network_security_config) → High
- NSAllowsArbitraryLoads = true → High
- TLS 1.0/1.1 supported → Medium
- Pinning only on some domains (gaps) → Medium

**Note:** If pinning bypass was trivial (objection one-liner worked), document the pinning implementation quality.

---

## M6: Inadequate Privacy Controls

**What:** PII exposure, excessive data collection, missing data minimization.

**Test in mtest phases:**
- Phase 4: Excessive data in API responses
- Phase 5: Data storage audit, clipboard, logs
- Phase 6: Data exposure in error messages

**Finding examples:**
- Full card number in API response (UI masks it) → High
- PII in application logs → Medium
- Sensitive data copied to clipboard → Medium
- Analytics SDK collecting device identifiers without consent → Medium
- User location tracked without clear consent → Medium

---

## M7: Insufficient Binary Protections

**What:** Missing obfuscation, no anti-tampering, no anti-debugging.

**Test in mtest phases:**
- Phase 2: Obfuscation assessment, binary protections
- Phase 3: How easily were root/jailbreak detections bypassed?

**Finding examples:**
- No code obfuscation (ProGuard/R8) → Low
- No root/jailbreak detection → Medium
- No anti-debugging protection → Low
- No integrity verification (app runs after patching) → Medium
- Missing PIE/stack canary (iOS) → Low

**Note:** These are defense-in-depth measures. Absence is typically Medium/Low unless combined with other findings that make exploitation trivial.

---

## M8: Security Misconfiguration

**What:** Debug flags, excessive permissions, insecure default settings.

**Test in mtest phases:**
- Phase 2: Manifest analysis (debuggable, backup, exported components)
- Phase 5: Intent injection on exported components

**Finding examples:**
- android:debuggable="true" in production → Critical
- android:allowBackup="true" with sensitive data → High
- Exported activity exposes sensitive functionality → High
- Excessive permissions (camera, contacts, location without need) → Low
- Debug endpoints accessible in production → High

---

## M9: Insecure Data Storage

**What:** Sensitive data stored insecurely on device.

**Test in mtest phases:**
- Phase 5: SharedPreferences, SQLite, Keychain, NSUserDefaults audit

**Finding examples:**
- Auth token in SharedPreferences (plaintext XML) → High
- PIN/password stored locally (even if encrypted with weak key) → High
- Keychain item with kSecAttrAccessibleAlways → High
- Sensitive data in SQLite without SQLCipher → Medium
- Session data survives app uninstall (external storage) → Medium
- Cached API responses with PII → Medium

**Severity depends on:**
- What data is stored (auth tokens > preferences)
- How it's protected (plaintext > weak encryption > strong encryption)
- Access requirements (no auth > device unlock > biometric)

---

## M10: Insufficient Cryptography

**What:** Weak algorithms, hardcoded keys, improper implementation.

**Test in mtest phases:**
- Phase 2: Identify crypto usage in source
- Phase 5: Crypto key extraction via Frida

**Finding examples:**
- Hardcoded AES key in source code → Critical
- MD5/SHA1 for password hashing → High
- ECB mode encryption → High
- Predictable IV (all zeros, static) → High
- Custom crypto implementation (not using standard libraries) → High
- Key derived from device ID (predictable) → Medium

**Tools:**
```javascript
// Frida: Monitor crypto operations (see frida-scripts.md crypto_hooks.js)
// Extracts: algorithm, key material, IV, plaintext/ciphertext
```

---

## Severity Mapping Quick Reference

| OWASP | Typical Severity | Key Question |
|-------|-----------------|--------------|
| M1 | Critical-High | Can attacker get credentials without device access? |
| M2 | Medium | Are vulnerable libs actually exploitable in context? |
| M3 | Critical-High | Can attacker access other users' data/actions? |
| M4 | Critical-High | Can attacker execute code or access unauthorized data? |
| M5 | High-Medium | Can attacker intercept sensitive traffic? |
| M6 | Medium | Is PII exposed beyond what's necessary? |
| M7 | Medium-Low | Do missing protections enable other attacks? |
| M8 | Critical-Low | Does misconfiguration directly expose data/functionality? |
| M9 | High-Medium | What data is at risk if device is compromised? |
| M10 | Critical-Medium | Can attacker decrypt sensitive data? |

---

## Report Mapping Template

When writing findings, include OWASP Mobile mapping:

```markdown
# MTEST-001: JWT Stored in SharedPreferences

**OWASP Mobile:** M1 (Improper Credential Usage), M9 (Insecure Data Storage)
**Severity:** High
**CWE:** CWE-312 (Cleartext Storage of Sensitive Information)
```
