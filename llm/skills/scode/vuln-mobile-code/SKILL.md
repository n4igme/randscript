---
name: vuln-mobile-code
description: "Scan for mobile app vulnerabilities in decompiled Android/iOS, React Native, and Flutter code (hardcoded secrets, insecure storage, cert pinning, WebView). Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Mobile Code Review

Scan for vulnerabilities in mobile app source code or decompiled output (Android, iOS, React Native, Flutter).

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Applicability

```bash
find . \( -name "*.smali" -o -name "*.dex" -o -name "AndroidManifest.xml" -o -name "Info.plist" -o -name "*.swift" -o -name "*.m" -o -name "index.android.bundle" -o -name "main.dart.js" \) -not -path "*/node_modules/*" | head -1
```
If no results → report "No mobile code found — scanner not applicable" and skip.

## Vulnerability Patterns

### Hardcoded Secrets
- Android: `BuildConfig` fields, `strings.xml`, gradle `buildConfigField`
- iOS: `Info.plist` keys, hardcoded string constants
- React Native: secrets in JS bundle (extractable without root)
- Flutter: `const` values, `.env` files bundled

**Grep patterns**: `BuildConfig.`, `api_key`, `secret`, `client_secret`, `CFBundleURLSchemes`

### Insecure Network Communication
- HTTP (not HTTPS) URLs in production
- Certificate pinning absent or trust-all implementations
- `AllowsArbitraryLoads` in iOS ATS config

**Grep patterns**: `http://`, `TrustAllCerts`, `ALLOW_ALL_HOSTNAME`, `AllowsArbitraryLoads`, `setHostnameVerifier`

### Insecure Data Storage
- Android: `MODE_WORLD_READABLE`, external storage for secrets, unencrypted SQLite
- iOS: `NSUserDefaults` for tokens, missing `FileProtectionType`
- React Native: `AsyncStorage` (unencrypted) for secrets
- Flutter: `shared_preferences` (plaintext) for tokens

**Grep patterns**: `MODE_WORLD_READABLE`, `getExternalStorage`, `UserDefaults`, `AsyncStorage.setItem`, `shared_preferences`

### WebView Security
- JavaScript enabled loading user-controlled URLs
- `@JavascriptInterface` exposing sensitive native methods
- File access enabled in WebView

**Grep patterns**: `setJavaScriptEnabled(true)`, `addJavascriptInterface`, `@JavascriptInterface`, `setAllowFileAccess`

### Intent/Deep Link Vulnerabilities (Android)
- Exported components without permission requirements
- Intent data used without validation
- WebView loading URLs from intents

**Grep patterns**: `exported="true"`, `getIntent().getData`, `android:scheme`

### Authentication Bypass
- Biometric auth without server-side validation
- Root/jailbreak detection only (client-side, bypassable)
- Token stored in SharedPreferences (not EncryptedSharedPreferences/Keystore)

**Grep patterns**: `BiometricPrompt`, `LAContext`, `isRooted`, `isJailbroken`, `SharedPreferences`

### Weak Cryptography
- DES/RC4/MD5/ECB mode for encryption
- Hardcoded keys/IVs in `SecretKeySpec` / `CCCrypt`
- `java.util.Random` / `arc4random` for security values

**Grep patterns**: `DES`, `RC4`, `ECB`, `SecretKeySpec`, `IvParameterSpec`, `java.util.Random`

## Process

1. **Find hardcoded secrets** — check BuildConfig, strings.xml, Info.plist, JS bundles
2. **Check network security** — HTTPS enforcement, cert pinning, ATS config
3. **Check data storage** — where are tokens/credentials stored? Encrypted?
4. **Audit WebView** — is JS enabled? Are native interfaces exposed? File access?
5. **Check exported components** — can other apps invoke sensitive activities?
6. **Verify auth mechanism** — is biometric/pin validated server-side?
7. **Assess impact** — credential theft, API key abuse, MitM, local bypass

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Mobile Code

**Date**: {date}
**Scanner**: vuln-mobile-code

## Findings

### VULN-MOB-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Hardcoded Secret / Insecure Network / Insecure Storage / WebView / Intent / Auth Bypass / Weak Crypto}
**Location**: `{file}:{line}`
**CWE**: CWE-{798|319|312|749|927|287|327}

**Description**:
{What the vulnerability is}

**Vulnerable Code**:
```{lang}
{code snippet}
`` `

**Attack Scenario**:
1. {How attacker exploits this — e.g., extract APK, decompile, find key}

**Impact**:
{API abuse, credential theft, MitM, unauthorized access}

**Remediation**:
```{lang}
{fixed code}
`` `

---
```

## Positive Observations

While scanning, note strong patterns. Add to `# Positive Security Observations` at end of `vulnerabilities.md`:

```markdown
- vuln-mobile-code: {what the codebase does well}
```

## Rules

- **Hardcoded read-only API keys for public data are Low** — only escalate if write access or private data.
- **Root/jailbreak detection alone is Low** — it's bypassable and only defense-in-depth.
- **Secrets in React Native bundles are extractable without root** — always High if production keys.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — Mobile Code` section, replace it entirely.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
