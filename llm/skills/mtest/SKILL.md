---
name: mtest
version: 1.0.0
description: "Structured mobile application penetration testing framework with gated phases for Android and iOS"
tags: [mobile, pentest, android, ios, frida, security]
trigger: "mobile pentest, mobile app test, APK test, IPA test, android security, ios security"
argument-hint: "<command: start|status|next|report>"
---

# Mobile Application Penetration Testing (mtest)

## Overview

Gated linear workflow for mobile application security testing. Each phase must complete before advancing. Covers both Android and iOS with static analysis, dynamic instrumentation, and API testing.

## Commands

| Command | Action |
|---------|--------|
| `start` | Begin new engagement — create output dir, define scope |
| `status` | Show current phase, progress, findings count |
| `resume` | Resume interrupted engagement — read state and continue |
| `next` | Advance to next phase (requires current phase gate satisfied) |
| `report` | Generate findings report (available from Phase 5+) |
| `cleanup` | Archive output, sanitize sensitive data |

## Output Structure

```
<workdir>/mtest-output/
├── state.yaml                # Engagement state tracker
├── scope.md                  # Engagement scope and targets
├── phase1-preflight/         # Tool setup verification
├── phase2-static/            # Decompilation, secrets, endpoints
│   ├── android/
│   └── ios/
├── phase3-dynamic-setup/     # Bypass scripts, proxy config
│   └── scripts/              # Frida scripts used
├── phase4-traffic/           # Intercepted requests, API map
├── phase5-runtime/           # Frida hooks, data storage, deep links
│   ├── screenshots/
│   └── frida-output/
├── phase6-api/               # Server-side API testing
├── findings/                 # Individual finding files
│   ├── MTEST-001.md
│   └── ...
└── report.md                 # Final report
```

## State Tracking

On `start`, create `state.yaml`:

```yaml
engagement:
  name: ""
  target_app: ""
  package_id: ""
  bundle_id: ""
  started: ""
  platforms: []  # android, ios, or both

gateways:
  1_preflight: OPEN
  2_static_analysis: LOCKED
  3_dynamic_setup: LOCKED
  4_traffic_analysis: LOCKED
  5_runtime_testing: LOCKED
  6_api_testing: LOCKED
  7_reporting: LOCKED

findings_count: 0
current_phase: 1

time_tracking:
  phase_1_start: ""
  phase_1_end: ""
  phase_2_start: ""
  phase_2_end: ""
  phase_3_start: ""
  phase_3_end: ""
  phase_4_start: ""
  phase_4_end: ""
  phase_5_start: ""
  phase_5_end: ""
  phase_6_start: ""
  phase_6_end: ""
  phase_7_start: ""
  phase_7_end: ""

notes: ""
```

### Finding ID Assignment

1. Read `findings_count` from `state.yaml`
2. Increment by 1
3. Use as finding ID: `MTEST-{count:03d}` (e.g., MTEST-001)
4. Write updated count back immediately

### Resume (`resume`)

1. Read `./mtest-output/state.yaml` to determine active phase
2. Read phase-specific output files to see what's completed
3. Report status and suggest next action
4. If `state.yaml` missing — scan output directories to reconstruct state

### Gateway Transition (`next`)

1. Verify phase gate criteria met (see each phase's Gate section)
2. Ask user confirmation: "Phase X complete. N findings. Advance to Phase Y?"
3. Update `state.yaml`: mark current gateway PASSED, unlock next, record timestamps

### Cleanup (`cleanup`)

1. Archive `./mtest-output/` to `mtest-output-{app}-{date}.tar.gz`
2. Remove YOUR credentials (proxy certs, test tokens) — keep found credentials as evidence
3. Print summary: findings by severity, phases completed, duration

---

## Phase 1: Preflight

### Gate: scope.md exists, target app identified, tools verified

**Steps:**

1. Define scope:
   - Platform(s): Android / iOS / Both
   - App name and package/bundle ID
   - Version(s) to test
   - Testing type: black-box / grey-box / white-box
   - Device requirements: rooted/jailbroken, emulator acceptable?
   - Rules of engagement: what's off-limits

2. Acquire target app:
   ```bash
   # Android — from device
   adb shell pm list packages | grep -i <keyword>
   adb shell pm path <package>
   adb pull <path> target.apk

   # Android — from APKMirror/APKPure (black-box)
   # Download manually or use apkeep
   pip install apkeep
   apkeep -a <package_name> .

   # iOS — from jailbroken device (decrypted)
   python frida-ios-dump/dump.py <bundle_id>

   # iOS — from App Store (encrypted, limited use)
   ipatool download -b <bundle_id> -o target.ipa
   ```

3. Verify tooling:
   ```bash
   # Core tools check
   which jadx apktool frida objection adb 2>/dev/null
   frida --version
   objection version

   # Android emulator or device
   adb devices

   # Proxy (Burp/Caido) running
   curl -x http://127.0.0.1:8080 http://example.com
   ```

4. Create output directory and scope.md

**Reference:** `preflight-checklist.md`

---

## Phase 2: Static Analysis

### Gate: decompilation complete, secrets scan done, endpoints extracted

**Steps:**

1. Decompile and disassemble:
   ```bash
   # Android
   jadx -d jadx_out/ target.apk
   apktool d target.apk -o apktool_out/

   # iOS
   unzip target.ipa -d ipa_out/
   class-dump ipa_out/Payload/*.app/* > headers.h
   ```

2. Manifest/Info.plist analysis:
   - Android: debuggable, allowBackup, exported components, network security config
   - iOS: ATS exceptions, URL schemes, entitlements

3. Secrets hunting:
   - API keys, tokens, credentials in source
   - Firebase/cloud URLs
   - Private keys/certs in assets
   - Base64-encoded secrets

4. Endpoint extraction:
   - All HTTP(S) URLs in source
   - API path patterns
   - WebSocket endpoints
   - Third-party service integrations

5. Binary protections check:
   - Android: ProGuard/R8 obfuscation, native libs
   - iOS: PIE, stack canary, ARC, code signing

6. Automated scanning:
   ```bash
   # MobSF (comprehensive)
   docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
   # Upload APK/IPA at http://localhost:8000
   ```

**Reference:** `static-analysis.md`

---

## Phase 3: Dynamic Setup

### Gate: proxy intercepting traffic, bypass scripts working, app launches normally

**Steps:**

1. Install proxy CA certificate:
   ```bash
   # Android (system-level, requires root)
   openssl x509 -inform DER -in cacert.der -out cacert.pem
   HASH=$(openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1)
   cp cacert.pem ${HASH}.0
   adb root && adb remount
   adb push ${HASH}.0 /system/etc/security/cacerts/
   adb shell "chmod 644 /system/etc/security/cacerts/${HASH}.0"
   adb reboot

   # iOS
   # Settings > General > Profile > Install Burp CA
   # Settings > About > Certificate Trust Settings > Enable Full Trust
   ```

2. Configure proxy:
   ```bash
   # Android
   adb shell settings put global http_proxy <host_ip>:8080

   # Invisible proxy (apps ignoring system proxy)
   adb shell iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to <host_ip>:8080
   adb shell iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to <host_ip>:8080
   ```

3. SSL pinning bypass:
   ```bash
   # Frida (comprehensive)
   frida -U -f <package> -l ssl_pinning_bypass.js --no-pause

   # Objection (quick)
   objection -g <package> explore
   android sslpinning disable   # or: ios sslpinning disable

   # APK patching (persistent, no Frida needed)
   # Inject network_security_config.xml trusting user CAs
   # Rebuild + re-sign APK
   ```

4. Root/jailbreak detection bypass:
   ```bash
   # Frida (comprehensive)
   frida -U -f <package> -l root_bypass.js --no-pause

   # Objection (quick)
   objection -g <package> explore
   android root disable   # or: ios jailbreak disable

   # Combined launch
   frida -U -f <package> -l root_bypass.js -l ssl_pinning_bypass.js --no-pause
   ```

5. Verify: app launches, traffic visible in proxy, no detection popups

**Reference:** `dynamic-setup.md`, `frida-scripts.md`

---

## Phase 4: Traffic Analysis

### Gate: API endpoints mapped, auth flow documented, at least one full user journey captured

**Steps:**

1. Capture baseline traffic:
   - Launch app, complete registration/login flow
   - Navigate all major features
   - Trigger push notifications, background sync
   - Export all requests from proxy

2. Map API surface:
   - Base URLs and versioning
   - Authentication mechanism (JWT, OAuth, session, API key)
   - Request/response patterns
   - File upload/download endpoints
   - WebSocket connections

3. Document auth flow:
   - Login sequence (OTP, biometric, PIN)
   - Token lifecycle (access token, refresh token, expiry)
   - Session management
   - Multi-factor authentication steps

4. Identify interesting patterns:
   - Sequential/predictable IDs (IDOR candidates)
   - Sensitive data in responses (PII, financial data)
   - Missing security headers
   - Verbose error messages
   - Rate limiting (or lack thereof)
   - Certificate pinning coverage gaps

**Reference:** `traffic-analysis.md`

---

## Phase 5: Runtime Testing

### Gate: at least 3 test categories completed from the checklist below

**Test Categories:**

1. **Data Storage:**
   ```bash
   # Android SharedPreferences
   adb shell "run-as <package> cat /data/data/<package>/shared_prefs/*.xml"

   # Android SQLite
   adb shell "run-as <package> ls /data/data/<package>/databases/"

   # iOS Keychain
   objection -g <bundle_id> explore
   ios keychain dump

   # iOS NSUserDefaults
   ios nsuserdefaults get

   # Clipboard monitoring
   # Logcat sensitive data
   adb logcat | grep -i "token\|password\|key\|secret"
   ```

2. **Deep Link / URL Scheme Injection:**
   ```bash
   # Android
   adb shell am start -a android.intent.action.VIEW -d "scheme://path?param=INJECTED"

   # iOS (via Frida)
   # Test: open redirect, XSS via WebView, auth bypass
   ```

3. **WebView Attacks:**
   - JavaScript enabled + addJavascriptInterface = RCE potential
   - File access from WebView context
   - URL loading with user-controlled input

4. **Intent/IPC Injection (Android):**
   ```bash
   adb shell am start -n <package>/.ExportedActivity
   adb shell am broadcast -a <package>.ACTION --es "data" "injected"
   adb shell content query --uri content://<package>.provider/table
   ```

5. **Biometric/PIN Bypass:**
   - Hook biometric callbacks via Frida
   - Check if auth is client-side only vs server-validated
   - Test fallback mechanisms

6. **Screenshot/Screen Recording Protection:**
   - Check FLAG_SECURE on sensitive screens
   - Test screen capture during sensitive operations

7. **Binary Patching:**
   - Modify smali to skip checks
   - Patch conditional jumps
   - Re-sign and test modified behavior

**Reference:** `runtime-testing.md`, `frida-scripts.md`

---

## Phase 6: API Testing (Server-side)

### Gate: at least BOLA, auth bypass, and injection tests completed

**Steps:**

1. **BOLA/IDOR:**
   - Swap user IDs, account numbers, transaction IDs
   - Test horizontal access (user A accessing user B's data)
   - Test vertical access (regular user accessing admin endpoints)

2. **Authentication Bypass:**
   - Remove/modify Authorization header
   - JWT manipulation (none algorithm, key confusion, expired token reuse)
   - OTP bypass (rate limit, reuse, predictable)
   - Password reset flow abuse

3. **Injection:**
   - SQL injection in API parameters
   - NoSQL injection (MongoDB operators)
   - Command injection in file processing
   - GraphQL injection (introspection, batching)

4. **Business Logic:**
   - Negative amounts in transfers
   - Race conditions (double-spend, parallel requests)
   - Step skipping in multi-step flows
   - Coupon/promo code abuse

5. **Rate Limiting & Brute Force:**
   - OTP brute force
   - Login attempts
   - API abuse (scraping, enumeration)

6. **Data Exposure:**
   - Excessive data in responses
   - Debug endpoints accessible
   - Stack traces in errors
   - Internal IPs/paths leaked

**Cross-reference:** Load ptest skill's `enumeration.md` and `attack-surface.md` for comprehensive API testing techniques.

---

## Phase 7: Reporting

### Steps:

1. Compile findings with:
   - Title and severity (Critical/High/Medium/Low/Info)
   - Affected component (client/server/both)
   - Platform (Android/iOS/both)
   - Steps to reproduce (with screenshots/video)
   - Impact statement
   - Remediation recommendation
   - OWASP Mobile Top 10 mapping

2. Generate report.md with:
   - Executive summary
   - Scope and methodology
   - Findings table (sorted by severity)
   - Detailed findings
   - Appendix: tool versions, device info, test dates

---

## Finding Template

```markdown
# MTEST-XXX: [Title]

**Severity:** Critical|High|Medium|Low|Info
**Platform:** Android|iOS|Both
**Component:** Client|Server|Both
**OWASP Mobile:** M1-M10 mapping

## Description
[What the vulnerability is]

## Steps to Reproduce
1. ...
2. ...
3. ...

## Evidence
[Screenshots, request/response, Frida output]

## Impact
[What an attacker can achieve]

## Remediation
[How to fix it]
```

---

## Severity Guidelines (Mobile-specific)

| Severity | Examples |
|----------|----------|
| Critical | Hardcoded credentials with server access, RCE via WebView, auth bypass exposing all accounts |
| High | SSL pinning absent on banking app, plaintext token storage, BOLA on financial endpoints |
| Medium | Missing root detection, exported activities with sensitive data, weak crypto |
| Low | Missing screenshot protection, clipboard exposure, verbose logs |
| Info | Missing obfuscation, outdated SDK versions, unused permissions |

---

## Operational Notes

- Always test on a **dedicated device/emulator** — never on a personal device with real accounts
- Some apps detect emulators (check for `generic`, `sdk`, `genymotion` in Build properties) — prefer rooted physical device
- Frida detection is increasingly common in banking apps — have fallback: Gadget injection, patched APK, or Magisk+Zygisk hide
- iOS testing requires a **jailbroken device** for most dynamic tests — checkra1n (A11 and below) or palera1n (A11-A16)
- Save all Frida scripts to `phase3-dynamic-setup/scripts/` for reproducibility
- When app uses certificate transparency or multiple pinning layers, combine approaches (Frida + patched config + invisible proxy)
- **Client-side only** findings (no server validation) are typically Medium unless they expose sensitive data
- Cross-reference extracted API endpoints with ptest skill for comprehensive server-side testing
