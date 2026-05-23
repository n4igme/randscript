---
name: mtest
version: 1.1.0
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

### N/A Phases

If a phase is genuinely not applicable (e.g., no API backend for Phase 6, no pinning/root detection for Phase 3), document the justification in the phase summary file and mark the gateway as `N/A` in state.yaml. Do NOT skip silently — always write a summary explaining why the phase doesn't apply. This counts as satisfying the gate.

### Offline/No-Network App Fast-Path

When the app has **no internet permission** and no HTTP URLs in source (purely local/offline app):
- Phase 3 (Dynamic Setup): Mark proxy/SSL pinning as N/A. Root/jailbreak bypass may still apply.
- Phase 4 (Traffic Analysis): Mark as N/A entirely — no network traffic to intercept.
- Phase 6 (API Testing): Mark as N/A entirely — no server-side API exists.
- Phase 5 (Runtime Testing): Still required — focus on broadcast injection, intent manipulation, data storage extraction, and Frida-based bypass validation.

Detect this early in Phase 2 by checking: (1) no `android.permission.INTERNET` in manifest, (2) no HTTP/HTTPS URLs in decompiled source, (3) no network security config. If all three: flag as offline app and pre-mark N/A phases at end of Phase 2.

### Exploit Validation

Critical and High findings discovered during static analysis (Phase 2) MUST be validated dynamically before advancing to Phase 7 (Reporting). Write exploitation evidence (logcat, proof files, screenshots) to the findings directory. If dynamic validation is not possible (no device, no account), document the limitation explicitly.

### Gateway Transition (`next`)

1. Verify phase gate criteria met (see each phase's Gate section)
2. Ask user confirmation: "Phase X complete. N findings. Advance to Phase Y?"
3. Update `state.yaml`: mark current gateway PASSED (or N/A), unlock next, record timestamps

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

   # If split APK (base + split_config.*.apk), merge before analysis:
   java -jar APKEditor-1.4.7.jar m -i <dir_with_splits> -o merged.apk -f
   # This produces a single APK with all DEX files, native libs, and resources combined.
   # Always analyze the merged APK — split analysis misses cross-module references.

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

   # Check for Unity IL2CPP (changes entire analysis approach)
   unzip -l target.apk | grep -q "libil2cpp.so" && echo "UNITY IL2CPP DETECTED"
   # If Unity: jadx is useless for game logic. Use global-metadata.dat strings instead.
   # See references/static-analysis.md → "Unity IL2CPP App Analysis" section.

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

5. Deep link → WebView hijack analysis (when deep links route to WebViews):
   - Find all `@DeepLink` annotations that contain "web" or "url" in the route
   - Check if the handler passes `bundle.getString("url")` to a WebView without validation
   - Check if the WebView has `addJavascriptInterface` — if yes, map ALL `@JavascriptInterface` methods
   - Check if multiple deep link routes delegate to the same vulnerable handler
   - Check for HTTPS app link → internal deep link conversion (e.g., `https://app.link/path` → `appscheme://path`)
   - If unvalidated URL + JS bridge found: **Critical** — document all entry points and bridge methods
   - See `deeplink-webview-hijack.md` for full exploitation patterns

6. Unsafe file operations (path traversal vectors):
   - `Uri.getLastPathSegment()` used as filename without sanitization
   - `new File(base, userInput)` with no canonical path check
   - `System.load()` / `System.loadLibrary()` from writable paths (getFilesDir, getCacheDir)
   - Deep link handlers that download and save files from attacker-controlled URIs

5b. Intent URI parsing (intent scheme hijacking):
   - Search for `Intent.parseUri(` — if the app parses user-controlled strings as intent URIs, this is a **high-value target**
   - Check what flags are passed: `Intent.parseUri(url, Intent.URI_INTENT_SCHEME)` (flag=1) allows full intent specification
   - Check if result is launched via `startActivity()` — enables launching non-exported activities
   - Check for sanitization: does the app strip component/package/extras before launching? Is the sanitization bypassable?
   - Common pattern: app allows `intent:` scheme in URL fields → attacker crafts `intent:#Intent;component=pkg/.InternalActivity;end`
   - **Key question:** Where does the URL string come from? If from user input, database, backup file, or deep link parameter — it's attacker-controlled

5c. Backup/restore as input validation bypass:
   - Check if app implements its own backup (not just `allowBackup` in manifest)
   - Look for: JSON/XML export to external storage, plaintext file writes to `getExternalFilesDir()`
   - **Critical check:** Does the restore path apply the SAME validation as the UI input path?
   - Common pattern: UI validates input (URL scheme, format, length) but restore/import reads raw data without checks
   - If backup is plaintext on external storage → any app (or adb) can modify it → inject payloads that bypass UI validation
   - Look for: `Gson.fromJson()`, `JSONObject()`, `ObjectInputStream` reading from external files without sanitization

6. Native library analysis (when .so files present):
   - List imports: `readelf -d lib/arm64-v8a/lib*.so` or `strings` + grep
   - **Dangerous imports:** `system`, `exec`, `popen`, `dlopen`, `Runtime.exec`
   - Check for embedded command strings: `strings lib.so | grep -iE "sh|bin|cmd|log|exec"`
   - Check for format string usage without bounds: `sprintf`, `printf` with user input
   - Identify JNI exports: `strings lib.so | grep Java_`
   - If `system()` + user input → likely command injection or buffer overflow
   - If fixed-size buffers + `memcpy`/`strcpy` without length check → overflow candidate
   - Test with long inputs (100, 200, 500 chars) and monitor `system()` via Frida
   - **Native "enabler" pattern:** Check what native functions ADD to objects, not just what they remove. A "sanitizer" that strips dangerous extras but then adds a validation flag (e.g., `putExtra("IS_VALID", true)`) makes the native function the enabler, not the blocker. Reverse the full function — don't stop at the first `removeExtra` call.
   - **Intent manipulation in native code:** Look for JNI calls to `putExtra`, `removeExtra`, `setData`, `setComponent`, `setPackage`, `getBooleanExtra`. Map the full sequence: what's removed vs what's added. The final state of the intent after native processing is what matters.

7. WebView + JavaScript bridge analysis (when WebView with JS enabled found):
   - Check for `addJavascriptInterface()` — exposes Java/native methods to JS
   - Map ALL `@JavascriptInterface` methods — these are the attack surface from any loaded page
   - Check if WebView loads attacker-controlled URLs (deep links, intent extras, no domain restriction)
   - Check for dangerous operations in bridge methods: file I/O, native calls, `system()`, `Runtime.exec()`, `ProcessBuilder`
   - Check URL validation in `shouldOverrideUrlLoading()` (or lack thereof)
   - Check WebView settings: `setAllowFileAccess`, `setAllowContentAccess`, `setMixedContentMode`, `usesCleartextTraffic`
   - If bridge exposes native methods with buffer operations → combine with native overflow analysis
   - If app accepts any http/https URL via deep link + has JS bridge → **remote RCE candidate**

8. Crypto analysis (when encryption/decryption is found):
   - Identify algorithm, mode, padding (e.g., AES/ECB/PKCS5Padding)
   - Check key derivation: hardcoded? small keyspace? no stretching?
   - Check for hardcoded ciphertext that can be attacked offline
   - If key is derived from user input (PIN, password): estimate brute-force time
   - Write a cracking script immediately if keyspace < 10M (runs in seconds)

7. Exported component analysis:
   - Identify all exported Activities, BroadcastReceivers, Services, ContentProviders
   - Check for permission protection (custom permissions, signature level)
   - Map intent-filters and actions — these are the external attack surface
   - BroadcastReceivers with no permission = any app can trigger them
   - Dynamic receivers registered without RECEIVER_NOT_EXPORTED flag (Android 14+ requirement)

8. Deserialization / unsafe parsing:
   - **SnakeYAML `yaml.load()`** — instantiates arbitrary classes via `!!` tag. Look for any class on classpath with a dangerous single-arg constructor (Runtime.exec, ProcessBuilder, file write). Safe alternative: `new Yaml(new SafeConstructor())` or `yaml.loadAs(input, Map.class)`
   - **ObjectInputStream** — Java native deserialization, gadget chains
   - **Gson/Jackson with polymorphic types** — type confusion attacks
   - **XMLDecoder** — arbitrary object instantiation
   - Pattern: find the "sink" class first (e.g., a class whose constructor calls `Runtime.exec()`), then find the deserialization entry point that can reach it

8. Deserialization analysis (when YAML/JSON/XML/Serializable processing found):
   - SnakeYAML `yaml.load()` without SafeConstructor → arbitrary object instantiation (see `yaml-deserialization-rce.md`)
   - Java `ObjectInputStream.readObject()` → classic Java deserialization
   - `XMLDecoder` → XML-based object instantiation
   - Check for gadget classes on classpath: constructors calling `Runtime.exec()`, `ProcessBuilder`, file I/O, reflection
   - Check input source: user-controlled (intents, file pickers, network) = exploitable

8. Deserialization analysis (when YAML/JSON/XML parsing found):
   - SnakeYAML `yaml.load()` without `SafeConstructor` → arbitrary class instantiation via `!!` tag
   - Jackson `ObjectMapper` with `enableDefaultTyping()` or `@JsonTypeInfo(use=CLASS)` → polymorphic RCE
   - Java `ObjectInputStream.readObject()` → gadget chain exploitation
   - `XMLDecoder.readObject()` → direct method invocation
   - Check for gadget classes: any constructor calling `Runtime.exec()`, `ProcessBuilder`, file I/O
   - If found: write exploit payload immediately (see `deserialization-attacks.md`)

9. Exported ContentProvider analysis:
   - Identify all providers with `android:exported="true"` and no `android:permission`
   - Check `query()` for SQL injection (raw string concatenation in selection)
   - Check `openFile()` for path traversal (unsanitized `getLastPathSegment()`)
   - Check for weak authentication (PIN/password in selection parameter with small keyspace)
   - Test access: `adb shell content query --uri content://<authority>`
   - See `content-provider-attacks.md` for exploitation patterns

10. Binary protections check:
   - Android: ProGuard/R8 obfuscation, native libs
   - iOS: PIE, stack canary, ARC, code signing

7. Automated scanning:
   ```bash
   # MobSF (comprehensive)
   docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
   # Upload APK/IPA at http://localhost:8000
   ```

**Reference:** `static-analysis.md`, `native-re-mcp.md`, `android-path-traversal-rce.md`, `crypto-key-cracking.md`, `native-buffer-overflow.md`, `deserialization-attacks.md`, `content-provider-attacks.md`, `yaml-deserialization-rce.md`, `deeplink-webview-hijack.md`

---

## Phase 3: Dynamic Setup

### Gate: proxy intercepting traffic OR documented as unnecessary; bypass scripts working OR documented as not needed; app launches normally

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
   frida -U -f <package> -l ssl_pinning_bypass.js

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
   frida -U -f <package> -l root_bypass.js

   # Objection (quick)
   objection -g <package> explore
   android root disable   # or: ios jailbreak disable

   # Combined launch
   frida -U -f <package> -l root_bypass.js -l ssl_pinning_bypass.js
   ```

5. Verify: app launches, traffic visible in proxy, no detection popups

**Reference:** `dynamic-setup.md`, `frida-scripts.md`, `dexguard-appfence-bypass.md`

---

## Phase 4: Traffic Analysis

### Gate: API endpoints mapped, auth flow documented, at least one full user journey captured (OR documented N/A with justification if app has no network communication)

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

### Gate: at least 3 test categories completed from the checklist below; Critical/High findings from Phase 2 must be dynamically validated

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
   - **Parameter name fuzzing:** When a deep link handler fails to extract a value despite correct URI format, the parameter name may differ from what hardcoded URLs suggest. Enumerate candidate names from: (1) field names in decompiled source/metadata (e.g., `updateHost` → try `host=`), (2) method names (`checkHost` → `host=`), (3) common variants (`url=`, `server=`, `target=`, `endpoint=`, `addr=`). Test each systematically before concluding extraction is broken.

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

**Reference:** `runtime-testing.md`, `frida-scripts.md`, `deep-link-path-traversal.md`

---

## Phase 6: API Testing (Server-side)

### Gate: at least BOLA, auth bypass, and injection tests completed (OR documented N/A with justification if no server-side API exists)

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
   - Attack chain diagram (how findings combine)
   - Remediation roadmap (prioritized)
   - Appendix: tool versions, device info, test dates

3. Generate exploitation-walkthrough.md (CTF/lab contexts, or when client requests):
   - Step-by-step reproduction from APK to full exploitation
   - Include all commands, scripts, and code needed to reproduce
   - Structure: identify target → reverse logic → build exploit → execute → verify
   - Include cracking scripts (Python) for any brute-forced secrets
   - Include PoC code (malicious app, Frida script, or adb commands)
   - Target audience: someone who has never seen the app before

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
- **Locked device workaround:** When the device screen is locked and UI automation fails, validate findings via non-UI paths: `adb shell am broadcast` (broadcast receivers), `adb shell am start` (exported activities), `run-as` (data extraction on debuggable apps), and `adb shell content query` (content providers). These don't require an unlocked screen.
- **Offline/no-network apps:** When the app has no internet permission and no HTTP URLs in source, mark Phases 3 (Dynamic Setup), 4 (Traffic Analysis), and 6 (API Testing) as N/A immediately after Phase 2. Focus Phase 5 on broadcast exploitation, SharedPreferences validation, and data storage inspection.
- **Client-side-only exploit chains (WebView RCE, broadcast injection):** When the exploit is entirely client-side (no server API involved), mark Phases 3/4/6 as N/A. Phase 5 validates the exploit dynamically.
- **Frida 16.x compatibility:** `--no-pause` flag removed (app auto-resumes on spawn). Use `frida -U -f <package> -l script.js`. For deep link exploitation, do NOT use `device.spawn(url=...)` — it doesn't work for Android intents. Instead: spawn app normally → install hooks → resume → trigger deep link via separate `adb shell am start -a android.intent.action.VIEW -d "scheme://..."` command. This two-step pattern is required for hooking deep link handlers.
- **Exploit hosting pitfall:** Python's `http.server` decodes `%2F` in URL paths and resolves `../`, causing 404 for path traversal payloads. Use a custom server that serves the payload for any request path (see `android-path-traversal-rce.md`)
- **Device-to-host connectivity:** When the device can't reach the host IP (different subnet, firewall, VPN), use `adb reverse tcp:PORT tcp:PORT` to forward device localhost to host. Then use `http://127.0.0.1:PORT/` in exploit URIs. Always verify with `adb shell curl http://127.0.0.1:PORT/file` before triggering the exploit.
- **App restart issues:** Use `adb shell am start -S -W` to force-stop then start. Pre-grant permissions with `pm grant` and `appops set` to avoid dialogs blocking the flow
- **Frida spawn on rooted devices:** `frida -U -f <package>` requires frida-server running on device (`adb shell "su -c '/data/local/tmp/frida-server -D'"`). Without it, you get "need Gadget to attach on jailed Android" even on rooted devices. Always verify with `frida-ps -U` before spawning.
- **`extractNativeLibs="false"` and Frida:** When this flag is set, .so files live inside the APK (not extracted). You cannot `System.loadLibrary()` arbitrary libs from Frida scripts — only the app's own loading path works. Hook the native function after the app loads the library itself.
- **Static analysis pattern for native lib hijack:** Look for `System.load()` with paths under `getFilesDir()`/`getCacheDir()` combined with unsanitized `getLastPathSegment()` in file download handlers
- **Frida on rooted devices:** Start frida-server with `adb shell "su -c '/data/local/tmp/frida-server -D'"`. Frida 16.x removed `--no-pause` (apps auto-resume on spawn). Use Python frida bindings for complex hooks (spawn + attach + inject + trigger deep link in sequence).
- **WebView + @JavascriptInterface = high-value target:** When an app has JS enabled + addJavascriptInterface, map ALL exposed methods. If any method calls Runtime.exec(), ProcessBuilder, or shell commands — that's an RCE chain. XSS in the WebView (via deep links, intent data, or stored content) becomes the trigger.
- **Deep link escape bypass patterns:** When the app escapes single quotes but NOT backslashes, inject `\\'` — after escape it becomes `\\\\'` which in JS is literal backslash + string terminator. Always check: does the escape cover `\`, `"`, `'`, backtick, `$`, and newlines?
- **Unity IL2CPP deep link parameter discovery:** Hardcoded URLs in `global-metadata.dat` may use DIFFERENT query parameter names than the deep link handler expects. Don't assume the parameter name from hardcoded strings — test systematically. Use `strings global-metadata.dat | grep -E "^(check|get|set|validate|parse)[A-Z]"` to find method names that hint at the actual parameter (e.g., `checkHost` → parameter is `host=`, not `patch=` from the hardcoded URL). When host extraction always returns empty despite correct URI format, the parameter name is likely wrong.
- **Unity IL2CPP reverse engineering:** For Unity 2020.x IL2CPP apps, all C# class/method/field/string-literal names are in `global-metadata.dat`. Key patterns: (1) grep for `[ClassName]` log prefixes to find the relevant class, (2) grep for method names like `Handle*`, `check*`, `validate*`, `get*` to understand the flow, (3) look for field names like `domainRegex`, `updateHost` that reveal validation logic, (4) coroutine names like `<MethodName>d__N` reveal async operations. The actual game logic is NOT in `classes.dex` — it's in `libil2cpp.so` + metadata.
- **Mono/Unity custom scheme URI parsing quirk:** In Unity 2020.x (Mono runtime), `System.Uri` does NOT reliably parse query parameters from custom scheme URIs (e.g., `customscheme://host?key=value`). The `Uri.Query` property may return empty. Apps work around this with manual string parsing or by using Android's Java-side `Uri.getQueryParameter()` via JNI. When testing deep links, if the app receives the full URI string (confirmed via logcat) but fails to extract parameters, try different parameter names — the extraction method may be parameter-name-specific.
- **extractNativeLibs="false":** Native libs stay inside the APK (not extracted to filesystem). `System.loadLibrary()` works but you can't `dlopen` from a custom path. For Frida hooking, the lib loads from the APK's zip — use `Process.findModuleByName()` after the app loads it.
- **Intent URI parsing (`Intent.parseUri`) is a high-value target:** When an app parses user-controlled strings as intent URIs (look for `Intent.parseUri(url, 1)` or `Intent.URI_INTENT_SCHEME`), it can launch ANY activity (including non-exported ones) with arbitrary extras. The attack surface is wherever the URL string originates: UI input, database, backup files, deep link parameters, QR codes. Even if the app "sanitizes" the intent before launching, check what the sanitizer ADDS (not just removes). TideLock challenge (2026-05): native `sanitizeIntent()` stripped all extras but then added `FLAG_REQUEST_VALID=true` — making it the enabler.
- **Backup/restore bypasses input validation:** Apps that implement their own backup (JSON/XML to external storage) often skip the validation applied on the UI path. If `isValidUrl()` blocks `intent:` schemes on the add-entry UI, but `restoreEntries()` reads raw JSON without checking — inject via modified backup file. Always check: does the restore/import path apply the same validation as the UI input path?
- **Intent URI injection via backup/restore:** When an app validates URLs on input (UI add) but NOT on restore/import, inject `intent:#Intent;component=pkg/.InternalActivity;end` into the backup file. If the app has any code path that calls `Intent.parseUri(url, 1)` + `startActivity()`, you can launch non-exported activities. Check: (1) backup format (plaintext JSON? XML?), (2) restore validation (usually missing), (3) code paths that handle `intent:` scheme. Common in password managers, note apps, bookmark managers.
- **Native "sanitizer" as enabler pattern:** When a native function strips extras/data from an intent but then ADDS a validation flag (e.g., `putExtra("VALID", true)`), the sanitizer IS the exploit enabler. The app assumes only sanitized intents reach the protected activity, but the sanitizer itself grants access. Reverse the native function to confirm: look for `removeExtra` loop followed by `putExtra` with a boolean `true` (mov w4, 1 in arm64).
- **XOR-obfuscated strings in native libs:** Common pattern in MHL challenges. Decode with: `''.join(chr(b ^ key) for b in byte_array)`. Try keys 0x00-0x7F. Look for readable scheme strings (intent:, http://, https://) to identify the key quickly.
- **r2 for quick native function analysis:** When Ghidra isn't running, use `r2 -q -c 'aa;s sym.Java_pkg_Class_method;pdf' lib.so` to disassemble JNI functions. Look for JNI call offsets (0xf8=GetObjectClass, 0x108=GetMethodID, 0x538=NewStringUTF, 0x2f0=GetFieldID, 0x2f8=GetObjectField, 0x558=GetArrayLength, 0x568=GetObjectArrayElement) to understand what Java methods the native code calls.
- **SnakeYAML deserialization RCE:** When an app uses `yaml.load()` (not `yaml.loadAs()` or `SafeConstructor`), it allows arbitrary object instantiation via `!!fully.qualified.ClassName [args]` tags. Look for gadget classes with dangerous constructors (Runtime.exec, ProcessBuilder, file I/O). Common in config editor/viewer apps. The safe alternative is `new Yaml(new SafeConstructor(new LoaderOptions()))`.
- **Runtime.exec(String) splitting pitfall:** `Runtime.exec(String)` uses `StringTokenizer` to split on whitespace — shell features (pipes, redirects, semicolons) are NOT interpreted. `exec("sh -c id")` works (3 tokens: sh, -c, id) but `exec("sh -c id > /tmp/out")` fails (sh only executes "id", "> /tmp/out" becomes $0/$1). Workaround: push a script to an executable path first, then exec the script path. Or use `exec(String[])` if you control the call site.
- **Exported ContentProvider brute-force:** When a ContentProvider is exported without permission protection and uses a small keyspace for access control (e.g., 4-digit PIN), extract crypto parameters from assets/resources and brute-force offline. Pattern: `content query --uri content://authority --where "pin=XXXX"`. For offline cracking: extract encryptedData/salt/iv/iterations from APK assets, then PBKDF2+AES decrypt in Python loop. 4-digit PIN = 10K attempts = <1 second.
- **adb reverse for exploit delivery:** When the device can't reach the host IP directly (different network/firewall), use `adb reverse tcp:PORT tcp:PORT` to forward device→host. Then use `http://127.0.0.1:PORT/` in the exploit URL. This is more reliable than finding the correct network interface IP.
- **DexGuard/AppFence bypass:** Enterprise apps using `libaf-android.so` (AppFence by Guardsquare) have a multi-layer kill chain: (1) inline `SVC #0` (exit_group, bypasses ALL libc hooks), (2) `syscall(94,0)` via libc wrapper, (3) `kill(getpid(), SIGKILL)` via dlsym'd function pointer, (4) `_exit(0)` + `abort()` fallbacks. Detection scans `/proc/self/maps` for non-whitelisted libraries. Kill runs on a separate thread spawned via `pthread_create` with a configurable delay (`usleep(N*1000000)`). The library has integrity checks that detect on-disk patching (triggers SIGBUS). **Working bypass (v24 pattern):** (1) hook `fopen`/`fgets` to filter Frida lines from `/proc/self/maps`, (2) hook `pthread_create` to neutralize kill thread, (3) patch inline SVC to NOP after library loads, (4) hook libc `syscall`/`kill`/`_exit`/`abort` as safety nets. The maps filter is the PRIMARY defense — if detection doesn't see Frida, the kill thread is never spawned. See `dexguard-appfence-bypass.md`.
- **Split APK merge:** Use `java -jar APKEditor.jar m -i <dir> -o merged.apk -f` to merge split APKs before jadx decompilation. Merged APK gives complete view (all DEX + native libs + resources in one file).
- **Split APK merging:** When pulling from device, apps often have split APKs (base + config.arm64 + config.xxhdpi). Merge before analysis: `java -jar APKEditor.jar m -i <dir_with_apks> -o merged.apk -f`. This produces a single APK suitable for jadx/apktool. Tool: REAndroid/APKEditor.
- **hluda-server (Frida anti-detection build):** When regular frida-server is detected (port 27042, /proc/self/maps strings), use hluda-server — a Frida build with anti-detection patches (randomized port, stripped strings, hidden from maps). Path on device: `/data/local/tmp/hluda-server`. Start same way: `su -c '/data/local/tmp/hluda-server -D'`. Still uses same `frida -U` client commands.
- **DexGuard inline syscall detection (unbypassable via Frida):** When an app uses DexGuard with inline `svc #0` assembly for exit_group, ALL userspace hooks fail — libc exit/kill hooks, syscall() wrapper hooks, pthread_create blocking. Symptoms: process exits cleanly (code 0), no hook messages fire for exit. The ONLY solutions are: (1) Shamiko/Zygisk (kernel-level root hiding), (2) non-rooted device, (3) APK patching to remove detection code. For bug bounty, static analysis evidence is sufficient — don't waste hours on bypass.
- **pthread_create thread identification:** To identify which native lib runs root detection, hook `pthread_create` and log `module.name` for each `start_routine`. Filter out system libs (libc, libart, libhwui, libutils, libgui). The detection thread is usually from a small obfuscated lib (e.g., 7KB `libh9740d.so`). But blocking the thread may crash the app if it's not actually the detection (e.g., ANR handler).
- **DexGuard native root detection defeats Frida hooks:** DexGuard (used by Gojek, banking apps) uses inline `svc #0` assembly to call exit_group directly, bypassing ALL libc hooks (exit, _exit, kill, syscall wrapper). Even with native Interceptor hooks on every libc function, the process still dies. Detection vectors: (1) `/proc/self/maps` for frida-agent strings, (2) `/proc/net/tcp` for port 27042 (frida default), (3) `access()` for su/magisk/kernelsu paths, (4) custom kernel string in `/proc/version`. Solutions in order of reliability: (1) Shamiko + Zygisk Next (kernel-level hiding), (2) hluda-server (Frida build with anti-detection patches — hides from /proc/maps, randomizes port), (3) Frida Gadget injection into patched APK, (4) non-rooted device for dynamic testing. For bug bounty, static code evidence is sufficient when the code path is unambiguous.
- **hluda-server (anti-detection Frida):** When standard frida-server is detected, use hluda-server (`/data/local/tmp/hluda-server -D`). It patches Frida's identifiable strings and port. However, hluda alone doesn't hide root — you still need root-hiding hooks or Shamiko. hluda solves frida detection; Shamiko solves root detection. For DexGuard apps that use inline syscalls, even hluda + Frida hooks may not suffice — the detection bypasses all userspace instrumentation.
- **KernelSU + Zygisk Next version requirement:** Zygisk Next requires recent KernelSU (ksud). If install fails with "ksud version is too old", update KernelSU first. KernelSU 0.7.1 is too old; need latest from GitHub releases.
- **APK merge for split APKs:** Use APKEditor (`java -jar APKEditor.jar m -i <dir> -o merged.apk -f`) to merge split APKs (base + config splits) into a single APK before analysis. This ensures jadx decompiles all DEX files and resources together. Tool: https://github.com/REAndroid/APKEditor
- **DexGuard root detection pattern:** Commercial apps (fintech, ride-hailing) use DexGuard with dedicated `ard` (App Root Detection) modules. Symptoms: app launches then immediately dies with `Process exited cleanly (0)` in logcat (NOT a crash — it's `System.exit(0)`). Detection is heavily obfuscated via reflection (`C15197fsZ.c()`, `C15197fsZ.d()` patterns). Often controlled by Firebase Remote Config (`RootCheckerRemoteConfig`). KernelSU without hiding modules (susfs/Shamiko) gets detected. Fix: install Zygisk Next + Shamiko for KernelSU, or use a non-rooted device. Key grep: `grep -rl "DexGuard\|AppProtection\|isRooted\|RootChecker" sources/` to confirm.
- **Split APK merging before analysis:** Modern apps ship as split APKs (base + config splits for ABI/density). Always merge with `java -jar APKEditor.jar m -i <dir> -o merged.apk -f` before running jadx. Analyzing base.apk alone misses native libs and density-specific resources. APKEditor also fixes `extractNativeLibs` and sanitizes the manifest automatically.
- **Large app static analysis (50K+ classes):** Delegate Phase 2 analysis to a subagent via `delegate_task` with specific goals (deeplinks, secrets, exported components, network security, webview analysis). The subagent writes results to `phase2-static/android/` as separate markdown files. This preserves main context for exploitation phases. Works well for apps like Gojek (79K classes, 17 DEX files).
- **Split APK handling:** Modern Play Store apps install as split APKs. Always merge with `java -jar APKEditor.jar m -i <dir> -o merged.apk -f` before jadx decompilation. Analyzing individual splits causes missing class errors and incomplete results.
