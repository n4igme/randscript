---
name: mtest
version: 2.0.0
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

1b. Cross-platform framework detection:
   ```bash
   # Detect framework from APK contents
   unzip -l target.apk | grep -qE "libflutter\.so|libapp\.so" && echo "FLUTTER DETECTED"
   unzip -l target.apk | grep -qE "index\.android\.bundle|libjsc\.so|libhermes\.so" && echo "REACT NATIVE DETECTED"
   unzip -l target.apk | grep -qE "assemblies/.*\.dll|libmonodroid\.so" && echo "XAMARIN DETECTED"
   ```

   **Flutter (libflutter.so + libapp.so):**
   - App logic is compiled to native ARM in `libapp.so` (Dart AOT snapshot) — jadx only shows the thin Flutter engine wrapper
   - `libapp.so` snapshot analysis: use `blutter` or `darter` to extract class/method names from the Dart snapshot
   - Traffic interception: Flutter uses its own HTTP stack (dart:io) that ignores system proxy and system CA store. Use `reFlutter` to patch `libflutter.so` with proxy settings, or hook `ssl_crypto_x509_session_verify_cert_chain` in `libflutter.so`
   - Dart AOT limitations: no source maps, no string-based decompilation — analysis is primarily at the snapshot metadata + native disassembly level
   - **String literals ARE preserved in Dart AOT snapshots.** API paths, URLs, JSON field names, class names, and package paths all survive compilation as readable strings in `libapp.so`. This is the PRIMARY static analysis technique for Flutter apps:
     ```bash
     # Extract ALL API endpoints (often 200-400 for banking apps)
     strings lib/arm64-v8a/libapp.so | grep -E "^/(bff-mobile|auth|account|api)" | sort -u
     # Extract base URLs
     strings lib/arm64-v8a/libapp.so | grep -iE "^https?://" | sort -u
     # Extract data model classes (reveals request/response structure)
     strings lib/arm64-v8a/libapp.so | grep -iE "Model\.(fromJson|toJson)" | sort -u
     # Extract Dart package paths (reveals app architecture)
     strings lib/arm64-v8a/libapp.so | grep "^package:" | sort -u
     # Extract JSON field names (request parameters)
     strings lib/arm64-v8a/libapp.so | grep -oE '[a-z][a-zA-Z0-9]*' | sort -u | grep -xE '(accountNumber|password|pin|otp|...)'
     # Find IDOR targets (path template variables)
     strings lib/arm64-v8a/libapp.so | grep -E "\{\{[a-zA-Z]+\}\}" | sort -u
     ```
   - jadx is still useful for: native Android components, third-party SDK configs, WebView implementations, security SDK code

   **React Native (index.android.bundle or libjsc.so/libhermes.so):**
   - Bundle extraction: `unzip target.apk assets/index.android.bundle` — this is the JS source (possibly minified/bundled)
   - If using Hermes engine (`libhermes.so`): the bundle is Hermes bytecode (`.hbc`), not plain JS. Decompile with `hbc-decompiler` or `hermes-dec`
   - Source map check: look for `index.android.bundle.map` in assets or fetch `<bundle_url>.map` from the server — if present, gives full original source
   - Plain JSC bundle (`libjsc.so`): bundle is readable JS, just beautify with `js-beautify`
   - API keys, tokens, and endpoints are commonly embedded in the JS bundle — grep extensively
   - Hook JS runtime via Frida: `Java.perform(() => { var module = Java.use('com.facebook.react.bridge.CatalystInstance'); ... })`

   **Xamarin (assemblies/*.dll + libmonodroid.so):**
   - DLL extraction: `unzip target.apk assemblies/*` — .NET assemblies contain the app logic
   - Decompilation: use `monodis` (Mono disassembler), ILSpy, or dnSpy on extracted DLLs — produces near-original C# source
   - Assemblies may be AOT-compiled (look for `.dll.so` files) — in that case, the .dll still contains metadata but method bodies are native
   - Mono runtime hooking via Frida: hook `mono_jit_runtime_invoke` or specific managed methods via `Mono.Cecil` method tokens
   - Look for `Xamarin.Essentials` usage — SecureStorage keys, preferences, and connectivity checks
   - Network: Xamarin uses platform HTTP handlers — standard proxy/SSL bypass approaches work (unlike Flutter)

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
   - **Check for SecureWebView pattern:** Does the WebView subclass override `loadUrl()` with a domain allowlist check? Look for `super.loadUrl()` gated behind a boolean, and config keys like `DOMAIN_WHITELIST_BATCH_*`. If present, the finding is Medium (not Critical) unless allowlist is bypassable.
   - **Check for feature flags:** If the allowlist logic has branching paths controlled by `getValue()` or remote config booleans, the behavior differs between flag ON/OFF. Static analysis CANNOT determine which path runs in production. Mark finding as Probable until dynamically verified on a non-rooted production device.
   - If unvalidated URL + JS bridge + NO allowlist: **Critical (Confirmed)** — document all entry points and bridge methods
   - If unvalidated URL + JS bridge + server-side allowlist: **Medium (Probable)** — document the allowlist as mitigating control and look for bypasses (open redirects on allowed domains, `allowAllAccess` partners, scheme bypass)
   - If unvalidated URL + JS bridge + allowlist with feature-flag-dependent bypass: **Medium (Theoretical)** — the bypass may work when flag is OFF but you cannot verify production flag state without dynamic testing on a non-rooted device
   - See `deeplink-webview-hijack.md` for full exploitation patterns

6. Unsafe file operations (path traversal vectors):
   - `Uri.getLastPathSegment()` used as filename without sanitization
   - `new File(base, userInput)` with no canonical path check
   - `System.load()` / `System.loadLibrary()` from writable paths (getFilesDir, getCacheDir)
   - Deep link handlers that download and save files from attacker-controlled URIs

6a. Intent URI parsing (intent scheme hijacking):
   - Search for `Intent.parseUri(` — if the app parses user-controlled strings as intent URIs, this is a **high-value target**
   - Check what flags are passed: `Intent.parseUri(url, Intent.URI_INTENT_SCHEME)` (flag=1) allows full intent specification
   - Check if result is launched via `startActivity()` — enables launching non-exported activities
   - Check for sanitization: does the app strip component/package/extras before launching? Is the sanitization bypassable?
   - Common pattern: app allows `intent:` scheme in URL fields → attacker crafts `intent:#Intent;component=pkg/.InternalActivity;end`
   - **Key question:** Where does the URL string come from? If from user input, database, backup file, or deep link parameter — it's attacker-controlled

6b. Backup/restore as input validation bypass:
   - Check if app implements its own backup (not just `allowBackup` in manifest)
   - Look for: JSON/XML export to external storage, plaintext file writes to `getExternalFilesDir()`
   - **Critical check:** Does the restore path apply the SAME validation as the UI input path?
   - Common pattern: UI validates input (URL scheme, format, length) but restore/import reads raw data without checks
   - If backup is plaintext on external storage → any app (or adb) can modify it → inject payloads that bypass UI validation
   - Look for: `Gson.fromJson()`, `JSONObject()`, `ObjectInputStream` reading from external files without sanitization

7. Native library analysis (when .so files present):
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

8. WebView + JavaScript bridge analysis (when WebView with JS enabled found):
   - Check for `addJavascriptInterface()` — exposes Java/native methods to JS
   - Map ALL `@JavascriptInterface` methods — these are the attack surface from any loaded page
   - Check if WebView loads attacker-controlled URLs (deep links, intent extras, no domain restriction)
   - Check for dangerous operations in bridge methods: file I/O, native calls, `system()`, `Runtime.exec()`, `ProcessBuilder`
   - Check URL validation in `shouldOverrideUrlLoading()` (or lack thereof)
   - Check WebView settings: `setAllowFileAccess`, `setAllowContentAccess`, `setMixedContentMode`, `usesCleartextTraffic`
   - If bridge exposes native methods with buffer operations → combine with native overflow analysis
   - If app accepts any http/https URL via deep link + has JS bridge → **remote RCE candidate**

9. Crypto analysis (when encryption/decryption is found):
   - Identify algorithm, mode, padding (e.g., AES/ECB/PKCS5Padding)
   - Check key derivation: hardcoded? small keyspace? no stretching?
   - Check for hardcoded ciphertext that can be attacked offline
   - If key is derived from user input (PIN, password): estimate brute-force time
   - Write a cracking script immediately if keyspace < 10M (runs in seconds)

10. Exported component analysis:
   - Identify all exported Activities, BroadcastReceivers, Services, ContentProviders
   - Check for permission protection (custom permissions, signature level)
   - Map intent-filters and actions — these are the external attack surface
   - BroadcastReceivers with no permission = any app can trigger them
   - Dynamic receivers registered without RECEIVER_NOT_EXPORTED flag (Android 14+ requirement)

11. Deserialization / unsafe parsing:
   - **SnakeYAML `yaml.load()`** — instantiates arbitrary classes via `!!` tag. Safe alternative: `new Yaml(new SafeConstructor())` or `yaml.loadAs(input, Map.class)`
   - **Jackson `ObjectMapper`** with `enableDefaultTyping()` or `@JsonTypeInfo(use=CLASS)` → polymorphic RCE
   - **ObjectInputStream** — Java native deserialization, gadget chains
   - **Gson/Jackson with polymorphic types** — type confusion attacks
   - **XMLDecoder** — arbitrary object instantiation, direct method invocation
   - Pattern: find the "sink" class first (e.g., a class whose constructor calls `Runtime.exec()`), then find the deserialization entry point that can reach it
   - Check for gadget classes on classpath: constructors calling `Runtime.exec()`, `ProcessBuilder`, file I/O, reflection
   - Check input source: user-controlled (intents, file pickers, network) = exploitable
   - If found: write exploit payload immediately (see `deserialization-attacks.md`, `yaml-deserialization-rce.md`)

12. Exported ContentProvider analysis:
   - Identify all providers with `android:exported="true"` and no `android:permission`
   - Check `query()` for SQL injection (raw string concatenation in selection)
   - Check `openFile()` for path traversal (unsanitized `getLastPathSegment()`)
   - Check for weak authentication (PIN/password in selection parameter with small keyspace)
   - Test access: `adb shell content query --uri content://<authority>`
   - See `content-provider-attacks.md` for exploitation patterns

13. Binary protections check:
   - Android: ProGuard/R8 obfuscation, native libs
   - iOS: PIE, stack canary, ARC, code signing

14. Automated scanning:
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
   - See Operational Notes → DexGuard section for full methodology
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

### Vulnerability Classes Reference (apply per-feature)

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

### General

- Always test on a **dedicated device/emulator** — never on a personal device with real accounts
- Some apps detect emulators (check for `generic`, `sdk`, `genymotion` in Build properties) — prefer rooted physical device
- iOS testing requires a **jailbroken device** for most dynamic tests — checkra1n (A11 and below) or palera1n (A11-A16)
- Save all Frida scripts to `phase3-protection/scripts/` for reproducibility
- When app uses certificate transparency or multiple pinning layers, combine approaches (Frida + patched config + invisible proxy)
- **Client-side only** findings (no server validation) are typically Medium unless they expose sensitive data
- Cross-reference extracted API endpoints with ptest skill for comprehensive server-side testing

**Cross-skill triggers from mtest:**
- API endpoints discovered in traffic → invoke `atest` for structured AuthN/AuthZ testing
- Cloud storage URLs (S3/GCS) in app config or traffic → invoke `ctest` Phase 3
- Web endpoints found → feed back into `ptest` findings-log
- Hardcoded secrets/source code in APK → invoke `scode` for review
- Smart contract/Web3 SDK in app → invoke `w3hunt`
- API geo-blocked from your location → see ptest `references/geo-restriction-bypass.md`
- **Large app static analysis (50K+ classes):** Delegate Phase 2 analysis to a subagent via `delegate_task` with specific goals (deeplinks, secrets, exported components, network security, webview analysis). The subagent writes results to `phase2-static/android/` as separate markdown files. This preserves main context for exploitation phases. Works well for apps like Gojek (79K classes, 17 DEX files).

### Split APK Merging

Modern Play Store apps install as split APKs (base + config.arm64 + config.xxhdpi + config.en). **Always merge before analysis** — analyzing base.apk alone misses native libs, density-specific resources, and cross-module references.

```bash
java -jar APKEditor.jar m -i <dir_with_splits> -o merged.apk -f
```

- Tool: [REAndroid/APKEditor](https://github.com/REAndroid/APKEditor)
- Produces a single APK with all DEX files, native libs, and resources combined
- Always merge before running jadx — split analysis causes missing class errors and incomplete results
- APKEditor also fixes `extractNativeLibs` and sanitizes the manifest automatically
- **`extractNativeLibs="false"` handling:** When this flag is set, native .so files live inside the APK (not extracted to filesystem). `System.loadLibrary()` works via the APK's zip, but you can't `dlopen` from a custom path. For Frida hooking, use `Process.findModuleByName()` after the app loads the library itself. You cannot `System.loadLibrary()` arbitrary libs from Frida scripts — only the app's own loading path works.

### Eversafe (kr.co.everspin) Anti-Tampering

Korean anti-tampering SDK used by Indonesian fintech apps (Bank Jago, etc.). Runs as an isolated service (`EversafeService` with `android:isolatedProcess="true"`).

**Key behavior difference:** Staging/dev builds often have relaxed Eversafe detection — the app stays alive on rooted devices with Frida attached. Always test staging builds first before investing in bypass work. Production builds may behave differently.

**Detection indicators in manifest:**
- `<service android:name="kr.co.everspin.eversafe.service.EversafeService" android:isolatedProcess="true"/>`
- Native libs: `libeversafe.so`, `libeversafe-loader.so`

**If Eversafe kills the app on production:**
1. Try hluda-server (anti-detection Frida build) — solves Frida detection
2. Shamiko + Zygisk — solves root detection at kernel level
3. Non-rooted device with WiFi proxy — avoids all detection
4. Submit findings with static evidence only

### DexGuard / AppFence / Root Detection

Enterprise apps (fintech, ride-hailing) use DexGuard with AppFence (`libaf-android.so`) and dedicated `ard` (App Root Detection) modules. Detection is heavily obfuscated via reflection (`C15197fsZ.c()`, `C15197fsZ.d()` patterns), often controlled by Firebase Remote Config (`RootCheckerRemoteConfig`).

**Symptoms:** App launches then immediately dies with `Process exited cleanly (0)` in logcat (NOT a crash — it's `System.exit(0)`). Key grep: `grep -rl "DexGuard\|AppProtection\|isRooted\|RootChecker" sources/` to confirm.

**Detection vectors:**
1. `/proc/self/maps` — scans for non-whitelisted libraries (frida-agent strings)
2. `/proc/net/tcp` — checks for port 27042 (frida default)
3. `access()` for su/magisk/kernelsu paths
4. Custom kernel string in `/proc/version`
5. Inline `SVC #0` assembly — calls exit_group directly, bypassing ALL libc hooks

**Kill chain (multi-layer):** (1) inline `SVC #0` (exit_group, bypasses ALL userspace hooks), (2) `syscall(94,0)` via libc wrapper, (3) `kill(getpid(), SIGKILL)` via dlsym'd function pointer, (4) `_exit(0)` + `abort()` fallbacks. Kill runs on a separate thread spawned via `pthread_create` with a configurable delay (`usleep(N*1000000)`). The library has integrity checks that detect on-disk patching (triggers SIGBUS).

**Bypass approaches (priority order):**

1. **Shamiko + Zygisk (kernel-level root hiding)** — most reliable, hides root from /proc entirely
2. **hluda-server** — anti-detection Frida build (see below), solves Frida detection but NOT root detection
3. **Frida Gadget injection** — inject into patched APK, no frida-server process to detect
4. **Non-rooted device** — no root indicators to find; use WiFi proxy for traffic capture
5. **Static evidence only** — for bug bounty, code-level evidence is sufficient when the code path is unambiguous

**Working Frida bypass (v24 pattern):** (1) hook `fopen`/`fgets` to filter Frida lines from `/proc/self/maps`, (2) hook `pthread_create` to neutralize kill thread, (3) patch inline SVC to NOP after library loads, (4) hook libc `syscall`/`kill`/`_exit`/`abort` as safety nets. The maps filter is the PRIMARY defense — if detection doesn't see Frida, the kill thread is never spawned. See `dexguard-appfence-bypass.md`.

**Inline syscall (unbypassable via Frida):** When DexGuard uses inline `svc #0` assembly for exit_group, ALL userspace hooks fail — libc exit/kill hooks, syscall() wrapper hooks, pthread_create blocking. Symptoms: process exits cleanly (code 0), no hook messages fire for exit. The ONLY solutions are: (1) Shamiko/Zygisk (kernel-level root hiding so detection never triggers), (2) non-rooted device, (3) APK patching to remove detection code. Don't waste hours on Frida bypass — static analysis evidence is sufficient for bug bounty.

**pthread_create thread identification:** To identify which native lib runs root detection, hook `pthread_create` and log `module.name` for each `start_routine`. Filter out system libs (libc, libart, libhwui, libutils, libgui). The detection thread is usually from a small obfuscated lib (e.g., 7KB `libh9740d.so`). But blocking the thread may crash the app if it's not actually the detection (e.g., ANR handler).

**Server-side device attestation (GoPay-1000 pattern):** Even when local root detection is bypassed (app stays alive, UI renders), the server may reject requests via Play Integrity / SafetyNet attestation. Symptom: app shows security error modal on login attempt (e.g., "Ada masalah keamanan (GoPay-1000)"). This CANNOT be bypassed with Frida alone — requires Zygisk + PlayIntegrityFix module. Document as a positive security control in the report, not a vulnerability.

**Auth-gated API testing when root blocks login:** When the rooted device can't log in (DexGuard kills app) and the non-rooted device isn't adb-accessible, use **WiFi proxy** (no adb needed): (1) Start Burp/Caido on Mac listening on 0.0.0.0:8080, (2) On phone: WiFi settings → proxy → Mac IP:8080, (3) Download CA cert via phone browser (http://burp), (4) Install cert, (5) Use app normally — all API calls captured. This works when no cert pinning is present. If cert pinning IS present, this approach fails and you must fix root hiding first.

### Flutter SSL Pinning Bypass (BoringSSL in libflutter.so)

**Problem:** Flutter uses its own BoringSSL in `libflutter.so` — ignores system proxy AND system CA store. Standard SSL bypass scripts (objection, generic Frida) don't work.

**Working approach (ARM64, Flutter 3.x):**

1. Find executable ranges only (avoid access violations from unmapped pages):
```javascript
var ranges = Process.enumerateRanges('r-x');
var flutterRanges = ranges.filter(r => r.base.compare(m.base) >= 0 && r.base.compare(m.base.add(m.size)) < 0);
```

2. Scan for `ssl_crypto_x509_session_verify_cert_chain` prologue pattern:
   - Primary: `FF 03 05 D1 FD 7B 0F A9` (sub sp, #0x140; stp x29, x30)
   - This typically yields 3-5 matches — hook ALL of them to return success

3. Hook all candidates (one of them is the verify function):
```javascript
Interceptor.attach(addr, { onLeave: function(retval) { retval.replace(0x1); } });
```

**Critical pitfall:** Do NOT use `Memory.scanSync(m.base, m.size, pattern)` directly — libflutter.so has unmapped pages within its address range that cause access violations. Always filter through `Process.enumerateRanges('r-x')` first.

**Traffic interception for Flutter:** Since Flutter ignores system proxy, use iptables DNAT:
```bash
# Get app UID from packages.list
UID=$(grep <package> /data/system/packages.list | awk '{print $2}')
iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner $UID --dport 443 -j DNAT --to <host_ip>:8080
iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner $UID --dport 80 -j DNAT --to <host_ip>:8080
```

**Verification:** Confirm `CERTIFICATE_VERIFY_FAILED` string exists in libflutter.so readable ranges to confirm BoringSSL is present. If the string is at offset ~0x26xxxx and your pattern matches are at ~0x5axxxx-0x9bxxxx, you're in the right area.

**For version-specific patterns, spawn scripts, and alternative approaches:** See `references/flutter-ssl-bypass.md`

**For Eversafe SDK token architecture, replay technique, and staging vs production behavior:** See `references/eversafe-attestation.md`

### Tyk API Gateway Pattern (Banking Apps)

Some banking apps use Tyk as API gateway with a static auth key:
- Header: `x-tyk-auth: <static_hex_key>`
- This key is the same across all requests from the app
- Extractable from traffic capture
- BUT: additional layers (Eversafe, JWT Bearer) still required
- The Tyk key alone returns `MISSING_API_TOKEN` or `EMPTY_AUTH_TOKEN`

When you see `x-tyk-auth` + `x-eversafe-verification-token` + `Authorization: Bearer`, the app has 3-layer auth:
1. Gateway key (static, extractable)
2. Device attestation (dynamic, device-bound)
3. User session (JWT, short-lived)

This makes direct API replay nearly impossible without going through the app.

### Burp MCP Integration for Traffic Analysis

When Burp Suite has the MCP extension installed (BApp Store), use it to query proxy history programmatically:

```python
# Key tools available:
# - get_proxy_http_history(count, offset) — all history
# - get_proxy_http_history_regex(regex, count, offset) — filtered
# - send_http1_request / send_http2_request — replay requests

# Connection: java -jar mcp-burp.jar --sse-url http://127.0.0.1:9876
# Protocol: JSON-RPC 2.0 over stdio
```

**Pitfalls:**
- `get_proxy_http_history` REQUIRES `count` and `offset` params (not optional)
- Response entries are newline-separated JSON objects (not a JSON array)
- Binary response bodies cause JSON parse errors — use try/except per entry
- SSE endpoint (port 9876) appears to hang on curl — it's long-polling, use `--max-time`
- The MCP server must be tested with `hermes mcp test burpsuite` to verify connectivity

### hluda-server (Anti-Detection Frida Build)

When regular frida-server is detected (port 27042, /proc/self/maps strings), use hluda-server — a Frida build with anti-detection patches (randomized port, stripped strings, hidden from maps).

- Path on device: `/data/local/tmp/hluda-server`
- Start: `su -c '/data/local/tmp/hluda-server -D'`
- Uses same `frida -U` client commands as standard frida-server
- **hluda solves Frida detection; Shamiko solves root detection** — they address different problems
- For DexGuard apps that use inline syscalls, even hluda + Frida hooks may not suffice — the detection bypasses all userspace instrumentation

### KernelSU / Magisk / Zygisk (Root Hiding Decision Tree)

**Decision tree based on kernel version:**

1. **Kernel ≥5.10:** Use KernelSU (latest .ko + ksud) → install Zygisk Next → install Shamiko → add target app to DenyList
2. **Kernel 4.4–5.9:** Modern KernelSU (v3.x) no longer ships .ko modules (minimum kernel 5.10). Options:
   - Flash a custom kernel with KernelSU built-in, OR
   - **Switch to Magisk** (supports all kernels, has native Zygisk + Shamiko) — this is the more reliable path
3. **Any kernel with Magisk:** Magisk + Zygisk (built-in) + Shamiko + DenyList — proven stack for DexGuard/AppFence apps

**Version requirements:**
- Zygisk Next requires KernelSU ksud 0.9+. KernelSU 0.7.1 is too old.
- Updating ksud requires a matching kernel module — you can't just replace the binary
- If KernelSU version is too old for Zygisk (< 0.9.x on kernel 4.4), options: (a) switch to Magisk, (b) use non-rooted device with WiFi proxy, (c) accept limitation and submit static findings only

### Frida Spawn / Compatibility

**Frida 16.x changes:** `--no-pause` flag removed — apps auto-resume on spawn. Use:
```bash
frida -U -f <package> -l script.js
```

**Starting frida-server:** Required for `frida -U -f <package>` on rooted devices:
```bash
adb shell "su -c '/data/local/tmp/frida-server -D'"
```
Without it, you get "need Gadget to attach on jailed Android" even on rooted devices. Always verify with `frida-ps -U` before spawning.

**Deep link two-step pattern:** Do NOT use `device.spawn(url=...)` — it doesn't work for Android intents. Instead:
1. Spawn app normally → install hooks → resume
2. Trigger deep link via separate command: `adb shell am start -a android.intent.action.VIEW -d "scheme://..."`

This two-step pattern is required for hooking deep link handlers. Use Python frida bindings for complex hooks (spawn + attach + inject + trigger deep link in sequence).

**Frida NativeCallback GC pitfall:** When replacing function pointers (e.g., `pthread_create` start_routine) with `new NativeCallback(...)` inside `onEnter`, the callback gets garbage-collected before the thread runs → SIGSEGV crash. **Fix:** declare ALL NativeCallbacks and Memory.alloc buffers as GLOBAL variables at script top level. Never create inline NativeCallbacks inside hook handlers. This is the #1 cause of "bypass works once then crashes on retry."

### Device & Connectivity

- **Locked device workaround:** When the device screen is locked and UI automation fails, validate findings via non-UI paths: `adb shell am broadcast` (broadcast receivers), `adb shell am start` (exported activities), `run-as` (data extraction on debuggable apps), and `adb shell content query` (content providers). These don't require an unlocked screen.
- **Device-to-host connectivity:** When the device can't reach the host IP (different subnet, firewall, VPN), use `adb reverse tcp:PORT tcp:PORT` to forward device localhost to host. Then use `http://127.0.0.1:PORT/` in exploit URIs. Always verify with `adb shell curl http://127.0.0.1:PORT/file` before triggering the exploit. This is more reliable than finding the correct network interface IP.
- **App restart issues:** Use `adb shell am start -S -W` to force-stop then start. Pre-grant permissions with `pm grant` and `appops set` to avoid dialogs blocking the flow.

### High-Value Attack Patterns

- **WebView + @JavascriptInterface = high-value target:** When an app has JS enabled + addJavascriptInterface, map ALL exposed methods. If any method calls Runtime.exec(), ProcessBuilder, or shell commands — that's an RCE chain. XSS in the WebView (via deep links, intent data, or stored content) becomes the trigger.
- **SecureWebView pattern (server-side domain allowlist):** Modern apps (Gojek, fintech) wrap WebView in a `SecureWebView` subclass that overrides `loadUrl()` with a server-fetched domain allowlist check. Even if the deep link handler passes unvalidated URLs, the WebView blocks loading non-allowlisted domains. Detection: look for `extends WebView` with `super.loadUrl()` gated behind a boolean check, and config keys like `DOMAIN_WHITELIST_BATCH_*` or `JS_BRIDGE_WHITELIST_BATCH_*`. This downgrades a "no validation in handler" finding from Critical to Medium unless you can bypass the allowlist. **Bypass vectors (in order):** (1) `data:` URI scheme — may bypass if allowlist only checks `http`/`https` schemes. **CAVEAT:** depends on feature flag state — always verify dynamically before rating as Confirmed. (2) Open redirect on an allowed domain. (3) Partner with `allowAllAccess=true`. (4) Empty allowlist fallback (fail-open when `DOMAIN_WHITELIST_BATCH_SIZE` returns 0). (5) Feature flag OFF (unlikely in production). See `deeplink-webview-hijack.md`.
- **Deep link escape bypass patterns:** When the app escapes single quotes but NOT backslashes, inject `\\\'` — after escape it becomes `\\\\\'` which in JS is literal backslash + string terminator. Always check: does the escape cover `\\`, `"`, `'`, backtick, `$`, and newlines?
- **Intent URI parsing (`Intent.parseUri`) is a high-value target:** When an app parses user-controlled strings as intent URIs (look for `Intent.parseUri(url, 1)` or `Intent.URI_INTENT_SCHEME`), it can launch ANY activity (including non-exported ones) with arbitrary extras. The attack surface is wherever the URL string originates: UI input, database, backup files, deep link parameters, QR codes. Even if the app "sanitizes" the intent before launching, check what the sanitizer ADDS (not just removes).
- **Backup/restore bypasses input validation:** Apps that implement their own backup (JSON/XML to external storage) often skip the validation applied on the UI path. If `isValidUrl()` blocks `intent:` schemes on the add-entry UI, but `restoreEntries()` reads raw JSON without checking — inject via modified backup file. Check: (1) backup format (plaintext JSON? XML?), (2) restore validation (usually missing), (3) code paths that handle `intent:` scheme. Common in password managers, note apps, bookmark managers.
- **Native "sanitizer" as enabler pattern:** When a native function strips extras/data from an intent but then ADDS a validation flag (e.g., `putExtra("VALID", true)`), the sanitizer IS the exploit enabler. The app assumes only sanitized intents reach the protected activity, but the sanitizer itself grants access. Reverse the native function to confirm: look for `removeExtra` loop followed by `putExtra` with a boolean `true` (mov w4, 1 in arm64).
- **Exported ContentProvider brute-force:** When a ContentProvider is exported without permission protection and uses a small keyspace for access control (e.g., 4-digit PIN), extract crypto parameters from assets/resources and brute-force offline. Pattern: `content query --uri content://authority --where "pin=XXXX"`. For offline cracking: extract encryptedData/salt/iv/iterations from APK assets, then PBKDF2+AES decrypt in Python loop. 4-digit PIN = 10K attempts = <1 second.
- **SnakeYAML deserialization RCE:** When an app uses `yaml.load()` (not `yaml.loadAs()` or `SafeConstructor`), it allows arbitrary object instantiation via `!!fully.qualified.ClassName [args]` tags. Look for gadget classes with dangerous constructors (Runtime.exec, ProcessBuilder, file I/O). Common in config editor/viewer apps. The safe alternative is `new Yaml(new SafeConstructor(new LoaderOptions()))`.

### Native Code Analysis

- **Static analysis pattern for native lib hijack:** Look for `System.load()` with paths under `getFilesDir()`/`getCacheDir()` combined with unsanitized `getLastPathSegment()` in file download handlers.
- **XOR-obfuscated strings in native libs:** Common pattern in MHL challenges. Decode with: `''.join(chr(b ^ key) for b in byte_array)`. Try keys 0x00-0x7F. Look for readable scheme strings (intent:, http://, https://) to identify the key quickly.
- **r2 for quick native function analysis:** When Ghidra isn't running, use `r2 -q -c 'aa;s sym.Java_pkg_Class_method;pdf' lib.so` to disassemble JNI functions. Look for JNI call offsets (0xf8=GetObjectClass, 0x108=GetMethodID, 0x538=NewStringUTF, 0x2f0=GetFieldID, 0x2f8=GetObjectField, 0x558=GetArrayLength, 0x568=GetObjectArrayElement) to understand what Java methods the native code calls.

### Unity / IL2CPP

- **Flutter deep link handler not in DEX:** When a Flutter app declares a `DeepLinkHandlerActivity` in the manifest but the class doesn't exist in any DEX file, it's handled by the Flutter engine via `flutter_deeplinking_enabled` meta-data and `HANDLE_DEEPLINKING_META_DATA_KEY`. The deep link URI is passed directly to the Dart layer (libapp.so) where a `DeeplinkBloc` routes it. You won't find the handler in jadx — instead, extract route names from `strings libapp.so | grep -E "^/"` and deep link config from `strings libapp.so | grep -i deeplink`.
- **Flutter app static analysis strategy:** For Flutter apps, jadx only shows the thin Java wrapper (Application class, native SDKs, third-party Java libraries). The real app logic is in `libapp.so`. Key extraction commands:
  - Routes: `strings libapp.so | grep -E "^/[a-z]" | sort -u`
  - API endpoints: `strings libapp.so | grep -iE "https?://" | sort -u`
  - Deep link config: `strings libapp.so | grep -iE "deeplink|deep_link" | sort -u`
  - WebView routes: `strings libapp.so | grep -iE "webview|web_view" | sort -u`
  - Dart package paths: `strings libapp.so | grep "^package:" | sort -u` (reveals module structure)
  - Secrets: `strings libapp.so | grep -iE "api.key|secret|token|password|firebase" | sort -u`
- **Staging builds have relaxed security:** Banking apps with Eversafe/DexGuard often disable root detection on staging builds. Always try launching on rooted device first — if it survives, you skip the entire bypass effort.

- **Unity IL2CPP reverse engineering:** For Unity 2020.x IL2CPP apps, all C# class/method/field/string-literal names are in `global-metadata.dat`. Key patterns: (1) grep for `[ClassName]` log prefixes to find the relevant class, (2) grep for method names like `Handle*`, `check*`, `validate*`, `get*` to understand the flow, (3) look for field names like `domainRegex`, `updateHost` that reveal validation logic, (4) coroutine names like `<MethodName>d__N` reveal async operations. The actual game logic is NOT in `classes.dex` — it's in `libil2cpp.so` + metadata.
- **Unity IL2CPP deep link parameter discovery:** Hardcoded URLs in `global-metadata.dat` may use DIFFERENT query parameter names than the deep link handler expects. Don't assume the parameter name from hardcoded strings — test systematically. Use `strings global-metadata.dat | grep -E "^(check|get|set|validate|parse)[A-Z]"` to find method names that hint at the actual parameter (e.g., `checkHost` → parameter is `host=`, not `patch=` from the hardcoded URL). When host extraction always returns empty despite correct URI format, the parameter name is likely wrong.
- **Mono/Unity custom scheme URI parsing quirk:** In Unity 2020.x (Mono runtime), `System.Uri` does NOT reliably parse query parameters from custom scheme URIs (e.g., `customscheme://host?key=value`). The `Uri.Query` property may return empty. Apps work around this with manual string parsing or by using Android's Java-side `Uri.getQueryParameter()` via JNI. When testing deep links, if the app receives the full URI string (confirmed via logcat) but fails to extract parameters, try different parameter names — the extraction method may be parameter-name-specific.

### Phase Skipping Rules

- **Offline/no-network apps:** When the app has no internet permission and no HTTP URLs in source, mark Phases 4 (Traffic Analysis) and 8 (API Testing) as N/A immediately after Phase 2. Focus Phase 6 on broadcast exploitation, SharedPreferences validation, and data storage inspection.
- **Client-side-only exploit chains (WebView RCE, broadcast injection):** When the exploit is entirely client-side (no server API involved), mark Phase 8 as N/A. Phase 9 validates the exploit dynamically.

### Exploit Hosting & Delivery

- **Exploit hosting pitfall:** Python's `http.server` decodes `%2F` in URL paths and resolves `../`, causing 404 for path traversal payloads. Use a custom server that serves the payload for any request path (see `android-path-traversal-rce.md`).
- **Runtime.exec(String) splitting pitfall:** `Runtime.exec(String)` uses `StringTokenizer` to split on whitespace — shell features (pipes, redirects, semicolons) are NOT interpreted. `exec("sh -c id")` works (3 tokens: sh, -c, id) but `exec("sh -c id > /tmp/out")` fails (sh only executes "id", "> /tmp/out" becomes $0/$1). Workaround: push a script to an executable path first, then exec the script path. Or use `exec(String[])` if you control the call site.
