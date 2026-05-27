# Operational Notes

Battle-tested patterns, pitfalls, and techniques from real mobile pentesting engagements. Load this reference when you hit a specific problem during testing.

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