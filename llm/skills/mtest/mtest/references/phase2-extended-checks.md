# Phase 2: Extended Static Analysis Checks (Steps 7-15)

These checks are performed AFTER the fast-path steps (1-6). Apply based on what Phase 1-6 reveals — not all are needed for every app.

## 7. Unsafe File Operations (Path Traversal Vectors)

- `Uri.getLastPathSegment()` used as filename without sanitization
- `new File(base, userInput)` with no canonical path check
- `System.load()` / `System.loadLibrary()` from writable paths (getFilesDir, getCacheDir)
- Deep link handlers that download and save files from attacker-controlled URIs

## 7a. Intent URI Parsing (Intent Scheme Hijacking)

- Search for `Intent.parseUri(` — if the app parses user-controlled strings as intent URIs, this is a **high-value target**
- Check what flags are passed: `Intent.parseUri(url, Intent.URI_INTENT_SCHEME)` (flag=1) allows full intent specification
- Check if result is launched via `startActivity()` — enables launching non-exported activities
- Check for sanitization: does the app strip component/package/extras before launching? Is the sanitization bypassable?
- Common pattern: app allows `intent:` scheme in URL fields → attacker crafts `intent:#Intent;component=pkg/.InternalActivity;end`
- **Key question:** Where does the URL string come from? If from user input, database, backup file, or deep link parameter — it's attacker-controlled

## 7b. Backup/Restore as Input Validation Bypass

- Check if app implements its own backup (not just `allowBackup` in manifest)
- Look for: JSON/XML export to external storage, plaintext file writes to `getExternalFilesDir()`
- **Critical check:** Does the restore path apply the SAME validation as the UI input path?
- Common pattern: UI validates input (URL scheme, format, length) but restore/import reads raw data without checks
- If backup is plaintext on external storage → any app (or adb) can modify it → inject payloads that bypass UI validation
- Look for: `Gson.fromJson()`, `JSONObject()`, `ObjectInputStream` reading from external files without sanitization

## 8. Native Library Analysis (When .so Files Present)

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

## 9. WebView + JavaScript Bridge Analysis

When WebView with JS enabled is found:
- Check for `addJavascriptInterface()` — exposes Java/native methods to JS
- Map ALL `@JavascriptInterface` methods — these are the attack surface from any loaded page
- Check if WebView loads attacker-controlled URLs (deep links, intent extras, no domain restriction)
- Check for dangerous operations in bridge methods: file I/O, native calls, `system()`, `Runtime.exec()`, `ProcessBuilder`
- Check URL validation in `shouldOverrideUrlLoading()` (or lack thereof)
- Check WebView settings: `setAllowFileAccess`, `setAllowContentAccess`, `setMixedContentMode`, `usesCleartextTraffic`
- If bridge exposes native methods with buffer operations → combine with native overflow analysis
- If app accepts any http/https URL via deep link + has JS bridge → **remote RCE candidate**

## 10. Crypto Analysis

When encryption/decryption is found:
- Identify algorithm, mode, padding (e.g., AES/ECB/PKCS5Padding)
- Check key derivation: hardcoded? small keyspace? no stretching?
- Check for hardcoded ciphertext that can be attacked offline
- If key is derived from user input (PIN, password): estimate brute-force time
- Write a cracking script immediately if keyspace < 10M (runs in seconds)

## 11. Exported Component Analysis

- Identify all exported Activities, BroadcastReceivers, Services, ContentProviders
- Check for permission protection (custom permissions, signature level)
- Map intent-filters and actions — these are the external attack surface
- BroadcastReceivers with no permission = any app can trigger them
- Dynamic receivers registered without RECEIVER_NOT_EXPORTED flag (Android 14+ requirement)

## 12. Deserialization / Unsafe Parsing

- **SnakeYAML `yaml.load()`** — instantiates arbitrary classes via `!!` tag. Safe alternative: `new Yaml(new SafeConstructor())` or `yaml.loadAs(input, Map.class)`
- **Jackson `ObjectMapper`** with `enableDefaultTyping()` or `@JsonTypeInfo(use=CLASS)` → polymorphic RCE
- **ObjectInputStream** — Java native deserialization, gadget chains
- **Gson/Jackson with polymorphic types** — type confusion attacks
- **XMLDecoder** — arbitrary object instantiation, direct method invocation
- Pattern: find the "sink" class first (e.g., a class whose constructor calls `Runtime.exec()`), then find the deserialization entry point that can reach it
- Check for gadget classes on classpath: constructors calling `Runtime.exec()`, `ProcessBuilder`, file I/O, reflection
- Check input source: user-controlled (intents, file pickers, network) = exploitable
- If found: write exploit payload immediately (see `deserialization-attacks.md`, `yaml-deserialization-rce.md`)

## 13. Exported ContentProvider Analysis

- Identify all providers with `android:exported="true"` and no `android:permission`
- Check `query()` for SQL injection (raw string concatenation in selection)
- Check `openFile()` for path traversal (unsanitized `getLastPathSegment()`)
- Check for weak authentication (PIN/password in selection parameter with small keyspace)
- Test access: `adb shell content query --uri content://<authority>`
- See `content-provider-attacks.md` for exploitation patterns

## 14. Binary Protections Check

- Android: ProGuard/R8 obfuscation, native libs
- iOS: PIE, stack canary, ARC, code signing

## 15. Automated Scanning

```bash
# MobSF (comprehensive)
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
# Upload APK/IPA at http://localhost:8000
```

## References

`static-analysis.md`, `native-re-mcp.md`, `android-path-traversal-rce.md`, `crypto-key-cracking.md`, `native-buffer-overflow.md`, `deserialization-attacks.md`, `content-provider-attacks.md`, `yaml-deserialization-rce.md`, `deeplink-webview-hijack.md`
