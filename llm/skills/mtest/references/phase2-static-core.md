# Phase 2: Static Analysis (Core Steps 1-6)

### Gate: decompilation complete, secrets scan done, endpoints extracted, framework identified

**Fast-path priority (do these first, depth checks 7-15 after):**
1. Decompile + framework detection (steps 1-2)
2. Manifest: exported components, debuggable, allowBackup (step 3)
3. Deep links + WebView + JS bridge (step 6)
4. Secrets: API keys, hardcoded creds (step 4)
5. Endpoints: all URLs, API paths (step 5)

**Steps:**

1. **[Both]** Decompile and disassemble:
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

2. **[Both]** Cross-platform framework detection:
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

3. **[Android]** Manifest analysis / **[iOS]** Info.plist analysis:
   - Android: debuggable, allowBackup, exported components, network security config
   - iOS: ATS exceptions, URL schemes, entitlements

4. **[Both]** Secrets hunting:
   - API keys, tokens, credentials in source
   - Firebase/cloud URLs
   - Private keys/certs in assets
   - Base64-encoded secrets

5. **[Both]** Endpoint extraction:
   - All HTTP(S) URLs in source
   - API path patterns
   - WebSocket endpoints
   - Third-party service integrations

6. **[Android]** Deep link → WebView hijack analysis / **[iOS]** URL scheme + Universal Link analysis:
   - Find all `@DeepLink` annotations containing "web" or "url" in the route
   - Check if handler passes unvalidated URL to WebView
   - Check if WebView has `addJavascriptInterface` — map ALL `@JavascriptInterface` methods
   - Check for SecureWebView pattern (domain allowlist gating `loadUrl()`)
   - Check for feature flags controlling allowlist behavior (static analysis CANNOT determine production state)
   - See `deeplink-webview-hijack.md` for full exploitation patterns and severity rating matrix

**After fast-path complete → load `references/phase2-extended-checks.md` for steps 7-15.**

**References:** `static-analysis.md`, `native-re-mcp.md`, `android-path-traversal-rce.md`, `crypto-key-cracking.md`, `native-buffer-overflow.md`, `deserialization-attacks.md`, `content-provider-attacks.md`, `yaml-deserialization-rce.md`, `deeplink-webview-hijack.md`
