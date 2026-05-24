# Mobile Code Review Patterns

Scanner ID: **3y — mobile-code**

## Skip Condition

```bash
# Skip if no mobile code in project
find . \( -name "*.smali" -o -name "*.dex" -o -name "AndroidManifest.xml" -o -name "Info.plist" -o -name "*.swift" -o -name "*.m" -o -name "index.android.bundle" -o -name "main.dart.js" \) -not -path "*/node_modules/*" | head -1
# If empty → SKIP this scanner
```

---

## Applies When

- Decompiled APK (jadx output — Java/Kotlin source)
- Decompiled IPA (Hopper/Ghidra output — Objective-C/Swift)
- React Native bundle (`index.android.bundle` / `index.ios.bundle`)
- Flutter build (`main.dart.js` for web, `libapp.so` for native)
- Xamarin assemblies (decompiled C#)
- Source code of mobile app provided directly

---

## 1. Hardcoded Secrets

### Android

```bash
# BuildConfig fields
grep -rn "BuildConfig\." --include="*.java" --include="*.kt" | grep -i "key\|secret\|token\|password\|api"

# strings.xml
grep -rn "api_key\|secret\|token\|password\|client_id\|client_secret" */res/values/strings.xml

# SharedPreferences with sensitive data
grep -rn "getSharedPreferences\|putString\|getString" --include="*.java" --include="*.kt" | grep -i "token\|key\|pass\|secret"

# Gradle/build config
grep -rn "buildConfigField\|resValue" --include="*.gradle" --include="*.gradle.kts" | grep -i "key\|secret\|token"
```

### iOS

```bash
# Info.plist keys
grep -rn "APIKey\|SecretKey\|ClientID\|ClientSecret\|Password" --include="*.plist"

# Hardcoded in source
grep -rn "let.*=.*\"[A-Za-z0-9+/=]{20,}\"" --include="*.swift" --include="*.m"
grep -rn "@\"[A-Za-z0-9+/=]{20,}\"" --include="*.m"  # Objective-C string literals

# Keychain usage (check if storing properly)
grep -rn "kSecClass\|SecItemAdd\|SecItemCopyMatching" --include="*.swift" --include="*.m"
```

### React Native

```bash
# Secrets in JS bundle
grep -oE "(api_key|apiKey|secret|token|password|client_id|CLIENT_SECRET)\s*[:=]\s*['\"][^'\"]+['\"]" index.android.bundle | head -20

# Environment config exposed
grep -oE "__DEV__|process\.env\.[A-Z_]+" index.android.bundle | sort -u
```

### Flutter

```bash
# Dart constants
grep -rn "const.*=.*'[A-Za-z0-9+/=]{16,}'" --include="*.dart"
grep -rn "apiKey\|secretKey\|apiSecret\|clientSecret" --include="*.dart"

# .env file bundled
find . -name ".env" -o -name "*.env" | head -5
```

---

## 2. Insecure Network Communication

```bash
# HTTP (not HTTPS) URLs
grep -rn "http://" --include="*.java" --include="*.kt" --include="*.swift" --include="*.m" --include="*.dart" | grep -v "http://localhost\|http://127\|http://10\.\|http://schemas\|http://www.w3.org\|http://ns.adobe"

# Certificate pinning implementation (check if present AND correct)
grep -rn "CertificatePinner\|TrustManager\|X509TrustManager\|SSLPinningMode\|evaluateServerTrust\|ATS\|NSAppTransportSecurity" --include="*.java" --include="*.kt" --include="*.swift" --include="*.m" --include="*.plist"

# Trust all certificates (VULNERABLE)
grep -rn "TrustAllCerts\|ALLOW_ALL_HOSTNAME\|setHostnameVerifier\|trustAllCerts\|InsecureTrustManager\|AllowsArbitraryLoads" --include="*.java" --include="*.kt" --include="*.swift" --include="*.plist"

# OkHttp/Retrofit without pinning
grep -rn "OkHttpClient\|Retrofit\.Builder" --include="*.java" --include="*.kt" | grep -v "certificatePinner\|sslSocketFactory"
```

---

## 3. Insecure Data Storage

### Android

```bash
# World-readable/writable files
grep -rn "MODE_WORLD_READABLE\|MODE_WORLD_WRITABLE\|openFileOutput" --include="*.java" --include="*.kt"

# SQLite without encryption
grep -rn "SQLiteDatabase\|openOrCreateDatabase\|Room\.databaseBuilder" --include="*.java" --include="*.kt" | grep -v "SQLCipher\|SupportFactory"

# External storage (accessible by other apps)
grep -rn "getExternalStorage\|getExternalFilesDir\|Environment\.getExternalStorageDirectory" --include="*.java" --include="*.kt"

# Logging sensitive data
grep -rn "Log\.\(d\|i\|v\|w\|e\)" --include="*.java" --include="*.kt" | grep -i "token\|password\|key\|secret\|session\|cookie"
```

### iOS

```bash
# NSUserDefaults for sensitive data (NOT secure)
grep -rn "UserDefaults\|NSUserDefaults" --include="*.swift" --include="*.m" | grep -i "token\|password\|key\|secret\|session"

# File protection level
grep -rn "FileProtectionType\|NSFileProtection" --include="*.swift" --include="*.m"
# Should be .complete or .completeUnlessOpen for sensitive files

# Pasteboard exposure
grep -rn "UIPasteboard\|generalPasteboard" --include="*.swift" --include="*.m"
```

---

## 4. Authentication & Session Management

```bash
# Biometric auth bypass (check if server-side validated)
grep -rn "BiometricPrompt\|LAContext\|evaluatePolicy\|canEvaluatePolicy\|deviceCredentialAllowed" --include="*.java" --include="*.kt" --include="*.swift" --include="*.m"
# VULNERABLE if: biometric success just unlocks local storage without server validation

# Token storage location
grep -rn "SharedPreferences\|UserDefaults\|AsyncStorage\|SecureStorage\|EncryptedSharedPreferences\|KeyStore\|Keychain" --include="*.java" --include="*.kt" --include="*.swift" --include="*.dart" --include="*.js"

# Session timeout / token refresh
grep -rn "refreshToken\|tokenExpir\|sessionTimeout\|autoLogout" --include="*.java" --include="*.kt" --include="*.swift" --include="*.dart"

# Root/jailbreak detection (check if bypassable)
grep -rn "isRooted\|isJailbroken\|RootBeer\|SafetyNet\|DeviceIntegrity\|checkRoot\|detectRoot" --include="*.java" --include="*.kt" --include="*.swift" --include="*.m"
```

---

## 5. Intent/Deep Link Vulnerabilities (Android)

```bash
# Exported components without permission
grep -rn "exported=\"true\"\|android:exported" AndroidManifest.xml
# Check: do exported activities/services/receivers have permission requirements?

# Deep link handlers
grep -rn "android:scheme\|android:host\|android:pathPattern" AndroidManifest.xml
grep -rn "intent://\|deeplink\|handleDeepLink\|getIntent\(\)\.getData" --include="*.java" --include="*.kt"

# Intent data used without validation
grep -rn "getIntent\(\)\.\(getStringExtra\|getData\|getExtras\)" --include="*.java" --include="*.kt"
# Check: is the data validated before use? (could be from malicious app)

# WebView with JavaScript enabled + loadUrl from intent
grep -rn "setJavaScriptEnabled\|addJavascriptInterface\|loadUrl\|loadData" --include="*.java" --include="*.kt"
```

---

## 6. iOS URL Scheme / Universal Link Vulnerabilities

```bash
# Custom URL schemes (can be hijacked by other apps)
grep -rn "CFBundleURLSchemes\|CFBundleURLTypes" --include="*.plist"

# Universal links (more secure but check validation)
grep -rn "applinks:\|apple-app-site-association\|userActivity\|continueUserActivity" --include="*.swift" --include="*.m" --include="*.plist"

# URL handling without validation
grep -rn "openURL\|application.*open.*url\|handleOpen" --include="*.swift" --include="*.m"
```

---

## 7. WebView Security

```bash
# JavaScript enabled (check what's loaded)
grep -rn "setJavaScriptEnabled\(true\)\|javaScriptEnabled\s*=\s*true\|WKWebViewConfiguration" --include="*.java" --include="*.kt" --include="*.swift"

# JavaScript interface (Android — exposes Java methods to JS)
grep -rn "addJavascriptInterface\|@JavascriptInterface" --include="*.java" --include="*.kt"
# CRITICAL if: interface methods access sensitive data or perform actions

# File access in WebView
grep -rn "setAllowFileAccess\|setAllowUniversalAccessFromFileURLs\|allowFileAccessFromFileURLs" --include="*.java" --include="*.kt"

# Loading user-controlled URLs
grep -rn "loadUrl\|loadRequest\|load(URL" --include="*.java" --include="*.kt" --include="*.swift" | grep -v "\"http"
```

---

## 8. Cryptography Issues

```bash
# Weak algorithms
grep -rn "DES\|RC4\|MD5\|SHA1\|ECB\|AES/ECB" --include="*.java" --include="*.kt" --include="*.swift" --include="*.m" | grep -v "SHA256\|SHA-256\|SHA512"

# Hardcoded keys/IVs
grep -rn "SecretKeySpec\|IvParameterSpec\|CCCrypt\|kCCAlgorithm" --include="*.java" --include="*.kt" --include="*.swift" --include="*.m"
# Check: is the key/IV derived from a constant or properly from KeyStore/Keychain?

# Insecure random
grep -rn "java\.util\.Random\|Math\.random\|arc4random\b" --include="*.java" --include="*.kt" --include="*.swift" | grep -v "SecureRandom\|arc4random_uniform"
```

---

## 9. React Native Specific

```bash
# AsyncStorage (unencrypted by default)
grep -rn "AsyncStorage\.\(setItem\|getItem\)" --include="*.js" --include="*.ts" | grep -i "token\|password\|key\|secret"

# Hermes bytecode (check if source maps bundled)
find . -name "*.hbc" -o -name "*.map" | head -5

# Native module bridges (custom native code)
grep -rn "@ReactMethod\|RCT_EXPORT_METHOD\|NativeModules\." --include="*.java" --include="*.kt" --include="*.m" --include="*.js"

# Debugging enabled in release
grep -rn "isDebuggable\|__DEV__\|debuggerEnabled" --include="*.java" --include="*.js"
```

---

## 10. Flutter Specific

```bash
# Platform channels (native bridge)
grep -rn "MethodChannel\|EventChannel\|BasicMessageChannel" --include="*.dart" --include="*.java" --include="*.kt" --include="*.swift"

# Insecure storage
grep -rn "shared_preferences\|flutter_secure_storage\|hive" --include="*.dart" --include="*.yaml"
# shared_preferences = NOT secure (plaintext). flutter_secure_storage = OK.

# Debug mode checks
grep -rn "kDebugMode\|kReleaseMode\|assert(" --include="*.dart"

# Obfuscation check
grep -rn "obfuscate\|--obfuscate\|--split-debug-info" --include="*.yaml" --include="*.sh" --include="Makefile"
```

---

## Finding Severity Guide (Mobile Context)

| Pattern | Typical Severity | Notes |
|---------|-----------------|-------|
| Hardcoded API key (production, write access) | Critical | Direct API abuse |
| Hardcoded API key (read-only, public data) | Low | Limited impact |
| No certificate pinning | Medium | Enables MitM on compromised network |
| Trust all certificates | High | Trivial MitM |
| Sensitive data in SharedPreferences/UserDefaults | Medium | Requires device access |
| Exported activity without auth | Medium-High | Depends on what it exposes |
| WebView JS interface with sensitive methods | High-Critical | Cross-app exploitation |
| Biometric auth without server validation | High | Local bypass → full access |
| Root/jailbreak detection only (no server check) | Low | Bypassable with Frida/Magisk |
| Secrets in React Native bundle | High | Extractable without root |

---

## Cross-Reference

- **mtest skill**: Full mobile pentest framework (dynamic testing, Frida, traffic interception)
- **ptest skill**: `references/mobile-app-testing.md` — black-box mobile testing
- **This scanner**: Static code review of decompiled/source mobile apps
- **vuln-data-exposure.md**: General secrets/PII patterns (language-agnostic)
- **vuln-crypto.md**: Cryptographic weakness patterns (language-agnostic)
