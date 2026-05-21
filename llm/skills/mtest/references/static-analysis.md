# Static Analysis Reference

## Android APK Analysis

### Decompilation Pipeline

```bash
# Full pipeline: APK → Java source + resources
jadx -d jadx_out/ target.apk          # DEX → Java (primary)
apktool d target.apk -o apktool_out/   # Disassemble to smali + raw resources
jadx-gui target.apk                    # GUI for browsing (optional)

# Alternative: dex2jar + JD-GUI
d2j-dex2jar target.apk -o target.jar
jd-gui target.jar
```

### AndroidManifest.xml Checklist

```bash
# Extract readable manifest
apktool d target.apk -o target_dir/
cat target_dir/AndroidManifest.xml
```

| Check | Command | Finding if True |
|-------|---------|-----------------|
| Debuggable | `grep "android:debuggable=\"true\"" AndroidManifest.xml` | CRITICAL — attach debugger in prod |
| Backup enabled | `grep "android:allowBackup=\"true\"" AndroidManifest.xml` | HIGH — extract app data via adb backup |
| Exported activities | `grep "android:exported=\"true\"" AndroidManifest.xml` | Check each for sensitive functionality |
| Network config | `grep "networkSecurityConfig" AndroidManifest.xml` | Review trust anchors |
| Custom permissions | `grep "android:protectionLevel" AndroidManifest.xml` | Check if signature vs dangerous |
| Min SDK | `grep "minSdkVersion" AndroidManifest.xml` | Low SDK = more attack surface |

### Network Security Config Analysis

```bash
cat target_dir/res/xml/network_security_config.xml
```

Red flags:
- `<certificates src="user" />` in base-config → trusts user CAs (good for testing, bad for prod)
- `cleartextTrafficPermitted="true"` → allows HTTP
- No `<pin-set>` → no certificate pinning
- `<pin-set expiration="...">` with past date → pinning expired

### Secrets Hunting

```bash
cd jadx_out/sources/

# Google API keys
grep -rn "AIza[0-9A-Za-z_-]\{35\}" --include="*.java"

# AWS keys
grep -rn "AKIA[0-9A-Z]\{16\}" --include="*.java"

# Generic secrets
grep -rn "api[_-]\?key\|api[_-]\?secret\|apikey" --include="*.java" | grep -i "=\s*\""

# Firebase URLs (check if .json accessible without auth)
grep -rn "firebaseio\.com" --include="*.java"
# Test: curl https://<project>.firebaseio.com/.json

# Hardcoded credentials
grep -rn "password\|passwd\|secret\|token" --include="*.java" | grep "=\s*\""

# Connection strings
grep -rn "jdbc:\|mongodb://\|redis://\|amqp://" --include="*.java"

# Private keys in assets
find . -name "*.pem" -o -name "*.p12" -o -name "*.bks" -o -name "*.keystore" -o -name "*.jks"
grep -rn "BEGIN RSA PRIVATE KEY\|BEGIN PRIVATE KEY" .

# Strings resources
grep -rn "api\|key\|secret\|password\|token" target_dir/res/values/strings.xml

# Base64 blobs (potential encoded secrets)
grep -rn "[A-Za-z0-9+/]\{40,\}=\{0,2\}" --include="*.java" | head -30
```

### Endpoint Extraction

```bash
# All URLs
grep -rn "https\?://[a-zA-Z0-9./_-]*" --include="*.java" -oh | sort -u

# API paths
grep -rn "\"/api/\|/v[0-9]/" --include="*.java" | sort -u

# Retrofit/OkHttp annotations
grep -rn "@GET\|@POST\|@PUT\|@DELETE\|@PATCH" --include="*.java"

# WebSocket endpoints
grep -rn "wss\?://" --include="*.java"

# Filter out noise (Google, Facebook, analytics)
grep -rn "https\?://" --include="*.java" -oh | sort -u | grep -v "google\|facebook\|crashlytics\|firebase\|android\|schema"
```

### Native Libraries

```bash
# Check for native libs
ls apktool_out/lib/*/
# arm64-v8a/ armeabi-v7a/ x86/ x86_64/

# Strings from native libs
strings apktool_out/lib/arm64-v8a/*.so | grep -i "key\|secret\|password\|http"

# Check if crypto/auth logic is in native code
nm -D apktool_out/lib/arm64-v8a/*.so | grep -i "encrypt\|decrypt\|verify\|sign\|auth"
```

### Obfuscation Assessment

```bash
# Check if ProGuard/R8 applied
# Obfuscated: single-letter class/method names (a.b.c, void a())
# Not obfuscated: full descriptive names

# Quick check
ls jadx_out/sources/ | head -20
# If you see: a/ b/ c/ → obfuscated
# If you see: com/target/app/LoginActivity → not obfuscated

# Check for ProGuard mapping
find apktool_out/ -name "mapping.txt" -o -name "proguard*"
```

---

## iOS IPA Analysis

### Extraction and Setup

```bash
# Unzip IPA
unzip target.ipa -d ipa_out/
ls ipa_out/Payload/*.app/

# Binary path
BINARY=$(ls ipa_out/Payload/*.app/*.app | head -1)
# Or: find ipa_out/Payload -type f -perm +111 -not -name "*.dylib"
```

### Binary Protections

```bash
# Architecture check
lipo -info ipa_out/Payload/*.app/<binary>
file ipa_out/Payload/*.app/<binary>

# PIE (Position Independent Executable) — should be enabled
otool -hv ipa_out/Payload/*.app/<binary> | grep PIE

# Stack canary — should be present
otool -Iv ipa_out/Payload/*.app/<binary> | grep "_stack_chk"

# ARC (Automatic Reference Counting) — should be used
otool -Iv ipa_out/Payload/*.app/<binary> | grep "_objc_release"

# Code signing
codesign -dvvv ipa_out/Payload/*.app/

# Entitlements (capabilities)
codesign -d --entitlements :- ipa_out/Payload/*.app/
# Or from embedded profile:
security cms -D -i ipa_out/Payload/*.app/embedded.mobileprovision
```

### Info.plist Analysis

```bash
# Convert to readable XML
plutil -convert xml1 ipa_out/Payload/*.app/Info.plist -o Info_readable.plist
cat Info_readable.plist

# Or use plutil -p for quick view
plutil -p ipa_out/Payload/*.app/Info.plist
```

Key checks:

```bash
# App Transport Security
plutil -p Info_readable.plist | grep -A20 "NSAppTransportSecurity"
# NSAllowsArbitraryLoads = true → HIGH (all HTTP allowed)
# NSExceptionAllowsInsecureHTTPLoads → domain-specific HTTP
# NSExceptionMinimumTLSVersion = TLSv1.0 → weak TLS

# URL Schemes
plutil -p Info_readable.plist | grep -A10 "CFBundleURLSchemes"

# Queried URL schemes (what other apps it checks for)
plutil -p Info_readable.plist | grep -A20 "LSApplicationQueriesSchemes"

# Background modes
plutil -p Info_readable.plist | grep -A5 "UIBackgroundModes"

# Exported UTIs (file type handlers)
plutil -p Info_readable.plist | grep -A10 "UTExportedTypeDeclarations"
```

### Header/Class Extraction

```bash
# Objective-C headers
class-dump ipa_out/Payload/*.app/<binary> > headers.h
class-dump -H ipa_out/Payload/*.app/<binary> -o headers/

# For Swift (class-dump won't work well)
# Use dsdump or swift-demangle
dsdump --objc ipa_out/Payload/*.app/<binary>
strings ipa_out/Payload/*.app/<binary> | swift-demangle | grep -i "auth\|login\|token\|key"

# Look for interesting class names
grep -i "auth\|login\|crypto\|keychain\|biometric\|pin\|jailbreak\|root\|ssl\|certificate" headers.h
```

### Secrets in iOS Binary

```bash
# Strings analysis
strings ipa_out/Payload/*.app/<binary> | grep -iE "api|key|secret|http|password|token|firebase" | sort -u

# Embedded plists/configs
find ipa_out/Payload/*.app/ -name "*.plist" -o -name "*.json" -o -name "*.xml" | while read f; do
  echo "=== $f ==="
  plutil -p "$f" 2>/dev/null || cat "$f"
done | grep -i "key\|secret\|token\|password\|api"

# Embedded frameworks
ls ipa_out/Payload/*.app/Frameworks/
# Check each framework for secrets too
for fw in ipa_out/Payload/*.app/Frameworks/*.framework/*; do
  strings "$fw" 2>/dev/null | grep -iE "api.key|secret|password"
done
```

### Universal Links / App Links

```bash
# Check associated domains entitlement
codesign -d --entitlements :- ipa_out/Payload/*.app/ | grep "associated-domains"

# Verify AASA file
# For each domain in entitlements:
curl https://<domain>/.well-known/apple-app-site-association
curl https://<domain>/apple-app-site-association
```

---

## Flutter App Analysis

### Identifying Flutter Apps

```bash
# Check for Flutter indicators in APK
apktool d target.apk -o apktool_out/
ls apktool_out/lib/arm64-v8a/ | grep -i "flutter\|app"
# Flutter apps have: libflutter.so + libapp.so

# Confirm Flutter version
strings apktool_out/lib/arm64-v8a/libflutter.so | grep "Flutter Engine"
strings apktool_out/lib/arm64-v8a/libflutter.so | grep -i "version"

# iOS: check for Flutter.framework
ls ipa_out/Payload/*.app/Frameworks/ | grep Flutter

# Key difference from native apps:
# - jadx/apktool show NOTHING useful (just Flutter engine bootstrap)
# - Business logic is compiled Dart AOT in libapp.so
# - Standard Frida SSL bypass may NOT work (Flutter uses BoringSSL, not Android TrustManager)
```

### Flutter Decompilation

```bash
# === Method 1: reFlutter (recommended for quick wins) ===
pip install reflutter

# Patch APK to disable SSL verification at engine level
reflutter target.apk
# Outputs: patched APK with SSL verification disabled
# Also outputs: dump of Dart classes/functions (snapshot_hash.dart)

# Sign and install patched APK
apksigner sign --ks debug.keystore --ks-pass pass:password target_patched.apk
adb install target_patched.apk

# reFlutter also dumps function offsets → use for Frida hooking

# === Method 2: Blutter (best for full analysis) ===
git clone https://github.com/aspect-build/aspect-cli
# Or the more maintained fork:
git clone https://github.com/aspect-build/aspect-cli.git
pip install blutter  # if available

# Extract libapp.so and analyze
blutter apktool_out/lib/arm64-v8a/libapp.so output/
# Outputs:
# - Class hierarchy
# - Function names and offsets
# - String constants
# - Type information

# === Method 3: Doldrums (Dart snapshot parser) ===
git clone https://github.com/nicolo-ribaudo/doldrums
cd doldrums
# Parse the Dart snapshot from libapp.so
python3 doldrums.py apktool_out/lib/arm64-v8a/libapp.so > dart_classes.txt

# === Method 4: darter (Dart AOT snapshot analyzer) ===
git clone https://github.com/aspect-build/aspect-cli
# Extracts class names, method names, and string literals

# === Method 5: Manual strings analysis (quick & dirty) ===
strings apktool_out/lib/arm64-v8a/libapp.so | grep -iE "api|http|key|secret|token|password|endpoint" | sort -u
strings apktool_out/lib/arm64-v8a/libapp.so | grep -E "https?://" | sort -u
strings apktool_out/lib/arm64-v8a/libapp.so | grep -iE "\.jago\.|jago\.com" | sort -u
```

### Flutter-Specific Secrets Hunting

```bash
# Dart string constants are embedded in libapp.so
# They're NOT in res/values/strings.xml or Java source

# Extract all readable strings
strings -n 10 apktool_out/lib/arm64-v8a/libapp.so > all_strings.txt

# Filter for secrets
grep -iE "api[_-]?key|api[_-]?secret|apikey" all_strings.txt
grep -iE "AIza[0-9A-Za-z_-]{35}" all_strings.txt          # Google API key
grep -iE "AKIA[0-9A-Z]{16}" all_strings.txt                # AWS key
grep -iE "sk_live_[0-9a-zA-Z]{24}" all_strings.txt         # Stripe
grep -iE "firebase|firestore|firebaseio" all_strings.txt    # Firebase
grep -iE "Bearer |token|jwt|auth" all_strings.txt

# API endpoints
grep -oE "https?://[a-zA-Z0-9./_-]+" all_strings.txt | sort -u

# Environment/config patterns
grep -iE "prod|staging|dev|uat|sit" all_strings.txt | grep -iE "url|host|api|endpoint"

# Package names (identify dependencies)
grep -iE "package:" all_strings.txt | sort -u
# Reveals: dio, http, shared_preferences, flutter_secure_storage, etc.
```

### Flutter SSL Pinning Bypass

```bash
# Standard Frida SSL bypass DOES NOT WORK for Flutter!
# Flutter uses BoringSSL (compiled into libflutter.so), not Android's TrustManager

# === Method 1: reFlutter (easiest) ===
reflutter target.apk
# Patches libflutter.so to disable SSL verification
# No Frida needed — just install patched APK

# === Method 2: Frida + BoringSSL hook ===
```

```javascript
// flutter_ssl_bypass.js - Hook BoringSSL's certificate verification
// Pattern-based — may need adjustment per Flutter version

function disableFlutterSSL() {
    var m = Process.findModuleByName("libflutter.so");
    if (!m) {
        console.log("[-] libflutter.so not found, trying libapp.so");
        m = Process.findModuleByName("libapp.so");
    }
    if (!m) {
        console.log("[-] Neither libflutter.so nor libapp.so found");
        return;
    }

    console.log("[*] Found " + m.name + " at " + m.base + " size: " + m.size);

    // Pattern for ssl_crypto_x509_session_verify_cert_chain
    // These patterns vary by Flutter/BoringSSL version
    var patterns = [
        // Flutter 3.x (arm64)
        "FF 03 01 D1 FD 7B 01 A9 F4 4F 02 A9 F5 07 00 AA",
        // Flutter 3.x alternate
        "FF C3 01 D1 FD 7B 01 A9 F4 4F 02 A9 F5 07 00 AA",
        // Flutter 2.x (arm64)
        "FF 43 01 D1 FD 7B 01 A9 F4 4F 02 A9 F5 07 00 AA",
        // Flutter 2.5+ (arm64)
        "2D E9 F0 4F AD F5 C6 6D 00 AF",
    ];

    for (var i = 0; i < patterns.length; i++) {
        try {
            var matches = Memory.scanSync(m.base, m.size, patterns[i]);
            if (matches.length > 0) {
                console.log("[+] Pattern " + i + " matched at: " + matches[0].address);
                Interceptor.attach(matches[0].address, {
                    onLeave: function(retval) {
                        retval.replace(0x1); // Return true (certificate valid)
                    }
                });
                console.log("[+] Flutter SSL verification bypassed!");
                return;
            }
        } catch(e) {
            // Pattern scan may fail on some memory regions
        }
    }

    // Fallback: search for "x509.cc" string reference (BoringSSL source file)
    var x509Refs = Memory.scanSync(m.base, m.size, "78 35 30 39 2E 63 63"); // "x509.cc"
    if (x509Refs.length > 0) {
        console.log("[*] Found x509.cc reference, searching nearby for verify function...");
        // Manual analysis needed — dump nearby functions
    }

    console.log("[-] No pattern matched. Try reFlutter or manual analysis.");
    console.log("[-] Flutter version may be too new. Check: strings libflutter.so | grep 'Flutter Engine'");
}

// Also try hooking Dart's SecurityContext
// Some Flutter apps use dart:io HttpClient with custom SecurityContext
Java.perform(function() {
    // This catches apps that configure pinning via Dart code
    // (in addition to BoringSSL engine-level pinning)
    try {
        // Hook the Dart HTTP client's badCertificateCallback
        console.log("[*] Attempting Dart-level SSL bypass...");
        // Dart functions are in libapp.so — need offset from reFlutter/blutter output
    } catch(e) {}
});

disableFlutterSSL();
```

```bash
# === Method 3: Proxy via ProxyDroid + iptables (no SSL bypass needed) ===
# If you can't bypass pinning, intercept at network level:
# 1. Use mitmproxy with --mode transparent
# 2. Route all traffic via iptables
adb shell su -c "iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination <proxy_ip>:8080"
# This won't decrypt HTTPS but shows connection targets

# === Method 4: Patch libflutter.so directly ===
# Find the ssl_verify function and NOP it out
# Requires: Ghidra/IDA analysis of libflutter.so
# Look for: ssl_crypto_x509_session_verify_cert_chain
# Patch return value to always return 1 (valid)
# Rebuild APK with patched .so
```

### Flutter-Specific Frida Hooking

```javascript
// flutter_function_hook.js
// Hook Dart functions by offset (get offsets from reFlutter/blutter output)

function hookDartFunction(libName, offset, name) {
    var module = Process.findModuleByName(libName);
    if (!module) { console.log("[-] " + libName + " not found"); return; }

    var addr = module.base.add(offset);
    console.log("[*] Hooking " + name + " at " + addr);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            console.log("[" + name + "] called");
            // Dart uses a custom calling convention
            // args[0] = Dart thread/isolate pointer
            // Actual arguments start at different offsets
        },
        onLeave: function(retval) {
            console.log("[" + name + "] returned: " + retval);
        }
    });
}

// Example: hook login function (offset from blutter/reFlutter output)
// hookDartFunction("libapp.so", 0x1A2B3C, "LoginService.authenticate");
// hookDartFunction("libapp.so", 0x4D5E6F, "ApiClient.post");

// Monitor all HTTP requests (hook Dart's _HttpClient)
// Offsets vary per build — use reFlutter dump to find them
```

### Flutter Asset Extraction

```bash
# Flutter assets are in: assets/flutter_assets/
ls apktool_out/assets/flutter_assets/

# Common interesting files:
cat apktool_out/assets/flutter_assets/AssetManifest.json
# Lists all bundled assets

# Check for embedded configs
find apktool_out/assets/ -name "*.json" -o -name "*.yaml" -o -name "*.env" | while read f; do
    echo "=== $f ==="
    cat "$f" | grep -iE "api|key|secret|url|host|token" && echo ""
done

# Font files, images (less interesting for security)
# But: check for embedded certificates (.pem, .cer, .crt)
find apktool_out/assets/ -name "*.pem" -o -name "*.cer" -o -name "*.crt" -o -name "*.p12"
```

### Flutter Testing Decision Tree

```
Is it a Flutter app? (libflutter.so + libapp.so present)
├── YES
│   ├── Static Analysis:
│   │   ├── strings on libapp.so (endpoints, secrets)
│   │   ├── reFlutter for class/function dump
│   │   ├── blutter for full decompilation (if time permits)
│   │   └── Asset extraction (flutter_assets/)
│   ├── SSL Bypass:
│   │   ├── Try reFlutter patched APK first (easiest)
│   │   ├── If fails → Frida BoringSSL pattern hook
│   │   ├── If fails → manual libflutter.so patching
│   │   └── If all fail → network-level interception only
│   └── Dynamic Testing:
│       ├── Frida hooks need function offsets from reFlutter/blutter
│       ├── Standard Java hooks still work for Android APIs (storage, crypto)
│       └── Dart-level hooking requires offset mapping
└── NO → Standard native analysis (jadx + apktool)
```

---

## Automated Tools

### MobSF (Mobile Security Framework)

```bash
# Run MobSF
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Upload APK/IPA at http://localhost:8000
# Provides: manifest analysis, code analysis, binary analysis, hardcoded secrets, API endpoints

# REST API for automation
curl -X POST http://localhost:8000/api/v1/upload \
  -H "Authorization: <api_key>" \
  -F "file=@target.apk"
```

### QARK (Quick Android Review Kit)

```bash
pip install qark
qark --apk target.apk --report-type html
# Outputs: HTML report with findings
```

### APKLeaks

```bash
pip install apkleaks
apkleaks -f target.apk -o endpoints.txt
# Extracts: URLs, IPs, secrets patterns from APK
```

### Nuclei Mobile Templates

```bash
# If API endpoints extracted, scan with nuclei
nuclei -l extracted_endpoints.txt -t mobile/ -t exposures/ -t tokens/
```

---

## What to Document (Phase 2 Output)

Save to `phase2-static/<platform>/`:

1. `manifest-analysis.md` — all manifest/plist findings
2. `secrets-found.md` — any hardcoded secrets with file:line
3. `endpoints.txt` — all extracted URLs/API paths
4. `components.md` — exported components, URL schemes, deep links
5. `protections.md` — binary protections, obfuscation level, pinning config
6. `third-party.md` — SDKs, frameworks, analytics identified
7. `mobsf-report.html` — automated scan results (if run)
