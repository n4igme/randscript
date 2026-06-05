# Meta/Instagram App Testing Patterns

## SSL Pinning Bypass (Partial)

Instagram uses multi-layer pinning:
1. Network Security Config (XML pin-set with SHA-256, expires 2027)
2. Java TrustManagerImpl.verifyChain (Conscrypt)
3. Native BoringSSL SSL_CTX_set_custom_verify callbacks
4. Binary push channel (b.i.instagram.com) — separate pinning, not bypassable

### What works (partial interception):
- Patch APK: remove pin-set from `res/xml/fb_network_security_config.xml`
- Frida hook: `TrustManagerImpl.verifyChain` → return untouched chain
- Block QUIC: `iptables -A OUTPUT -p udp --dport 443 -j DROP`
- Install proxy CA via tmpfs overlay on `/system/etc/security/cacerts/`

### What doesn't work:
- Patched APK can't login (server-side signature validation)
- Frida Gadget + signature spoof (PackageManager hook) — server checks sig hash in HTTP headers
- Native SSL hooks alone (crash or insufficient)
- `overridePins="true"` in NSC alone (native layer ignores it)

### Recommended approach:
Skip authenticated traffic interception. Use Frida runtime hooks on original APK for:
- WebView.loadUrl monitoring
- Intent routing tracing
- Deep link handler analysis
- Content provider access monitoring

## Deep Link Testing (Frida Python Pattern)

```python
import frida, subprocess, time

device = frida.get_usb_device()
session = device.attach(PID)

js = '''
Java.perform(function(){
    var A = Java.use('android.app.Activity');
    A.onCreate.overload('android.os.Bundle').implementation = function(b) {
        var d = this.getIntent().getData();
        var e = this.getIntent().getExtras();
        send('CREATE:' + this.getClass().getName() + '|data=' + d + '|extras=' + e);
        this.onCreate(b);
    };
    A.startActivityForResult.overload('android.content.Intent', 'int').implementation = function(i,c) {
        var d = i.getData(); var comp = i.getComponent();
        send('START:' + (comp?comp.getClassName():'nocomp') + '|data=' + d);
        this.startActivityForResult(i,c);
    };
    var W = Java.use('android.webkit.WebView');
    W.loadUrl.overload('java.lang.String').implementation = function(u) {
        send('WEBVIEW:' + u); this.loadUrl(u);
    };
    send('READY');
});
'''

messages = []
def on_message(msg, data):
    if msg['type'] == 'send':
        messages.append(msg['payload'])

script_obj = session.create_script(js)
script_obj.on('message', on_message)
script_obj.load()
time.sleep(3)

# Trigger deep links
for dl in deep_links:
    subprocess.run(['adb', '-s', SERIAL, 'shell', 'am', 'start', '-a',
        'android.intent.action.VIEW', '-d', dl, '--activity-clear-task', PACKAGE], capture_output=True)
    time.sleep(3)

session.detach()
for m in messages:
    print(m)
```

## Key Indicators in Frida Output

| Pattern | Meaning |
|---------|---------|
| `[START] no-comp \| data=https://evil.com` | Open redirect — URL opened in external browser |
| `key_sanitized_uri=...--sanitized--` | URL validation active — redirect blocked |
| `IgSessionManager.SESSION_TOKEN_KEY=...` | Session token in intent extras (intra-app, not directly exploitable) |
| `[WEBVIEW] https://...` | WebView loaded attacker URL — potential XSS |
| `fragment_name=open_trustly_lightbox` | Payment lightbox triggered (Trustly SDK) |

## Instagram Deep Link Routing

```
instagram://extbrowser?url=X        → OpenInExternalBrowserUrlHandlerActivity → Chrome (NO VALIDATION) ⚠️
instagram://redirect_to_app?url=X   → IGRedirectHandlerActivity → ModalActivity (URL SANITIZED, session token leaked)
instagram://third_party_oauth?...   → FxIgThirdPartyOAuthActivity (redirect_uri SANITIZED)
instagram://oauth_account_linking    → IgOAuthAccountLinkingActivity (redirect_uri SANITIZED)
instagram://in_app_webview?url=X    → UrlHandlerActivity (NO WebView load — likely allowlisted)
```

## Validated Findings & Reportability (Meta Bug Bounty)

### MTEST-001: extbrowser Open Redirect (Low-Medium)

`instagram://extbrowser?url=http://evil.com` opens any `http://` URL in Chrome without validation. The `https://` URLs are sanitized (opened in Instagram's in-app browser), but `http://` scheme bypasses to external browser.

**PoC app pattern (Android):**
```java
// Malicious app triggers open redirect
Intent i = new Intent(Intent.ACTION_VIEW);
i.setData(Uri.parse("instagram://extbrowser?url=http://attacker.com/phish"));
i.setPackage("com.instagram.android");
startActivity(i);
```

**Why it's only Low-Medium for Meta:**
- No JS bridge access (opens in Chrome, not WebView)
- No session token leakage to attacker domain
- Impact limited to phishing (user sees Chrome open attacker URL)
- Meta's bar for deep link findings is High+ unless chained with token theft

### What's NOT reportable for Meta:

| Finding | Why Not |
|---------|---------|
| Session token in intent extras | Intra-app IPC, not cross-app leakage |
| `direct-thread?thread_id=X` opens DM | UI navigation only, no message sending, no data exfil |
| Flipper diagnostic activity exported | `enabled=false` in prod, requires Flipper desktop |
| Content providers exported | Signature-enforced at runtime |
| `redirect_to_app` leaks Trustly session | Token is for Trustly payment SDK, not Instagram session |

### Meta-specific severity calibration:

- **Open redirect (no chain):** Low or N/A — Meta considers phishing-only redirects low value
- **Deep link → WebView + JS bridge:** High-Critical (but Instagram doesn't expose bridges to attacker URLs)
- **Deep link → auto-action (send message, follow, etc.):** High — but Instagram requires user interaction for all actions
- **IDOR via API:** High-Critical — but requires authenticated traffic interception (blocked by server-side sig validation)

### Lesson: Meta apps are hardened against unauthenticated mobile testing

Without authenticated traffic interception, the attack surface is limited to:
1. Deep link routing (most are sanitized)
2. Exported components (signature-protected)
3. Local data storage (requires physical access)
4. WebView content (no attacker-controlled URLs reach JS bridges)

**Recommendation:** For Meta bug bounty, prioritize web-scope targets (*.instagram.com, *.facebook.com) over mobile app testing unless you have a working authenticated proxy setup.

## Threads (com.instagram.barcelona) Specifics

### Package & Scheme
- Package: `com.instagram.barcelona`
- Deep link scheme: `barcelona://` (NOT `instagram://`)
- Also registers `instagram://` scheme (handles Instagram deep links)
- Web links: threads.net, threads.com, chat.threads.com, chat.threads.net, familycenter.threads.com

### Key Differences from Instagram
- **No `extbrowser` host** — the open redirect vector from Instagram does NOT exist in Threads
- **No `in_app_webview` host** — no direct WebView loading deep link
- **Threads-specific hosts:** `inject`, `inter_app_redirect`, `slide`, `slide_thread`, `slide_create_chat`, `slide_meta_ai`, `slide_pending`, `slide_requests_nux`, `group_invite_link_deeplink`, `live_chat_invite_link_deeplink`, `chat_inbox_deeplink`, `community_notes_hub`, `dear_algo`, `approval_queue`, `dogfooding_assistant`
- **Shared with Instagram:** `third_party_oauth`, `oauth_account_linking`, `media`, `user`, `search`, `feed`, `tag`, `settings_2`

### High-Value Deep Link Hosts to Test
| Host | Why |
|------|-----|
| `inject` | Suspicious name — could accept arbitrary content/URL |
| `inter_app_redirect` | Explicit redirect functionality |
| `third_party_oauth` | OAuth redirect_uri manipulation |
| `group_invite_link_deeplink` | Invite link handling — potential IDOR or join-without-consent |
| `live_chat_invite_link_deeplink` | Same as above for live chats |
| `slide_meta_ai` | Meta AI integration — potential prompt injection |
| `dogfooding_assistant` | Debug/internal tool in production |

### NSC (Same as Instagram)
- `overridePins="true" src="user"` in base-config — user CA bypasses pins
- Same 18 SHA-256 pins, same domain list
- Cleartext allowed for: h.facebook.com, l.facebook.com, l.instagram.com

### Exported Components (Threads)
- **Activities (6 enabled):** BarcelonaActivity, ClipsMusicShareHandlerActivity, ClipsThreadShareHandlerActivity, NotesMusicShareHandlerActivity, BarcelonaShareHandlerActivity, BarcelonaUrlHandlerActivity
- **Services (1 enabled):** check which
- **Receivers (0 enabled):** all disabled
- **Providers (0 enabled):** all disabled

### Validated Finding: barcelona://create Content Injection (Low-Medium)

`barcelona://create?text=<URL-encoded text>` pre-fills the Threads post composer with attacker-controlled content:
- Text with phishing URLs gets rendered with link previews
- @mentions are preserved in the pre-filled text
- The scheme is BROWSABLE — triggerable from any web page via `<a href="barcelona://create?text=...">` or JS `window.location`
- User must still tap "Post" (no auto-post) — limits severity

**PoC (HTML page):**
```html
<a href="barcelona://create?text=%40zuck%20is%20giving%20away%20free%20crypto%20https%3A%2F%2Fevil.com%2Fscam">
  Claim Prize
</a>
```

**Impact:** Social engineering amplification — attacker crafts convincing pre-filled post with phishing links and fake @mentions. Victim sees composer ready to post. Combined with UI redressing (e.g., "tap anywhere to continue" overlay), could trick users into posting spam/phishing.

**Severity rationale:** Low-Medium because user interaction required (tap Post). Meta may downgrade to Informational since no auto-action occurs. Stronger if chained with:
- Task hijacking (overlay "Post" button area)
- Accessibility service abuse
- Combined with `barcelona://user?username=X` to first show a trusted profile

**Test also:** `instagram://create?text=...` on Instagram app — likely same behavior since shared codebase.

**Web-to-app chain validation pattern:**
1. Write PoC HTML with `<a href="barcelona://create?text=...">` link
2. Serve from Mac: `python3 -m http.server 8889` in the PoC directory
3. Open on device: `adb shell am start -a android.intent.action.VIEW -d "http://<HOST_IP>:8889/poc.html" -n com.android.chrome/...`
4. Tap link in Chrome → verify Threads opens with pre-filled composer
5. Note: Chrome blocks `file:///sdcard/` access (ERR_ACCESS_DENIED) — must use HTTP server
6. Note: device lock screen blocks validation — set `adb shell settings put system screen_off_timeout 600000` early

### Deep Links That Do NOT Work for Exploitation

| Host | Behavior |
|------|----------|
| `inject` | Navigates to user profile (no URL loading) |
| `inter_app_redirect` | Navigates to user profile (ignores url param) |
| `third_party_oauth` | Navigates to user profile (redirect_uri ignored) |
| `wearable_link` | "Activity not started, unable to resolve" |
| `consent-launcher` | Navigates to feed (no URL loading) |
| `ads_consent_growth_url` | Navigates to feed |
| `slide_*` | Triggers "Switch profiles" / "Log in" dialog |
| `group_invite_link_deeplink` | Navigates to feed |
| `live_chat_invite_link_deeplink` | Navigates to feed |
| `oauth_account_linking` | Navigates to feed |

### chat.threads.com Behavior

URLs with `chat.threads.com` host fall through to Chrome (domain doesn't resolve publicly). Threads registers it in manifest but can't handle it in-app. NOT an open redirect — Chrome loads the original full URL, not an extracted parameter.

### www.threads.com/account_link_auth → Custom Tab

When host is `www.threads.com` AND path is `/account_link_auth`, the app opens `FxChromeCustomTabsActivity` (in-app Custom Tab) with the full intent data URI. The Custom Tab loads the threads.com URL itself — no parameter extraction, no redirect to attacker domain.

### Frida Attach Fails

hluda-server 16.1.8 cannot attach or spawn Threads (same anti-Frida as Instagram). Both `-p PID` and `-f com.instagram.barcelona` fail with "connection closed". No workaround on kernel 4.4 / KernelSU 0.7.1.

### Testing Prerequisite
Threads requires login (via Instagram account) before deep link handlers route properly. Without login, all `barcelona://` deep links redirect to the login/signup screen. Login on device first, then test deep links.

### APK Structure
- Split APK: base + arm64_v8a + xxhdpi (3 splits)
- 12 DEX files (same as Instagram — shared codebase)
- Merge with: `java -jar APKEditor-1.4.7.jar m -i <dir> -o threads-merged.apk`

## Exported Components Status (Instagram)

- **Content Providers (16):** All `enabled=false` + runtime signature check. Not exploitable from third-party.
- **Services (MFA, CrossSigning, TrustedDevice, ACDC):** All `enabled=false`. Can be started but binding requires Meta family app signature.
- **Activities (29 exported):** Most route through UrlHandlerActivity with sanitization.
- **Debug components (Flipper, DebugCommandsReceiver):** `enabled=false` in production.

## Native Libraries (14 arm64-v8a)

No anti-tampering native libs. No exploitable buffer overflows found:
- libsuperpack-jni.so: Missing NULL checks after realloc (DoS only, input from APK assets)
- libbreakpad.so: Hook detection strings but primarily crash reporting
- All others: utility/rendering, no attacker-controlled input paths
