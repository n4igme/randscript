# Meta/Instagram App Testing Patterns

## SSL Pinning Bypass (Instagram v431+)

Instagram uses multi-layer pinning:
1. **Network Security Config** — SHA-256 pin-set on Meta domains (expires 2027). Has `overridePins="true"` for user CAs but this alone is NOT sufficient.
2. **Java layer** — `TrustManagerImpl.verifyChain()` via Conscrypt.
3. **Native layer** — BoringSSL `SSL_CTX_set_custom_verify` callbacks enforce pinning independently.
4. **Binary push** — `b.i.instagram.com` uses separate MQTT/binary protocol with additional pinning (not bypassable with standard methods).

### What Works (partial interception)
Combined approach: **Patched APK + Frida + QUIC block**

1. Decompile with apktool, replace `res/xml/fb_network_security_config.xml` with trust-all config (no pin-set)
2. Rebuild, zipalign, sign with debug key
3. Block QUIC: `iptables -A OUTPUT -p udp --dport 443 -j DROP`
4. Install mitmproxy CA via tmpfs overlay on `/system/etc/security/cacerts/`
5. Frida hook `TrustManagerImpl.verifyChain` + native SSL hooks
6. Result: `i.instagram.com/api/v1/*` intercepted, `b.i.instagram.com` still pinned

### Login Blocker
Server-side signature validation rejects login on repackaged APKs. Signature spoofing via PackageManager hooks doesn't work — Instagram sends signature hash in HTTP headers computed at startup.

### Practical Approach for Bug Bounty
Skip authenticated traffic interception. Use **Frida runtime hooks on original APK** (no repackaging needed):
- Frida attaches cleanly (no root/Frida detection with hluda-server)
- Hook internal methods to trace deep link routing, WebView loads, intent handling
- Test exported components, deep links, content providers without needing traffic capture

## Deep Link Testing (Instagram)

### Architecture
Instagram uses a custom internal navigation system:
- `UrlHandlerLauncherActivity` → `UrlHandlerActivity` → specific handler activity
- Does NOT use standard `WebView.loadUrl` or `Activity.startActivity` for internal navigation
- Must hook `Activity.onCreate`, `onNewIntent`, `startActivityForResult` to trace routing

### Frida Hooking Strategy
**CLI Frida with background + tee has buffering issues.** Use Python frida bindings instead:

```python
import frida
device = frida.get_usb_device()
session = device.attach(pid)
script = session.create_script(js_code)
messages = []
script.on('message', lambda m, d: messages.append(m['payload']) if m['type']=='send' else None)
script.load()
# trigger deep links via subprocess adb calls
# read messages[] after
session.detach()
```

### Key Hooks for Instagram Deep Link Analysis
```javascript
Java.perform(function(){
    var A = Java.use('android.app.Activity');
    A.onCreate.overload('android.os.Bundle').implementation = function(b) {
        send('CREATE:' + this.getClass().getName() + '|data=' + this.getIntent().getData() + '|extras=' + this.getIntent().getExtras());
        this.onCreate(b);
    };
    A.startActivityForResult.overload('android.content.Intent', 'int').implementation = function(i,c) {
        send('START:' + (i.getComponent()?i.getComponent().getClassName():'nocomp') + '|data=' + i.getData());
        this.startActivityForResult(i,c);
    };
    // ContextWrapper.startActivity catches external launches
    var CW = Java.use('android.content.ContextWrapper');
    CW.startActivity.overload('android.content.Intent').implementation = function(i) {
        send('CTXSTART:' + (i.getComponent()?i.getComponent().getClassName():'nocomp') + '|data=' + i.getData());
        this.startActivity(i);
    };
});
```

### Confirmed Findings Pattern
- `instagram://extbrowser?url=http://<ANY>` → opens Chrome (open redirect, http only)
- `instagram://extbrowser?url=https://<ANY>` → opens in-app browser (not external)
- `instagram://redirect_to_app?url=<ANY>` → URL sanitized but session token leaked in intent extras
- OAuth `redirect_uri` → sanitized (`--sanitized--`)
- Content providers → runtime signature check ("Component access not allowed... Called by: com.android.shell")
- Most exported components → `android:enabled="false"` until user logs in

### Instagram Security Hardening Summary
- No RASP/root detection (hluda-server works fine)
- No Frida detection
- SSL pinning: multi-layer (NSC + Java + native BoringSSL)
- Deep links: URL params sanitized for sensitive routes
- Content providers: signature-based caller validation (Meta family apps only)
- Services: disabled by default, gatekeeper validates caller
- WebView: uses SecureWebView with domain allowlist, not reachable from attacker URLs
- Server-side: APK signature validation on login, token validation on cross-app login
