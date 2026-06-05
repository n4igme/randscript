# Dynamic Setup Reference

## Android Device/Emulator Preparation

### Rooted Physical Device (Recommended for Banking Apps)

```bash
# Verify root
adb shell su -c "id"
# Should return: uid=0(root)

# Magisk recommended (systemless root)
# Magisk Manager → Settings → MagiskHide/DenyList → add target app
# This hides root from specific apps before we even need Frida

# Verify Frida server
adb shell "su -c 'ls /data/local/tmp/frida-server'"
adb shell "su -c '/data/local/tmp/frida-server --version'"
```

### Emulator Setup

```bash
# Android Studio emulator (with Google APIs, NOT Google Play — those are locked)
# System image: Google APIs, x86_64, API 30+
emulator -avd <name> -writable-system -no-snapshot

# Root the emulator
adb root
adb remount

# For apps with emulator detection, use:
# - Genymotion (better hardware fingerprint)
# - Physical device (best)

# Common emulator detection checks apps perform:
# Build.FINGERPRINT contains "generic"
# Build.MODEL contains "sdk" or "Emulator"
# Build.HARDWARE = "goldfish" or "ranchu"
# /dev/socket/qemud exists
# ro.hardware = "goldfish"
```

### Frida Server Installation

```bash
# Check device architecture
adb shell getprop ro.product.cpu.abi
# arm64-v8a, armeabi-v7a, x86, x86_64

# Download matching Frida server
FRIDA_VERSION=$(frida --version)
ARCH="arm64"  # adjust based on above
wget "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-${ARCH}.xz"
xz -d frida-server-*.xz

# Push and start
adb push frida-server-* /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c '/data/local/tmp/frida-server -D &'"

# Verify
frida-ps -U | head -5
```

### Anti-Frida Countermeasures

Some banking apps detect Frida by:
- Scanning `/proc/self/maps` for frida-agent
- Checking for frida-server port (27042)
- Scanning for frida-related strings in memory
- Detecting Frida's thread naming patterns

Bypasses:

```bash
# 1. Rename frida-server binary
cp frida-server frida-server-renamed
adb push frida-server-renamed /data/local/tmp/hluda-server
adb shell "su -c '/data/local/tmp/hluda-server -l 0.0.0.0:1337 &'"
frida -H 127.0.0.1:1337 -f <package>

# 2. Use Frida Gadget (injected into APK, no server needed)
# Download gadget: frida-gadget-<version>-android-<arch>.so
# Inject into APK lib folder, add System.loadLibrary call
# See "Gadget Injection" section below

# 3. Use Magisk + Zygisk + shamiko (hide from detection)
# Magisk → Settings → Zygisk → Enable
# Install Shamiko module → configure deny list

# 4. Use alternative: LIEF to patch binary
pip install lief
# Patch the app binary to load gadget on startup
```

### Frida Gadget Injection (No Server Required)

```bash
# Download gadget for target arch
wget "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-gadget-${FRIDA_VERSION}-android-${ARCH}.so.xz"
xz -d frida-gadget-*.so.xz
mv frida-gadget-*.so libfrida-gadget.so

# Disassemble APK
apktool d target.apk -o target_mod/

# Inject gadget into lib folder
mkdir -p target_mod/lib/arm64-v8a/  # match target arch
cp libfrida-gadget.so target_mod/lib/arm64-v8a/

# Add loadLibrary call to main activity smali
# Find main activity in AndroidManifest.xml
# Edit its smali to add in onCreate or <clinit>:
# const-string v0, "frida-gadget"
# invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

# Rebuild and sign
apktool b target_mod/ -o target_gadget.apk
keytool -genkey -v -keystore debug.keystore -alias debug -keyalg RSA -keysize 2048 -validity 10000 -storepass password -keypass password -dname "CN=Debug"
apksigner sign --ks debug.keystore --ks-pass pass:password target_gadget.apk

# Install and run
adb install target_gadget.apk
# App will pause on startup waiting for Frida to attach
frida -U -n Gadget
```

---

## iOS Device Preparation

### Jailbreak Options (2024-2025)

| Device | iOS Version | Tool |
|--------|-------------|------|
| A8-A11 | 14.x-15.x | checkra1n (hardware exploit, survives updates) |
| A11-A16 | 15.0-16.x | palera1n (checkm8-based) |
| A12+ | 15.0-15.4.1 | Dopamine (Fugu15) |
| A12+ | 14.0-14.8.1 | unc0ver |

```bash
# Verify jailbreak
ssh root@<device_ip>  # default password: alpine (CHANGE IT)
which cydia sileo zebra 2>/dev/null

# Install Frida on jailbroken device
# Via Sileo/Cydia: add https://build.frida.re repo, install Frida

# Or manually:
ssh root@<device_ip>
wget "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-ios-arm64.xz"
xz -d frida-server-*.xz
chmod +x frida-server-*
./frida-server-* &

# Verify from host
frida-ps -U | grep -i <app_name>
```

### iOS Anti-Jailbreak Countermeasures

```bash
# Liberty Lite (Cydia tweak) — hides jailbreak from specific apps
# A-Bypass — more comprehensive
# Shadow — modern alternative
# Hestia — blocks jailbreak detection at dyld level

# For Frida detection on iOS:
# Use frida-server with --listen on non-default port
# Or inject Gadget into decrypted IPA
```

---

## Proxy Configuration

### Burp Suite Setup

```bash
# Generate CA cert
# Proxy → Options → Import/Export CA Certificate → Export Certificate in DER format
# Save as cacert.der

# Convert for Android system store
openssl x509 -inform DER -in cacert.der -out cacert.pem
HASH=$(openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1)
cp cacert.pem ${HASH}.0

# Install on Android (system level)
adb root
adb remount
adb push ${HASH}.0 /system/etc/security/cacerts/
adb shell "chmod 644 /system/etc/security/cacerts/${HASH}.0"
adb reboot

# Set proxy
adb shell settings put global http_proxy <host_ip>:8080

# Remove proxy when done
adb shell settings put global http_proxy :0
```

### Invisible Proxy (Apps Ignoring System Proxy)

Some apps use their own HTTP stack and ignore Android's system proxy setting.

```bash
# Method 1: iptables redirect (requires root)
adb shell su -c "iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination <host_ip>:8080"
adb shell su -c "iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination <host_ip>:8080"

# In Burp: Proxy → Options → Add listener
# Bind to: All interfaces, port 8080
# Check: "Support invisible proxying"

# Method 2: ProxyDroid app (root, GUI-based)
# Supports per-app proxy rules

# Method 3: VPN-based (no root needed)
# Use apps like HttpCanary, Packet Capture, or Charles Proxy on-device

# Remove iptables rules when done
adb shell su -c "iptables -t nat -F"
```

### iOS Proxy Setup

```bash
# WiFi proxy: Settings → WiFi → (i) → Configure Proxy → Manual
# Host: <host_ip>, Port: 8080

# Install Burp CA:
# 1. Navigate to http://<host_ip>:8080 in Safari
# 2. Download CA cert
# 3. Settings → General → Profile → Install
# 4. Settings → General → About → Certificate Trust Settings → Enable Full Trust

# For apps ignoring proxy:
# Use Surge/Shadowrocket as VPN-based proxy
# Or: SSH tunnel + proxychains on device
```

---

## SSL Pinning Bypass

### Android — Frida Script (Universal)

```javascript
// ssl_pinning_bypass.js
Java.perform(function() {
    // === TrustManager (Android system) ===
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] TrustManagerImpl bypass: ' + host);
            return untrustedChain;
        };
    } catch(e) { console.log('[-] TrustManagerImpl not found'); }

    // === OkHttp3 CertificatePinner ===
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[+] OkHttp3 pinning bypass: ' + hostname);
            return;
        };
        // Older overload
        CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(hostname, certs) {
            console.log('[+] OkHttp3 pinning bypass (alt): ' + hostname);
            return;
        };
    } catch(e) { console.log('[-] OkHttp3 CertificatePinner not found'); }

    // === Retrofit/OkHttp (older versions) ===
    try {
        var OldPinner = Java.use('com.squareup.okhttp.CertificatePinner');
        OldPinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(hostname, chain) {
            console.log('[+] OkHttp (old) pinning bypass: ' + hostname);
            return;
        };
    } catch(e) {}

    // === WebViewClient SSL errors ===
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log('[+] WebView SSL error bypass');
            handler.proceed();
        };
    } catch(e) {}

    // === HttpsURLConnection (legacy) ===
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {
            console.log('[+] Bypassing HostnameVerifier');
            return;
        };
    } catch(e) {}

    // === Custom TrustManager that accepts all ===
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManagers = [Java.registerClass({
            name: 'com.bypass.TrustAllManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        }).$new()];
        var sslContext = SSLContext.getInstance('TLS');
        sslContext.init(null, TrustManagers, null);
        SSLContext.getInstance.overload('java.lang.String').implementation = function(protocol) {
            return sslContext;
        };
    } catch(e) {}

    // === Conscrypt (newer Android) ===
    try {
        var Platform = Java.use('com.android.org.conscrypt.Platform');
        Platform.checkServerTrusted.implementation = function() {
            console.log('[+] Conscrypt Platform bypass');
        };
    } catch(e) {}

    // === Network Security Config (programmatic pinning) ===
    try {
        var NetworkSecurityTrustManager = Java.use('android.security.net.config.NetworkSecurityTrustManager');
        NetworkSecurityTrustManager.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function(certs, authType) {
            console.log('[+] NetworkSecurityConfig bypass');
        };
    } catch(e) {}

    console.log('[+] SSL pinning bypass loaded');
});
```

### Android — APK Patching (Persistent, No Frida)

```bash
# 1. Disassemble
apktool d target.apk -o target_mod/

# 2. Create permissive network security config
cat > target_mod/res/xml/network_security_config.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
EOF

# 3. Add reference in AndroidManifest.xml (if not already present)
# In <application> tag, add: android:networkSecurityConfig="@xml/network_security_config"
sed -i 's/<application/<application android:networkSecurityConfig="@xml\/network_security_config"/' target_mod/AndroidManifest.xml

# 4. Rebuild
apktool b target_mod/ -o target_patched.apk

# 5. Sign
keytool -genkey -v -keystore test.keystore -alias test -keyalg RSA -keysize 2048 -validity 10000 -storepass password -keypass password -dname "CN=Test"
apksigner sign --ks test.keystore --ks-pass pass:password target_patched.apk

# 6. Install (uninstall original first)
adb uninstall <package>
adb install target_patched.apk
```

### iOS — Frida Script

```javascript
// ios_ssl_bypass.js
if (ObjC.available) {
    // NSURLSession delegate
    var resolver = new ApiResolver('objc');
    resolver.enumerateMatches('*[* URLSession:didReceiveChallenge:completionHandler:]', {
        onMatch: function(match) {
            Interceptor.attach(match.address, {
                onEnter: function(args) {
                    var completionHandler = new ObjC.Block(args[4]);
                    var NSURLSessionAuthChallengeUseCredential = 0;
                    var serverTrust = ObjC.Object(args[3]).protectionSpace().serverTrust();
                    var credential = ObjC.classes.NSURLCredential.credentialForTrust_(serverTrust);
                    completionHandler.implementation = function() {
                        return completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
                    };
                }
            });
        },
        onComplete: function() {}
    });

    // TrustKit
    try {
        var TrustKit = ObjC.classes.TSKPinningValidator;
        if (TrustKit) {
            Interceptor.attach(TrustKit['- evaluateTrust:forHostname:'].implementation, {
                onLeave: function(retval) { retval.replace(0); }
            });
        }
    } catch(e) {}

    // AFNetworking
    try {
        var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
        if (AFSecurityPolicy) {
            Interceptor.attach(AFSecurityPolicy['- setSSLPinningMode:'].implementation, {
                onEnter: function(args) { args[2] = ptr(0); } // AFSSLPinningModeNone
            });
        }
    } catch(e) {}

    // Alamofire ServerTrustManager
    try {
        var ServerTrustManager = ObjC.classes.ServerTrustManager;
        if (ServerTrustManager) {
            Interceptor.attach(ServerTrustManager['- serverTrustEvaluator:didReceiveChallenge:completionHandler:'].implementation, {
                onEnter: function(args) {
                    console.log('[+] Alamofire trust bypass');
                }
            });
        }
    } catch(e) {}

    console.log('[+] iOS SSL pinning bypass loaded');
}
```

---

## Root/Jailbreak Detection Bypass

### Android — Comprehensive Root Bypass

```javascript
// root_bypass.js — see frida-scripts.md for full version
// Quick reference: hooks File.exists, Runtime.exec, PackageManager,
// Build.TAGS, System.getProperty, Settings.Secure
frida -U -f <package> -l root_bypass.js --no-pause
```

### iOS — Comprehensive Jailbreak Bypass

```javascript
// ios_jailbreak_bypass.js — see frida-scripts.md for full version
// Quick reference: hooks NSFileManager, fork(), canOpenURL,
// access(), dyld image names, fopen()
frida -U -f <bundle_id> -l ios_jailbreak_bypass.js --no-pause
```

### Combined Launch Commands

```bash
# Android: root + SSL bypass
frida -U -f <package> -l root_bypass.js -l ssl_pinning_bypass.js --no-pause

# iOS: jailbreak + SSL bypass
frida -U -f <bundle_id> -l ios_jailbreak_bypass.js -l ios_ssl_bypass.js --no-pause

# With anti-Frida bypass too (if needed)
frida -U -f <package> -l anti_frida_bypass.js -l root_bypass.js -l ssl_pinning_bypass.js --no-pause
```

---

## Verification Checklist

Before proceeding to Phase 4 (Traffic Analysis), confirm:

- [ ] App launches without crashing
- [ ] No root/jailbreak detection popups
- [ ] Proxy shows HTTPS traffic (pinning bypassed)
- [ ] Can complete login flow through proxy
- [ ] All API domains visible in proxy (no traffic escaping)
- [ ] Screenshots of successful bypass for evidence
