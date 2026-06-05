# Frida Scripts Collection

## Root Detection Bypass (Android)

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
        '/sbin/.magisk', '/data/adb/magisk', '/data/adb/modules',
        '/system/xbin/magisk', '/cache/.disable_magisk',
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

    // 2. Runtime.exec() - block "which su", "su" commands
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

    // 7. Native system property check (getprop)
    try {
        var SystemProperties = Java.use('android.os.SystemProperties');
        SystemProperties.get.overload('java.lang.String').implementation = function(key) {
            if (key === 'ro.debuggable' || key === 'service.adb.root') { return '0'; }
            if (key === 'ro.secure') { return '1'; }
            if (key === 'ro.build.tags') { return 'release-keys'; }
            return this.get(key);
        };
    } catch(e) {}

    console.log('[+] Root detection bypass loaded - all checks hooked');
});
```

---

## Jailbreak Detection Bypass (iOS)

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
        '/jb/offsets.plist', '/.installed_unc0ver',
        '/.bootstrapped_electra', '/usr/lib/libjailbreak.dylib',
        '/var/binpack', '/var/checkra1n.dmg'
    ];

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

    // 2. Block fork() - detect jailbreak via fork success
    var fork = Module.findExportByName(null, 'fork');
    if (fork) {
        Interceptor.attach(fork, {
            onLeave: function(retval) {
                console.log('[JB Bypass] fork() blocked');
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

    // 4. Block access() for jailbreak paths
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

    // 5. Block dyld image checks (detect Substrate/Substitute/Frida)
    var _dyld_get_image_name = Module.findExportByName(null, '_dyld_get_image_name');
    if (_dyld_get_image_name) {
        Interceptor.attach(_dyld_get_image_name, {
            onLeave: function(retval) {
                var name = retval.readUtf8String();
                if (name && (name.indexOf('substrate') !== -1 ||
                    name.indexOf('substitute') !== -1 ||
                    name.indexOf('frida') !== -1 ||
                    name.indexOf('cycript') !== -1 ||
                    name.indexOf('libhooker') !== -1)) {
                    console.log('[JB Bypass] Hiding dylib: ' + name);
                    retval.replace(Memory.allocUtf8String('/usr/lib/libSystem.B.dylib'));
                }
            }
        });
    }

    // 6. Block sandbox escape write test
    var fopen = Module.findExportByName(null, 'fopen');
    if (fopen) {
        Interceptor.attach(fopen, {
            onEnter: function(args) {
                this.path = args[0].readUtf8String();
                this.mode = args[1].readUtf8String();
            },
            onLeave: function(retval) {
                if (this.path && this.mode && this.mode.indexOf('w') !== -1) {
                    if (this.path.indexOf('jailbreak') !== -1 ||
                        this.path === '/private/jailbreak_test') {
                        console.log('[JB Bypass] Blocking write test: ' + this.path);
                        retval.replace(ptr(0));
                    }
                }
            }
        });
    }

    // 7. stat() bypass
    var stat = Module.findExportByName(null, 'stat');
    if (stat) {
        Interceptor.attach(stat, {
            onEnter: function(args) {
                this.path = args[0].readUtf8String();
            },
            onLeave: function(retval) {
                if (this.path) {
                    for (var i = 0; i < jbPaths.length; i++) {
                        if (this.path === jbPaths[i]) {
                            retval.replace(-1);
                            return;
                        }
                    }
                }
            }
        });
    }

    console.log('[+] iOS jailbreak detection bypass loaded');
}
```

---

## SSL Pinning Bypass (Android)

```javascript
// ssl_pinning_bypass.js - Universal Android SSL pinning bypass
Java.perform(function() {
    // TrustManagerImpl (system)
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] TrustManagerImpl bypass: ' + host);
            return untrustedChain;
        };
    } catch(e) {}

    // OkHttp3
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[+] OkHttp3 bypass: ' + hostname);
            return;
        };
    } catch(e) {}

    // Retrofit/OkHttp older
    try {
        var OldPinner = Java.use('com.squareup.okhttp.CertificatePinner');
        OldPinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(hostname, chain) {
            console.log('[+] OkHttp (old) bypass: ' + hostname);
            return;
        };
    } catch(e) {}

    // WebViewClient
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log('[+] WebView SSL bypass');
            handler.proceed();
        };
    } catch(e) {}

    // HttpsURLConnection
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(v) {
            console.log('[+] HostnameVerifier bypass');
            return;
        };
    } catch(e) {}

    // Conscrypt Platform
    try {
        var Platform = Java.use('com.android.org.conscrypt.Platform');
        Platform.checkServerTrusted.implementation = function() {
            console.log('[+] Conscrypt bypass');
        };
    } catch(e) {}

    // NetworkSecurityConfig TrustManager
    try {
        var NSTM = Java.use('android.security.net.config.NetworkSecurityTrustManager');
        NSTM.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function(certs, authType) {
            console.log('[+] NetworkSecurityConfig bypass');
        };
    } catch(e) {}

    console.log('[+] SSL pinning bypass loaded');
});
```

---

## SSL Pinning Bypass (iOS)

```javascript
// ios_ssl_bypass.js - Universal iOS SSL pinning bypass
if (ObjC.available) {
    // NSURLSession delegate
    var resolver = new ApiResolver('objc');
    resolver.enumerateMatches('*[* URLSession:didReceiveChallenge:completionHandler:]', {
        onMatch: function(match) {
            Interceptor.attach(match.address, {
                onEnter: function(args) {
                    var completionHandler = new ObjC.Block(args[4]);
                    var NSURLSessionAuthChallengeUseCredential = 0;
                    completionHandler.implementation = function(disposition, credential) {
                        var serverTrust = ObjC.Object(args[3]).protectionSpace().serverTrust();
                        var cred = ObjC.classes.NSURLCredential.credentialForTrust_(serverTrust);
                        completionHandler(NSURLSessionAuthChallengeUseCredential, cred);
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
            console.log('[+] TrustKit hooked');
        }
    } catch(e) {}

    // AFNetworking
    try {
        var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
        if (AFSecurityPolicy) {
            Interceptor.attach(AFSecurityPolicy['- setSSLPinningMode:'].implementation, {
                onEnter: function(args) { args[2] = ptr(0); }
            });
            console.log('[+] AFNetworking hooked');
        }
    } catch(e) {}

    console.log('[+] iOS SSL pinning bypass loaded');
}
```

---

## Anti-Frida Detection Bypass

```javascript
// anti_frida_bypass.js - Bypass Frida detection mechanisms
Java.perform(function() {
    // 1. Hide frida-server port (27042)
    try {
        var InetAddress = Java.use('java.net.InetAddress');
        var Socket = Java.use('java.net.Socket');
        Socket.$init.overload('java.net.InetAddress', 'int').implementation = function(addr, port) {
            if (port === 27042 || port === 27043) {
                console.log('[Anti-Frida] Blocking port scan: ' + port);
                throw Java.use('java.net.ConnectException').$new('Connection refused');
            }
            return this.$init(addr, port);
        };
    } catch(e) {}

    // 2. Hide frida from /proc/self/maps
    try {
        var BufferedReader = Java.use('java.io.BufferedReader');
        BufferedReader.readLine.overload().implementation = function() {
            var line = this.readLine();
            if (line && (line.indexOf('frida') !== -1 || line.indexOf('gadget') !== -1)) {
                console.log('[Anti-Frida] Hiding maps entry: ' + line.substring(0, 50));
                return this.readLine(); // skip this line
            }
            return line;
        };
    } catch(e) {}

    // 3. Hide frida thread names
    try {
        var Thread = Java.use('java.lang.Thread');
        Thread.getName.implementation = function() {
            var name = this.getName();
            if (name && (name.indexOf('frida') !== -1 || name.indexOf('gmain') !== -1 ||
                name.indexOf('gdbus') !== -1 || name.indexOf('gum-js-loop') !== -1)) {
                console.log('[Anti-Frida] Hiding thread: ' + name);
                return 'Thread-' + Math.floor(Math.random() * 100);
            }
            return name;
        };
    } catch(e) {}

    // 4. Block dlopen checks for frida libraries
    try {
        var Runtime = Java.use('java.lang.Runtime');
        var originalLoadLibrary = Runtime.loadLibrary0.overload('java.lang.Class', 'java.lang.String');
        // Don't block, just monitor
    } catch(e) {}

    console.log('[+] Anti-Frida detection bypass loaded');
});
```

```javascript
// anti_frida_bypass_ios.js - iOS Frida detection bypass
if (ObjC.available) {
    // Hide frida from dyld
    var _dyld_get_image_name = Module.findExportByName(null, '_dyld_get_image_name');
    if (_dyld_get_image_name) {
        Interceptor.attach(_dyld_get_image_name, {
            onLeave: function(retval) {
                var name = retval.readUtf8String();
                if (name && name.indexOf('frida') !== -1) {
                    retval.replace(Memory.allocUtf8String('/usr/lib/libSystem.B.dylib'));
                }
            }
        });
    }

    // Hide frida port
    var connect = Module.findExportByName(null, 'connect');
    if (connect) {
        Interceptor.attach(connect, {
            onEnter: function(args) {
                var sockaddr = args[1];
                var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                if (port === 27042 || port === 27043) {
                    console.log('[Anti-Frida] Blocking connect to port: ' + port);
                    this.block = true;
                }
            },
            onLeave: function(retval) {
                if (this.block) { retval.replace(-1); }
            }
        });
    }

    console.log('[+] iOS anti-Frida bypass loaded');
}
```

---

## Emulator Detection Bypass (Android)

```javascript
// emulator_bypass.js - Comprehensive Android emulator detection bypass
Java.perform(function() {
    // 1. Build properties — most common detection method
    var Build = Java.use('android.os.Build');
    
    // Spoof to look like a real device
    Build.FINGERPRINT.value = 'google/raven/raven:13/TP1A.220624.021/8877034:user/release-keys';
    Build.MODEL.value = 'Pixel 6 Pro';
    Build.MANUFACTURER.value = 'Google';
    Build.BRAND.value = 'google';
    Build.DEVICE.value = 'raven';
    Build.PRODUCT.value = 'raven';
    Build.HARDWARE.value = 'raven';
    Build.BOARD.value = 'raven';
    Build.HOST.value = 'abfarm-release-rbe-64';
    Build.TAGS.value = 'release-keys';
    Build.TYPE.value = 'user';
    Build.DISPLAY.value = 'TP1A.220624.021';
    
    // These specifically flag emulators:
    // Build.FINGERPRINT containing "generic", "sdk", "google_sdk", "vbox"
    // Build.MODEL containing "sdk", "Emulator", "Android SDK"
    // Build.HARDWARE = "goldfish" or "ranchu"
    // Build.PRODUCT = "sdk" or "google_sdk" or "sdk_gphone"
    
    console.log('[Emulator Bypass] Build properties spoofed');

    // 2. System properties (getprop)
    try {
        var SystemProperties = Java.use('android.os.SystemProperties');
        var originalGet = SystemProperties.get.overload('java.lang.String', 'java.lang.String');
        originalGet.implementation = function(key, def) {
            var spoofed = {
                'ro.hardware': 'raven',
                'ro.product.model': 'Pixel 6 Pro',
                'ro.product.brand': 'google',
                'ro.product.device': 'raven',
                'ro.product.manufacturer': 'Google',
                'ro.build.characteristics': 'default',
                'ro.kernel.qemu': '0',
                'ro.hardware.chipname': 'exynos990',
                'ro.boot.hardware': 'raven',
                'init.svc.qemud': '',
                'init.svc.qemu-props': '',
                'ro.bootimage.build.fingerprint': 'google/raven/raven:13/TP1A.220624.021/8877034:user/release-keys',
                'gsm.version.ril-impl': 'android samsung-ril 1.0',
            };
            if (spoofed.hasOwnProperty(key)) {
                console.log('[Emulator Bypass] Spoofing prop: ' + key);
                return spoofed[key];
            }
            return originalGet.call(this, key, def);
        };
    } catch(e) { console.log('SystemProperties hook failed: ' + e); }

    // 3. File-based detection (emulator-specific files)
    var File = Java.use('java.io.File');
    var emuPaths = [
        '/dev/socket/qemud',
        '/dev/qemu_pipe',
        '/system/lib/libc_malloc_debug_qemu.so',
        '/sys/qemu_trace',
        '/system/bin/qemu-props',
        '/dev/socket/genyd',           // Genymotion
        '/dev/socket/baseband_genyd',  // Genymotion
        '/proc/tty/drivers',           // goldfish in content
        '/proc/cpuinfo',               // goldfish in content
    ];

    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        for (var i = 0; i < emuPaths.length; i++) {
            if (path === emuPaths[i]) {
                console.log('[Emulator Bypass] Hiding file: ' + path);
                return false;
            }
        }
        return this.exists();
    };

    // 4. Telephony-based detection
    try {
        var TelephonyManager = Java.use('android.telephony.TelephonyManager');
        
        // getDeviceId returns null/empty on emulators
        TelephonyManager.getDeviceId.overload().implementation = function() {
            console.log('[Emulator Bypass] Spoofing IMEI');
            return '353456789012345';
        };
        
        // getSubscriberId (IMSI) — "310260000000000" is emulator default
        TelephonyManager.getSubscriberId.overload().implementation = function() {
            return '510101234567890'; // Indonesian operator prefix
        };
        
        // getLine1Number — emulators return "15555215554" etc.
        TelephonyManager.getLine1Number.overload().implementation = function() {
            return '+6281234567890';
        };
        
        // getNetworkOperatorName — empty on emulator
        TelephonyManager.getNetworkOperatorName.overload().implementation = function() {
            return 'Telkomsel';
        };
        
        // getSimOperatorName
        TelephonyManager.getSimOperatorName.overload().implementation = function() {
            return 'Telkomsel';
        };
        
        // getNetworkOperator — "310260" is Android emulator
        TelephonyManager.getNetworkOperator.overload().implementation = function() {
            return '51010'; // Telkomsel MCC+MNC
        };
        
        // getPhoneType — emulator returns PHONE_TYPE_GSM but some checks look for specific behavior
        TelephonyManager.getSimState.overload().implementation = function() {
            return 5; // SIM_STATE_READY
        };
    } catch(e) { console.log('TelephonyManager hook failed: ' + e); }

    // 5. Sensor-based detection (emulators lack real sensors)
    try {
        var SensorManager = Java.use('android.hardware.SensorManager');
        SensorManager.getSensorList.overload('int').implementation = function(type) {
            var list = this.getSensorList(type);
            // If list is empty (emulator), some apps flag it
            // We can't fake sensors, but we can prevent the check from triggering
            console.log('[Emulator Bypass] getSensorList type=' + type + ' count=' + list.size());
            return list;
        };
    } catch(e) {}

    // 6. Battery-based detection (emulators always show "charging" or fixed level)
    try {
        var BatteryManager = Java.use('android.os.BatteryManager');
        // Hook intent filter for ACTION_BATTERY_CHANGED if needed
    } catch(e) {}

    // 7. IP/Network-based detection
    try {
        var NetworkInterface = Java.use('java.net.NetworkInterface');
        // Emulators use 10.0.2.x (Android emulator) or 192.168.x.x (Genymotion)
        // Some apps check for these specific ranges
    } catch(e) {}

    // 8. /proc/cpuinfo check (goldfish/ranchu)
    try {
        var BufferedReader = Java.use('java.io.BufferedReader');
        BufferedReader.readLine.overload().implementation = function() {
            var line = this.readLine();
            if (line && (line.indexOf('goldfish') !== -1 || line.indexOf('ranchu') !== -1)) {
                console.log('[Emulator Bypass] Hiding goldfish/ranchu in cpuinfo');
                return line.replace('goldfish', 'exynos').replace('ranchu', 'exynos');
            }
            return line;
        };
    } catch(e) {}

    // 9. Google Play Services check (emulators may not have it)
    try {
        var GoogleApiAvailability = Java.use('com.google.android.gms.common.GoogleApiAvailability');
        GoogleApiAvailability.getInstance.implementation = function() {
            var instance = this.getInstance();
            return instance;
        };
    } catch(e) {}

    // 10. OpenGL renderer check (emulators use "Android Emulator" or "SwiftShader")
    // This is checked via GLES20.glGetString(GLES20.GL_RENDERER)
    // Harder to hook — usually requires native hook on libGLESv2.so

    console.log('[+] Emulator detection bypass loaded — all checks hooked');
});
```

```bash
# Run emulator detection bypass
frida -U -f <package> -l emulator_bypass.js --no-pause

# Combined: emulator + root + SSL pinning
frida -U -f <package> \
    -l emulator_bypass.js \
    -l root_bypass.js \
    -l ssl_pinning_bypass.js \
    --no-pause

# For Flutter apps: emulator + root + flutter SSL
frida -U -f <package> \
    -l emulator_bypass.js \
    -l root_bypass.js \
    -l flutter_ssl_bypass.js \
    --no-pause

# If emulator detection happens BEFORE Frida can hook (native init):
# Use Magisk + props module to spoof build properties at boot level
# Or: patch the APK to remove detection code (smali editing)
```

---

## Biometric Bypass

```javascript
// biometric_bypass.js - Bypass fingerprint/face authentication (Android)
Java.perform(function() {
    // BiometricPrompt (Android 9+)
    try {
        var BiometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt');
        BiometricPrompt.authenticate.overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback').implementation = function(cancel, executor, callback) {
            console.log('[Biometric] BiometricPrompt.authenticate intercepted');
            // Trigger success callback
            var AuthResult = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
            // Call onAuthenticationSucceeded with null result
            callback.onAuthenticationSucceeded(null);
        };
    } catch(e) { console.log('BiometricPrompt not found: ' + e); }

    // FingerprintManager (deprecated but still used)
    try {
        var FingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
        FingerprintManager.authenticate.implementation = function(crypto, cancel, flags, callback, handler) {
            console.log('[Biometric] FingerprintManager.authenticate intercepted');
            var AuthResult = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');
            callback.onAuthenticationSucceeded(null);
        };
    } catch(e) {}

    // AndroidX BiometricPrompt
    try {
        var AndroidXBiometric = Java.use('androidx.biometric.BiometricPrompt');
        AndroidXBiometric.authenticate.overload('androidx.biometric.BiometricPrompt$PromptInfo').implementation = function(info) {
            console.log('[Biometric] AndroidX BiometricPrompt intercepted');
            // Find the callback field and trigger success
            var callback = this.mAuthenticationCallback.value;
            if (callback) {
                callback.onAuthenticationSucceeded(null);
            }
        };
    } catch(e) {}

    console.log('[+] Biometric bypass loaded');
});
```

```javascript
// biometric_bypass_ios.js - Bypass Touch ID / Face ID (iOS)
if (ObjC.available) {
    // LAContext evaluatePolicy bypass
    var LAContext = ObjC.classes.LAContext;
    Interceptor.attach(LAContext['- evaluatePolicy:localizedReason:reply:'].implementation, {
        onEnter: function(args) {
            console.log('[Biometric] LAContext.evaluatePolicy intercepted');
            var reply = new ObjC.Block(args[4]);
            // Call reply with success=true, error=nil
            reply.implementation = function(success, error) {
                reply(true, null);
            };
        }
    });

    // Also hook canEvaluatePolicy to always return true
    Interceptor.attach(LAContext['- canEvaluatePolicy:error:'].implementation, {
        onLeave: function(retval) {
            retval.replace(1); // YES
        }
    });

    console.log('[+] iOS biometric bypass loaded');
}
```

---

## Crypto Key Extraction

```javascript
// crypto_hooks.js - Extract encryption keys and plaintext
Java.perform(function() {
    // AES key extraction
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) {
        console.log('[Crypto] SecretKeySpec: algo=' + algo + ' key=' + bytesToHex(key));
        return this.$init(key, algo);
    };

    // Cipher operations
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(input) {
        var result = this.doFinal(input);
        var mode = this.getOpmode ? this.getOpmode() : 'unknown';
        console.log('[Crypto] Cipher.doFinal mode=' + mode);
        console.log('  Input:  ' + bytesToHex(input));
        console.log('  Output: ' + bytesToHex(result));
        return result;
    };

    // IV extraction
    var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
    IvParameterSpec.$init.overload('[B').implementation = function(iv) {
        console.log('[Crypto] IV: ' + bytesToHex(iv));
        return this.$init(iv);
    };

    // SharedPreferences encryption key (EncryptedSharedPreferences)
    try {
        var MasterKey = Java.use('androidx.security.crypto.MasterKey');
        // Monitor key generation
    } catch(e) {}

    function bytesToHex(bytes) {
        var hex = '';
        for (var i = 0; i < bytes.length; i++) {
            hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        return hex;
    }

    console.log('[+] Crypto hooks loaded');
});
```

---

## Network Traffic Logger

```javascript
// traffic_logger.js - Log all HTTP(S) requests/responses
Java.perform(function() {
    // OkHttp3 Interceptor
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Interceptor = Java.use('okhttp3.Interceptor');
        var Buffer = Java.use('okio.Buffer');

        // Hook newCall to log requests
        var RealCall = Java.use('okhttp3.RealCall');
        RealCall.execute.implementation = function() {
            var request = this.request();
            console.log('[HTTP] ' + request.method() + ' ' + request.url().toString());
            var headers = request.headers();
            for (var i = 0; i < headers.size(); i++) {
                console.log('  ' + headers.name(i) + ': ' + headers.value(i));
            }
            var body = request.body();
            if (body) {
                var buffer = Buffer.$new();
                body.writeTo(buffer);
                console.log('  Body: ' + buffer.readUtf8());
            }
            var response = this.execute();
            console.log('[HTTP] Response: ' + response.code());
            return response;
        };
    } catch(e) { console.log('OkHttp3 hooking failed: ' + e); }

    // HttpURLConnection
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function() {
            var conn = this.openConnection();
            console.log('[HTTP] URL.openConnection: ' + this.toString());
            return conn;
        };
    } catch(e) {}

    console.log('[+] Traffic logger loaded');
});
```

---

## DexGuard / Native Root Detection Bypass (Aggressive)

When standard Java-level hooks fail because the app kills itself before hooks establish (common with DexGuard, Promon, Guardsquare), use native-level interception:

```javascript
// dexguard_bypass.js - Native-level anti-kill + anti-detection
// Use when: app exits cleanly (exit code 0) despite Java System.exit hooks
// Symptom: "Process exited cleanly (0)" in logcat, hooks fire but process dies

// ===== BLOCK ALL EXIT PATHS AT NATIVE LEVEL (before Java loads) =====
Interceptor.attach(Module.findExportByName("libc.so", "exit"), {
    onEnter: function(args) {
        console.log("[!] NATIVE exit(" + args[0] + ") BLOCKED");
        // Replace with infinite sleep to prevent termination
        var nanosleep = new NativeFunction(
            Module.findExportByName("libc.so", "nanosleep"), 'int', ['pointer', 'pointer']);
        var ts = Memory.alloc(16);
        ts.writeU64(0x7FFFFFFF);
        nanosleep(ts, ptr(0));
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "_exit"), {
    onEnter: function(args) {
        console.log("[!] NATIVE _exit(" + args[0] + ") BLOCKED");
        var nanosleep = new NativeFunction(
            Module.findExportByName("libc.so", "nanosleep"), 'int', ['pointer', 'pointer']);
        var ts = Memory.alloc(16);
        ts.writeU64(0x7FFFFFFF);
        nanosleep(ts, ptr(0));
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "kill"), {
    onEnter: function(args) {
        if (args[0].toInt32() === Process.id) {
            console.log("[!] NATIVE kill(self, " + args[1] + ") BLOCKED");
            args[0] = ptr(-1);  // Invalid PID
        }
    }
});

// ===== HIDE FRIDA FROM /proc/self/maps =====
// DexGuard reads maps via fgets or direct read() syscall
Interceptor.attach(Module.findExportByName("libc.so", "fgets"), {
    onEnter: function(args) { this.buf = args[0]; },
    onLeave: function(retval) {
        if (!retval.isNull() && this.buf) {
            try {
                var line = this.buf.readUtf8String();
                if (line && (line.indexOf("frida") !== -1 || line.indexOf("gadget") !== -1 ||
                    line.indexOf("linjector") !== -1)) {
                    this.buf.writeUtf8String("");
                    retval.replace(ptr(0));
                }
            } catch(e) {}
        }
    }
});

// ===== HIDE FRIDA PORT (27042) FROM /proc/net/tcp =====
// DexGuard scans /proc/net/tcp for 0x69A2 (27042 in hex)
// Solution: also filter fgets for "69A2" when reading tcp
Interceptor.attach(Module.findExportByName("libc.so", "fgets"), {
    onEnter: function(args) { this.buf2 = args[0]; },
    onLeave: function(retval) {
        if (!retval.isNull() && this.buf2) {
            try {
                var line = this.buf2.readUtf8String();
                if (line && line.indexOf("69A2") !== -1) {
                    this.buf2.writeUtf8String("");
                    retval.replace(ptr(0));
                }
            } catch(e) {}
        }
    }
});

// ===== HIDE ROOT BINARIES AT NATIVE LEVEL =====
Interceptor.attach(Module.findExportByName("libc.so", "access"), {
    onEnter: function(args) {
        var path = args[0].readUtf8String();
        if (path && (path.indexOf("/su") !== -1 || path.indexOf("magisk") !== -1 ||
            path.indexOf("kernelsu") !== -1 || path.indexOf("frida") !== -1 ||
            path.indexOf("xposed") !== -1 || path.indexOf("supersu") !== -1)) {
            args[0] = Memory.allocUtf8String("/nonexistent");
        }
    }
});

// ===== FILTER strstr FOR DETECTION STRINGS =====
Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {
    onEnter: function(args) {
        try { this.needle = args[1].readUtf8String(); } catch(e) { this.needle = null; }
    },
    onLeave: function(retval) {
        if (this.needle && !retval.isNull()) {
            var n = this.needle.toLowerCase();
            if (n.indexOf("frida") !== -1 || n.indexOf("xposed") !== -1 ||
                n.indexOf("substrate") !== -1 || n.indexOf("magisk") !== -1 ||
                n.indexOf("kernelsu") !== -1) {
                retval.replace(ptr(0));
            }
        }
    }
});

// ===== JAVA HOOKS (loaded after native) =====
Java.perform(function() {
    Java.use("java.lang.System").exit.implementation = function(code) {
        console.log("[!] System.exit(" + code + ") BLOCKED");
    };
    Java.use("java.lang.Runtime").exit.implementation = function(code) {
        console.log("[!] Runtime.exit(" + code + ") BLOCKED");
    };
    Java.use("android.os.Process").killProcess.implementation = function(pid) {
        if (pid === Java.use("android.os.Process").myPid()) {
            console.log("[!] killProcess(self) BLOCKED");
            return;
        }
        this.killProcess(pid);
    };
    console.log("[+] DexGuard bypass active (native + Java)");
});
```

**When this still fails** (DexGuard uses direct syscalls bypassing libc):
1. **Shamiko + Zygisk Next** — hides root at kernel level (requires Magisk or updated KernelSU)
2. **Frida Gadget injection** — patch APK with gadget.so (avoids frida-server detection entirely)
3. **APK patching** — remove DexGuard init from smali (complex for multi-DEX apps)
4. **Non-rooted device** — cleanest for bug bounty (static evidence is sufficient for submission)

**Detection layers in DexGuard (observed in Gojek 5.61.1):**
- File-based: `access()` for /su, /magisk, /kernelsu, /frida paths
- Port-based: reads `/proc/net/tcp` for 0x69A2 (frida port 27042)
- Maps-based: reads `/proc/self/maps` for frida-agent strings (4+ reads per cycle)
- Native watchdog: spawns thread that kills process via direct syscall (bypasses libc hooks)
- Remote config: `RootCheckerRemoteConfig` via Firebase controls detection behavior
- Kill method: `exit(0)` — clean exit, not crash

---

## Flutter SSL Pinning Bypass (BoringSSL in libflutter.so)

Flutter apps use their own HTTP stack (dart:io) with BoringSSL compiled into libflutter.so. Standard Android SSL hooks (TrustManager, OkHttp, etc.) do NOT work. You must hook the native verify function inside libflutter.so.

**Key challenges:**
- libflutter.so strips all symbols — no exports to hook by name
- Module memory may have unmapped pages — scanning full range causes access violations
- Must scan only `r-x` (executable) ranges within the module
- The verify function pattern changes between Flutter versions

```javascript
// flutter_ssl_bypass.js — Proven for Flutter 3.19–3.24+ (ARM64)
// Hooks ssl_crypto_x509_session_verify_cert_chain by byte pattern
// Forces return value to 1 (success) on all candidates

function bypassFlutterSSL() {
    var m = Process.findModuleByName('libflutter.so');
    if (!m) { setTimeout(bypassFlutterSSL, 500); return; }

    // CRITICAL: scan only executable ranges to avoid access violations
    var ranges = Process.enumerateRanges('r-x');
    var flutterRanges = [];
    var mEnd = m.base.add(m.size);
    for (var i = 0; i < ranges.length; i++) {
        if (ranges[i].base.compare(m.base) >= 0 && ranges[i].base.compare(mEnd) < 0) {
            flutterRanges.push(ranges[i]);
        }
    }

    // Patterns for ssl_crypto_x509_session_verify_cert_chain prologue (ARM64)
    // Format: sub sp, sp, #N; stp x29, x30, [sp, #offset]
    // The first 8 bytes are most stable across versions
    var patterns = [
        'FF 03 05 D1 FD 7B 0F A9',  // sub sp, #0x140 (Flutter 3.22-3.24+)
        'FF 83 04 D1 FD 7B 0F A9',  // sub sp, #0x120 (Flutter 3.19-3.21)
        'FF C3 03 D1 FD 7B 0E A9',  // sub sp, #0xF0 (Flutter 3.16-3.18)
        'FF 43 03 D1 FD 7B 0C A9',  // sub sp, #0xD0 (Flutter 3.13-3.15)
        'FF 03 04 D1 FD 7B 0F A9',  // sub sp, #0x100 (alternate)
        'FF C3 04 D1 FD 7B 0F A9',  // sub sp, #0x130 (alternate)
    ];

    var hooked = false;
    for (var p = 0; p < patterns.length && !hooked; p++) {
        var allMatches = [];
        for (var r = 0; r < flutterRanges.length; r++) {
            try {
                var matches = Memory.scanSync(flutterRanges[r].base, flutterRanges[r].size, patterns[p]);
                for (var j = 0; j < matches.length; j++) {
                    allMatches.push(matches[j].address);
                }
            } catch(e) {}
        }
        // Good candidate: 1-5 matches (too many = wrong pattern)
        if (allMatches.length > 0 && allMatches.length <= 5) {
            for (var i = 0; i < allMatches.length; i++) {
                Interceptor.attach(allMatches[i], {
                    onLeave: function(retval) { retval.replace(0x1); }
                });
            }
            console.log('[+] Flutter SSL bypass: pattern ' + p + ', ' + allMatches.length + ' hooks');
            hooked = true;
        }
    }

    if (!hooked) {
        console.log('[-] Flutter SSL bypass FAILED — manual analysis needed');
        console.log('[*] Try: strings libflutter.so | grep CERTIFICATE_VERIFY_FAILED');
        console.log('[*] Then xref that string to find the verify function');
    }
}

setTimeout(bypassFlutterSSL, 500);
```

**Usage with spawn (Python — recommended for Flutter):**
```python
import frida, time
device = frida.get_usb_device()
pid = device.spawn(['com.example.flutter_app'])
session = device.attach(pid)
with open('flutter_ssl_bypass.js') as f:
    script = session.create_script(f.read())
script.load()
device.resume(pid)
import sys; sys.stdin.read()  # keep session alive
```

**Why Python over CLI:** Frida CLI detaches on script completion. For Flutter SSL bypass to persist, the session must stay alive. Python's `sys.stdin.read()` blocks indefinitely.

**Combined with iptables (required for Flutter):**
Flutter ignores Android system proxy settings. You MUST redirect traffic at the network level:
```bash
# Get app UID
adb shell cat /data/system/packages.list | grep <package>
# Redirect HTTPS to proxy (targeted by UID)
adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner <UID> --dport 443 -j DNAT --to <HOST_IP>:8080'"
adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner <UID> --dport 80 -j DNAT --to <HOST_IP>:8080'"
# Cleanup after testing
adb shell "su -c 'iptables -t nat -F OUTPUT'"
```

**Pitfalls:**
- If `Memory.scanSync` on the full module throws access violations, you MUST use `Process.enumerateRanges('r-x')` and filter to the module's address range
- Hook ALL matches (up to 5) — the real verify function may not be the first match
- If no pattern matches, the Flutter version uses a different stack frame size. Extract libflutter.so and check with: `strings libflutter.so | grep "flutter/third_party/boringssl"` to confirm BoringSSL presence, then use r2/Ghidra to find the function manually
- Staging/debug Flutter builds may have relaxed pinning — test without bypass first

---

## Flutter Deep Link Monitoring

When testing Flutter apps that handle deep links via the Dart layer (not Java Activities), use this hook combination to trace the flow:

```javascript
// flutter_deeplink_monitor.js — Trace deep link handling in Flutter apps
Java.perform(function() {
    // Hook Activity.onNewIntent — catches deep links delivered to running app
    var Activity = Java.use('android.app.Activity');
    Activity.onNewIntent.implementation = function(intent) {
        var uri = intent.getData();
        if (uri) { send('[DEEPLINK] onNewIntent: ' + uri.toString()); }
        this.onNewIntent(intent);
    };

    // Hook Intent.getData — catches all URI reads (Flutter reads multiple times)
    var Intent = Java.use('android.content.Intent');
    Intent.getData.implementation = function() {
        var result = this.getData();
        if (result) {
            var str = result.toString();
            if (str.indexOf('://') !== -1 && str.indexOf('content://') === -1) {
                send('[DEEPLINK] getData: ' + str);
            }
        }
        return result;
    };

    // Hook WebView.loadUrl — detect if deep link triggers WebView navigation
    var WebView = Java.use('android.webkit.WebView');
    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        send('[WEBVIEW] loadUrl: ' + url);
        this.loadUrl(url);
    };

    send('[+] Flutter deep link monitor active');
});
```

**Testing pattern for Flutter deep links:**
```bash
# Trigger deep link while Frida monitors
adb shell am start -a android.intent.action.VIEW \
  -d "scheme://host/path?param=value" \
  <package_name>
```

**Key insight:** In Flutter apps, deep links are received by the Java Activity layer but routed to the Dart layer via a MethodChannel. If `WebView.loadUrl` is NOT called after a deep link with a URL parameter, the app either:
1. Gates the route behind authentication (common in banking apps)
2. Uses a Flutter WebView widget (still uses Android WebView under the hood — hook will fire)
3. Validates/rejects the URL in Dart before loading

---

## Usage Quick Reference

```bash
# === Common Combinations ===

# Banking app (root detection + SSL pinning + anti-frida)
frida -U -f <package> \
  -l anti_frida_bypass.js \
  -l root_bypass.js \
  -l ssl_pinning_bypass.js \
  --no-pause

# iOS banking app (jailbreak + SSL + anti-frida)
frida -U -f <bundle_id> \
  -l anti_frida_bypass_ios.js \
  -l ios_jailbreak_bypass.js \
  -l ios_ssl_bypass.js \
  --no-pause

# Crypto analysis (extract keys during operation)
frida -U -f <package> -l crypto_hooks.js --no-pause

# Biometric bypass + traffic logging
frida -U -f <package> \
  -l biometric_bypass.js \
  -l traffic_logger.js \
  --no-pause

# === Objection Quick Commands ===
objection -g <package> explore
> android sslpinning disable
> android root disable
> android hooking list classes
> android hooking list class_methods <class>
> android hooking watch class <class>
> android keystore list
> android clipboard monitor

# iOS objection
objection -g <bundle_id> explore
> ios sslpinning disable
> ios jailbreak disable
> ios keychain dump
> ios nsuserdefaults get
> ios cookies get
> ios bundles list_frameworks
```
