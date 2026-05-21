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
