/**
 * root_bypass.js — Universal Root/Jailbreak Detection Bypass for Android
 * 
 * Covers:
 * - File existence checks (su, magisk, kernelsu, busybox)
 * - Build.TAGS check (test-keys)
 * - System property checks (ro.debuggable, ro.secure)
 * - Package manager checks (Magisk, KernelSU, SuperSU apps)
 * - Runtime.exec("which su") and shell commands
 * - Native file access() calls
 * - /proc/self/maps filtering (Magisk/KernelSU modules)
 * - RootBeer library
 * - SafetyNet/Play Integrity basic checks
 * 
 * Usage: frida -U -f <package> -l root_bypass.js
 * 
 * NOTE: This handles Java-layer and basic native detection.
 * For DexGuard/AppFence with inline SVC syscalls, this is NOT sufficient.
 * See mtest skill → Operational Notes → DexGuard section.
 */

'use strict';

// ==========================================
// GLOBAL: Paths and packages to hide
// ==========================================
var ROOT_BINARIES = [
    'su', 'daemonsu', 'magisk', 'magiskhide', 'magiskpolicy',
    'busybox', 'ksu', 'ksud', 'kernelsu',
    'supersu', 'Superuser.apk', '.supersu',
    'frida-server', 'hluda-server'
];

var ROOT_PATHS = [
    '/system/bin/su', '/system/xbin/su', '/sbin/su',
    '/system/app/Superuser.apk', '/system/app/SuperSU.apk',
    '/data/local/tmp/frida-server', '/data/local/tmp/hluda-server',
    '/system/xbin/daemonsu', '/system/xbin/busybox',
    '/data/adb/magisk', '/data/adb/ksu', '/data/adb/ksud',
    '/sbin/magisk', '/sbin/.magisk',
    '/cache/.disable_magisk', '/dev/.magisk/mirror',
    '/data/local/bin/su', '/data/local/xbin/su'
];

var ROOT_PACKAGES = [
    'com.topjohnwu.magisk', 'me.weishu.kernelsu',
    'com.noshufou.android.su', 'com.thirdparty.superuser',
    'eu.chainfire.supersu', 'com.koushikdutta.superuser',
    'com.zachspong.temprootremovejb', 'com.ramdroid.appquarantine',
    'de.robv.android.xposed.installer', 'io.github.vvb2060.magisk',
    'me.weishu.exp', 'com.formyhm.hiderootPremium',
    'com.amphoras.hidemyroot', 'com.saurik.substrate'
];

var ROOT_PROPS = [
    'ro.build.selinux', 'ro.debuggable', 'service.adb.root',
    'ro.secure'
];

Java.perform(function () {
    console.log('[*] Root Detection Bypass — loading hooks...');

    // ==========================================
    // 1. File existence checks (Java)
    // ==========================================
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            for (var i = 0; i < ROOT_PATHS.length; i++) {
                if (path === ROOT_PATHS[i]) {
                    console.log('[+] File.exists() hidden: ' + path);
                    return false;
                }
            }
            for (var j = 0; j < ROOT_BINARIES.length; j++) {
                if (path.indexOf(ROOT_BINARIES[j]) !== -1 && path.indexOf('/data/data/') === -1) {
                    console.log('[+] File.exists() hidden: ' + path);
                    return false;
                }
            }
            return this.exists();
        };
    } catch (e) {
        console.log('[-] File.exists hook failed: ' + e);
    }

    // ==========================================
    // 2. Runtime.exec — hide su/which su output
    // ==========================================
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1 || cmd.indexOf('magisk') !== -1) {
                console.log('[+] Runtime.exec() blocked: ' + cmd);
                // Return a process that outputs nothing
                return Runtime.exec.call(this, 'echo');
            }
            return Runtime.exec.call(this, cmd);
        };

        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdArray) {
            var cmd = cmdArray.join(' ');
            if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1 || cmd.indexOf('magisk') !== -1) {
                console.log('[+] Runtime.exec(String[]) blocked: ' + cmd);
                return Runtime.exec.call(this, ['echo']);
            }
            return Runtime.exec.call(this, cmdArray);
        };
    } catch (e) {
        console.log('[-] Runtime.exec hook failed: ' + e);
    }

    // ==========================================
    // 3. ProcessBuilder — hide su commands
    // ==========================================
    try {
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        ProcessBuilder.start.implementation = function () {
            var cmd = this.command().toString();
            if (cmd.indexOf('su') !== -1 || cmd.indexOf('magisk') !== -1) {
                console.log('[+] ProcessBuilder.start() blocked: ' + cmd);
                this.command(Java.use('java.util.Arrays').asList(['echo']));
            }
            return this.start();
        };
    } catch (e) { }

    // ==========================================
    // 4. Build.TAGS — hide test-keys
    // ==========================================
    try {
        var Build = Java.use('android.os.Build');
        var tags = Build.TAGS.value;
        if (tags && tags.indexOf('test-keys') !== -1) {
            Build.TAGS.value = 'release-keys';
            console.log('[+] Build.TAGS changed from "' + tags + '" to "release-keys"');
        }
    } catch (e) { }

    // ==========================================
    // 5. System properties
    // ==========================================
    try {
        var SystemProperties = Java.use('android.os.SystemProperties');
        SystemProperties.get.overload('java.lang.String').implementation = function (key) {
            if (key === 'ro.build.tags') {
                console.log('[+] SystemProperties.get(ro.build.tags) → release-keys');
                return 'release-keys';
            }
            if (key === 'ro.debuggable') {
                return '0';
            }
            if (key === 'ro.secure') {
                return '1';
            }
            return this.get(key);
        };

        SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function (key, def) {
            if (key === 'ro.build.tags') {
                return 'release-keys';
            }
            if (key === 'ro.debuggable') {
                return '0';
            }
            if (key === 'ro.secure') {
                return '1';
            }
            return this.get(key, def);
        };
    } catch (e) { }

    // ==========================================
    // 6. PackageManager — hide root apps
    // ==========================================
    try {
        var PackageManager = Java.use('android.app.ApplicationPackageManager');
        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (packageName, flags) {
            for (var i = 0; i < ROOT_PACKAGES.length; i++) {
                if (packageName === ROOT_PACKAGES[i]) {
                    console.log('[+] PackageManager.getPackageInfo() hidden: ' + packageName);
                    throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(packageName);
                }
            }
            return this.getPackageInfo(packageName, flags);
        };
    } catch (e) { }

    // Also hide from getInstalledPackages/getInstalledApplications
    try {
        var ApplicationPackageManager = Java.use('android.app.ApplicationPackageManager');
        ApplicationPackageManager.getInstalledApplications.overload('int').implementation = function (flags) {
            var apps = this.getInstalledApplications(flags);
            var filtered = Java.use('java.util.ArrayList').$new();
            for (var i = 0; i < apps.size(); i++) {
                var app = apps.get(i);
                var pkgName = app.packageName.value;
                var isRoot = false;
                for (var j = 0; j < ROOT_PACKAGES.length; j++) {
                    if (pkgName === ROOT_PACKAGES[j]) {
                        isRoot = true;
                        break;
                    }
                }
                if (!isRoot) {
                    filtered.add(app);
                }
            }
            return filtered;
        };
    } catch (e) { }

    // ==========================================
    // 7. ContentResolver — hide Magisk provider
    // ==========================================
    try {
        var ContentResolver = Java.use('android.content.ContentResolver');
        ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
            var uriStr = uri.toString();
            if (uriStr.indexOf('magisk') !== -1 || uriStr.indexOf('supersu') !== -1) {
                console.log('[+] ContentResolver.query() blocked for: ' + uriStr);
                return null;
            }
            return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };
    } catch (e) { }

    // ==========================================
    // 8. RootBeer library (common detection lib)
    // ==========================================
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function () {
            console.log('[+] RootBeer.isRooted() → false');
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function () {
            console.log('[+] RootBeer.isRootedWithoutBusyBoxCheck() → false');
            return false;
        };
        RootBeer.detectRootManagementApps.implementation = function () { return false; };
        RootBeer.detectPotentiallyDangerousApps.implementation = function () { return false; };
        RootBeer.detectTestKeys.implementation = function () { return false; };
        RootBeer.checkForBusyBoxBinary.implementation = function () { return false; };
        RootBeer.checkForSuBinary.implementation = function () { return false; };
        RootBeer.checkSuExists.implementation = function () { return false; };
        RootBeer.checkForRWPaths.implementation = function () { return false; };
        RootBeer.checkForDangerousProps.implementation = function () { return false; };
        RootBeer.checkForRootNative.implementation = function () { return false; };
        RootBeer.detectRootCloakingApps.implementation = function () { return false; };
        RootBeer.isSelinuxFlagInEnabled.implementation = function () { return false; };
        console.log('[+] RootBeer library fully bypassed');
    } catch (e) {
        console.log('[-] RootBeer not found (app uses different detection)');
    }

    // ==========================================
    // 9. Native access() — hide root files
    // ==========================================
    try {
        var access = new NativeFunction(Module.findExportByName('libc.so', 'access'), 'int', ['pointer', 'int']);
        Interceptor.replace(Module.findExportByName('libc.so', 'access'), new NativeCallback(function (pathname, mode) {
            var path = pathname.readCString();
            if (path) {
                for (var i = 0; i < ROOT_PATHS.length; i++) {
                    if (path === ROOT_PATHS[i]) {
                        return -1; // ENOENT
                    }
                }
                for (var j = 0; j < ROOT_BINARIES.length; j++) {
                    if (path.indexOf(ROOT_BINARIES[j]) !== -1) {
                        return -1;
                    }
                }
            }
            return access(pathname, mode);
        }, 'int', ['pointer', 'int']));
        console.log('[+] Native access() hooked — root paths hidden');
    } catch (e) {
        console.log('[-] Native access() hook failed: ' + e);
    }

    // ==========================================
    // 10. /proc/self/maps filtering (hide Frida/Magisk)
    // ==========================================
    try {
        var fopen = new NativeFunction(Module.findExportByName('libc.so', 'fopen'), 'pointer', ['pointer', 'pointer']);
        var fgets = new NativeFunction(Module.findExportByName('libc.so', 'fgets'), 'pointer', ['pointer', 'int', 'pointer']);

        var mapsFile = null;

        Interceptor.attach(Module.findExportByName('libc.so', 'fopen'), {
            onEnter: function (args) {
                var path = args[0].readCString();
                if (path && (path.indexOf('/proc/self/maps') !== -1 || path.indexOf('/proc/' + Process.id + '/maps') !== -1)) {
                    this.isMaps = true;
                }
            },
            onLeave: function (retval) {
                if (this.isMaps) {
                    mapsFile = retval;
                }
            }
        });

        Interceptor.attach(Module.findExportByName('libc.so', 'fgets'), {
            onLeave: function (retval) {
                if (!retval.isNull()) {
                    var line = retval.readCString();
                    if (line && (
                        line.indexOf('frida') !== -1 ||
                        line.indexOf('gadget') !== -1 ||
                        line.indexOf('hluda') !== -1 ||
                        line.indexOf('magisk') !== -1 ||
                        line.indexOf('kernelsu') !== -1 ||
                        line.indexOf('lspd') !== -1
                    )) {
                        // Replace with empty/innocuous line
                        retval.writeUtf8String('');
                    }
                }
            }
        });
        console.log('[+] /proc/self/maps filtering active');
    } catch (e) {
        console.log('[-] Maps filtering failed: ' + e);
    }

    // ==========================================
    // 11. Settings.Secure — hide ADB enabled
    // ==========================================
    try {
        var Settings = Java.use('android.provider.Settings$Secure');
        Settings.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function (resolver, name, def) {
            if (name === 'adb_enabled') {
                console.log('[+] Settings.Secure.getInt(adb_enabled) → 0');
                return 0;
            }
            return this.getInt(resolver, name, def);
        };
    } catch (e) { }

    // ==========================================
    // 12. Generic "isRooted" / "isDeviceRooted" method hooks
    // ==========================================
    try {
        Java.enumerateLoadedClasses({
            onMatch: function (className) {
                if (className.toLowerCase().indexOf('root') !== -1 ||
                    className.toLowerCase().indexOf('device') !== -1) {
                    try {
                        var cls = Java.use(className);
                        var methods = cls.class.getDeclaredMethods();
                        for (var i = 0; i < methods.length; i++) {
                            var methodName = methods[i].getName();
                            if ((methodName.toLowerCase().indexOf('isroot') !== -1 ||
                                 methodName.toLowerCase().indexOf('isdevicerooted') !== -1 ||
                                 methodName.toLowerCase().indexOf('checkroot') !== -1 ||
                                 methodName.toLowerCase().indexOf('detectroot') !== -1) &&
                                methods[i].getReturnType().getName() === 'boolean') {
                                try {
                                    cls[methodName].implementation = function () {
                                        return false;
                                    };
                                    console.log('[+] Hooked: ' + className + '.' + methodName + '() → false');
                                } catch (hookErr) { }
                            }
                        }
                    } catch (e) { }
                }
            },
            onComplete: function () { }
        });
    } catch (e) { }

    console.log('[*] Root Detection Bypass — all hooks installed');
    console.log('[*] NOTE: For DexGuard/AppFence with inline SVC, this may not suffice.');
    console.log('[*]       Use Shamiko+Zygisk for kernel-level hiding.');
});
