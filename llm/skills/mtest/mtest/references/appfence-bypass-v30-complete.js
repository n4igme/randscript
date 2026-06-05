// DexGuard/AppFence Complete Bypass v30
// Combines: root indicator hiding + maps filtering + kill thread blocking + libc hooks
// Use case: App with DexGuard that detects BOTH root AND Frida
// Tested on: Gojek (com.gojek.app) - keeps app alive ~7min but eventually detected
// Limitation: Inline SVC #0 (exit_group) bypasses all userspace hooks

var _refs = [];
function keepRef(obj) { _refs.push(obj); return obj; }

// ==========================================
// PART 1: ROOT DETECTION BYPASS
// ==========================================

var rootPaths = [
    "/system/bin/su", "/system/xbin/su", "/sbin/su",
    "/data/adb/", "/data/adb/ksu", "/data/adb/modules",
    "/system/app/Superuser", "/system/app/SuperSU",
    "/data/local/bin/su", "/data/local/xbin/su",
    "com.topjohnwu.magisk", "eu.chainfire.supersu",
    "me.weishu.kernelsu", "com.noshufou.android.su",
    "/sys/module/kernelsu", "/sys/fs/kernelsu"
];

function isRootPath(path) {
    if (!path) return false;
    for (var i = 0; i < rootPaths.length; i++) {
        if (path.indexOf(rootPaths[i]) !== -1) return true;
    }
    return false;
}

// Hook access() - return -1 for root paths
Interceptor.attach(Module.findExportByName("libc.so", "access"), {
    onEnter: function(args) {
        try { if (isRootPath(args[0].readCString())) this.hide = true; } catch(e) {}
    },
    onLeave: function(retval) { if (this.hide) retval.replace(-1); }
});

// Hook stat/lstat
["stat", "lstat", "stat64", "lstat64"].forEach(function(func) {
    try {
        Interceptor.attach(Module.findExportByName("libc.so", func), {
            onEnter: function(args) {
                try { if (isRootPath(args[0].readCString())) this.hide = true; } catch(e) {}
            },
            onLeave: function(retval) { if (this.hide) retval.replace(-1); }
        });
    } catch(e) {}
});

// Hook fopen - return NULL for root paths + track maps files
var mapsFiles = {};
Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
    onEnter: function(args) {
        try {
            var path = args[0].readCString();
            if (path && isRootPath(path)) this.hide = true;
            if (path && path.indexOf("/proc/self/maps") !== -1) this.isMaps = true;
        } catch(e) {}
    },
    onLeave: function(retval) {
        if (this.hide) { retval.replace(ptr(0)); return; }
        if (this.isMaps && !retval.isNull()) mapsFiles[retval.toString()] = true;
    }
});

// ==========================================
// PART 2: MAPS FILTERING (hide Frida/hluda)
// ==========================================

Interceptor.attach(Module.findExportByName("libc.so", "fgets"), {
    onEnter: function(args) {
        this.buf = args[0];
        this.isMaps = mapsFiles[args[2].toString()] === true;
    },
    onLeave: function(retval) {
        if (!this.isMaps || retval.isNull()) return;
        try {
            var line = this.buf.readUtf8String();
            if (line && (line.indexOf("frida") !== -1 ||
                         line.indexOf("gadget") !== -1 ||
                         line.indexOf("hluda") !== -1 ||
                         line.indexOf("linjector") !== -1 ||
                         line.indexOf("agent") !== -1)) {
                this.buf.writeUtf8String("/dev/null 00000000-00000000 r--p 00000000 00:00 0\n");
            }
        } catch(e) {}
    }
});

// Hook open() for fd-based maps/version reading + root path hiding
var mapsFd = -1;
var versionFd = -1;
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        try {
            var path = args[0].readCString();
            if (path) {
                if (isRootPath(path)) this.hide = true;
                if (path.indexOf("/proc/self/maps") !== -1) this.isMaps = true;
                if (path.indexOf("/proc/version") !== -1) this.isVersion = true;
            }
        } catch(e) {}
    },
    onLeave: function(retval) {
        if (this.hide) { retval.replace(-1); return; }
        if (this.isMaps) mapsFd = retval.toInt32();
        if (this.isVersion) versionFd = retval.toInt32();
    }
});

// Hook read() - filter maps content + spoof /proc/version
Interceptor.attach(Module.findExportByName("libc.so", "read"), {
    onEnter: function(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.isMaps = (this.fd === mapsFd && mapsFd !== -1);
        this.isVersion = (this.fd === versionFd && versionFd !== -1);
    },
    onLeave: function(retval) {
        if (retval.toInt32() <= 0) return;
        try {
            if (this.isMaps) {
                var content = this.buf.readUtf8String(retval.toInt32());
                if (content && (content.indexOf("frida") !== -1 ||
                               content.indexOf("hluda") !== -1 ||
                               content.indexOf("gadget") !== -1 ||
                               content.indexOf("agent") !== -1)) {
                    var filtered = content.split("\n").filter(function(line) {
                        return line.indexOf("frida") === -1 &&
                               line.indexOf("hluda") === -1 &&
                               line.indexOf("gadget") === -1 &&
                               line.indexOf("linjector") === -1 &&
                               line.indexOf("agent") === -1;
                    }).join("\n");
                    this.buf.writeUtf8String(filtered);
                    retval.replace(filtered.length);
                }
            }
            if (this.isVersion) {
                var fake = "Linux version 4.4.302-perf+ (builder@android-build) (gcc version 4.9.x) #1 SMP PREEMPT\n";
                this.buf.writeUtf8String(fake);
                retval.replace(fake.length);
            }
        } catch(e) {
            // Binary data on non-maps fd — ignore silently
            // This try/catch is MANDATORY — read() fires for ALL fds
        }
    }
});

// Hook __system_property_get to hide root properties
try {
    Interceptor.attach(Module.findExportByName("libc.so", "__system_property_get"), {
        onEnter: function(args) {
            this.name = args[0].readCString();
            this.valueBuf = args[1];
        },
        onLeave: function(retval) {
            if (this.name === "ro.debuggable") this.valueBuf.writeUtf8String("0");
            if (this.name === "ro.secure") this.valueBuf.writeUtf8String("1");
        }
    });
} catch(e) {}

// ==========================================
// PART 3: KILL THREAD BLOCKING (GC-safe)
// ==========================================

Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"), {
    onEnter: function(args) {
        var startRoutine = args[2];
        var mod = Process.findModuleByAddress(startRoutine);
        if (mod && mod.name === "libaf-android.so") {
            var offset = startRoutine.sub(mod.base);
            console.log("[*] Blocking kill thread at offset: 0x" + offset.toString(16));
            // GC-safe: keepRef prevents garbage collection of NativeCallback
            var sleepForever = keepRef(new NativeCallback(function() {
                var sleep = new NativeFunction(
                    Module.findExportByName("libc.so", "sleep"), 'uint', ['uint']);
                while(true) { sleep(2147483647); }
            }, 'pointer', []));
            args[2] = sleepForever;
        }
    }
});

// ==========================================
// PART 4: LIBC SAFETY NETS
// ==========================================

Interceptor.attach(Module.findExportByName("libc.so", "syscall"), {
    onEnter: function(args) {
        var num = args[0].toInt32();
        if (num === 94) { // exit_group
            console.log("[*] Blocked syscall(exit_group)");
            args[0] = ptr(39); // getpid (harmless)
        }
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "kill"), {
    onEnter: function(args) {
        var sig = args[1].toInt32();
        if (sig === 9 || sig === 6) {
            console.log("[*] Blocked kill(sig=" + sig + ")");
            args[1] = ptr(0); // signal 0 = check existence (harmless)
        }
    }
});

Interceptor.replace(Module.findExportByName("libc.so", "_exit"), keepRef(new NativeCallback(function(status) {
    console.log("[*] Blocked _exit(" + status + ")");
    var sleep = new NativeFunction(Module.findExportByName("libc.so", "sleep"), 'uint', ['uint']);
    while(true) { sleep(2147483647); }
}, 'void', ['int'])));

Interceptor.replace(Module.findExportByName("libc.so", "abort"), keepRef(new NativeCallback(function() {
    console.log("[*] Blocked abort()");
    var sleep = new NativeFunction(Module.findExportByName("libc.so", "sleep"), 'uint', ['uint']);
    while(true) { sleep(2147483647); }
}, 'void', [])));

// ==========================================
// PART 5: JAVA LAYER (PackageManager hide)
// ==========================================

Java.perform(function() {
    try {
        var PM = Java.use("android.app.ApplicationPackageManager");
        PM.getPackageInfo.overload("java.lang.String", "int").implementation = function(pkg, flags) {
            var rootPkgs = ["com.topjohnwu.magisk", "eu.chainfire.supersu",
                           "com.noshufou.android.su", "me.weishu.kernelsu",
                           "com.koushikdutta.superuser", "com.thirdparty.superuser"];
            if (rootPkgs.indexOf(pkg) !== -1) {
                throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(pkg);
            }
            return this.getPackageInfo(pkg, flags);
        };
        console.log("[+] Java PackageManager hook active");
    } catch(e) {
        console.log("[!] Java hook failed: " + e);
    }
});

console.log("[+] Complete Bypass v30 loaded");
console.log("[+] Root hiding: file access + properties + package manager");
console.log("[+] Maps filtering: fopen/fgets + open/read");
console.log("[+] /proc/version: spoofed to generic kernel");
console.log("[+] Kill thread blocking: pthread_create hook (GC-safe)");
console.log("[+] Libc safety nets: syscall/kill/_exit/abort");
console.log("[!] NOTE: Inline SVC #0 still bypasses all hooks — app may die after delay");
