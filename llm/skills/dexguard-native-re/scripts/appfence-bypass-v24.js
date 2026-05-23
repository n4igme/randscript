// AppFence/DexGuard bypass v24 - WORKING template
// Tested on: Gojek (com.gojek.app) with libaf-android.so
// Strategy: maps filtering + kill thread blocking + SVC patch + libc hooks
// Result: App stays alive, shows login screen. ANR dismissible with "Wait".
//
// CUSTOMIZE: Update KILL_THREAD_OFFSET and SVC_OFFSET for your target.
// Find them via: Python struct scan for SVC #0, then trace caller chain.

var KILL_THREAD_OFFSET = 0xa9b80; // pthread start_routine that does the kill
var SVC_OFFSET = 0xa9bd8;         // Inline SVC #0 (exit_group)
var LIB_NAME = "libaf-android.so";

var pthreadCreatePtr = Module.findExportByName("libc.so", "pthread_create");
var fopenPtr = Module.findExportByName("libc.so", "fopen");
var fgetsPtr = Module.findExportByName("libc.so", "fgets");
var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
var mapsFiles = {};

// === 1. KILL THREAD BLOCKING ===
Interceptor.attach(pthreadCreatePtr, {
    onEnter: function(args) {
        var startRoutine = args[2];
        var mod = Process.findModuleByAddress(startRoutine);
        if (mod && mod.name === LIB_NAME) {
            var offset = startRoutine.sub(mod.base).toInt32();
            if (offset === KILL_THREAD_OFFSET) {
                console.log("[+] Blocking kill thread at offset 0x" + offset.toString(16));
                args[2] = new NativeCallback(function(arg) {
                    // Sleep forever - thread stays alive but harmless
                    // May cause ANR after ~10s - dismiss with "Wait"
                    var ts = Memory.alloc(16);
                    ts.writeU64(0x7FFFFFFF);
                    ts.add(8).writeU64(0);
                    var nanosleep = new NativeFunction(
                        Module.findExportByName("libc.so", "nanosleep"), 'int', ['pointer', 'pointer']);
                    nanosleep(ts, ptr(0));
                    return ptr(0);
                }, 'pointer', ['pointer']);
            }
        }
    }
});

// === 2. /proc/self/maps FILTERING ===
Interceptor.attach(fopenPtr, {
    onEnter: function(args) {
        var path = args[0].readCString();
        this.isMaps = path && (path.indexOf("/proc/self/maps") !== -1 || 
                     path.indexOf("/proc/" + Process.id + "/maps") !== -1);
    },
    onLeave: function(retval) {
        if (this.isMaps && !retval.isNull()) {
            mapsFiles[retval.toString()] = true;
        }
    }
});

Interceptor.attach(fgetsPtr, {
    onEnter: function(args) {
        this.buf = args[0];
        this.size = args[1].toInt32();
        this.stream = args[2];
        this.isMaps = mapsFiles[this.stream.toString()] === true;
    },
    onLeave: function(retval) {
        if (!this.isMaps || retval.isNull()) return;
        try {
            var line = this.buf.readCString();
            if (line && (line.indexOf("frida") !== -1 || 
                         line.indexOf("gadget") !== -1 ||
                         line.indexOf("linjector") !== -1 ||
                         line.indexOf("/data/local/tmp") !== -1 ||
                         line.indexOf("re.frida") !== -1 ||
                         line.indexOf("gum-js-loop") !== -1 ||
                         line.indexOf("frida-agent") !== -1 ||
                         (line.indexOf("rwxp") !== -1 && line.indexOf("/memfd:") !== -1) ||
                         (line.indexOf("rwxp") !== -1 && line.indexOf("deleted") !== -1))) {
                // Skip this line by reading the next one
                var next = fgets(this.buf, this.size, this.stream);
                if (next.isNull()) retval.replace(ptr(0));
            }
        } catch(e) {}
    }
});

// === 3. LIBC SAFETY NETS ===
Interceptor.attach(Module.findExportByName("libc.so", "syscall"), {
    onEnter: function(args) {
        var nr = args[0].toInt32();
        // 93=exit, 94=exit_group, 129=kill, 131=tgkill, 134=tkill
        if (nr === 93 || nr === 94 || nr === 129 || nr === 131 || nr === 134) {
            args[0] = ptr(39); // getpid (harmless)
        }
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "kill"), {
    onEnter: function(args) {
        var sig = args[1].toInt32();
        if (sig === 9 || sig === 6 || sig === 15) args[1] = ptr(0);
    }
});

var tgkillPtr = Module.findExportByName("libc.so", "tgkill");
if (tgkillPtr) {
    Interceptor.attach(tgkillPtr, {
        onEnter: function(args) {
            if (args[2].toInt32() === 9 || args[2].toInt32() === 6) args[2] = ptr(0);
        }
    });
}

Interceptor.replace(Module.findExportByName("libc.so", "abort"),
    new NativeCallback(function(){}, 'void', []));
Interceptor.replace(Module.findExportByName("libc.so", "_exit"),
    new NativeCallback(function(c){}, 'void', ['int']));
Interceptor.replace(Module.findExportByName("libc.so", "exit"),
    new NativeCallback(function(c){}, 'void', ['int']));

// === 4. INLINE SVC PATCH ===
Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
    onEnter: function(args) {
        this.name = args[0] ? args[0].readCString() : "";
    },
    onLeave: function(retval) {
        if (this.name && this.name.indexOf(LIB_NAME) !== -1) {
            var mod = Process.findModuleByName(LIB_NAME);
            if (mod) {
                console.log("[+] " + LIB_NAME + " at " + mod.base);
                try {
                    var NOP = [0x1f, 0x20, 0x03, 0xd5]; // ARM64 NOP
                    Memory.protect(mod.base.add(SVC_OFFSET), 4, 'rwx');
                    Memory.writeByteArray(mod.base.add(SVC_OFFSET), NOP);
                    console.log("[+] Patched inline SVC at +0x" + SVC_OFFSET.toString(16));
                } catch(e) {
                    console.log("[-] SVC patch failed: " + e);
                }
            }
        }
    }
});

// === 5. JAVA SAFETY ===
Java.perform(function() {
    try { Java.use("java.lang.System").exit.implementation = function(c) {}; } catch(e) {}
    try { Java.use("android.os.Process").killProcess.implementation = function(p) {}; } catch(e) {}
});

console.log("[+] AppFence bypass loaded");
console.log("[*] Usage: frida -U -f <package> -l appfence-bypass-v24.js");
