// Flutter + Eversafe Full Bypass (use WITH reFlutter-patched libflutter.so)
// reFlutter handles SSL verify disable; this script handles:
//   1. Eversafe debugger alert suppression (Handler msg 84/100)
//   2. Process termination blocking (System.exit, Runtime.exit, killProcess)
//   3. Connect() redirect to Burp invisible proxy
//   4. Root hiding (Java + native level)
//
// Usage: Load with frida -f or spawn via Python API
// Requires: hluda-server (anti-detection frida), adb reverse tcp:8443 tcp:8443

// === EVERSAFE BYPASS ===
Java.perform(function() {
    var Handler = Java.use("android.os.Handler");
    Handler.dispatchMessage.implementation = function(msg) {
        if (msg.what.value === 84 || msg.what.value === 100) return;
        this.dispatchMessage(msg);
    };
    var System = Java.use("java.lang.System");
    System.exit.implementation = function(c) {};
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exit.implementation = function(c) {};
    var Process2 = Java.use("android.os.Process");
    Process2.killProcess.implementation = function(p) {};

    // Root hiding: filter /proc/self/mounts reads
    var BufferedReader = Java.use("java.io.BufferedReader");
    BufferedReader.readLine.overload().implementation = function() {
        var line = this.readLine();
        if (line !== null) {
            var s = line.toString();
            if (s.indexOf("KSU") !== -1 || s.indexOf("/data/adb/modules") !== -1 ||
                s.indexOf("magisk") !== -1 || s.indexOf("kernelsu") !== -1) {
                return this.readLine();
            }
        }
        return line;
    };

    // Root hiding: File.exists for su paths
    var File = Java.use("java.io.File");
    var rootPaths = ["/system/bin/su", "/system/xbin/su", "/sbin/su",
                     "/data/local/bin/su", "/data/local/su", "/su/bin/su",
                     "/data/adb/ksu", "/data/adb/ksud"];
    var origExists = File.exists;
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        for (var i = 0; i < rootPaths.length; i++) {
            if (path === rootPaths[i]) return false;
        }
        return origExists.call(this);
    };

    send("[+] Eversafe bypass + root hiding active");
});

// === NATIVE ROOT HIDING ===
var access = Module.findExportByName("libc.so", "access");
Interceptor.attach(access, {
    onEnter: function(args) {
        var path = args[0].readUtf8String();
        if (path && (path.indexOf("/su") !== -1 || path.indexOf("ksu") !== -1 ||
                     path.indexOf("magisk") !== -1)) {
            this.hide = true;
        }
    },
    onLeave: function(retval) {
        if (this.hide) retval.replace(-1);
    }
});
send("[+] Native root hiding active");

// === CONNECT REDIRECT ===
// UPDATE THESE IPs for your target (resolve via: dig +short api.target.com)
var TARGET_IPS = ["172.64.148.24", "104.18.39.232", "104.18.38.232"];
var PROXY_PORT_HI = 0x20; // 8443 >> 8
var PROXY_PORT_LO = 0xFB; // 8443 & 0xFF
Interceptor.attach(Module.findExportByName("libc.so", "connect"), {
    onEnter: function(args) {
        if (args[1].readU16() === 2) { // AF_INET
            var port = (args[1].add(2).readU8() << 8) | args[1].add(3).readU8();
            if (port === 443) {
                var ip = args[1].add(4).readU8() + "." + args[1].add(5).readU8() + "." +
                         args[1].add(6).readU8() + "." + args[1].add(7).readU8();
                if (TARGET_IPS.indexOf(ip) !== -1) {
                    args[1].add(2).writeU8(PROXY_PORT_HI);
                    args[1].add(3).writeU8(PROXY_PORT_LO);
                    args[1].add(4).writeU8(127);
                    args[1].add(5).writeU8(0);
                    args[1].add(6).writeU8(0);
                    args[1].add(7).writeU8(1);
                }
            }
        }
    }
});
send("[+] Connect redirect -> 127.0.0.1:8443");
