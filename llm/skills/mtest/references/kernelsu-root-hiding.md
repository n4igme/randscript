# KernelSU Root Hiding via Frida

## When to Use

App detects root via KernelSU artifacts visible in `/proc/self/mounts`, filesystem checks for `su` binary, or `/data/adb` module mounts. Common with Eversafe SDK (`EversafeService.MGCheck` reads `/proc/self/mounts` via Java I/O).

## Detection Vectors (KernelSU-specific)

```
/proc/self/mounts:
  KSU /system overlay ro,seclabel,noatime,lowerdir=/data/adb/modules/...
  /dev/block/loop0 /data/adb/modules ext4 rw,...

Filesystem:
  /system/bin/su (exists, 352KB)
  /data/adb/ksu (directory)
  /data/adb/ksud (binary)

Note: KSU has NO DenyList (unlike Magisk). No built-in per-app mount namespace hiding.
ksud profile commands exist but don't offer unmount/hide functionality.
```

## Java-Level Hooks (catches EversafeService.MGCheck + most root detectors)

```javascript
Java.perform(function() {
    // Filter /proc/self/mounts reads via BufferedReader
    var BufferedReader = Java.use("java.io.BufferedReader");
    BufferedReader.readLine.overload().implementation = function() {
        var line = this.readLine();
        if (line !== null) {
            var s = line.toString();
            if (s.indexOf("KSU") !== -1 || s.indexOf("/data/adb/modules") !== -1 ||
                s.indexOf("magisk") !== -1 || s.indexOf("kernelsu") !== -1) {
                return this.readLine(); // skip line
            }
        }
        return line;
    };

    // Hide su/ksu binaries from File.exists()
    // IMPORTANT: Save reference BEFORE overriding to avoid infinite recursion.
    // `this.exists.call(this)` re-enters the hook → stack overflow.
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

    // Block Runtime.exec for su checks
    var RuntimeCls = Java.use("java.lang.Runtime");
    RuntimeCls.exec.overload("[Ljava.lang.String;").implementation = function(cmds) {
        if (cmds !== null && cmds.length > 0) {
            var joined = "";
            for (var i = 0; i < cmds.length; i++) joined += cmds[i] + " ";
            if (joined.indexOf("su") !== -1) {
                throw Java.use("java.io.IOException").$new("not found");
            }
        }
        return this.exec(cmds);
    };
});
```

## Native-Level Hooks (catches libeversafe.so Java-layer I/O and NDK checks)

Note: These catch Java FileInputStream → libc path, NOT raw `svc #0` syscalls.
Eversafe MGCheck uses Java BufferedReader (caught above), but some checks go through libc.

```javascript
// Hide su from access() / stat()
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
        if (this.hide) retval.replace(-1); // ENOENT
    }
});

// Filter /proc/self/mounts at fgets level
var openPtr = Module.findExportByName("libc.so", "fopen");
var fgets = Module.findExportByName("libc.so", "fgets");
var mountsFd = {};

Interceptor.attach(openPtr, {
    onEnter: function(args) {
        var path = args[0].readUtf8String();
        if (path && (path === "/proc/self/mounts" || path === "/proc/mounts")) {
            this.isMounts = true;
        }
    },
    onLeave: function(retval) {
        if (this.isMounts && !retval.isNull()) {
            mountsFd[retval.toString()] = true;
        }
    }
});

Interceptor.attach(fgets, {
    onEnter: function(args) {
        this.buf = args[0];
        this.fp = args[2].toString();
    },
    onLeave: function(retval) {
        if (mountsFd[this.fp] && !retval.isNull()) {
            var line = this.buf.readUtf8String();
            if (line && (line.indexOf("KSU") !== -1 || line.indexOf("/data/adb") !== -1)) {
                this.buf.writeUtf8String("none /mnt/empty tmpfs rw 0 0\n");
            }
        }
    }
});
```

## Limitations

- **Raw syscall detection (`svc #0`):** If `libeversafe.so` reads mounts via direct syscalls (like it does for `/proc/net/tcp` in debugger detection), these hooks won't catch it. In practice, MGCheck (root) uses Java BufferedReader, while debugger detection uses raw syscalls.
- **KSU overlay in /proc/self/mountinfo:** Some detectors check `/proc/self/mountinfo` (more detail than `/proc/self/mounts`). Add the same filtering for that path.
- **Build.prop checks:** Some apps check `ro.build.tags=test-keys`. Not applicable to KSU (uses stock kernel).

## Combined Script Pattern

For apps with Eversafe + Flutter + KSU, use a single combined script:
1. Eversafe Handler msg 84/100 suppress + exit blocks
2. Root hiding (Java + native)
3. Connect redirect (Flutter ignores system proxy)
4. SSL bypass (BoringSSL pattern hook, return 1)

See `templates/flutter_eversafe_full_bypass.js` for ready-to-use template.

## Verification

After loading the script, verify from another terminal:
```bash
# Check if app can see su
adb shell "run-as <package> cat /proc/self/mounts" | grep -i ksu
# Should return nothing if hooks are active

# Or check via Frida console:
# Java.use("java.io.File").$new("/system/bin/su").exists() → should return false
```
