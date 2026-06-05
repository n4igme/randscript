# Frida Scripting Reference

Quick reference for Frida instrumentation across platforms.

## Setup

```bash
# Install
pip install frida-tools frida

# Check version
frida --version

# List devices
frida-ls-devices

# List processes
frida-ps -U          # USB device
frida-ps -H host:port  # remote
```

## Spawn vs Attach

```bash
# Attach to running process
frida -U -n "com.target.app" -l script.js

# Spawn (starts app fresh, hooks early)
frida -U -f com.target.app -l script.js --no-pause

# Python API (preferred for automation)
import frida
device = frida.get_usb_device()
pid = device.spawn(["com.target.app"])
session = device.attach(pid)
script = session.create_script(open("script.js").read())
script.load()
device.resume(pid)
```

## Core Patterns

### Hook Java Method (Android)

```javascript
Java.perform(function() {
    var cls = Java.use("com.target.ClassName");
    cls.methodName.implementation = function(arg1, arg2) {
        console.log("[*] methodName called: " + arg1 + ", " + arg2);
        var ret = this.methodName(arg1, arg2);
        console.log("[*] returns: " + ret);
        return ret;
    };
});
```

### Hook Overloaded Method

```javascript
Java.perform(function() {
    var cls = Java.use("com.target.ClassName");
    cls.method.overload("java.lang.String", "int").implementation = function(s, i) {
        return this.method(s, i);
    };
});
```

### Hook Native Function

```javascript
var targetFunc = Module.findExportByName("libtarget.so", "verify_signature");
Interceptor.attach(targetFunc, {
    onEnter: function(args) {
        console.log("[*] verify_signature called");
        console.log("  arg0: " + args[0]);
        console.log("  arg1: " + Memory.readUtf8String(args[1]));
    },
    onLeave: function(retval) {
        console.log("  returns: " + retval);
        retval.replace(0x1);  // force return true
    }
});
```

### Hook by Address Offset

```javascript
var base = Module.findBaseAddress("libtarget.so");
var offset = 0x1234;
Interceptor.attach(base.add(offset), {
    onEnter: function(args) {
        console.log("[*] hit offset " + offset.toString(16));
    }
});
```

### Replace Function Entirely

```javascript
var orig = Module.findExportByName("libtarget.so", "isRooted");
Interceptor.replace(orig, new NativeCallback(function() {
    console.log("[*] isRooted → returning 0");
    return 0;
}, 'int', []));
```

## SSL Pinning Bypass (Generic)

```javascript
// OkHttp3 CertificatePinner
Java.perform(function() {
    var CertPinner = Java.use("okhttp3.CertificatePinner");
    CertPinner.check.overload("java.lang.String", "java.util.List")
        .implementation = function(hostname, peerCerts) {
        console.log("[*] Bypassing pin for: " + hostname);
    };
});
```

## Root Detection Bypass (Generic)

```javascript
Java.perform(function() {
    // Common root checks
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
        if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
            console.log("[*] Blocked exec: " + cmd);
            throw Java.use("java.io.IOException").$new("blocked");
        }
        return this.exec(cmd);
    };

    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var blocked = ["/system/app/Superuser", "/sbin/su", "/system/bin/su",
                       "/data/local/bin/su", "/su/bin/su", "/system/xbin/su"];
        if (blocked.indexOf(path) !== -1) {
            console.log("[*] File.exists blocked: " + path);
            return false;
        }
        return this.exists();
    };
});
```

## Enumerate Classes and Methods

```javascript
Java.perform(function() {
    // Find classes matching pattern
    Java.enumerateLoadedClasses({
        onMatch: function(name) {
            if (name.indexOf("com.target") !== -1) {
                console.log(name);
            }
        },
        onComplete: function() {}
    });

    // List methods of a class
    var cls = Java.use("com.target.ClassName");
    var methods = cls.class.getDeclaredMethods();
    methods.forEach(function(m) {
        console.log(m.getName());
    });
});
```

## Memory Operations

```javascript
// Read memory
var buf = Memory.readByteArray(ptr(0x12345678), 64);
console.log(hexdump(buf));

// Write memory
Memory.writeByteArray(ptr(0x12345678), [0x90, 0x90, 0x90, 0x90]);

// Scan memory for pattern
Memory.scan(base, size, "48 8B ?? ?? ?? 00 00", {
    onMatch: function(address, size) {
        console.log("Found at: " + address);
    },
    onComplete: function() {}
});
```

## Python API (Automation)

```python
import frida
import sys

def on_message(message, data):
    if message["type"] == "send":
        print(f"[*] {message['payload']}")
    elif message["type"] == "error":
        print(f"[!] {message['stack']}")

device = frida.get_usb_device()
pid = device.spawn(["com.target.app"])
session = device.attach(pid)

with open("hook.js") as f:
    script = session.create_script(f.read())

script.on("message", on_message)
script.load()
device.resume(pid)

# Keep alive
sys.stdin.read()
```

## Pitfalls

- Frida 16.x removed `--no-kill` and `--no-pause` flags — use Python API spawn+resume
- `Java.perform` must wrap ALL Java hooks — calls outside it silently fail
- `Module.findExportByName` returns null if lib not yet loaded — use `Module.load()` first or hook `dlopen`
- ARM64 function offsets need +1 for Thumb mode on 32-bit ARM (not ARM64)
- Anti-Frida: apps check `/proc/self/maps` for "frida" — rename frida-server binary
- Spawn mode is slower but catches early init hooks; attach misses constructors
- On rooted Android: `setenforce 0` if Frida can't inject (SELinux)
- Flutter apps: hooks on Dart code require `reFlutter` or pattern-based .so patching
