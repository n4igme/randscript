---
name: dexguard-native-re
version: 1.0.0
description: "DexGuard/AppFence native library reverse engineering and bypass methodology for libaf-android.so"
tags: [mobile, pentest, android, frida, reverse-engineering, dexguard, native]
trigger: "dexguard bypass, appfence bypass, libaf-android, native root detection, inline svc bypass"
---

# DexGuard/AppFence Native Library RE & Bypass

## Overview

Commercial Android protection by Guardsquare. The `libaf-android.so` library (~2MB) implements root/hook/tamper detection with a multi-layer kill chain. This skill covers systematic RE and bypass.

## Detection Architecture

```
JNI_OnLoad
  → RegisterNatives("com/<pkg>/f4/F4Initializer", 14 methods)
  → Java calls native detection method
    → Scans /proc/self/maps for non-whitelisted libraries
    → If suspicious mapping found:
      → FUN_kill_thread_spawner(): pthread_create(kill_thread, arg)
        → kill_thread(): usleep(N*1000000) → SVC #0 → dlsym kill chain
```

### Kill Chain (4 layers, in order)

| Layer | Mechanism | Bypasses libc hooks? |
|-------|-----------|---------------------|
| 1 | Inline `SVC #0` (exit_group) | YES — direct kernel call |
| 2 | `syscall(94, 0)` via libc wrapper | No |
| 3 | `kill(getpid(), SIGKILL)` via dlsym'd pointer | No |
| 4 | `_exit(0)` + `abort()` | No |

### Detection Vectors

- `/proc/self/maps` — scans for frida-agent, linjector, /data/local/tmp, rwxp+memfd, rwxp+deleted
- `/proc/self/status` — TracerPid check
- `/proc/net/tcp` — port 27042 (Frida default)
- File access checks — su, magisk, kernelsu paths
- Memory integrity — verifies own .text pages (detects on-disk patching)

## RE Methodology

### Step 1: Identify the detection library

```bash
# Pull native libs from device
adb shell "pm path <package>" | grep base
adb pull <path>/lib/arm64/

# Identify detection lib (usually 1-3MB, single JNI_OnLoad export)
readelf -s lib/arm64/libaf-android.so | grep -c FUNC
# Typically 1 export (JNI_OnLoad), everything else registered dynamically
```

### Step 2: Find inline SVC instructions

```python
# Search for SVC #0 (0xd4000001) at 4-byte aligned addresses
import struct
data = open('libaf-android.so', 'rb').read()
svc_bytes = struct.pack('<I', 0xd4000001)
for i in range(0, len(data) - 3, 4):
    if data[i:i+4] == svc_bytes:
        # Check preceding MOV X8/W8 for syscall number
        for j in range(max(0, i-32), i, 4):
            instr = struct.unpack('<I', data[j:j+4])[0]
            if (instr & 0xFFE0001F) == 0xd2800008:  # MOVZ X8, #imm
                imm = (instr >> 5) & 0xFFFF
                print(f"  0x{i:06x}: SVC #0 (X8={imm}={'exit_group' if imm==94 else imm})")
```

### Step 3: Map kill functions via BL targets

```python
# Find all BL to syscall/abort/_exit PLT entries
# First identify PLT addresses from imports, then find all callers
for i in range(0, len(data)-3, 4):
    instr = struct.unpack('<I', data[i:i+4])[0]
    if (instr & 0xFC000000) == 0x94000000:  # BL
        offset_val = instr & 0x03FFFFFF
        if offset_val & 0x02000000: offset_val -= 0x04000000
        target = i + (offset_val * 4)
        if target == SYSCALL_PLT:
            print(f"  0x{i:06x}: BL syscall")
```

### Step 4: Find function boundaries

```python
# ARM64 function prologue: STP X29, X30, [SP, #-N]!
for i in range(start, end, 4):
    instr = struct.unpack('<I', data[i:i+4])[0]
    if (instr & 0xFFC07FFF) == 0xa9807bfd:
        print(f"  Function at 0x{i:06x}")
```

### Step 5: Ghidra MCP analysis

```
# Ghidra adds 0x100000 to file offsets
# File offset 0xa9bd8 → Ghidra address 0x1a9bd8

# Key functions to decompile:
# - JNI_OnLoad (find via: search_functions_by_name("JNI_OnLoad"))
# - Kill thread (contains SVC)
# - Kill orchestrator (dlsym + syscall + kill + abort)
# - Thread spawner (pthread_create with kill thread)
# - Maps scanner (fopen + fgets loop with string comparisons)
```

### Step 6: Identify detection trigger from Java

From crash backtrace or Ghidra xrefs, find the Java class that calls native detection:
- Typically: `com/<pkg>/f4/F4Initializer` or similar obfuscated name
- Called during app initialization (coroutine/async)
- Native method registered via `RegisterNatives` in `JNI_OnLoad`

## Bypass Strategy (Ranked by Reliability)

### 1. /proc/self/maps filtering (PRIMARY)

The most effective defense — if detection doesn't see Frida, kill is never triggered.

```javascript
var fopenPtr = Module.findExportByName("libc.so", "fopen");
var fgetsPtr = Module.findExportByName("libc.so", "fgets");
var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
var mapsFiles = {};

Interceptor.attach(fopenPtr, {
    onEnter: function(args) {
        var path = args[0].readCString();
        this.isMaps = path && (path.indexOf("/proc/self/maps") !== -1 || 
                     path.indexOf("/proc/" + Process.id + "/maps") !== -1);
    },
    onLeave: function(retval) {
        if (this.isMaps && !retval.isNull()) mapsFiles[retval.toString()] = true;
    }
});

Interceptor.attach(fgetsPtr, {
    onEnter: function(args) {
        this.buf = args[0]; this.size = args[1].toInt32();
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
                var next = fgets(this.buf, this.size, this.stream);
                if (next.isNull()) retval.replace(ptr(0));
            }
        } catch(e) {}
    }
});
```

### 2. Kill thread neutralization

```javascript
Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"), {
    onEnter: function(args) {
        var startRoutine = args[2];
        var mod = Process.findModuleByAddress(startRoutine);
        if (mod && mod.name === "libaf-android.so") {
            var offset = startRoutine.sub(mod.base).toInt32();
            if (offset === KILL_THREAD_OFFSET) { // e.g., 0xa9b80
                // Sleep forever — keeps thread alive, prevents kill
                // WARNING: may cause ANR after ~10s (dismiss with "Wait")
                args[2] = new NativeCallback(function(arg) {
                    var ts = Memory.alloc(16);
                    ts.writeU64(0x7FFFFFFF); ts.add(8).writeU64(0);
                    var nanosleep = new NativeFunction(
                        Module.findExportByName("libc.so", "nanosleep"), 'int', ['pointer', 'pointer']);
                    nanosleep(ts, ptr(0));
                    return ptr(0);
                }, 'pointer', ['pointer']);
            }
        }
    }
});
```

### 3. Inline SVC patch (after library loads)

```javascript
Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
    onEnter: function(args) { this.name = args[0] ? args[0].readCString() : ""; },
    onLeave: function(retval) {
        if (this.name && this.name.indexOf("libaf-android") !== -1) {
            var mod = Process.findModuleByName("libaf-android.so");
            if (mod) {
                Memory.protect(mod.base.add(SVC_OFFSET), 4, 'rwx');
                Memory.writeByteArray(mod.base.add(SVC_OFFSET), [0x1f, 0x20, 0x03, 0xd5]); // NOP
            }
        }
    }
});
```

### 4. Libc safety nets

```javascript
// syscall redirect
Interceptor.attach(Module.findExportByName("libc.so", "syscall"), {
    onEnter: function(args) {
        var nr = args[0].toInt32();
        if (nr === 93 || nr === 94 || nr === 129 || nr === 131 || nr === 134)
            args[0] = ptr(39); // getpid
    }
});
// kill signal neutralize
Interceptor.attach(Module.findExportByName("libc.so", "kill"), {
    onEnter: function(args) {
        if (args[1].toInt32() === 9 || args[1].toInt32() === 6) args[1] = ptr(0);
    }
});
// abort/exit no-ops
Interceptor.replace(Module.findExportByName("libc.so", "abort"), new NativeCallback(function(){}, 'void', []));
Interceptor.replace(Module.findExportByName("libc.so", "_exit"), new NativeCallback(function(c){}, 'void', ['int']));
```

## Critical Pitfalls

1. **On-disk patching triggers integrity check** — the library reads its own .text pages and compares against expected values. Patching the .so file on disk causes SIGBUS crash. Only runtime patching works.

2. **`Interceptor.replace` writes trampolines** — these modify the function's first bytes, which the integrity checker detects. Use `Interceptor.attach` (breakpoint-based) or patch AFTER integrity check completes.

3. **`_exit` replacement with empty return** — causes undefined behavior. The calling thread continues executing past where `_exit` should have terminated. Can cause "Process terminated" in Frida. Use sleep-forever pattern instead.

4. **Kill thread return-immediately crashes** — the parent function (`pthread_create` caller) uses the thread's arg struct after the thread completes. If thread returns too fast, use-after-free occurs. Sleep-forever or long-sleep avoids this.

5. **ANR from sleep-forever** — Android shows "App Not Responding" after ~10s if a thread blocks. User can dismiss with "Wait". Acceptable for testing.

6. **Maps filter must be comprehensive** — detection checks for: `frida`, `gadget`, `linjector`, `/data/local/tmp`, `re.frida`, `gum-js-loop`, `frida-agent`, rwxp+memfd, rwxp+deleted. Missing any one triggers kill.

7. **Timing sensitivity** — maps filter must be active BEFORE detection reads /proc/self/maps. Hook fopen/fgets early (before library loads). The detection runs on a coroutine thread shortly after app init.

8. **Multiple detection passes** — the library scans maps repeatedly (observed 10+ fopen calls). Filter must work consistently, not just once.

## When to Stop

If 10+ bypass iterations fail:
- Submit static findings (code path evidence is sufficient for bug bounty)
- Document the detection mechanism and kill chain
- Note: "Dynamic validation blocked by DexGuard AppFence with inline SVC + integrity checks"
- The decompiled code showing unvalidated deep links → WebView → JS bridge is exploitable regardless of whether you can demonstrate it dynamically

## Ghidra Address Mapping

```
Ghidra address = file_offset + 0x100000 (default ELF base)
File offset 0xa9bd8 → Ghidra 0x1a9bd8
```

Always verify by checking known function signatures (JNI_OnLoad export address).
