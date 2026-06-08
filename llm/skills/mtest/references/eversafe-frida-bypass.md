# Eversafe (Everspin) Frida Detection Bypass

## Detection Architecture (Deep Dive)

### Threat Bitmask System

`EversafeThreat.createThreats(int scanResult, int policy)` controls whether an alert fires. BOTH conditions must be true:

```java
(scanResult & 0x80) == 128   // libeversafe.so detected a debugger (native scan)
(policy & 0x80) == 128       // EversafeConfig says "enforce DEBUGGER check"
```

**Bitmask flags** (from `EversafeThreat.java`):
| Flag | Hex | Check |
|------|-----|-------|
| OS (root) | 0x0F | Rooted device |
| WIFI | 0x10 | Unsafe WiFi |
| USB | 0x20 | USB connected |
| ADB | 0x40 | ADB enabled |
| DEBUGGER | 0x80 | Debugger/Frida detected |
| APP | 0x100 | Malicious app found |
| C_ROM | 0x200 | Custom ROM |
| PROXY | 0x400 | Proxy detected |
| EMULATOR | 0x1800 | Emulator detected |

**Policy source** — `EversafeConfig` enum (set at SDK init, NOT downloaded):
```java
DEBUG("debug", true),        // → 0x80 ENFORCED (Jago PROD)
OS_FORGERY("osForgery", true), // → 0x0F ENFORCED
ADB("adb", false),           // → 0x40 NOT enforced
PROXY("proxy", true),        // → 0x400 ENFORCED
EMULATE("emulator", false),  // → 0x1800 NOT enforced
```

**Two bypass angles:**
1. **Scan side**: Make `scanResult` not have 0x80 (hide from native detection)
2. **Policy side**: Make `policy` not have 0x80 (hook EversafeConfig to return false for DEBUG)

### Full Detection → Alert Chain

```
libeversafe.so (native, in-app process, raw svc #0 syscalls)
  ↓ reads /proc/net/tcp directly via kernel (bypasses libc)
  ↓ finds listening port → sets DEBUGGER bit (0x80) in scanResult
  ↓ sends Android Message (msg.what = 84 = MESSAGE_THREATS_FOUND)
  ↓
EversafeHandler.handleMessage()
  ↓ case 84: eversafeContext.threatsFound((String)msg.obj)
  ↓ msg.obj = JSON: [{"code":"DEBUGGER","localized_description":"local_detected"}]
  ↓
EversafeSubscriber.onEversafeThreatFound(ArrayList<EversafeThreat>)
  ↓
Flutter Plugin (Java) → MethodChannel/EventChannel → Dart
  ↓
Dart renders full-screen "Debugger alert" widget (NOT native AlertDialog)
```

### Why libc Hooks Fail

`libeversafe.so` uses **inline `svc #0` assembly** (direct ARM64 syscalls) to read `/proc/net/tcp`:
```asm
mov x8, #56    ; __NR_openat
svc #0
mov x8, #63    ; __NR_read
svc #0
```
Frida `Interceptor.attach` on libc `open`/`openat`/`read`/`connect` NEVER fires because libc is bypassed entirely. Confirmed: hooks installed, zero hits during Eversafe scan.

### What libeversafe.so Scans For

Primary: reads `/proc/net/tcp` and finds ANY unusual TCP LISTEN port on 127.0.0.1 or 0.0.0.0. Not just port 27042 — ANY port triggers further probing (D-Bus AUTH handshake pattern match).

### Detection is Purely Local

- Alert appears immediately, before any API response
- Blocking bindService to EversafeService → alert still shows (sometimes)
- Traffic logs show API calls succeeding — server isn't rejecting
- When native lib blocked from loading → app crashes (no alert) = lib is the source
- No server-side verification for the DEBUGGER flag

## Thread-Based Detection (First Vector ~10s)

Eversafe scans `/proc/self/task/*/comm` on a ~10-second cycle looking for known Frida thread names:

| Frida Thread | Purpose |
|---|---|
| `gmain` | GLib main event loop |
| `gdbus` | GLib D-Bus communication |
| `gum-js-loop` | Frida Gum JavaScript engine |
| `pool-ggbond` | Frida internal thread pool |
| `linjector` | Frida injector (sometimes present) |

When any are found, Eversafe kills the app process (signal 9).

## Bypass: Thread Renaming

Rename Frida threads to innocent Android names by writing to `/proc/<pid>/task/<tid>/comm`:

```javascript
// anti_eversafe.js — Load BEFORE device.resume() and again 3s after
(function() {
    var fopen = new NativeFunction(Module.findExportByName(null, 'fopen'), 'pointer', ['pointer', 'pointer']);
    var fputs = new NativeFunction(Module.findExportByName(null, 'fputs'), 'int', ['pointer', 'pointer']);
    var fgets = new NativeFunction(Module.findExportByName(null, 'fgets'), 'pointer', ['pointer', 'int', 'pointer']);
    var fclose = new NativeFunction(Module.findExportByName(null, 'fclose'), 'int', ['pointer']);
    var opendir = new NativeFunction(Module.findExportByName(null, 'opendir'), 'pointer', ['pointer']);
    var readdir = new NativeFunction(Module.findExportByName(null, 'readdir'), 'pointer', ['pointer']);
    var closedir = new NativeFunction(Module.findExportByName(null, 'closedir'), 'int', ['pointer']);

    var renames = {
        'gmain': 'Binder:main',
        'gdbus': 'Binder:dbus',
        'gum-js-loop': 'Chrome_IOThread',
        'pool-ggbond': 'pool-3-thread-1',
        'linjector': 'AsyncTask #1'
    };

    var pid = Process.id;
    var taskDir = '/proc/' + pid + '/task';
    var dir = opendir(Memory.allocUtf8String(taskDir));
    if (!dir.isNull()) {
        var entry;
        while (!(entry = readdir(dir)).isNull()) {
            var tidStr = entry.add(19).readCString();
            if (tidStr === '.' || tidStr === '..') continue;
            var commPath = '/proc/' + pid + '/task/' + tidStr + '/comm';
            var f = fopen(Memory.allocUtf8String(commPath), Memory.allocUtf8String('r'));
            if (!f.isNull()) {
                var buf = Memory.alloc(256);
                var r = fgets(buf, 256, f);
                if (!r.isNull()) {
                    var tname = buf.readCString().trim();
                    if (renames[tname]) {
                        fclose(f);
                        var wf = fopen(Memory.allocUtf8String(commPath), Memory.allocUtf8String('w'));
                        if (!wf.isNull()) {
                            fputs(Memory.allocUtf8String(renames[tname]), wf);
                            fclose(wf);
                        }
                        continue;
                    }
                }
                fclose(f);
            }
        }
        closedir(dir);
    }
})();
```

## Python Launcher Pattern

```python
import frida, time

device = frida.get_usb_device()
pid = device.spawn(['com.example.app'])
session = device.attach(pid)

# Load anti-eversafe BEFORE resume
with open('anti_eversafe.js') as f:
    s0 = session.create_script(f.read())
    s0.on('message', lambda m,d: None)
    s0.load()

device.resume(pid)
time.sleep(3)

# Rename again (new threads spawn after resume)
with open('anti_eversafe.js') as f:
    s0b = session.create_script(f.read())
    s0b.on('message', lambda m,d: None)
    s0b.load()

# Now load other bypasses (SSL, root, etc.)
# App will survive indefinitely
time.sleep(600)
session.detach()
```

## Timing

- Load anti_eversafe.js BEFORE `device.resume()`
- Load again 3s AFTER resume (Frida spawns additional threads on resume)
- Eversafe's first scan is ~10s after app start
- If threads are renamed before that scan, app survives indefinitely

## Proof (Jago App, June 2026)

- Without bypass: app killed at ~10s consistently
- With thread rename: survived 68s+ (full test duration), confirmed alive at every 5s check
- Earlier 10-minute session also survived (proc_424a680bfb65, exit code 0)

## Architecture (Confirmed June 2026, Jago App v8.86.0)

Eversafe uses a multi-process, multi-layer detection architecture:

| Component | Location | Size | Role |
|---|---|---|---|
| `libeversafe.so` | Main app process | 405KB | Core library, loaded after resume |
| `.eversafe_basic_*_x2.so` | Main app process (unpacked from cache) | 1.8MB | Unpacked detection engine |
| `EversafeService` | Separate process (u0_i*) | — | External monitor, reads /proc/<pid>/* |
| `libcodemix-env.so` + `cdmx*.so` | Main app process | 36KB + 57KB | CodeMix environment checks |
| `libeversafe-loader.so` | APK native libs | — | Loader stub |

**Key insight:** `libeversafe.so` uses 54 inline SVC #0 instructions (all calling mmap syscall 222) to unpack detection code into RWX memory at runtime. Static analysis of the .so reveals no detection strings — they're encrypted and unpacked.

## Detection Timeline (Two Phases)

| Time | Vector | Source | Bypassable? |
|---|---|---|---|
| ~10s | Thread name scan `/proc/self/task/*/comm` | In-process (first scan) | ✅ Thread rename |
| ~50-60s | External `/proc/<pid>/net/tcp` scan for port 27042 | EversafeService process | ✅ Custom port (not 27042) + renamed binary (see Option A) |

The second detection comes from the **EversafeService** (separate process, isolated UID u0_i*) reading the main app's `/proc/<pid>/net/tcp` externally. It finds port 27042 (0x69A2) — hluda/frida-server's listening socket. This cannot be hidden from userspace without kernel-level /proc hardening.

**Evidence:** hluda-server already hides frida-agent from `/proc/self/maps` (confirmed: 0 suspicious entries found via Frida memory scan). The maps are clean. But `/proc/<pid>/net/tcp` still shows port 27042 LISTENING, which is readable by any process with the same GID or root (hidepid=2 is already set but gid=3009 exception group bypasses it).

**Port 27042 cannot be moved for USB transport:** Starting hluda with `-l 127.0.0.1:31337` changes the TCP listener but breaks Frida's USB transport (spawn fails with "need Gadget"). The USB protocol requires the default port internally. Blocking port 27042 via iptables also doesn't help — the service reads `/proc/net/tcp` as a file, not by connecting.

**Network connectivity affects kill timing:**
- Service CAN phone home (iptables OFF): kills at ~20s (faster backend verification)
- Service CANNOT phone home (iptables ON): kills at ~53s (falls back to local scan only)

## What Does NOT Work for Second Detection

| Approach | Result |
|---|---|
| Patching SVC in libeversafe.so | SVCs are for mmap (unpacking), not detection reads |
| Blocking `.eversafe_basic_*.so` via dlopen hook | App dies slightly earlier (triggers load-failure detection) |
| Killing EversafeService | Respawns immediately, kill doesn't prevent the scan |
| Disabling EversafeService via `pm disable` | App dies FASTER (~20s) — failsafe triggers when service missing |
| NOP'ing SVCs after load | Pattern scan finds 0 matches (code already unpacked/relocated) |
| Hooking kill/tgkill in EversafeService | Attaching Frida to service triggers its OWN anti-Frida, kills app faster (~20s) |
| Starting hluda on port 31337 (`-l` flag) via USB transport | Breaks USB transport — Frida can't spawn ("need Gadget"). FIX: use TCP transport via `add_remote_device()` + `adb forward` instead (see Option A above) |
| iptables blocking port 27042 from isolated UIDs | No effect — service reads /proc/net/tcp as file, doesn't connect |
| Hooking read() in app to filter /proc/net/tcp content | No effect — service reads from its OWN process context, not app's |
| Clearing Eversafe cache files | No effect on detection timing |
| Hooking libc open/openat/read/connect in app process | No effect — libeversafe.so uses raw `svc #0` inline syscalls, bypasses libc entirely |
| Blocking libeversafe.so from loading (dlopen/System.loadLibrary hook) | App CRASHES — depends on the native lib for startup |
| Blocking bindService to EversafeService (when login needed) | Alert suppressed BUT login fails — backend requires `x-eversafe-token` from the service session. "Sorry, can't log you in" error. Only use bindService block for pre-auth testing. |
| `pm disable` on EversafeService component | Unreliable — service re-enables itself, and when disabled the app sometimes triggers a faster failsafe kill |
| hluda Unix socket (`-l unix:/path`) | Version-dependent — older hluda builds silently ignore the flag and don't bind. Verify with `cat /proc/net/unix | grep <path>` after start. |
| Renaming frida-server + custom port (stock, not hluda) | Still detected — Eversafe probes D-Bus AUTH pattern + scans for LIBFRIDA in memory |
| Java AlertDialog.setMessage hook | Alert is Flutter widget, not native dialog — hook never fires |
| Hooking EversafeThreat.createThreats / IEversafeAIDLService$Stub$Proxy | ClassNotFoundException — these classes in service process classloader, not main app |
| bindService block alone (without hiding TCP port) | Unreliable — native lib does its own in-process scan independent of service |
| Using hluda on ANY TCP port | Still shows in /proc/net/tcp — native raw syscall finds it |

## Limitations

- Thread rename alone extends survival from 10s → 53s (5x improvement) but NOT indefinite
- The ~60s kill from external /proc/net/tcp scan looks for port 27042 specifically — fully bypassed by running on a custom port with renamed binary (Option A)
- On kernel 4.4 (too old for Zygisk), Shamiko/Zygisk approach won't work — use Option A (renamed binary + custom port + TCP transport) instead
- For USB transport specifically, custom port DOES break spawn — must use TCP transport via `add_remote_device()` + `adb forward`
- Thread names must be re-applied if Frida creates new threads mid-session (rare after initial load)
- When Eversafe service can phone home (no iptables blocking), kill happens at ~20s instead of ~53s (thread-rename-only scenario)
- Blocking service network via iptables extends thread-rename window to 53s (service falls back to slower local-only scan)

## Option A++ : Handler.dispatchMessage msg=84 Suppression (MOST RELIABLE)

**This is the proven working bypass for Jago PROD v8.86.0 (June 2026).** It intercepts the DEBUGGER threat at the Android Handler level — AFTER the native scan completes but BEFORE the message reaches Flutter. This works regardless of how the native lib detects (raw syscalls, port probing, etc.) because we catch the result at the Java framework layer.

**Why this is the best approach:**
- Native `libeversafe.so` uses raw `svc #0` syscalls → libc hooks useless
- EversafeThreat classes in service classloader → Java.use() fails with ClassNotFoundException
- Blocking the lib from loading → app crashes
- Unix socket may not be supported by all hluda builds
- bindService block alone is UNRELIABLE (sometimes alert still fires from in-process scan)
- Handler hook catches ALL detection paths (service AIDL + in-process native) at a single choke point

**How it works:**
```
libeversafe.so (raw syscalls, finds port in /proc/net/tcp)
  → sets scanResult |= 0x80
  → sends Message(what=84, obj=JSON threat array) to EversafeHandler
  → WE INTERCEPT HERE ← Handler.dispatchMessage suppresses msg.what=84
  → Flutter NEVER receives the threat → no alert rendered
```

**Bypass script (proven working — full version with exit blocking):**
```javascript
Java.perform(function() {
    // Suppress MESSAGE_THREATS_FOUND (msg.what=84) + MESSAGE_SYSTEM_EXIT (msg.what=100)
    var Handler = Java.use("android.os.Handler");
    Handler.dispatchMessage.implementation = function(msg) {
        if (msg.what.value === 84) {
            console.log("[Eversafe] SUPPRESSED msg 84 (THREATS_FOUND)");
            return;
        }
        if (msg.what.value === 100) {
            console.log("[Eversafe] SUPPRESSED msg 100 (SYSTEM_EXIT)");
            return;
        }
        return this.dispatchMessage(msg);
    };

    // Block all exit paths
    var System = Java.use("java.lang.System");
    System.exit.implementation = function(code) {
        console.log("[Eversafe] BLOCKED System.exit(" + code + ")");
    };
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exit.implementation = function(code) {
        console.log("[Eversafe] BLOCKED Runtime.exit(" + code + ")");
    };
    var Process = Java.use("android.os.Process");
    Process.killProcess.implementation = function(pid) {
        console.log("[Eversafe] BLOCKED killProcess(" + pid + ")");
    };

    // Hide ADB/dev mode
    var Settings = Java.use("android.provider.Settings$Global");
    Settings.getInt.overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function(cr, name, def) {
        if (name === "adb_enabled" || name === "development_settings_enabled") return 0;
        return this.getInt(cr, name, def);
    };
    Settings.getInt.overload("android.content.ContentResolver", "java.lang.String").implementation = function(cr, name) {
        if (name === "adb_enabled" || name === "development_settings_enabled") return 0;
        return this.getInt(cr, name);
    };
});
```

**NOTE on bindService:** Do NOT include a bindService block if you need login to work. The Eversafe session token is generated via the AIDL service. If you block it, the backend rejects auth requests. The Handler msg 84+100 suppression alone is sufficient — it lets the SDK session work while suppressing the UI alert and kill signals.

**Confirmed output when working:**
```
[Eversafe] SUPPRESSED Handler msg 84 (THREATS_FOUND): [{
  "code": "DEBUGGER",
  "relevant_items": [],
  "localized_description": "The app is threatened and can not be launched."
}]
```

**Requirements:**
- Must use hluda (not stock frida-server) — stock still gets killed by memory/D-Bus signature checks
- Eversafe bypass script must load BEFORE `device.resume()` so Handler hook is active before native lib starts scanning
- Works with hluda on ANY TCP port (38291, etc.) — the port still shows in /proc/net/tcp but the alert is suppressed at message level
- Combined with traffic capture hooks (connect redirect + SSL bypass) in same session
- Must also suppress msg.what=100 (MESSAGE_SYSTEM_EXIT) and block System.exit/Runtime.exit/Process.killProcess — Eversafe calls these after detection
- **CRITICAL: Do NOT block bindService to EversafeService if you need authenticated login.** The Eversafe session generates an `x-eversafe-token` required by the backend for auth. Blocking bindService → "Sorry, can't log you in" error. Instead, let the service run and ONLY suppress msg 84+100 at the Handler level.

**Full working chain (Jago PROD v8.86.0):**
1. hluda-server on :38291 (127.0.0.1) — no frida signatures in memory
2. `adb forward tcp:38291 tcp:38291` + `adb reverse tcp:8443 tcp:8443`
3. Spawn app, load eversafe_bypass.js (Handler hook) BEFORE resume
4. Load jago_traffic_capture.js (SSL + connect redirect)
5. Resume → native scan fires, msg 84 suppressed → no alert → app runs normally
6. FLAG_SECURE active on app screens (screenshots are black = app loaded correctly past alert)

**Important: bindService block alone is UNRELIABLE:**
In testing (June 2026), blocking bindService sometimes worked and sometimes didn't. The native lib `libeversafe.so` does its OWN in-process detection scan (via raw syscalls) independent of the AIDL service. The Handler hook catches BOTH paths (service result AND in-process scan result) because both ultimately deliver msg.what=84 to the same Handler.

---

## Option A+ : bindService Block (Partial — use as supplement only)

When Eversafe detection produces a **Flutter-rendered full-screen "Debugger alert"** (not a native AlertDialog), blocking the AIDL service connection can SOMETIMES prevent the alert. However, this is unreliable alone because `libeversafe.so` also scans in-process. **Always combine with Handler msg 84 suppression (Option A++) above.**

**Why native AlertDialog hooks fail:** The alert is a Flutter widget rendered by Dart code on the Flutter surface. Java-side `AlertDialog$Builder` hooks have zero effect.

**Why EversafeThreat/AIDL class hooks fail:** These classes (`kr.co.everspin.eversafe.EversafeThreat`, `IEversafeAIDLService$Stub$Proxy`) are loaded in the **service process classloader** (UID u0_i*), NOT the main app's classloader. `Java.use()` throws `ClassNotFoundException` in the main process.

**Detection result flow:**
```
EversafeService (separate process, AIDL)
  → subscriber.impl.a (main app, Java)
    → Flutter MethodChannel
      → Dart code renders full-screen alert widget
```

**Bypass script (add to your Frida script):**
```javascript
Java.perform(function() {
    var ContextWrapper = Java.use("android.content.ContextWrapper");
    ContextWrapper.bindService.overload("android.content.Intent", "android.content.ServiceConnection", "int").implementation = function(intent, conn, flags) {
        var component = intent.getComponent();
        var compStr = component ? component.toString() : "";
        if (compStr.indexOf("eversafe") !== -1 || compStr.indexOf("everspin") !== -1 ||
            compStr.indexOf("EversafeService") !== -1) {
            console.log("[Eversafe] BLOCKED bindService to: " + compStr);
            return false;
        }
        return this.bindService(intent, conn, flags);
    };
    // Also suppress ADB/dev mode detection
    var Settings = Java.use("android.provider.Settings$Global");
    Settings.getInt.overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function(cr, name, def) {
        if (name === "adb_enabled" || name === "development_settings_enabled") return 0;
        return this.getInt(cr, name, def);
    };
    Settings.getInt.overload("android.content.ContentResolver", "java.lang.String").implementation = function(cr, name) {
        if (name === "adb_enabled" || name === "development_settings_enabled") return 0;
        return this.getInt(cr, name);
    };
});
```

**Confirmed:** Jago PROD v8.86.0, June 2026. Combined with hluda on :38291 + SSL bypass + connect() redirect, app bypasses alert completely and reaches account selection screen. No thread rename needed.

**Combine with Option A (hluda + custom port) for full chain:**
1. hluda-server on non-standard port (evades process/port detection)
2. bindService block (prevents alert UI from rendering)
3. Settings.Global spoof (hides ADB/dev mode)
4. Result: indefinite instrumentation with no alerts

---

## Practical Setup for Pentest

**DECISION ORDER (follow this, don't skip):**
1. Check if hluda is already on device: `ls /data/local/tmp/hluda*`
2. If yes → Option A0 (Unix socket) first, fall back to Option A (TCP custom port) if Unix socket unsupported
3. If no → download hluda matching your Frida version (github.com/Exo1i/MagiskHluda)
4. NEVER waste time renaming stock frida-server — Eversafe probes D-Bus AUTH + scans LIBFRIDA in memory, renamed stock STILL triggers detection
5. Always combine with policy hook (EversafeConfig DEBUG=false) as insurance

**ADB forward/reverse pitfall:** When ADB server restarts (kill-server, USB reconnect, device sleep), ALL forwards are lost. Re-establish before reconnecting Frida:
```bash
adb -s <serial> forward tcp:38291 tcp:38291   # hluda port
adb -s <serial> reverse tcp:8443 tcp:8443     # proxy port (if using traffic capture)
```

**Option A0: hluda-server + Unix Domain Socket (BEST — invisible to /proc/net/tcp)**

This is the strongest approach. Unix sockets don't appear in `/proc/net/tcp` at all — only in `/proc/net/unix` which Eversafe doesn't scan. Combined with policy hook, this eliminates both detection vectors.

```bash
# On device:
su -c 'kill $(ps -A | grep hluda | awk "{print \$2}") 2>/dev/null'
su -c 'rm -f /data/local/tmp/.es_sock'
su -c 'nohup /data/local/tmp/hluda-server -l unix:/data/local/tmp/.es_sock &'

# On host:
adb -s <serial> forward tcp:38291 localfilesystem:/data/local/tmp/.es_sock
```

Then connect via TCP transport as usual:
```python
device = frida.get_device_manager().add_remote_device('127.0.0.1:38291')
```

**Why this works:**
- `/proc/net/tcp` shows ZERO listening ports from hluda
- Eversafe's raw syscall reads of `/proc/net/tcp` find nothing
- No port probe possible (nothing to connect to from localhost)
- `(scanResult & 0x80)` stays 0 → DEBUGGER alert never fires
- Even without policy hook, the scan side is clean

**Combine with policy hook (belt + suspenders):**
- Hook `EversafeConfig.DEBUG` to return false → `policy & 0x80 == 0`
- Even if somehow detected, alert is suppressed at createThreats()

**Option A: hluda-server + Custom Port + TCP Transport (SIMPLEST — fully persistent, no extra tools)**
- Use `hluda-server` (patched Frida with stripped signatures), NOT stock frida-server
- Push to device: `/data/local/tmp/hluda-server` (chmod 755)
- Delete stock frida-server: `rm /data/local/tmp/frida-server` (Eversafe scans filenames)
- Start on non-standard port: `/data/local/tmp/hluda-server -l 0.0.0.0:38291`
- Use `adb forward tcp:38291 tcp:38291` to bridge to host
- Connect via TCP transport (NOT USB): `frida.get_device_manager().add_remote_device('127.0.0.1:38291')`
- Spawn works normally: `device.spawn(['com.jago.digitalBanking'])`
- No thread rename needed, no time limit, no Shamiko/Zygisk required
- Confirmed: Jago v8.86.0 PROD, June 2026. App survived indefinitely with 4 SSL hooks + connect() redirect active. No debugger alert.
- Why hluda not just renamed stock: Renaming stock frida-server + custom port evades filename + port checks, BUT Eversafe also probes listening sockets with D-Bus AUTH handshake and scans memory for `LIBFRIDA` strings. Stock frida (even renamed) fails these checks → "debugger alert" persists. hluda patches out all signatures.
- CRITICAL: must use `add_remote_device()` (TCP transport), NOT `get_usb_device()`. USB transport requires port 27042 internally and WILL break with custom port.
- hluda sources: github.com/Exo1i/MagiskHluda (Magisk module, latest versions), github.com/aspect-404/hluda-server (standalone binary)
- Version matching: hluda version should roughly match host Frida version (same major). Minor mismatches usually work.

**Option B: Magisk + Shamiko (fully persistent, requires Zygisk)**
- If device has Magisk with Shamiko/Zygisk hiding enabled, Eversafe detection is completely neutralized
- Frida spawns and attaches indefinitely without ANY bypass scripts
- Shamiko hides frida-server from /proc/net/tcp AND renames threads at kernel level
- This approach requires Zygisk-compatible kernel (5.x+); older kernels (4.4) may not support it

**Option B: Without Shamiko (53s window)**
1. Block Eversafe service network: `iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner <app_uid> --dport 443 -j REDIRECT --to-port 12345`
2. Load anti_eversafe.js BEFORE resume
3. Load again 3s after resume
4. Load target hooks (SSL bypass, function hooks, etc.)
5. Execute one-shot operations within 45s safety margin

**Option C: Persistent traffic interception without Frida**
- Use HTTP Toolkit (VPN-based, handles SSL bypass without Frida)
- No Eversafe detection since no Frida process instrumentation involved

## Reporting

Severity: High (internal pentest) / Medium (bug bounty, requires rooted device)

The finding is that Eversafe's anti-tampering relies on a single easily-bypassed detection vector (thread names), allowing persistent runtime instrumentation.
