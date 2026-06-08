# Eversafe Anti-Tamper Bypass (Flutter Apps)

## Architecture

```
libeversafe.so (native, raw syscalls)
  → scans /proc/net/tcp for listening ports (debugger detection)
  → returns int scanResult bitmask
  → sends Android Handler Message (msg.what=84, obj=JSON threats)

EversafeHandler.handleMessage()
  → case 84: eversafeContext.threatsFound(JSON)
  → subscriber.onEversafeThreatFound(ArrayList<EversafeThreat>)
  → Flutter MethodChannel/EventChannel → Dart renders alert
```

## Threat Bitmask (EversafeThreat.createThreats)

```java
(scanResult & flag) != 0 && (policy & flag) != 0  // BOTH must be set

OS/ROOT    = 0x0F (bits 1,2,4,8)
WIFI       = 0x10 (16)
USB        = 0x20 (32)
ADB        = 0x40 (64)
DEBUGGER   = 0x80 (128)  ← frida/hluda detection
APP        = 0x100 (256)
C_ROM      = 0x200 (512)
PROXY      = 0x400 (1024)
EMULATOR   = 0x1800 (2048+4096)
```

## Policy Source (EversafeConfig enum)

```java
DEBUG("debug", true),          // → 0x80 ENFORCED
OS_FORGERY("osForgery", true), // → 0x0F ENFORCED
ADB("adb", false),             // → 0x40 NOT enforced
PROXY("proxy", true),          // → 0x400 ENFORCED
EMULATE("emulator", false),    // → 0x1800 NOT enforced
```

## Why libc Hooks Fail

`libeversafe.so` uses inline ARM64 syscalls (`svc #0`) to read `/proc/net/tcp`:
```
mov x8, #56    ; __NR_openat
svc #0
mov x8, #63    ; __NR_read
svc #0
```
Interceptor.attach on libc `open`/`openat`/`read`/`connect` never fires.

## Working Bypass: Handler.dispatchMessage Intercept

```javascript
Java.perform(function() {
    // Suppress THREATS_FOUND + SYSTEM_EXIT
    var Handler = Java.use("android.os.Handler");
    Handler.dispatchMessage.implementation = function(msg) {
        if (msg.what.value === 84) return;  // THREATS_FOUND
        if (msg.what.value === 100) return; // SYSTEM_EXIT
        return this.dispatchMessage(msg);
    };

    // Block app termination
    Java.use("java.lang.System").exit.implementation = function(c) { return; };
    Java.use("java.lang.Runtime").exit.implementation = function(c) { return; };
    Java.use("android.os.Process").killProcess.implementation = function(p) { return; };
});
```

## Critical: Do NOT Block bindService

Blocking `bindService` to EversafeService kills the session token.
Backend requires `x-eversafe-token` header for authenticated requests.
Without it: "Sorry, we can't log you in" error, no login traffic sent.

## Script Load Order (CRITICAL)

Load eversafe bypass **BEFORE** traffic capture script. If bypass isn't active before `device.resume(pid)`, detection fires before hooks are in place.

```python
# CORRECT order:
session = device.attach(pid)
s1 = session.create_script(eversafe_bypass_js)  # FIRST
s1.load()
s2 = session.create_script(traffic_capture_js)   # SECOND
s2.load()
device.resume(pid)  # Only after both loaded
```

## What Doesn't Work

| Approach | Why it fails |
|----------|-------------|
| Rename frida-server | Still detected via port scan |
| Non-standard port | Native lib scans ALL /proc/net/tcp entries |
| hluda-server (TCP) | Helps with memory signatures but port still visible |
| hluda Unix socket (`-l unix:`) | Older builds don't support it (fails silently) |
| libc hook (open/read/connect) | Native uses raw svc #0 syscalls |
| Block System.loadLibrary("eversafe") | App crashes without the lib |
| pm disable EversafeService | Unreliable (re-enables) + kills token generation |
| Block bindService | Token generation fails → login blocked |
| AlertDialog.setMessage hook | Alert is Flutter widget, not native dialog |
| Flutter MethodChannel.invokeMethod hook | Detection doesn't go through MethodChannel |
| EversafeThreat.createThreats hook | Class in service classloader (ClassNotFoundException) |
| IEversafeAIDLService$Stub$Proxy hook | Same classloader issue |

## What Works

| Approach | Effect |
|----------|--------|
| Handler msg 84 suppress | Alert never reaches Flutter UI |
| System.exit/killProcess block | App survives after detection |
| Allow EversafeService | Token generated, backend auth works |
| hluda + non-default port | Reduces other signature checks |

## Discovering Native Methods (Stripped Binary)

`libeversafe.so` has only 2 exports (`JNI_OnLoad`, `JNI_OnUnload`) and 0 symbols. Native methods are registered dynamically. Hook `RegisterNatives` BEFORE lib loads to capture them:

```javascript
var libart = Process.findModuleByName("libart.so");
var regNatives = null;
libart.enumerateSymbols().forEach(function(s) {
    if (s.name.indexOf("RegisterNatives") !== -1 && s.name.indexOf("Check") === -1 && !regNatives) {
        regNatives = s.address;
    }
});

Interceptor.attach(regNatives, {
    onEnter: function(args) {
        var nMethods = args[3].toInt32();
        for (var i = 0; i < nMethods; i++) {
            var namePtr = args[2].add(i * Process.pointerSize * 3).readPointer();
            var sigPtr = args[2].add(i * Process.pointerSize * 3 + Process.pointerSize).readPointer();
            var fnPtr = args[2].add(i * Process.pointerSize * 3 + Process.pointerSize * 2).readPointer();
            var name = namePtr.readUtf8String();
            var sig = sigPtr.readUtf8String();
            var mod = Process.findModuleByAddress(fnPtr);
            if (mod && mod.name.indexOf("eversafe") !== -1) {
                send("[REG] " + name + " " + sig + " -> " + fnPtr);
            }
        }
    }
});
```

**Must load BEFORE `device.resume(pid)`** — RegisterNatives fires during JNI_OnLoad.

**Known native methods (Jago PROD, Eversafe 3.10.43):**
- `encrypt_token([B)[B` — encrypts TLV token (libeversafe.so)
- `decryptAndLoadBasicModule(Object)Z` — unpacks secondary .so (libeversafe.so)
- `register(Context,Handler)V` — starts detection loop (secondary .so)
- `encrypt(String,[B)[B` — general encrypt (secondary .so)
- `decrypt(String,[B)[B` — general decrypt (secondary .so)
- `launch(Context)V`, `relaunch(Context)V`, `unregister(I)V`, `setWakeupTryCount(I)V`

**Flutter MethodChannel:** `jago.digitalbanking.com/eversafe/methodChannel` — Dart↔Java communication for token passing.

## Handler Message Types (EversafeHandler)

```
0  = MESSAGE_STATE_INITIALIZED
1  = MESSAGE_STATE_AUTHORIZED
4  = MESSAGE_STATE_LAUNCHING
5  = MESSAGE_STATE_LAUNCHED
9  = MESSAGE_STATE_TERMINATED
10 = MESSAGE_STATE_NORMAL
11 = MESSAGE_STATE_EMERGENCY
12 = MESSAGE_STATE_TIMEOUT_EMERGENCY
13 = MESSAGE_STATE_BASIC
14 = MESSAGE_STATE_VERSION
80 = MESSAGE_SESSION_DECIDED
81 = MESSAGE_SESSION_OK
82 = MESSAGE_SESSION_ERROR
83 = MESSAGE_SESSION_WARNING
84 = MESSAGE_THREATS_FOUND  ← suppress this
85 = MESSAGE_KEY_EXCHANGE
86 = MESSAGE_DIAGNOSIS_RESULT
100 = MESSAGE_SYSTEM_EXIT   ← suppress this
```

## Burp Integration

With Frida `connect()` hook redirecting traffic:
- Traffic arrives as raw TLS (not CONNECT tunnel)
- SNI preserved in ClientHello
- Burp invisible proxy on :8443 reads SNI, routes correctly
- `adb reverse tcp:8443 tcp:8443` → points to Burp listener
- No need for custom TLS proxy if Burp invisible proxy is configured

**Burp listener setup:**
- Proxy → Proxy settings → Proxy listeners → Add
- Bind port: 8443, Bind address: All interfaces
- Request handling: ✓ "Support invisible proxying"

**Fallback (if Burp invisible proxy fails):** Use `jago_tls_proxy.py` (custom Python TLS MITM) which reads SNI from ClientHello, generates per-host certs with mitmproxy CA, and logs plaintext to file. Force HTTP/1.1 ALPN both sides for readable capture.

## Login Failure with "Something Went Wrong"

Even with msg 84 suppressed and app running:
- Eversafe service **still reports DEBUGGER to its backend** (runs in separate process)
- Backend may taint the `x-eversafe-token` → Jago server rejects login
- Fix: Forge a clean token using the TLV 0x02 structure (see `references/eversafe-attestation.md`)
- For PROD: package = `com.jago.digitalBanking`, device ID from SharedPrefs

**Java token interception (OkHttp/HttpURLConnection hooks) DOES NOT work for Flutter:**
Flutter uses `dart:io` HTTP client — never touches Java HTTP layer. Token replacement must happen at either:
1. Native TLS write level (complex, fragile)
2. Burp match/replace with a dynamic extension
3. Forge token and inject via Frida Dart hooks (advanced)
4. Use Burp session handling rule with a macro that calls a Python token generator

## Full Interception Chain Summary

```
Device:  hluda-server -l 127.0.0.1:27042 (or any port)
         adb forward tcp:27042 tcp:27042
         adb reverse tcp:8443 tcp:8443

Host:    Burp invisible proxy on :8443
         OR jago_tls_proxy.py on :8443 (file logging)

Frida:   1. eversafe_bypass.js (Handler msg 84/100 suppress + exit block)
         2. jago_traffic_capture.js (connect() redirect + SSL bypass)

Order:   spawn → attach → load bypass → load traffic → resume
```
