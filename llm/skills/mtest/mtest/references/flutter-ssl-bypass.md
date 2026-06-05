# Flutter SSL Pinning Bypass (BoringSSL)

## Overview

Flutter apps compile BoringSSL into `libflutter.so`. The Dart HTTP client (`dart:io`) uses this directly, bypassing Android's Java TLS stack entirely. Standard Android SSL bypass techniques (TrustManager hooks, OkHttp interceptors, network_security_config patching) do NOT work.

## Working Frida Script (ARM64, Flutter 3.19+)

```javascript
// Flutter SSL Pinning Bypass
// Hooks ssl_crypto_x509_session_verify_cert_chain candidates in libflutter.so
// Must scan only executable ranges to avoid access violations on unmapped pages

function bypass() {
    var m = Process.findModuleByName('libflutter.so');
    if (!m) {
        console.log('[!] libflutter.so not loaded yet, retrying...');
        setTimeout(bypass, 500);
        return;
    }
    console.log('[*] libflutter.so: ' + m.base + ' size: ' + m.size);

    // Get only executable ranges within libflutter.so
    var ranges = Process.enumerateRanges('r-x');
    var flutterRanges = [];
    var mEnd = m.base.add(m.size);
    for (var i = 0; i < ranges.length; i++) {
        if (ranges[i].base.compare(m.base) >= 0 && ranges[i].base.compare(mEnd) < 0) {
            flutterRanges.push(ranges[i]);
        }
    }

    // Pattern: sub sp, #0x140; stp x29, x30, [sp, #offset]
    // This is the prologue of ssl_crypto_x509_session_verify_cert_chain
    var pattern = 'FF 03 05 D1 FD 7B 0F A9';
    var allMatches = [];
    for (var r = 0; r < flutterRanges.length; r++) {
        try {
            var matches = Memory.scanSync(flutterRanges[r].base, flutterRanges[r].size, pattern);
            for (var j = 0; j < matches.length; j++) {
                allMatches.push(matches[j].address);
            }
        } catch(e) {}
    }

    console.log('[*] Found ' + allMatches.length + ' candidates');
    for (var i = 0; i < allMatches.length; i++) {
        (function(idx, addr) {
            Interceptor.attach(addr, {
                onLeave: function(retval) {
                    retval.replace(0x1); // 1 = verification success
                }
            });
        })(i, allMatches[i]);
        console.log('[+] Hooked candidate ' + i + ' at ' + allMatches[i]);
    }
    console.log('[+] SSL pinning bypass active (' + allMatches.length + ' hooks)');
}

setTimeout(bypass, 500);
```

## Python Spawn Script

```python
import frida
import time

device = frida.get_usb_device()
pid = device.spawn(['com.example.app'])
session = device.attach(pid)

with open('flutter_ssl_bypass.js', 'r') as f:
    script_code = f.read()

script = session.create_script(script_code)
script.on('message', lambda msg, data: print(msg.get('payload', msg)))
script.load()
device.resume(pid)

# Keep alive
import sys
sys.stdin.read()
```

## Traffic Redirection (Required)

Flutter's `dart:io` HTTP client ignores Android system proxy settings. Must use iptables:

```bash
# Get app UID
APP_UID=$(cat /data/system/packages.list | grep <package> | awk '{print $2}')

# Redirect HTTPS to proxy
iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner $APP_UID --dport 443 -j DNAT --to-destination <HOST_IP>:8080
iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner $APP_UID --dport 80 -j DNAT --to-destination <HOST_IP>:8080

# Cleanup
iptables -t nat -F OUTPUT
```

## Alternative Patterns (if primary doesn't match)

If `FF 03 05 D1 FD 7B 0F A9` yields 0 matches, try these (older Flutter versions):

| Flutter Version | Pattern (first 8 bytes of prologue) |
|----------------|--------------------------------------|
| 3.24.x | FF 03 05 D1 FD 7B 0F A9 |
| 3.22.x | FF 83 04 D1 FD 7B 0F A9 |
| 3.19.x | FF C3 03 D1 FD 7B 0E A9 |
| 3.16.x | FF 43 03 D1 FD 7B 0C A9 |
| 3.13.x | FF 43 02 D1 FD 7B 08 A9 |
| 3.10.x | FF 03 02 D1 FD 7B 07 A9 |

## Verification

Confirm BoringSSL is present by searching for the `CERTIFICATE_VERIFY_FAILED` string:
```javascript
// In readable ranges of libflutter.so
Memory.scanSync(range.base, range.size, '43 45 52 54 49 46 49 43 41 54 45 5F 56 45 52 49 46 59 5F 46 41 49 4C 45 44');
```

Also check for source file references:
```bash
strings libflutter.so | grep "boringssl"
# Expected: ../../../flutter/third_party/boringssl/src/ssl/handshake_client.cc
```

## Fallback: Ghidra RE + Frida Backtrace (Flutter 3.22+, compileSdk 36)

When ALL pattern-based approaches fail (hooks install but never trigger during TLS), use this control-flow-based approach to find the real `ssl_verify_peer_cert`:

### Step 1: Identify the TLS call chain via Frida backtrace

Hook `writev`/`write`/`sendto` syscalls and capture backtraces from libflutter.so during TLS handshake. The handshake sends ClientHello via these syscalls.

```javascript
function doHook() {
    var flutter = Process.findModuleByName('libflutter.so');
    if (!flutter) { setTimeout(doHook, 500); return; }
    var flutterBase = flutter.base;
    var flutterEnd = flutter.base.add(flutter.size);
    var logged = 0;
    function hookSyscall(name) {
        var ptr = Module.findExportByName(null, name);
        if (!ptr) return;
        Interceptor.attach(ptr, {
            onEnter: function(args) {
                if (logged >= 5) return;
                var bt = Thread.backtrace(this.context, Backtracer.FUZZY);
                var hasFlutter = false;
                for (var i = 0; i < bt.length; i++) {
                    if (bt[i].compare(flutterBase) >= 0 && bt[i].compare(flutterEnd) < 0) {
                        hasFlutter = true; break;
                    }
                }
                if (hasFlutter) {
                    logged++;
                    var offsets = [];
                    for (var i = 0; i < bt.length; i++) {
                        if (bt[i].compare(flutterBase) >= 0 && bt[i].compare(flutterEnd) < 0)
                            offsets.push('0x' + bt[i].sub(flutterBase).toString(16));
                    }
                    send({type: 'bt', name: name, offsets: offsets});
                }
            }
        });
    }
    hookSyscall('write');
    hookSyscall('writev');
    hookSyscall('sendto');
    hookSyscall('sendmsg');
}
doHook();
```

Run with redsocks active (so TLS handshake actually happens). The deepest offset in the backtrace is closest to the handshake entry point.

### Step 2: Analyze candidates in Ghidra headless

Import libflutter.so into Ghidra, then use a script to analyze the functions from the backtrace. The verify function has these characteristics:
- **Size:** 150-250 bytes (small wrapper)
- **BLR count:** Exactly 1 (calls `custom_verify_callback` via function pointer)
- **Called from:** 5-10 locations (various handshake states)
- **Calls:** 8-12 functions (SSL struct accessors + the callback)

```java
// Ghidra headless script: check BLR count and callee count
// The function with exactly 1 BLR in the handshake call chain = ssl_verify_peer_cert
Function func = funcMgr.getFunctionContaining(addr);
InstructionIterator iter = program.getListing().getInstructions(func.getBody(), true);
int blrCount = 0;
while (iter.hasNext()) {
    if (iter.next().getMnemonicString().equals("blr")) blrCount++;
}
// blrCount == 1 → strong indicator of verify function
```

### Step 3: Replace with Interceptor.replace

Once identified, use `Interceptor.replace` (NOT `Interceptor.attach` with `onLeave`). The function takes `(SSL_HANDSHAKE*, uint8_t* out_alert)` and returns enum `ssl_verify_result_t` (0 = ok).

```javascript
var verifyFunc = m.base.add(OFFSET);  // e.g., 0x4819e8
Interceptor.replace(verifyFunc, new NativeCallback(function(hs, out_alert) {
    return 0;  // ssl_verify_ok
}, 'int', ['pointer', 'pointer']));
```

### Key insight: why pattern matching fails on 3.22+

The function prologue changed from `FF 03 05 D1 FD 7B 0F A9` (SUB SP, #0x140; STP X29, X30) to build-specific variants like `FF 83 01 D1 FE 67 02 A9` (SUB SP, #0x60; STP X30, X25). The register allocation and stack frame size vary per build. The BLR-based identification via Ghidra is build-independent.

### Confirmed working example (Jago Banking, Flutter 3.22+, June 2026)

- **libflutter.so:** 11MB, ARM64, fully stripped (no SSL exports)
- **String `CERTIFICATE_VERIFY_FAILED`:** found at 0x36a7ca (rodata) but NO xrefs in Ghidra (referenced via error code table, not direct pointer)
- **Backtrace offsets from `writev` hook:** `0x4b4630 → 0x4a6078 → 0x4a5640 → 0x4819e8`
- **Verified function:** Ghidra address `0x00581938` (file offset `0x481938`, runtime offset from base `0x481938`)
  - Prologue: `FF 83 01 D1 FE 67 02 A9` (SUB SP, #0x60; STP X30, X25, [SP, #0x20])
  - Size: 212 bytes, exactly 1 BLR instruction, called from 7 locations, calls 11 functions
- **Frida offset for `Interceptor.replace`:** `base + 0x481938` (NOT the backtrace return address `0x4819e8`)
- **Important:** Frida backtrace gives RETURN ADDRESSES (after BL), not function entries. Subtract to find the containing function's entry point via Ghidra.

### Eversafe anti-tampering interaction

Eversafe (kr.co.everspin) detects Frida via thread name scanning (`/proc/self/task/*/comm`) on a ~10s cycle. Without mitigation, app is killed at ~10-15s.

**Full bypass:** Load `anti_eversafe.js` (thread rename script) BEFORE `device.resume()` and again 3s after. App survives indefinitely. See `references/eversafe-frida-bypass.md` for the script.

**Additional notes:**
- **Binary patching does NOT work** — Eversafe or Flutter engine checks .so integrity at load time (SIGSEGV at unrelated address 0x6a8 during FlutterJNI.performNativeAttach)
- **hluda-server alone is NOT sufficient** — hides some indicators but not thread names
- **Load order:** anti_eversafe.js → resume → anti_eversafe.js again (3s) → wait for libflutter.so (12s) → SSL bypass

### Redsocks requirement

This approach requires redsocks running on-device to generate actual TLS handshake traffic through Burp. Without it, the backtrace hook never fires (no network I/O from libflutter.so).

```
redsocks config: type = http-connect, ip = <host_ip>, port = <burp_port>
iptables: -t nat -A OUTPUT -p tcp -m owner --uid-owner <APP_UID> --dport 443 -j REDIRECT --to-port 12345
```

**Critical:** verify Burp's actual listening port with `lsof -i -P | grep java | grep LISTEN`. Default may be 8081 or 8082, not 8080/8888.

---

## Pitfalls

1. **Access violations** — NEVER scan the full module range (`m.base, m.size`). Flutter's memory layout has unmapped pages between sections. Always use `Process.enumerateRanges('r-x')` filtered to the module.

2. **Multiple matches** — Expect 3-5 matches for the pattern. Hook ALL of them. The actual verify function is one of them; the others are harmless (hooking them just makes unrelated functions return 1).

3. **No exports** — Modern Flutter strips all symbols. Don't waste time looking for `SSL_write`, `SSL_read`, or `ssl_crypto_x509_session_verify_cert_chain` by name.

4. **Timing** — libflutter.so loads AFTER the app process starts. If you spawn with Frida, the library isn't mapped yet at script load time. Always use `setTimeout` with retry.

5. **Proxy not enough** — Even with SSL bypass working, Flutter ignores system proxy. You MUST use iptables DNAT or the traffic won't reach your proxy.

6. **reFlutter alternative** — If Frida-based bypass is too fragile, use [reFlutter](https://github.com/nicolo-ribaudo/reflutter) to patch `libflutter.so` directly (inserts proxy settings + disables cert verify at binary level). This survives app restarts without Frida.
