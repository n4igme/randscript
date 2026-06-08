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

Flutter's `dart:io` HTTP client ignores Android system proxy settings. Two approaches:

### Approach A: Frida connect() redirect + Burp Invisible Proxy (PREFERRED)

Best for apps with Eversafe or other anti-tamper that blocks iptables/redsocks. Preserves SNI in ClientHello so Burp can generate per-host certs.

```javascript
// Redirect connect() for known app server IPs to Burp invisible proxy
var TARGET_IPS = ["172.64.148.24", "104.18.39.232"]; // resolve target hosts
var connect = Module.findExportByName("libc.so", "connect");
Interceptor.attach(connect, {
    onEnter: function(args) {
        var family = args[1].readU16();
        if (family === 2) { // AF_INET
            var port = (args[1].add(2).readU8() << 8) | args[1].add(3).readU8();
            if (port === 443) {
                var ip = args[1].add(4).readU8() + "." + args[1].add(5).readU8() + "." +
                         args[1].add(6).readU8() + "." + args[1].add(7).readU8();
                if (TARGET_IPS.indexOf(ip) !== -1) {
                    // Redirect to localhost:8443 (Burp invisible proxy via adb reverse)
                    args[1].add(2).writeU8(0x20); // port 8443 high byte
                    args[1].add(3).writeU8(0xFB); // port 8443 low byte
                    args[1].add(4).writeU8(127);
                    args[1].add(5).writeU8(0);
                    args[1].add(6).writeU8(0);
                    args[1].add(7).writeU8(1);
                }
            }
        }
    }
});
```

**Setup:**
```bash
adb reverse tcp:8443 tcp:8443  # forward device 8443 → host Burp
# Burp: Proxy → Options → Add → Port 8443 → Binding: All interfaces
#   → Request Handling → "Support invisible proxying" ✓
```

**Why this works:** Flutter sends correct SNI in TLS ClientHello regardless of the IP it connects to. Burp invisible proxy reads SNI, generates per-host cert, and forwards to the real server.

**Diagnostic:** If you see 100+ connect() redirects in 20s, SSL bypass is NOT working (connection retry storm). Working bypass = ~5 connections then stable (HTTP/2 multiplexing).

### Approach B: iptables DNAT (simpler but conflicts with Eversafe)

```bash
APP_UID=$(cat /data/system/packages.list | grep <package> | awk '{print $2}')
iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner $APP_UID --dport 443 -j DNAT --to-destination <HOST_IP>:8080
iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner $APP_UID --dport 80 -j DNAT --to-destination <HOST_IP>:8080
# Cleanup: iptables -t nat -F OUTPUT
```

**Warning:** iptables may conflict with Eversafe's native HTTP stack (it uses its own connections to `/appprotect/eversafe/` endpoints). Use Approach A when Eversafe is present.

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

2. **Multiple matches — NOT all are verify functions** — Pattern `FF 03 05 D1 FD 7B 0F A9` typically finds 3-5 matches. **Critical:** NOT all matches are ssl_verify_peer_cert. In Jago PROD (Flutter 3.22+, 11MB libflutter.so), 4 matches found but func#1 returned POINTER values (0x746e...) and was called hundreds of times per second — clearly NOT a verify function. Patching/hooking ALL matches breaks unrelated functionality. **Identify the real verify function by:**
   - Monitoring return values: verify functions return int 0 or 1, NOT pointers
   - Call frequency: verify is called once per TLS handshake, not continuously
   - If func returns non-zero pointers constantly = wrong function, skip it

3. **Return value semantics vary per match** — `ssl_crypto_x509_session_verify_cert_chain` returns BOOLEAN (1 = chain valid). `ssl_verify_peer_cert` returns enum (0 = ssl_verify_ok). When unsure, try: patch [0]→ret 0, patch [2],[3]→ret 1, SKIP [1] if it returns pointers. This is trial-and-error when symbols are stripped.

4. **Retry storm diagnostic** — If connect() redirect fires 100+ times in 20s, the SSL bypass is NOT working (TLS handshake fails → Dart retries). A working bypass shows ~5 connections then stabilizes (HTTP/2 multiplexes on one connection). ~5 redirects + no retry = TLS succeeding.

5. **No exports** — Modern Flutter strips all symbols. Don't waste time looking for `SSL_write`, `SSL_read`, or `ssl_crypto_x509_session_verify_cert_chain` by name.

6. **Timing** — libflutter.so loads AFTER the app process starts. If you spawn with Frida, the library isn't mapped yet at script load time. Always use `setTimeout` with retry.

7. **Proxy not enough** — Even with SSL bypass working, Flutter ignores system proxy. You MUST use connect() redirect (Approach A) or iptables DNAT (Approach B).

8. **reFlutter alternative** — If Frida-based bypass is too fragile, use [reFlutter](https://github.com/nicolo-ribaudo/reflutter) to patch `libflutter.so` directly (inserts proxy settings + disables cert verify at binary level). This survives app restarts without Frida.

9. **NVISO disable-flutter-tls.js patterns may fail** — The NVISO script (github.com/NVISOsecurity/disable-flutter-tls-verification) uses arm64 patterns that target specific Flutter versions. On custom/newer Flutter builds (e.g., Jago PROD 8.86.0), ALL three NVISO patterns (`F? 0F 1C F8...`, `F? 43 01 D1 FE 67 01 A9...`, `FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94...`) return 0 matches. Fallback: use the generic `FF 03 05 D1 FD 7B 0F A9` with selective patching (skip pointer-returning functions).

10. **Interceptor.attach/replace does NOT persist after Frida detach** — Hooks are removed when session ends. connect() redirect dies too. **`Memory.patchCode` DOES persist** (writes actual ARM64 opcodes: `mov w0, #0` = 0x52800000, `ret` = 0xD65F03C0). But connect() redirect cannot be made persistent via patchCode (it's dynamic logic). **You MUST keep the Frida session alive** for traffic interception. Use a background Python process with `while True: time.sleep(1)`.

11. **TLS succeeding ≠ HTTP traffic in Burp** — Even with SSL bypass working (no retry storm, connections established), Burp may show empty history if the patched functions break the HTTP/2 framing or response parsing. If Burp shows 200+ ESTABLISHED connections but 0 HTTP history entries, you've patched a wrong function that corrupts the data path rather than just the verify path.

12. **reFlutter as ultimate fallback** — When ALL Frida pattern approaches fail (NVISO, generic prologue, xref-based, Ghidra backtrace), use reFlutter to binary-patch libflutter.so. It patches the verify at build-hash level (SnapshotHash matching) regardless of compiler optimizations. See "reFlutter Binary Patch Approach" section below.

---

## reFlutter Binary Patch Approach (Last Resort — Always Works)

When Frida-based SSL bypass fails after 3+ attempts with different patterns, use reFlutter:

### Prerequisites
```bash
pip3 install reflutter  # or brew install reflutter
```

### Workflow

```bash
# 1. Patch the APK (enter proxy IP when prompted — use 127.0.0.1)
echo "127.0.0.1" | reflutter target.apk
# Output: release.RE.apk with patched libflutter.so

# 2. Sign and align
zipalign -f 4 release.RE.apk release.RE.aligned.apk
apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android release.RE.aligned.apk

# 3a. If single APK — install directly
adb install release.RE.aligned.apk

# 3b. If split APK (INSTALL_FAILED_INVALID_APK: Full install must include a base package):
#     Extract patched libflutter.so and replace on device
python3 -c "
import zipfile
z = zipfile.ZipFile('release.RE.apk')
z.extract('lib/arm64-v8a/libflutter.so', '/tmp/reflutter_out')
"
adb push /tmp/reflutter_out/lib/arm64-v8a/libflutter.so /data/local/tmp/libflutter_patched.so

# 4. Replace original lib on device (requires root)
#    First find install path:
adb shell "pm path com.target.app"
#    Then overwrite:
adb shell "su -c 'cp /data/local/tmp/libflutter_patched.so /data/app/~~HASH==/com.target.app-HASH==/lib/arm64/libflutter.so'"
adb shell "su -c 'chmod 755 /data/app/~~HASH==/com.target.app-HASH==/lib/arm64/libflutter.so'"
adb shell "am force-stop com.target.app"
```

### Split APK Reinstall (when app was uninstalled)
```bash
# If you have the original split APKs:
adb install-multiple base.apk split_config.arm64_v8a.apk split_config.en.apk split_config.xxhdpi.apk
# Then replace libflutter.so as above
```

### What reFlutter Does
- Patches `ssl_crypto_x509_session_verify_cert_chain` to return 1 (valid)
- Uses SnapshotHash matching (build-hash specific, not pattern-based)
- Works on ANY Flutter version regardless of compiler optimizations
- Does NOT add proxy routing — you still need Frida connect() redirect or iptables

### Combining reFlutter + Frida
After libflutter.so replacement, use Frida ONLY for:
- Eversafe/anti-tamper bypass (Handler msg suppression)
- connect() redirect to Burp (reFlutter doesn't route traffic)
- Root hiding hooks

```python
# Minimal Frida script with reFlutter (no SSL hooks needed):
# 1. eversafe_bypass.js (msg 84/100 suppression)
# 2. connect() redirect to 127.0.0.1:8443
# NO ssl pattern scanning needed — reFlutter handles it at binary level
```

### Key Advantages Over Frida SSL Bypass
- Build-independent (works when ALL patterns fail)
- Survives app restart (binary patch, not runtime hook)
- No retry storms (verify is truly disabled, not just hooked)
- No need to identify which of 4+ pattern matches is the real function

### Limitations
- Requires root (to overwrite lib on device)
- Changes app signature (may trigger server-side sig checks)
- Must redo after app update
- reFlutter must support the Flutter engine version (SnapshotHash match)
