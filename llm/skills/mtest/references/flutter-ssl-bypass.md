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

## Pitfalls

1. **Access violations** — NEVER scan the full module range (`m.base, m.size`). Flutter's memory layout has unmapped pages between sections. Always use `Process.enumerateRanges('r-x')` filtered to the module.

2. **Multiple matches** — Expect 3-5 matches for the pattern. Hook ALL of them. The actual verify function is one of them; the others are harmless (hooking them just makes unrelated functions return 1).

3. **No exports** — Modern Flutter strips all symbols. Don't waste time looking for `SSL_write`, `SSL_read`, or `ssl_crypto_x509_session_verify_cert_chain` by name.

4. **Timing** — libflutter.so loads AFTER the app process starts. If you spawn with Frida, the library isn't mapped yet at script load time. Always use `setTimeout` with retry.

5. **Proxy not enough** — Even with SSL bypass working, Flutter ignores system proxy. You MUST use iptables DNAT or the traffic won't reach your proxy.

6. **reFlutter alternative** — If Frida-based bypass is too fragile, use [reFlutter](https://github.com/nicolo-ribaudo/reflutter) to patch `libflutter.so` directly (inserts proxy settings + disables cert verify at binary level). This survives app restarts without Frida.
