# Phase 3: Protection Assessment & Bypass

### Gate: protection mechanisms identified and bypassed (or documented as not needed/not bypassable); app launches with instrumentation capability

This phase assesses and bypasses client-side protections (RASP, root detection, SSL pinning, anti-tampering) BEFORE traffic analysis. Without bypasses working, Phases 4-9 are blocked.

**Steps:**

1. **[Both]** Identify protection mechanisms:
   - Root/jailbreak detection (su binary, Magisk, KernelSU, Cydia)
   - Frida/instrumentation detection (port 27042, /proc/self/maps, frida-agent strings)
   - SSL certificate pinning (OkHttp, TrustManager, network_security_config)
   - Anti-tampering / integrity checks (signature verification, DEX checksum)
   - Emulator detection (Build properties, sensors, telephony)
   - Debug detection (debuggable flag, TracerPid, JDWP)
   - Commercial SDKs: DexGuard/AppFence, Eversafe, Promon, Arxan

2. **[Android]** SSL pinning bypass / **[iOS]** SSL pinning bypass:
   ```bash
   # Frida (comprehensive — native Android apps)
   frida -U -f <package> -l ssl_pinning_bypass.js

   # Flutter apps — MUST use flutter_ssl_bypass.js (standard hooks don't work)
   # Flutter uses BoringSSL in libflutter.so, ignores system proxy + CA store
   # See frida-scripts.md → "Flutter SSL Pinning Bypass" for full script
   # Key: scan only r-x ranges, hook by byte pattern, use Python to keep session alive
   # IMPORTANT: After hooking, verify hooks TRIGGER by adding onEnter logging.
   #   If hooks never fire during TLS handshake, patterns matched wrong functions.
   #   Try NVISO disable-flutter-tls.js as alternative (different patterns).
   #   If both fail → redsocks + system cert (see redsocks-transparent-proxy.md)
   # Also requires iptables redirect (Flutter ignores system proxy):
   # TRAFFIC ROUTING for Flutter (ignores system proxy):
   #   PREFERRED: redsocks on device (works with Burp on any OS)
   #     See references/redsocks-transparent-proxy.md
   #   FALLBACK: iptables DNAT (ONLY works if Burp runs on Linux, NOT macOS)
   #     iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner <UID> --dport 443 -j DNAT --to <HOST>:8080
   #   WARNING: DNAT to macOS Burp silently fails (no SO_ORIGINAL_DST)
   #   1. iptables DNAT: iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner <UID> --dport 443 -j DNAT --to <HOST_IP>:<BURP_PORT>
   #   2. Burp listener: bind to "All interfaces" (not loopback) — device can't reach 127.0.0.1
   #   3. Burp invisible proxy: Edit listener → Request handling → ✓ "Support invisible proxying"
   #      Without this, DNAT'd TLS connections establish but produce ZERO HTTP history entries.
   #      Burp expects CONNECT for explicit proxy; invisible mode handles raw TLS via SNI.
   #
   # Get app UID: adb shell pm list packages -U | grep <package>
   # Verify DNAT matching: iptables -t nat -L OUTPUT -n -v (check packet counters)
   # Verify Burp receiving: lsof -i :<port> | grep ESTABLISHED (connections from device IP)

   # Objection (quick — native apps only, NOT Flutter)
   objection -g <package> explore
   android sslpinning disable   # or: ios sslpinning disable

   # APK patching (persistent, no Frida needed)
   # Inject network_security_config.xml trusting user CAs
   # Rebuild + re-sign APK
   ```

3. **[Android]** Root detection bypass / **[iOS]** Jailbreak detection bypass:
   ```bash
   # Frida (comprehensive)
   frida -U -f <package> -l root_bypass.js

   # Objection (quick)
   objection -g <package> explore
   android root disable   # or: ios jailbreak disable

   # Combined launch
   frida -U -f <package> -l root_bypass.js -l ssl_pinning_bypass.js
   ```

4. **[Android]** Anti-tampering bypass (DexGuard/AppFence/Eversafe):
   - See `references/operational-notes.md` → DexGuard section for full methodology
   - Priority order: Shamiko+Zygisk > hluda-server > Frida Gadget > non-rooted device > static evidence only
   - Apply "When to Stop Chasing a Bypass" decision tree

5. **[Both]** Verify: app launches, Frida attaches successfully, no detection popups/crashes

**Pitfall — Meta apps (Instagram, Facebook, WhatsApp, Threads):**
- NSC `overridePins="true"` does NOT mean proxy works — native BoringSSL enforces pins independently
- Patched APK (NSC pins removed) + Frida hooks intercepts traffic BUT server rejects login (signature validation in API headers)
- Best approach: skip traffic interception, use Frida runtime hooks on original APK for deep link/WebView/provider analysis
- See `references/meta-instagram-testing.md` for full methodology

**Reference:** `dynamic-setup.md`, `frida-scripts.md`, `dexguard-appfence-bypass.md`, `meta-instagram-bypass.md`, `redsocks-transparent-proxy.md`

**When pattern-based Flutter SSL bypass fails (Flutter 3.22+, 2026 builds):**
1. All known patterns (mtest + NVISO May 2025) may not match `ssl_verify_peer_cert` in newer builds
2. Verify hooks are actually triggered (add `onEnter` logging) — if never called, patterns matched wrong functions
3. Fallback: use redsocks on-device + Burp system cert. See `redsocks-transparent-proxy.md`
4. If staging build has no pinning, redsocks + system cert alone may suffice (no Frida SSL hooks needed)
5. Last resort: Ghidra RE of `libflutter.so` to find actual verify function via control flow analysis, `redsocks-transparent-proxy.md`, `redsocks-transparent-proxy.md`

**Meta/Instagram/Facebook apps:** Standard Frida-only or NSC-patch-only bypasses do NOT work for Meta apps. They use multi-layer pinning: NSC XML pin-set + native BoringSSL verify callbacks + server-side APK signature validation. Requires combined approach:
1. Patch APK: remove pin-set from network_security_config.xml
2. Inject Frida Gadget (loads script automatically, no external frida-server needed for bypass)
3. Spoof original Meta signing certificate via PackageManager hook (server validates signature at login)
4. Block QUIC: `iptables -A OUTPUT -p udp --dport 443 -j DROP` (forces TCP fallback to proxy)
5. Hook TrustManagerImpl.verifyChain + native SSL_CTX_set_custom_verify

**Pitfalls (Meta apps):**
- Do NOT enumerate Conscrypt exports via `enumerateExports()` — causes SIGBUS crash
- Do NOT hook `dlopen` — interferes with Instagram's native library loading, causes SIGBUS
- `overridePins="true"` in NSC does NOT bypass native-level pinning alone
- `b.i.instagram.com` (binary push/MQTT) has separate pinning that resists all bypass — not needed for API testing
- Patched APK with different signature will fail login without signature spoof hook
- Frida attach to running process won't bypass already-established TLS connections — must spawn fresh

See `references/meta-instagram-bypass.md` for full step-by-step procedure.

**Pitfalls — Frida DNAT + Burp Setup:**
- `frida -U -f <pkg>` opens an interactive REPL that blocks terminal. For automated spawn+attach, ALWAYS use a Python script with `frida.get_usb_device().spawn()` + `device.resume()` + `time.sleep()` keep-alive loop.
**Pitfalls — Flutter DNAT + Burp Setup:**
- Burp default listener is **loopback only** (`listen_mode: loopback_only`). For iptables DNAT to work, Burp MUST listen on **all interfaces** (`listen_mode: all_interfaces`). Check with `lsof -i :8080` — if it shows `localhost` only, traffic from device DNAT will be refused. Change in Proxy → Settings → Proxy Listeners → Edit → Bind to: All interfaces.
- Burp MCP `set_project_options` may be disabled ("Enable tools that can edit your config" toggle in MCP tab). If so, instruct user to change listener manually.
- `frida -U -f <pkg> -l script.js -q` exits immediately after script load (no REPL). Hooks are lost on detach. For persistent bypass during testing, use a Python script with `while True: time.sleep(1)` keep-alive loop.
- `frida` Python module is NOT available in `execute_code` sandbox. Use `terminal()` with inline `python3 -c "..."` or a standalone `.py` script for Frida Python bindings.
- Frida 16.1.8 does NOT support `--no-pause` flag. Spawn with `-f` auto-resumes.
- **USB disconnect kills frida-server.** Error appears as `frida.NotSupportedError: need Gadget to attach on jailed Android` — misleading; it means frida-server stopped. Fix: `adb shell "su -c 'killall frida-server 2>/dev/null; /data/local/tmp/frida-server -D &'"` then wait 3s.
- Frida interactive REPL (`frida -U -f pkg`) blocks terminal and stdin not available in background mode. Always use a Python script with `frida` module instead.

**Flutter SSL Bypass — Transparent Proxy Setup (CRITICAL):**

The `flutter_ssl_bypass.js` pattern-matching approach may hook functions that are NEVER CALLED during TLS verification in some Flutter 3.22+ builds. Verify hooks are triggered by adding `onEnter` logging. If `ssl_verify called` never appears, the pattern matched wrong functions.

**iptables DNAT to remote Burp on macOS DOES NOT WORK:**
- macOS lacks `SO_ORIGINAL_DST` socket option
- Burp receives TLS ClientHello but cannot determine original destination
- TCP connections show ESTABLISHED in `lsof` but no HTTP traffic appears in proxy history
- DNAT packet counters (`iptables -t nat -L OUTPUT -n -v`) show matches, confirming redirect works at kernel level

**Working approaches for Flutter + Burp on macOS:**
1. **Burp invisible proxy + "Force use of TLS"** — Burp reads SNI from ClientHello to determine target host. Requires BOTH "Support invisible proxying" AND "Force use of TLS" checked on the listener. Without "Force use of TLS", Burp tries to parse TLS ClientHello as HTTP.
2. **redsocks on device** — runs locally, reads SO_ORIGINAL_DST (works on Linux/Android), forwards as CONNECT to remote Burp. Flow: App → iptables REDIRECT (local port) → redsocks → CONNECT → Burp.
3. **Burp on device** — eliminates the remote proxy problem entirely.
4. **mitmproxy transparent mode on macOS** — uses pfctl rdr rules + macOS as gateway.

**Burp listener config for invisible proxy with DNAT:**
- Bind: All interfaces
- Support invisible proxying: ✓
- Force use of TLS: ✓
- Do NOT set "Redirect to host" (breaks multi-host apps)

**System cert installation on Android 13 (KernelSU):**
```bash
# Export Burp CA
curl -s -o /tmp/burp_ca.der http://127.0.0.1:8080/cert
openssl x509 -inform DER -in /tmp/burp_ca.der -out /tmp/burp_ca.pem
HASH=$(openssl x509 -inform PEM -subject_hash_old -in /tmp/burp_ca.pem -noout)
cp /tmp/burp_ca.pem /tmp/${HASH}.0
adb push /tmp/${HASH}.0 /data/local/tmp/
adb shell su -c 'mount -o rw,remount / && cp /data/local/tmp/${HASH}.0 /system/etc/security/cacerts/ && mount -o ro,remount /'
# NOTE: Requires REBOOT for Android to load new system certs into memory
# chmod may fail but file is created with correct 644 perms from cp
```

**Scripts:**
- `scripts/flutter_ssl_bypass.js` — Flutter BoringSSL bypass for ARM64 (Flutter 3.10-3.24). Despite earlier belief, pattern 0 (`FF 03 05 D1 FD 7B 0F A9`) DOES work on some SDK 36 / 2026+ builds (confirmed: Jago v8.86.0, compileSdk 36, 4 hooks installed). Try it first before escalating to Ghidra RE. If hooks install but never fire during TLS handshake, THEN escalate.
- `scripts/ssl_pinning_bypass.js` — universal SSL pinning bypass for native Android
- `scripts/root_bypass.js` — universal root/jailbreak detection bypass

**When flutter_ssl_bypass.js pattern hooks never trigger:**

The pattern-matching approach (`SUB SP, #N; STP X29, X30, [SP, #offset]`) can match wrong functions in Flutter 3.22+ builds (compileSdk 36). Symptoms: hooks install successfully but `onEnter`/`onLeave` never fire during TLS handshake.

Root cause: BoringSSL in modern Flutter references error strings (like `CERTIFICATE_VERIFY_FAILED`) via an **error code lookup table**, not direct pointers. There are NO xrefs (ADRP+ADD, ADR, or raw pointer) from code to the string. r2/radare2 `axt` and manual binary scanning both fail to find the verify function.

**Fallback approaches (in order):**
1. **Ghidra full analysis** — load libflutter.so, find `ssl_crypto_x509_session_verify_cert_chain` via control flow from SSL handshake entry. Multi-hour RE effort.
2. **redsocks + system cert** — if the app uses Dart's default SecurityContext (loads system CA store), installing Burp CA as system cert + redsocks proxy chain may work without Frida SSL hooks. Requires reboot after cert install for Android to pick it up.
3. **APK patching** — patch libflutter.so binary to NOP the verify call. Requires identifying the exact instruction via Ghidra.
4. **Accept limitation** — proceed with Frida runtime testing + direct API calls using captured tokens. Document as Phase 4 N/A.

**redsocks transparent proxy (when Burp is on macOS):**

macOS Burp CANNOT determine original destination from iptables DNAT'd connections (no `SO_ORIGINAL_DST` socket option on macOS). Symptoms: DNAT packets match (iptables counters increase), Burp shows ESTABLISHED TCP connections, but NO HTTP traffic appears in proxy history.

Solution: run redsocks on the Android device. See `references/redsocks-transparent-proxy.md`.

Flow: `App → iptables REDIRECT → redsocks (device:12345) → CONNECT host:port → Burp (host:8080)`

**Burp listener settings for redsocks:**
- Listen on: All interfaces (0.0.0.0:8080)
- Support invisible proxying: **OFF** (redsocks sends explicit CONNECT)
- Force use of TLS: **OFF** (redsocks sends plain HTTP CONNECT)
- Intercept: **OFF** (or CONNECT requests get stuck)

**When flutter_ssl_bypass.js hooks don't trigger:**
If hooks install (4 matches, pattern 0) but `onEnter` never fires during TLS handshakes, the pattern matched wrong functions. Escalation path:
1. Verify with `onEnter` logging — if never called, pattern is wrong for this Flutter version
2. Try redsocks approach (transparent proxy) — bypasses the need for BoringSSL hooks entirely
3. Use Ghidra/r2 to find actual verify function via xref to `CERTIFICATE_VERIFY_FAILED` string in libflutter.so
4. Fall back to runtime testing without traffic interception (Frida hooks + direct API calls)

**Cross-reference:** For DexGuard/AppFence protected apps, load `dexguard-native-re` skill for full RE methodology.
