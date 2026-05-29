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
   # Also requires iptables redirect (Flutter ignores system proxy):
   #   iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner <UID> --dport 443 -j DNAT --to <HOST>:8080

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

**Reference:** `dynamic-setup.md`, `frida-scripts.md`, `dexguard-appfence-bypass.md`

**Scripts:**
- `scripts/flutter_ssl_bypass.js` — Flutter BoringSSL bypass for ARM64 (Flutter 3.10-3.24+)
- `scripts/ssl_pinning_bypass.js` — universal SSL pinning bypass for native Android
- `scripts/root_bypass.js` — universal root/jailbreak detection bypass

**Cross-reference:** For DexGuard/AppFence protected apps, load `dexguard-native-re` skill for full RE methodology.
