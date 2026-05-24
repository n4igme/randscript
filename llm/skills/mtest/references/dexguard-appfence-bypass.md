# DexGuard / AppFence Root & Frida Detection Bypass

## Overview

DexGuard (by Guardsquare) and its AppFence SDK (`libaf-android.so`) implement enterprise-grade root/hook detection with multiple layers. Standard Frida hooks on `exit()`, `_exit()`, `kill()` are insufficient because the library uses `syscall()` wrapper with computed syscall numbers and has a triple-kill fallback.

## Detection Layers (from RE of libaf-android.so)

### Root Detection
- `access()` checks: `/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/debug_ramdisk/su`, `/su/bin/`
- Magisk paths: `/sbin/.magisk/`, `/debug_ramdisk/magisk*`, `/system/addon.d/99-magisk.sh`
- Shamiko: `/sbin/.magisk/modules/zygisk_shamiko`, `/debug_ramdisk/shamiko`
- LSPosed: `/sbin/.magisk/modules/zygisk_lsposed`
- KingRoot, SuperSU, Xposed paths
- `popen("which su")` execution
- `readdir` scanning for su binaries
- `/proc/self/mountinfo` for overlay mounts
- `dir_root_permissions` check
- `system_mounted_as_readwrite` check
- `is_magisk_mounted` check
- Package detection: magisk, kernelsu, supersu, xposed modules
- SystemProperties: `ro.debuggable`, `ro.secure`, `service.adb.root`, `ro.kernel.qemu`

### Hook/Instrumentation Detection
- `HookChecker.checkDexMemory()` — scans DEX in memory for modifications
- `HookChecker.checkBionicMemory()` — scans libc for inline hooks
- `hook_libc_injection` / `hook_libc_injection_via_memory` — detects injected code
- `hook_rwxp_libc` — checks for RWX pages in libc (instrumentation signature)
- `hook_port_found` — scans for Frida default port (27042)
- `hook_port_ws_connection_available` — checks Frida WebSocket
- `hook_process_found` — checks running processes for frida/xposed
- `hook_related_files` — checks filesystem for hook tool artifacts
- `hook_user_mode_injection_found` — generic injection detection
- `/proc/self/maps` reading (multiple times) — looks for frida-agent, gadget, linjector
- `/proc/self/mem` reading via `pread64` — direct memory inspection
- `hook_exec_permission_map` — checks memory page permissions

### Kill Mechanism (4 layers, from Ghidra RE + binary analysis)

```
Layer 1: Inline SVC #0 (exit_group) — BYPASSES ALL libc hooks
  MOVZ X8, #94        → syscall number in register
  MOVZ X0, #0         → exit code
  SVC #0              → direct kernel call

Layer 2: libc syscall() wrapper
  getpid()            → save own PID
  mov w8, 0x5e (94)   → SYS_exit_group
  syscall(94, 0)      → exit_group via libc

Layer 3: dlsym'd function pointers
  kill_fn = dlsym(dlopen("libc.so",1), "kill")
  _exit_fn = dlsym(dlopen("libc.so",1), "_exit")
  kill_fn(self_pid, 9)  → SIGKILL via BLR (indirect call)
  _exit_fn(0)           → via BLR

Layer 4: abort() — final fallback
```

**Critical:** Layer 1 uses inline `SVC #0` which goes directly to kernel — NO libc function is called, so Interceptor hooks on `syscall()`, `kill()`, `_exit()` etc. are completely bypassed. This is the primary kill mechanism.

The kill runs on a **separate thread** spawned via `pthread_create` with a configurable delay (`usleep(N * 1000000)` before killing). The thread start routine address is identifiable via Ghidra xrefs to `pthread_create`.

**dlsym resolution:** Layer 3 resolves `kill` and `_exit` at runtime via `dlopen`+`dlsym`, then calls via function pointer (`BLR Xn`). This defeats static analysis looking for BL to kill/exit PLT entries.

### Other Detection
- `is_app_clone_detected` — detects dual/clone apps
- `apk_checksum_value` — APK integrity verification
- VibrationProcessor / pressure monitoring (anti-emulator)

## Bypass Strategy (Proven Working)

### Requirements
- **hluda-server** (not regular frida-server) — anti-detection Frida build
  - Hides from /proc/self/maps
  - Uses random port (not 27042)
  - Strips frida strings from memory

### Working Script (root-bypass-v10.js)

Core technique — hook `syscall()` and replace exit_group with harmless getpid:

```javascript
var syscallAddr = Module.findExportByName("libc.so", "syscall");
Interceptor.attach(syscallAddr, {
    onEnter: function(args) {
        var sysno = args[0].toInt32();
        if (sysno === 94 || sysno === 93) {  // exit_group / exit
            args[0] = ptr(172);  // replace with getpid
        } else if (sysno === 129) {  // kill
            if (args[1].toInt32() === Process.id && args[2].toInt32() === 9) {
                args[0] = ptr(172);
            }
        }
    }
});
```

Plus:
- `Interceptor.replace(abort, no-op)` — neutralize triple fallback
- Block `pthread_create` from `libaf-android.so` — sleep detection threads forever
- Hide root files via `access()`, `open()`, `openat()`, `popen()` hooks
- Java-level: `System.exit`, `Runtime.exit`, `Process.killProcess`, `File.exists`, `PackageManager.getPackageInfo`, `SystemProperties.get`

### Why Previous Attempts Failed (Gojek, 27 iterations)
1. **v10-v13 (libc hooks only):** Inline SVC bypasses all libc hooks — process dies with no hook output
2. **v14-v16 (Memory.writeByteArray patches):** Patches applied but integrity check detects modified .text pages → SIGBUS or second kill path fires
3. **v17 (patch only inline SVC):** Other kill paths (BL syscall, BLR kill) still active via libc — caught by hooks but `_exit` replacement causes "Process terminated"
4. **v18 (_exit sleep-forever):** Main thread got stuck in sleep → Frida reports "Process terminated"
5. **v19 (delayed patch after integrity):** Detection fires before 3s delay — kill thread already spawned
6. **v20-v22 (various combinations):** Maps filter not comprehensive enough — detection still sees Frida via uncovered strings
7. **v23 (seccomp BPF):** Timed out (promising but incomplete)
8. **v24 (maps filter + pthread block + SVC patch + libc hooks):** ✅ WORKS — app alive 40+ seconds, login screen visible, all detection paths neutralized
9. **v25-v27 (refinements):** Removing pthread block or changing sleep duration caused crashes (use-after-free from parent function accessing freed thread arg)

**Root cause of inconsistency:** The bypass is timing-sensitive. Maps filter must catch ALL reads before detection triggers. If even one scan gets through unfiltered, the kill thread spawns. Once spawned, the kill thread's inline SVC fires after the configured delay regardless of other hooks.

### Key Lessons
- `libh9740d.so` (7KB) = ANR SigQuit observer, NOT root detection
- `libaf-android.so` (2MB) = AppFence security SDK with ALL detection logic
- **HAS inline `svc #0`** at one location (exit_group) — this is the PRIMARY kill that bypasses all libc hooks
- Also uses libc `syscall()` wrapper as Layer 2 (catchable via Interceptor.attach)
- Also uses `dlsym("libc.so", "kill")` + `dlsym("libc.so", "_exit")` for Layer 3 (indirect BLR calls)
- The kill is `exit_group(0)` = clean exit (looks like normal shutdown in logcat)
- Detection scans `/proc/self/maps` via `fopen`+`fgets` — filtering Frida lines is the PRIMARY defense
- Must use hluda-server (anti-detection Frida) to avoid hook_port/hook_process/maps detection
- Thread blocking alone insufficient — must also patch inline SVC and hook libc kill paths
- On-disk patching of libaf-android.so triggers integrity check (SIGBUS crash)
- `Interceptor.replace` on functions inside libaf-android.so triggers integrity check (writes trampoline bytes)
- Kill thread sleeps N seconds before killing — gives time for hooks to establish but NOT for delayed patching

### Working Bypass (v24 pattern — confirmed on Gojek)

Combined approach (all layers needed simultaneously):
1. **`/proc/self/maps` filtering** via `fopen`/`fgets` hooks — hides Frida from detection scanner
2. **Kill thread blocking** via `pthread_create` hook — replace start routine with sleep-forever
3. **Inline SVC patch** — NOP the `SVC #0` instruction after library loads via `android_dlopen_ext` hook
4. **Libc safety nets** — `syscall()` redirect (94→39), `kill()` signal neutralize, `abort()`/`_exit()` no-ops
5. **Java safety** — `System.exit()`, `Process.killProcess()` implementations blocked

See `dexguard-native-re` skill for the full script template (`scripts/appfence-bypass-v24.js`).

## APK Merge (Split APK Handling)

Gojek uses split APKs. Merge before analysis:
```bash
java -jar APKEditor-1.4.7.jar m -i <dir_with_splits> -o merged.apk -f
```

## Identification

Detect AppFence/DexGuard in an APK:
```bash
# Check for libaf-android.so
unzip -l app.apk | grep libaf-android
# Check for DexGuard obfuscation patterns
strings libaf-android.so | grep -i "hook_\|is_magisk\|su_binary\|HookChecker"
# Check for ard module in Java
grep -r "DexGuard\|dexguard\|ard.*Root\|AppFence" jadx_out/sources/
```
