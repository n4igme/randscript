# Android Native Exploitation

## Attack Surface

### Binder IPC
```
# Primary IPC mechanism — all inter-process communication goes through Binder
# Kernel driver: /dev/binder, /dev/hwbinder, /dev/vndbinder
# Attack surface: service implementations parsing untrusted Parcel data
# Reachable from app context (no root needed)

# Enumerate services:
adb shell service list
adb shell dumpsys <service_name>
```

### Native System Services
```
# mediaserver / mediaextractor: parse media files (historically bug-rich)
# surfaceflinger: display compositor (shared memory, GPU)
# installd: package installation (runs as root)
# vold: volume management (runs as root)
# netd: network daemon
# zygote: app process forking (high-value target)
```

### Kernel Attack Surface
```
# Linux kernel + Android-specific drivers:
# - Binder driver (binder_ioctl)
# - Ashmem (shared memory)
# - ION/DMA-BUF (GPU memory allocation)
# - GPU drivers (Adreno, Mali, PowerVR) — massive attack surface
# - Vendor HAL drivers (camera, sensors, modem)
# - /dev/kmsg, /proc interfaces
```

### GPU Drivers
```
# Most prolific source of Android kernel bugs
# Qualcomm Adreno: /dev/kgsl-3d0
# ARM Mali: /dev/mali0
# Accessible from app sandbox (needed for rendering)
# Complex memory management → UAF, OOB, race conditions

# Adreno IOCTL fuzzing:
# IOCTL_KGSL_GPUMEM_ALLOC, IOCTL_KGSL_MAP_USER_MEM
# IOCTL_KGSL_GPU_COMMAND (submit GPU commands)
```

## Exploitation Techniques

### Binder Exploitation
```c
// Binder transaction overflow / type confusion
// Parcel deserialization bugs: readInt32 vs readInt64 mismatch
// Flat_binder_object confusion: BINDER vs HANDLE vs FD

// From app context:
// 1. Find vulnerable service method (fuzzing or code audit)
// 2. Craft malicious Parcel with overflow/confusion
// 3. Trigger bug in target service process
// 4. If service is privileged → privilege escalation

// Binder UAF pattern:
// Service holds reference to Binder object
// Client dies → Binder object freed
// Service uses dangling reference → UAF in service context
```

### SELinux Bypass
```
# SELinux enforces mandatory access control on Android
# Even root can't do everything — policy restricts operations
# Exploit must either:
# 1. Exploit kernel (SELinux is kernel-enforced, kernel bypass = game over)
# 2. Transition to permissive domain (find allowed transition)
# 3. Exploit process already in permissive/privileged domain
# 4. Modify SELinux policy (requires kernel write)

# Check current context:
adb shell id -Z
# u:r:untrusted_app:s0:c... (app context)
# u:r:shell:s0 (adb shell)
# u:r:su:s0 (root with Magisk)

# Find allowed transitions:
adb shell sesearch --allow -s untrusted_app -t <target_type> /sys/fs/selinux/policy
```

### Kernel Exploitation (Android-Specific)

#### Binder Driver Bugs
```c
// Binder driver runs in kernel context
// Bugs in binder_ioctl → kernel code execution
// Common: race conditions in binder_thread cleanup
// Reference counting bugs on binder_node/binder_ref

// Exploitation:
// 1. Trigger UAF on binder_node/binder_ref
// 2. Reclaim with controlled data (pipe_buffer, msg_msg)
// 3. Corrupt function pointer or linked list
// 4. Trigger use → kernel RIP control
```

#### GPU Driver Exploitation
```c
// Mali GPU (ARM) example:
// 1. Allocate GPU memory regions
// 2. Trigger UAF via race in memory mapping/unmapping
// 3. Reclaim freed GPU memory object with controlled data
// 4. Use corrupted object to get kernel R/W

// Adreno (Qualcomm) example:
// KGSL memory management bugs
// Map/unmap race → page UAF
// Corrupt page tables → arbitrary physical memory access
```

#### ION/DMA-BUF Exploitation
```c
// ION: Android memory allocator (deprecated but still present)
// DMA-BUF: replacement for ION
// Shared memory between user/kernel/GPU

// Attack: corrupt DMA-BUF metadata
// If you can control physical page mapping → kernel R/W
// Race between map and use → TOCTOU on physical pages
```

### Privilege Escalation Chains

#### App → System (uid 1000)
```
# Target: system_server or system-uid services
# Via: Binder transaction bugs, intent handling, content provider
# Result: access to all user data, install packages, control device

# Common path:
# 1. Find bug in system_server's Binder interface
# 2. Achieve code execution in system_server
# 3. Now running as system (uid 1000) with broad SELinux permissions
```

#### App → Root (uid 0)
```
# Target: root-running daemons (vold, installd) or kernel
# Via: Binder to root service, or kernel exploit
# Result: full device control (within SELinux constraints)

# With kernel exploit:
# 1. Overwrite current task's cred (uid=0, gid=0)
# 2. Modify SELinux enforcing → permissive
# 3. Or: patch selinux_enforcing in kernel memory
```

#### App → Kernel
```
# Direct kernel exploitation from app context
# Via: GPU driver IOCTL, Binder driver bug, /proc interface
# Result: arbitrary kernel code execution

# Post-exploitation:
# 1. Disable SELinux: selinux_enforcing = 0
# 2. Escalate creds: commit_creds(prepare_kernel_cred(0))
# 3. Escape namespace if in container/profile
```

## Android-Specific Mitigations

### Seccomp-BPF
```
# Android apps have seccomp filter limiting available syscalls
# Zygote installs filter before forking app processes
# Blocked: most kernel interfaces, raw socket, ptrace

# Check filter:
adb shell cat /proc/<pid>/status | grep Seccomp
# Seccomp: 2 (filter mode)

# Dump filter rules:
# seccomp-tools dump -p <pid>
# Or extract from zygote source: bionic/libc/seccomp/

# Bypass: exploit allowed syscalls only
# Or: kernel exploit bypasses seccomp entirely
```

### MTE (Memory Tagging Extension) — ARMv8.5+
```
# Hardware memory tagging: 4-bit tag per 16-byte granule
# Pointer tag must match memory tag on access
# Catches: UAF (freed memory retagged), OOB (adjacent has different tag)

# Bypass strategies:
# 1. Brute force: 16 possible tags, 1/16 chance per attempt
# 2. Use-before-retag: exploit before allocator changes tag
# 3. Speculative bypass: speculative execution may ignore tag mismatch
# 4. Tag oracle: side-channel to determine correct tag
# 5. Target non-MTE memory: not all allocations are tagged

# Check if MTE enabled:
adb shell cat /proc/<pid>/smaps | grep mt  # [mt] flag on tagged pages
```

### CFI (Control Flow Integrity)
```
# Android kernel compiled with Clang CFI
# Validates indirect call targets match expected type
# Violation → kernel panic

# Bypass:
# 1. Data-only attacks (don't corrupt code pointers)
# 2. Find valid call target that's useful (e.g., calls function pointer from data)
# 3. Corrupt data pointer that's later used as call target indirectly
# 4. JIT pages (if accessible from kernel context)
```

## Post-Exploitation

### Disable SELinux
```c
// From kernel context:
// Find selinux_enforcing variable
// Write 0 to disable enforcement

// Alternative: modify loaded policy
// Or: change process SELinux context to permissive domain
```

### Persistent Root
```
# After kernel exploit:
# 1. Remount /system as R/W (or modify /data)
# 2. Install su binary
# 3. Patch boot image for persistence across reboot
# Or: use Magisk-style systemless root (modify boot.img ramdisk)
```

### Data Extraction
```bash
# With root + SELinux disabled:
# Access any app's private data
ls /data/data/<package>/
# Access keystore
ls /data/misc/keystore/
# Dump credential storage
sqlite3 /data/system/locksettings.db
# Access encrypted storage (need FBE keys)
```

## Tools

| Tool | Purpose |
|------|---------|
| adb + root shell | Device interaction |
| Frida | Dynamic instrumentation |
| Ghidra / IDA | Driver/binary RE |
| syzkaller (Android) | Kernel fuzzer with Android support |
| binder_trace | Binder transaction tracing |
| strace / ltrace | Syscall/library tracing |
| crash (Android) | Kernel crash analysis |
| kASLR bypass | Android-specific KASLR defeats |
| checkpolicy | SELinux policy analysis |
| sepolicy-inject | Modify SELinux policy |

## Testing Setup

```bash
# Android emulator with kernel debugging
emulator -avd <name> -kernel <custom_bzImage> -show-kernel -qemu -s

# Or: physical device with custom kernel (unlocked bootloader)
# Build kernel with KASAN, debug symbols
# Flash: fastboot flash boot boot-debug.img

# GDB attach to emulator kernel
adb forward tcp:1234 tcp:1234
gdb vmlinux -ex "target remote :1234"

# Useful kernel configs for exploit dev:
# CONFIG_KASAN=y (memory error detection)
# CONFIG_DEBUG_INFO=y (symbols)
# CONFIG_RANDOMIZE_BASE=n (disable KASLR for dev)
```
