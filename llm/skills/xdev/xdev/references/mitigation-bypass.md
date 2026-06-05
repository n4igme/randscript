# Mitigation Bypass Techniques

## ASLR (Address Space Layout Randomization)

### Info Leak Techniques
```
# Most reliable ASLR bypass: leak a runtime address, calculate base

# Stack leak → defeat stack ASLR
# Heap leak → defeat heap ASLR
# Code pointer leak → defeat PIE/library ASLR
# Kernel pointer leak → defeat KASLR

# Common leak sources:
# - Uninitialized memory (stack/heap contains stale pointers)
# - Format string (%p reads stack)
# - OOB read (read adjacent pointer)
# - UAF read (freed object contains allocator metadata / old pointers)
# - Error messages (verbose errors print addresses)
# - /proc/self/maps (if readable — Android pre-hardening)
# - Timing side channels (cache, branch prediction)
```

### Partial Overwrite
```
# ASLR randomizes base but preserves page offset (low 12 bits)
# Overwrite only low 1-2 bytes of pointer → limited brute force

# Example: return address on stack
# Original: 0x7f1234567890
# Overwrite low 2 bytes: 0x7f12345678XX (256 possibilities for 1 byte)
# If target is in same page/nearby → no brute force needed

# Heap pointers: low 12 bits fixed within page
# Partial overwrite of heap pointer → redirect within same page
```

### Brute Force
```
# 32-bit: ASLR entropy is low (8-16 bits for libraries)
# ~256-65536 attempts to guess correct base
# Feasible for: forking servers (address space preserved across fork)

# 64-bit: too much entropy for direct brute force
# But: partial overwrite reduces to 4-12 bits in some cases
# PIE on x86_64: typically 28 bits of entropy (not feasible to brute)
```

### Fixed Addresses
```
# Some regions are not randomized:
# - vsyscall page (0xffffffffff600000 on older Linux — fixed, mapped RX)
# - vDSO (randomized but can be leaked)
# - Non-PIE binaries (base at 0x400000)
# - Large mmap allocations (may be predictable on 32-bit)
# - SharedUserData on Windows (0x7ffe0000 — always mapped)
```

## DEP / NX (Data Execution Prevention)

### ROP (Return-Oriented Programming)
```
# Chain existing code snippets ending in RET
# Each "gadget" performs small operation then returns to next gadget
# Turing-complete: can perform any computation via ROP

# Strategy: ROP to mprotect/VirtualProtect → make buffer RWX → jump to shellcode
# Or: pure ROP chain that does everything (execve, connect, etc.)

# Key gadgets needed:
# pop rdi; ret          — load first argument
# pop rsi; ret          — load second argument
# pop rdx; ret          — load third argument (rare, use alternative)
# pop rcx; ret          — Windows first arg
# syscall; ret          — trigger syscall
# ret                   — NOP slide in ROP
```

### ret2libc
```python
# Call libc functions directly (no shellcode needed)
# system("/bin/sh") — simplest
# execve("/bin/sh", NULL, NULL) — more reliable (no shell features needed)
# mprotect(addr, size, PROT_RWX) → then jump to shellcode

from pwn import *
libc = ELF('./libc.so.6')
# After leaking libc base:
system = libc_base + libc.symbols['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))
```

### JIT Spray
```
# JavaScript/JIT engines create RWX pages with predictable content
# Embed shellcode as immediate values in JIT-compiled code
# Example: var x = 0x90909090 ^ 0x90909090 ^ ... (XOR operations)
# JIT compiles to: xor eax, 0x90909090 (contains NOP sled as immediate)
# Jump into middle of instruction → execute embedded shellcode

# Modern mitigations: W^X for JIT (separate RW and RX mappings)
# Bypass: corrupt JIT page permissions, or use JIT as gadget source
```

### Signal Frame (SROP — Sigreturn-Oriented Programming)
```python
# sigreturn syscall restores ALL registers from signal frame on stack
# Forge fake signal frame → control all registers + RIP in one gadget

from pwn import *
frame = SigreturnFrame()
frame.rax = 59          # execve
frame.rdi = binsh_addr  # "/bin/sh"
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret # syscall; ret gadget
frame.rsp = new_stack

# ROP: set rax=15 (sigreturn) → syscall → kernel restores frame → execve
payload = p64(pop_rax) + p64(15) + p64(syscall_ret) + bytes(frame)
```

## Stack Canary Bypass

### Leak Canary
```
# Format string: %<offset>$p to read canary from stack
# OOB read: read canary from adjacent buffer
# Byte-by-byte brute force (forking server): try each byte, no crash = correct

# Canary properties:
# - Random per-process (set at exec time)
# - Same for all threads in process
# - Starts with \x00 (null byte) on Linux x86_64
# - Located at [rbp-8] or [rsp+offset] depending on frame layout
```

### Overwrite Past Canary
```
# If you can write to specific offset without sequential overflow:
# - Write-what-where primitive (skip canary, write return address)
# - Array index overflow (arr[controlled_index] = value)
# - Partial overwrite of saved RBP (frame pointer overwrite)
#   → on function return, caller's RSP is corrupted → control RIP on next ret
```

### Thread-Local Canary Overwrite
```
# Canary stored in TLS (fs:[0x28] on x86_64 Linux)
# If you have arbitrary write: overwrite TLS canary to match your overflow
# Then stack check passes even with corrupted canary on stack
# TLS location: pthread struct, typically at high address near stack
```

## CFI (Control Flow Integrity)

### Forward-Edge CFI Bypass
```
# CFI validates indirect calls match expected type signature
# Bypass: find valid target with useful side effects

# Clang CFI: checks target is valid function of correct type
# Counterfeit Object-Oriented Programming (COOP):
#   Chain calls to virtual methods on fake objects
#   Each call is "valid" (correct vtable type) but does attacker's bidding

# Microsoft CFG: bitmap of valid call targets (function entry points)
# Bypass: call any valid function (VirtualProtect, LoadLibrary, etc.)
# Or: corrupt CFG bitmap (requires arbitrary write to ntdll region)
```

### Backward-Edge (Shadow Stack / CET)
```
# Intel CET Shadow Stack: hardware-maintained return address copy
# ROP breaks because shadow stack doesn't match corrupted return address

# Bypass:
# 1. Don't use ROP — use forward-edge attacks (JOP, COOP, data-only)
# 2. Corrupt shadow stack itself (if writable from exploit context)
# 3. Signal frame manipulation (sigreturn may update shadow stack)
# 4. Exception handling (longjmp, C++ exceptions may desync shadow stack)
# 5. Switch to thread without CET enabled
```

## SMEP / SMAP (Kernel)

### SMEP Bypass
```
# SMEP: kernel can't execute user-mode pages
# Bypass options:
# 1. Kernel ROP (all gadgets from kernel text / modules)
# 2. Flip CR4.SMEP bit: mov cr4, <value_without_smep>
#    Gadget: mov cr4, rdi; ret (or equivalent)
#    Then execute user-mode shellcode
# 3. physmap spray: kernel maps all physical memory at known offset
#    Write shellcode to user page → execute via physmap address (kernel VA)
# 4. ret2dir: similar to physmap, use direct-mapped region
```

### SMAP Bypass
```
# SMAP: kernel can't read/write user-mode pages
# Bypass options:
# 1. copy_from_user / copy_to_user (legitimate kernel functions)
#    ROP to copy_from_user(kernel_buf, user_buf, size)
# 2. STAC instruction (set AC flag → temporarily disable SMAP)
#    Find stac gadget in kernel
# 3. Use only kernel memory for exploit data (spray into kernel heap)
# 4. Pipe/socket buffers: user writes data → kernel copies to kernel memory
#    Then use kernel address of that data
```

## KASLR Bypass

### Kernel Info Leaks
```bash
# /proc/kallsyms (if kptr_restrict=0 or root)
cat /proc/kallsyms | head

# dmesg (may contain kernel pointers)
dmesg | grep -E '0x[0-9a-f]{12,}'

# /sys/kernel/notes (build ID → identify exact kernel)
# Uninitialized kernel memory returned to userspace
# eBPF verifier bugs (leak kernel pointers via maps)
```

### Side Channels
```
# Prefetch timing: prefetch kernel address, measure time
#   Mapped page: fast prefetch
#   Unmapped: slow (TLB miss)
#   → binary search for kernel base

# EntryBLEED (CVE-2022-4543): syscall entry timing varies with KASLR offset
# TSX (if available): aborted transaction timing reveals valid mappings
# Branch prediction: train predictor on kernel address, measure user-mode effect
```

### Partial Overwrite (Kernel)
```
# Kernel text is 2MB-aligned → low 21 bits are fixed
# If you can corrupt low bytes of kernel pointer:
# Only need to guess bits [21:28] or so (128-256 possibilities)
# Feasible with retry if exploit is non-destructive on failure
```

## Sandbox Escape

### Linux Seccomp Bypass
```
# Seccomp-BPF filters syscalls — can't be removed once installed
# Bypass strategies:
# 1. Use allowed syscalls creatively
#    (e.g., if write() allowed → write to /proc/self/mem)
# 2. Exploit kernel bug (seccomp is userspace policy, kernel bypass = escape)
# 3. Race condition in filter installation
# 4. Confused deputy: make unsandboxed process do your bidding via IPC

# Check filter:
seccomp-tools dump ./binary
# Shows allowed/blocked syscalls
```

### Chrome Sandbox Escape
```
# Chrome renderer is sandboxed (seccomp + namespaces + no filesystem)
# Escape via: Mojo IPC bugs to browser process
# Browser process is unsandboxed (or less sandboxed)

# Pattern:
# 1. Renderer exploit (V8 bug → RCE in renderer)
# 2. Mojo IPC vulnerability (type confusion, UAF in IPC handler)
# 3. Browser process code execution (unsandboxed)
```

## Modern Mitigations Summary

| Mitigation | Protects Against | Bypass Difficulty |
|-----------|-----------------|-------------------|
| ASLR | Known addresses | Low (with info leak) |
| DEP/NX | Code injection | Low (ROP) |
| Stack Canary | Stack overflow | Medium (leak or brute) |
| RELRO (Full) | GOT overwrite | Medium (target other pointers) |
| PIE | Code address prediction | Low (with info leak) |
| CFI (forward) | Indirect call hijack | Medium-High |
| CET/Shadow Stack | ROP | High (data-only attacks) |
| PAC (ARM64) | Pointer corruption | High (oracle or speculation) |
| MTE (ARM64) | Memory safety bugs | Medium (brute force 4 bits) |
| SMEP/SMAP | ret2usr | Medium (kernel ROP) |
| KASLR | Kernel address prediction | Medium (side channels) |
| Sandbox | Process escape | High (needs separate bug) |
