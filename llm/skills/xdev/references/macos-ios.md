# macOS / iOS Exploitation

## Attack Surface

### XNU Kernel
```
# Mach IPC (mach_msg): primary kernel attack surface
# IOKit drivers: hardware abstraction, complex C++ objects
# BSD syscalls: file system, networking, process management
# Sysctl: kernel parameter interface
# MIG (Mach Interface Generator): auto-generated message handlers
```

### Mach Ports
```
# Mach ports = kernel IPC mechanism, capability-based
# Every resource is a port: tasks, threads, memory, devices
# Port rights: send, receive, send-once
# Key ports:
#   task_self: full control over own process
#   host_priv: privileged host operations (root only)
#   kernel_task: god-mode (direct kernel memory access)

# Exploitation value: steal/forge port rights → escalate privileges
```

### IOKit Drivers
```
# User-space accessible via IOServiceOpen → IOConnectCallMethod
# Complex C++ inheritance → type confusion opportunities
# External methods table: array of {function, input_count, output_count}
# Overflow in external method → kernel code execution

# Enumerate available drivers:
# ioreg -l | grep -A5 "IOUserClient"
# List external methods: reverse the driver binary
```

## Exploitation Techniques

### Mach Port UAF / Type Confusion
```c
// Pattern: port deallocated but reference retained in message/voucher
// Reallocate port memory with controlled data
// When original reference is used → controlled kernel object

// Mach voucher exploitation (common pattern):
// 1. Create mach voucher with specific attributes
// 2. Trigger UAF on voucher's internal port
// 3. Reallocate with controlled data (e.g., via OOL ports in message)
// 4. Trigger use of dangling reference → fake kernel object
```

### IOKit Heap Overflow
```c
// IOConnectCallMethod with oversized input
// Overflow into adjacent IOKit object on kalloc heap

// kalloc zones (iOS/macOS):
// kalloc.16, kalloc.32, kalloc.48, kalloc.64, ...
// Objects of same zone are adjacent in memory
// Spray IOKit objects of target size → overflow into them

kern_return_t kr = IOConnectCallMethod(
    connection,
    selector,           // external method index
    scalar_input, scalar_count,
    struct_input, struct_input_size,  // overflow here
    scalar_output, &scalar_output_count,
    struct_output, &struct_output_size
);
```

### Zone Spray (kalloc)
```c
// iOS/macOS kernel uses zone allocator (similar to Linux SLUB)
// Spray objects of target size to fill zone pages

// Common spray primitives:
// - OOL mach message data (arbitrary size, arbitrary content)
// - IOKit properties (OSString, OSData — controlled size/content)
// - Pipe buffers
// - Socket options

// OOL message spray:
mach_msg_header_t msg;
msg.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
// Add OOL descriptor with controlled data and size
// Send to holding port (don't receive yet — keeps allocation alive)
```

### Kernel Task Port (tfp0)
```c
// Ultimate goal on iOS: get send right to kernel_task port
// With tfp0: mach_vm_read/write kernel memory directly from userspace
// Full kernel R/W → patch anything, disable all protections

// Modern iOS (15+): tfp0 is heavily restricted
// Alternative: construct kernel R/W primitive without tfp0
// Use corrupted IOKit object or fake port to read/write kernel memory
```

## PAC (Pointer Authentication) Bypass

### PAC Overview
```
# ARM64e (A12+, M1+): pointers signed with context-specific keys
# PAC keys: IA (instruction), IB, DA (data), DB, GA (generic)
# Signing: PACIA, PACDA, etc. — adds signature to upper bits
# Verification: AUTIA, AUTDA — traps if signature invalid

# Signed pointers: function pointers, return addresses, vtables
# Unsigned: data pointers (usually), some legacy code paths
```

### PAC Bypass Techniques
```c
// 1. PAC Oracle: find code that signs attacker-controlled value
//    If you can call PACIA with your pointer + context → get valid PAC
//    Look for: signing gadgets in JIT, IOKit method dispatch

// 2. Context confusion: same pointer signed with different context
//    PAC(ptr, contextA) ≠ PAC(ptr, contextB)
//    But if you find where contextA is reused incorrectly...

// 3. PAC-less code paths: not all code uses arm64e
//    Legacy libraries, third-party code may use arm64 (no PAC)
//    Corrupt pointers in non-PAC code → pivot to PAC-signed context

// 4. Signing gadget chain:
//    Find: ldr x0, [x1]; pacia x0, x2; str x0, [x3]; ret
//    Control x1 (pointer to sign), x2 (context), x3 (where to store)
//    → forge arbitrary signed pointer

// 5. PACMAN (speculative): speculative execution ignores PAC failure
//    Side-channel to determine correct PAC value
//    Requires specific microarchitectural conditions

// 6. dyld interposing abuse (real-world, iOS 18.x):
//    - Force dlopen of framework via corrupted ImageBitmap class pointer
//    - Inject interpose tuples into dyld RuntimeState
//    - dyld signs replacement pointers with PACIA during interposing
//    - Harvest signed pointers from softLink tables after dlopen completes
//    - Get signed dlopen/dlsym/signPointer → forge any pointer
//    See: references/ios-webkit-chain.md (Stage 2)
```

## PPL (Page Protection Layer) Bypass

```
# PPL: kernel code integrity on iOS
# Certain kernel pages marked as PPL-protected
# Only PPL-mode code can modify them (trust cache, AMFI, code signing)
# Even kernel exploit can't directly patch PPL-protected pages

# Bypass strategies:
# 1. Corrupt PPL data structures from non-PPL context
#    (if PPL reads data from non-protected memory)
# 2. Race condition in PPL entry/exit
# 3. Find bug within PPL code itself
# 4. Modify page tables to remap PPL pages (if PTE not PPL-protected)
```

## Sandbox Escape

### macOS Sandbox
```c
// App Sandbox restricts file access, network, IPC
// Escape via: XPC service vulnerabilities, Mach port leaks
// Check sandbox profile: sandbox-exec -p "(version 1)(allow default)"

// Common escape vectors:
// 1. Vulnerable XPC service (runs outside sandbox)
//    Find: launchctl list | grep -i <service>
//    Fuzz: send malformed XPC messages
// 2. Mach port name collision / confusion
// 3. Symlink/hardlink race in sandbox-accessible paths
// 4. Kernel vulnerability (sandbox is userspace policy)
```

### iOS Sandbox
```
# iOS apps are heavily sandboxed (container + entitlements)
# Escape vectors:
# 1. Kernel exploit (bypass all userspace restrictions)
# 2. IPC to unsandboxed process (e.g., installd, mediaserverd)
# 3. Exploit entitled process (has more capabilities)
# 4. WebKit → kernel chain (remote jailbreak)
```

## Jailbreak Chain (iOS)

**See also:** `references/ios-webkit-chain.md` for a complete real-world Safari RCE → sandbox escape → LPE chain with code patterns.

```
# Modern jailbreak requires multiple bugs chained:
# 1. Initial code execution (WebKit bug, app-level bug, or physical)
# 2. Sandbox escape (IPC to privileged service, or kernel bug)
# 3. Kernel exploit (UAF, type confusion → kernel R/W)
# 4. PAC bypass (forge signed pointers for code execution)
# 5. PPL bypass (patch trust cache to load unsigned code)
# 6. Persistence (optional: survive reboot)

# Post-exploitation:
# - Patch AMFI to allow unsigned code
# - Modify trust cache to add your code hash
# - Remount rootfs as R/W (rootful) or use rootless approach
# - Install package manager (Sileo, Zebra)
```

## Tools

| Tool | Purpose |
|------|---------|
| lldb | macOS/iOS debugger |
| Ghidra / IDA | Kernel/driver RE |
| jtool2 / ipsw | iOS binary analysis, kernel cache extraction |
| iometa | IOKit metadata extraction |
| ktrw | iOS kernel debugger (requires JTAG) |
| checkra1n | A5-A11 bootrom exploit (hardware) |
| Corellium | iOS virtualization for research |
| frida (macOS) | Dynamic instrumentation |
| ProcessMonitor | macOS syscall tracing |
| kdv | Kernel debug via virtualization |

## Kernel Cache Analysis

```bash
# Extract kernelcache from IPSW
unzip -p firmware.ipsw kernelcache.* > kernelcache.im4p
# Decompress (img4lib or ipsw tool)
ipsw kernel dec kernelcache.im4p

# Find symbols
nm kernelcache | grep commit_creds
# Or use ipsw symbolicate

# Extract IOKit driver
ipsw kernel kmutil kernelcache --kext com.apple.iokit.IOHIDFamily -o ./

# Find PAC signing gadgets
objdump -d kernelcache | grep -E "paci[ab]|pacd[ab]|auti[ab]|autd[ab]"
```
