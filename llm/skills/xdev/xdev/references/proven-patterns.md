# Proven Exploit Development Patterns

Techniques that have produced working exploits in past engagements or CTFs.

## Linux Userland (glibc)

| Pattern | Trigger | Technique | Yield |
|---------|---------|-----------|-------|
| Tcache poison → __free_hook | UAF on chunk ≤0x410 (glibc <2.32) | Free twice, overwrite fd → __free_hook, write system | Shell |
| House of Force | Heap overflow into top chunk | Corrupt top chunk size → malloc returns arbitrary addr | Arbitrary write |
| Fastbin dup → __malloc_hook | Double free in fastbin range | Classic dup, land on __malloc_hook with one_gadget | Shell |
| Safe-linking bypass | Known heap base + UAF (glibc 2.32+) | XOR fd with (pos>>12), reconstruct mangled pointer | Arbitrary alloc |
| Partial overwrite ASLR | 1-2 byte overflow on pointer | Overwrite LSB to redirect within same page/library | Code exec (brute) |

## Linux Kernel

| Pattern | Trigger | Technique | Yield |
|---------|---------|-----------|-------|
| msg_msg spray | UAF/OOB in kmalloc-64 to kmalloc-4k | msgsnd to reclaim freed object, read/write OOB | Info leak + write |
| pipe_buffer overwrite | UAF in kmalloc-1k | splice to create pipe_buffer, corrupt page pointer | Arbitrary page R/W |
| modprobe_path overwrite | Arbitrary kernel write primitive | Write to modprobe_path, trigger unknown binfmt | Root shell |
| setuid cred spray | UAF near cred struct | Fork spray to place cred, corrupt uid fields | Privilege escalation |
| userfaultfd stall | Race condition in kernel | Register uffd on page, stall copy_from_user mid-operation | Widen race window |

## ARM64 / iOS / macOS

| Pattern | Trigger | Technique | Yield |
|---------|---------|-----------|-------|
| PAC signing gadget | Need code exec on A12+ | Find PACIZA/AUTIZA gadget pair, sign custom pointer | Bypass PAC |
| Zone spray via mach msg | UAF in kalloc zone | ool_ports in mach messages to reclaim freed zone chunk | Kernel R/W |
| IOKit object spray | UAF in IOKit driver | Create IOKit user clients to spray controlled objects | vtable hijack |
| JIT page abuse | WebKit JIT RWX pages | Write shellcode into JIT region via addrof/fakeobj | Code exec |

## Windows

| Pattern | Trigger | Technique | Yield |
|---------|---------|-----------|-------|
| Named pipe spray | Pool UAF/OOB | NtCreateNamedPipeFile to spray NonPagedPool | Pool corruption |
| Token steal via pool | Kernel pool overflow | Overwrite adjacent _TOKEN object, copy SYSTEM token | EoP |
| LFH bucket prediction | Userland UAF in LFH | Fill LFH bucket, free target, reallocate with controlled data | Vtable hijack |
| TypedArray confusion (Edge/Chrome) | JIT type confusion | Construct addrof/fakeobj via ArrayBuffer backing store | Browser RCE |

## Cross-Platform Reliability Tricks

| Trick | When | Effect |
|-------|------|--------|
| Fork-before-exploit | Kernel exploits that panic on failure | Child crashes, parent survives to retry |
| Heap feng shui warmup | Heap state is unpredictable | Allocate+free pattern to normalize allocator state |
| Multi-attempt brute | Partial ASLR bypass (12-bit entropy) | 1/4096 per attempt, ~4000 tries for reliable hit |
| Timing side-channel leak | Need info leak, no direct read | Measure access time to distinguish mapped vs unmapped |
| Ret-slide (ret sled) | Imprecise stack control | Chain of `ret` gadgets absorbs alignment errors |

## Anti-Patterns (Don't Do This)

- Don't assume heap layout from a single run — always spray first
- Don't hardcode offsets without documenting kernel/libc version
- Don't skip info leak phase — blind exploitation wastes hours
- Don't test kernel exploits without snapshots — you WILL panic
- Don't use `system("/bin/sh")` in exploits where stdin is closed — use reverse shell or `execve` directly
