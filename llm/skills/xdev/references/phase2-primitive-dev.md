## Phase 2: Primitive Development

### Gate: at least one useful primitive demonstrated (read, write, or exec)

**Techniques:**

1. **Info Leak (ASLR/KASLR Defeat):**
   - Heap spray + OOB read to leak adjacent object pointers
   - UAF: read freed object's fd/bk pointers (heap base), vtable pointers (code base)
   - Side channels: timing, cache, branch prediction (speculative execution)
   - Partial overwrite: corrupt low bytes of pointer (no ASLR on low 12 bits)
   - `/proc/self/maps` if accessible (Android pre-hardening, debug builds)

2. **Arbitrary Read:**
   - Corrupted length field → OOB read
   - Fake object with controlled data pointer → read through object interface
   - Format string `%s` with controlled pointer on stack

3. **Arbitrary Write:**
   - Heap overflow into adjacent object's function pointer
   - UAF: replace freed object with controlled data, trigger virtual call
   - Format string `%n` with controlled pointer
   - Integer overflow in size → undersized allocation → heap overflow

4. **Code Execution:**
   - Overwrite return address (stack overflow)
   - Overwrite vtable/function pointer (heap corruption)
   - Overwrite GOT entry (format string / arbitrary write)
   - JIT spray (browser/JS engine targets)

5. **Heap Shaping (allocator-specific):**

   **Linux glibc (ptmalloc2):**
   - tcache: LIFO, per-thread, no integrity checks (< 2.32) → tcache poisoning trivial
   - fastbin: single-linked, size check only → fastbin dup, double-free
   - Unsorted bin: fd/bk leak → libc base. Corrupt bk → unsorted bin attack (write)

   **Linux kernel (SLUB):**
   - Cross-cache attack: free target object, reclaim slab page with different cache
   - Spray objects: `msg_msg` (variable size), `pipe_buffer` (1024), `sk_buff`, `tty_struct`
   - `userfaultfd` / `FUSE`: stall page faults to widen race windows

   **Windows (LFH / Segment Heap):**
   - LFH: randomized within bucket, spray heavily (256+ objects) for adjacency
   - Segment heap (Win10+): VS/LFH subsegments, less predictable → need larger spray
   - Pool (kernel): `NtCreateNamedPipeFile`, `IoCompletionPort` for pool spray

   **Browser (PartitionAlloc / jemalloc):**
   - PartitionAlloc (Chrome/WebKit): bucket-based, same-size guarantee → spray same-type objects
   - jemalloc (Firefox): region-based, predictable adjacency with large sprays
   - ArrayBuffer/TypedArray for controlled data placement

   **iOS/macOS (kalloc / zone):**
   - Zone allocator: spray with mach messages (`mach_msg` OOL descriptors)
   - kalloc zones: size-segregated, spray IOKit objects or `ipc_kmsg`
   - Cross-zone: free in one zone, reclaim from another (harder post-iOS 15)

   ```
   # General strategy:
   # 1. Spray objects of target size to fill holes
   # 2. Free strategic objects to create holes
   # 3. Trigger vulnerable allocation into the hole
   # 4. Adjacent object is now your target for corruption
   ```

**Reference:** `references/linux-userland.md`, `references/linux-kernel.md`, `references/arm64-exploitation.md`, `references/ios-webkit-chain.md`

### Fuzzing Tools (integration points)

| Target | Tool | Notes |
|--------|------|-------|
| General userspace | AFL++, libFuzzer | Instrumented fuzzing for known parsers |
| Windows kernel | WinAFL | IOCTL-driven fuzzing |
| Browser JS engine | js-fuzz, Fuzzilli | JIT-focused, generates valid JS |
| Android kernel | syzkaller | Directed at Android configs |
| Network protocols | boofuzz, Peach Fuzzer | Stateful protocol fuzzing |
| File formats | PE-sieve, binbloom | Format-aware corpus generation |

---
