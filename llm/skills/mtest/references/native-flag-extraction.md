# Native Flag Extraction (MHL Labs)

## Problem

MHL labs hide flags inside native `.so` libraries. The JNI function (e.g., `getflag()`) often returns a decoy string like "Success" via `NewStringUTF`, while the real flag is constructed in a .bss buffer through XOR operations on .rodata arrays.

## Detection

1. Run `strings lib*.so | grep -iE "MHL|flag|CTF|{.*}"` — if no `MHL{...}` found, flag is runtime-constructed
2. Check for `NewStringUTF` in disassembly — if it points to "Success" or generic text, that's a decoy
3. Look for multiple helper functions with XOR patterns writing to .bss addresses

## Extraction Workflow

### Step 1: Identify the target architecture

Use x86_64 variant for easiest disassembly (no Thumb mode, clear RIP-relative addressing):
```bash
objdump -d lib/x86_64/libflag.so | grep -A 50 "getflag"
```

### Step 2: Map helper functions

Look for the pattern:
```asm
leaq  <offset>(%rip), %rsi    # source array in .rodata
movl  $0x4c, %edx             # 0x4c = 76 bytes = 19 int32s
callq memcpy
...
addl  $<constant>, %ecx       # XOR constant
xorl  %ecx, %eax              # XOR operation
movb  %al, %dl                # take low byte
leaq  <buf>(%rip), %rax       # destination buffer in .bss
movb  %dl, (%rax,%rcx)        # write to buffer[i]
```

### Step 3: Identify XOR formulas

Common patterns seen in MHL native libs:
- `arr[i] ^ (i*i + constant)` — quadratic index (addl $const, %ecx after imull %reg, %reg)
- `arr[i] ^ (i*N + constant)` — linear index (imull $N, %reg, %ecx then addl)
- `buf2[i] ^ (i*2 + 1)` — reads from secondary buffer built by earlier function

Key instructions to identify formula:
- `imull %ecx, %ecx` → `i*i`
- `imull $0xf, %reg, %ecx` → `i*15`
- `shll $0x1, %ecx` then `addl $0x1` → `i*2 + 1`
- `addl $0x0c, %ecx` → constant is 0x0c

### Step 4: Dump .rodata and emulate

```python
import struct

with open('lib/x86_64/libflag.so', 'rb') as f:
    data = f.read()

# Read int32 array from identified offset
def read_arr(offset, count=19):
    return [struct.unpack_from('<i', data, offset + i*4)[0] for i in range(count)]

arr = read_arr(0xOFFSET)  # replace with actual offset

# Apply identified XOR formula
flag = bytes([(arr[i] ^ (i * MULTIPLIER + CONSTANT)) & 0xFF for i in range(18)])
print(flag.decode())
```

### Step 5: Handle multi-buffer patterns

Some labs use two buffers:
- Buffer A (0x3f60): decoy, overwritten by many functions with junk
- Buffer B (0x3fc0): real flag, written by specific function

Check which buffer `NewStringUTF` actually reads (RIP-relative `leaq` before the call). If it reads .rodata directly ("Success"), the flag is in one of the .bss buffers — identify which function writes meaningful output.

## Strings Lab Specific

- `dddff()`: src=0xa20, formula=`arr[i] ^ (i*15 + 0x0b)`, dest=0x3fc0 → `MHL{IN_THE_MEMORY}`
- `getflag()` ignores computed buffers, returns hardcoded "Success" via NewStringUTF(0xb0c)
- 10+ helper functions are pure obfuscation — overwrite buf 0x3f60 repeatedly

## Pitfalls

- NEVER assume "Success" or any plaintext string from `strings` output is the flag
- MHL labs ALWAYS use `MHL{...}` format
- File offset == VMA when first LOAD segment has vaddr=0x0 and offset=0x0 (common in Android .so)
- Use x86_64 for analysis (clearest disassembly), but verify on arm64 if needed
- Multiple functions may write to the same buffer — the LAST write before return determines content
- Some functions read FROM one buffer and write TO another — trace data flow carefully
