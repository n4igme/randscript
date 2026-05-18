---
name: vuln-memory
description: "Step 3p of bug bounty workflow. Scan for memory safety vulnerabilities (buffer overflow, use-after-free, format strings) in C/C++/Rust/native code. Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Step 3p: Memory Safety Vulnerabilities

Scan for memory corruption vulnerabilities in C, C++, Rust unsafe blocks, native extensions, and FFI bindings.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Applicability

This scanner applies when the codebase contains:
- C/C++ source files (`.c`, `.cpp`, `.h`, `.hpp`)
- Rust `unsafe` blocks
- Native Node.js addons (N-API, node-gyp, `.node` files)
- Python C extensions (`.pyx`, `cffi`, `ctypes`)
- Go `unsafe` package or CGo
- WebAssembly modules compiled from C/C++/Rust
- JNI (Java Native Interface) code

If none of these are present, report "No native/unsafe code found — scanner not applicable" and skip.

## Vulnerability Patterns

### Buffer Overflow (Stack & Heap)
- `strcpy`, `strcat`, `sprintf`, `gets` without bounds checking
- Fixed-size buffers with user-controlled input length
- Off-by-one errors in loop bounds
- Integer overflow leading to undersized allocation

**Grep patterns**: `strcpy`, `strcat`, `sprintf`, `gets(`, `scanf(`, `memcpy(`, `memmove(`, `alloca(`, `char [`, `malloc(`, `realloc(`, `buffer`, `buf[`

### Use-After-Free
- Pointer used after `free()`/`delete`
- Dangling references after container reallocation
- Callback/closure capturing freed memory
- Double-free conditions

**Grep patterns**: `free(`, `delete `, `delete[]`, `release(`, `destroy(`, `drop(`, `weak_ptr`, `shared_ptr`, `unique_ptr`

### Format String Vulnerabilities
- User input passed as format string to `printf`-family functions
- Logging functions with user-controlled format
- `syslog()` with user input as first argument

**Grep patterns**: `printf(`, `fprintf(`, `sprintf(`, `snprintf(`, `syslog(`, `NSLog(`, `format(`, `fmt::format`

### Integer Overflow → Memory Corruption
- Multiplication for allocation size without overflow check
- User-controlled size cast to smaller type before allocation
- Signed/unsigned comparison leading to large allocation or negative index
- Length calculation wrapping around

**Grep patterns**: `size_t`, `uint32_t`, `int32_t`, `(int)`, `(unsigned)`, `(size_t)`, `sizeof(`, `len *`, `count *`, `nmemb`

### Out-of-Bounds Access
- Array index from user input without bounds check
- Pointer arithmetic with user-controlled offset
- Missing null terminator leading to over-read
- Struct field access on undersized buffer

**Grep patterns**: `[i]`, `[index]`, `[offset]`, `ptr +`, `*(ptr`, `->`, `memcmp(`, `strncmp(`, `strlen(`

### Rust Unsafe / FFI Boundaries
- `unsafe` blocks with raw pointer dereference
- Missing lifetime validation at FFI boundary
- Transmute between incompatible types
- Unchecked slice creation from raw pointer

**Grep patterns**: `unsafe {`, `unsafe fn`, `*const`, `*mut`, `transmute`, `from_raw_parts`, `as_ptr`, `offset(`, `extern "C"`

### Native Extension Vulnerabilities
- N-API/nan buffer handling without length validation
- Python `ctypes` with user-controlled arguments
- JNI `GetStringUTFChars` without null check
- Missing error handling on native calls

**Grep patterns**: `napi_`, `Nan::`, `node::Buffer`, `ctypes`, `cffi`, `ffi`, `JNIEnv`, `GetStringUTFChars`, `NewStringUTF`

## Process

1. **Identify native code** — find all C/C++/Rust unsafe/FFI/native extension files
2. **Map user input paths** — trace how external data reaches native code (network → parsing → native function)
3. **Check bounds** — are all buffer operations bounded by validated lengths?
4. **Check lifetimes** — are pointers/references valid for their entire usage scope?
5. **Check arithmetic** — can size/length calculations overflow before allocation?
6. **Assess exploitability** — can the corruption be controlled for code execution or info leak?

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Memory Safety

**Date**: {date}
**Scanner**: vuln-memory

## Findings

### VULN-MEM-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Category**: {Buffer Overflow / Use-After-Free / Format String / Integer Overflow / OOB Access / Unsafe FFI}
**Location**: `{file}:{line}`
**CWE**: CWE-{120|416|134|190|125|787}

**Description**:
{What the vulnerability is}

**Vulnerable Code**:
```{lang}
{code snippet}
`` `

**Attack Scenario**:
1. {Step-by-step exploitation}

**Proof of Concept**:
{Malicious input triggering the corruption}

**Impact**:
{RCE, information leak, crash/DoS}

**Remediation**:
```{lang}
{fixed code}
`` `

---
```

## Rules

- **Only report if user input can reach the vulnerable code path.**
- **Check for mitigations** — ASLR, stack canaries, safe functions (`strncpy`, `snprintf`), Rust's borrow checker.
- **If no native/unsafe code exists, skip this scanner** and state it's not applicable.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
