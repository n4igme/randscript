# Unknown Binary Triage

Methodology for approaching an unfamiliar binary. 15-minute triage before deep analysis.

## Step 1: Identify (2 min)

```bash
file ./binary
readelf -h ./binary 2>/dev/null || otool -h ./binary
strings ./binary | head -20
```

Key info: architecture, endianness, stripped?, static/dynamic, OS.

## Step 2: Metadata (3 min)

```bash
# Sections and segments
readelf -S ./binary          # ELF
otool -l ./binary            # Mach-O

# Imports — what does it call?
readelf -d ./binary | grep NEEDED   # shared libs
r2 -q -c 'ii' ./binary             # imports list

# Exports — what does it offer?
r2 -q -c 'iE' ./binary

# Symbols (if not stripped)
nm ./binary | grep -i " T "   # text symbols
```

## Step 3: Strings (3 min)

```bash
# Categorized string extraction
strings -n 6 ./binary | sort -u > /tmp/strings.txt

# High-value patterns
grep -iE 'http|api|key|secret|password|token|flag' /tmp/strings.txt
grep -iE '\.com|\.io|\.net|/api/' /tmp/strings.txt
grep -iE 'error|fail|denied|invalid' /tmp/strings.txt
grep -iE 'AES|RSA|SHA|MD5|HMAC' /tmp/strings.txt

# Wide strings (UTF-16, common in Windows)
strings -el ./binary | grep -iE 'password|key|http'
```

## Step 4: Quick Dynamic (5 min)

```bash
# Trace syscalls
strace ./binary 2>&1 | head -100         # Linux
dtruss ./binary 2>&1 | head -100         # macOS

# Network activity
strace -e network ./binary 2>&1
ltrace ./binary 2>&1 | head -50          # library calls

# Run in sandbox if untrusted
firejail ./binary                        # Linux
sandbox-exec -p '(deny default)' ./binary  # macOS
```

## Step 5: Decide Tool

| Binary type | Best tool | Why |
|-------------|-----------|-----|
| Small ELF (<1MB), has symbols | r2 | Fast, scriptable |
| Large ELF, stripped | Ghidra | Better decompilation |
| Windows PE | IDA or Ghidra | Best PE support |
| ARM64 stripped .so | Ghidra | Superior ARM64 decompiler |
| Mach-O (iOS/macOS) | Ghidra or IDA | Both good |
| Go binary | Ghidra + GoReSym | Restore symbols first |
| Rust binary | Ghidra | Demangler handles Rust |
| .NET assembly | dnSpy / ILSpy | Native tools, no RE needed |
| Java JAR | JADX / JD-GUI | Decompile directly |
| Python bytecode | uncompyle6 / decompyle3 | Direct decompile |

## Quick Triage Checklist

```
[ ] Architecture + OS identified
[ ] Static or dynamic linked?
[ ] Stripped or symbols present?
[ ] Language identified (C/C++/Go/Rust/other)
[ ] Dangerous imports found? (system, exec, eval, connect)
[ ] Hardcoded strings of interest?
[ ] Network behavior observed?
[ ] File system access patterns?
[ ] Crypto usage identified?
[ ] Tool selected for deep dive
```

## Language Detection Heuristics

| Signal | Language |
|--------|----------|
| `runtime.gopanic`, `go.string.*` | Go |
| `_Unwind_Resume`, `std::` | C++ |
| `core::panicking`, `alloc::` | Rust |
| `PyObject`, `Py_Initialize` | Embedded Python |
| `_objc_msgSend`, `NSObject` | Objective-C |
| `JNI_OnLoad`, `Java_` prefix | JNI (Android native) |
| `mono_`, `il2cpp_` | Unity/.NET |
| `v8::Isolate`, `node::` | Node.js native addon |

## Pitfalls

- Go binaries are huge (10-50MB) — don't panic, run GoReSym first
- Stripped C++ with templates: Ghidra decompilation is noisy but functional
- UPX-packed: `upx -d binary` before analysis (check `strings | grep UPX`)
- .NET obfuscated: de4dot first, then dnSpy
- Anti-analysis: if binary exits immediately, check for debugger/VM detection
