# Native Library Reverse Engineering via MCP

## Overview

When mobile apps use native libraries (.so files), combine two MCP-connected tools:
- **jadx-mcp-server** — Java/Kotlin layer (APK decompilation, manifest, smali, xrefs)
- **GhidraMCP** — Native layer (ARM64/ARM32 .so decompilation, disassembly, xrefs)

Both expose tools to Hermes, enabling LLM-assisted RE without leaving the terminal.

## Setup

### jadx-mcp-server (Java layer)

Hermes MCP config (already added):
```yaml
jadx-mcp-server:
  command: uv
  args: [run, /opt/jadx-mcp-server/jadx_mcp_server.py]
```

Requires: JADX GUI open with jadx-ai-mcp plugin active + APK loaded.

Key tools (32 total):
- `fetch_current_class` — currently selected class
- `get_class_source` — full Java source of a class
- `search_method_by_name` — find methods across all classes
- `get_methods_of_class` — list methods in a class
- `get_xrefs_to_method` — find callers of a method
- `get_android_manifest` — full manifest
- `get_smali_of_class` — smali for patching

### GhidraMCP (Native layer)

Plugin runs HTTP server on port 8080 (configurable in Ghidra Tool Options).

Key endpoints:
- `GET /methods` — list all defined functions
- `GET /decompile_function?address=<addr>` — decompile by address
- `GET /get_function_by_address?address=<addr>` — function info (name, signature, body range)
- `GET /disassemble_function?address=<addr>` — raw disassembly
- `GET /segments` — memory layout
- `GET /xrefs_to?address=<addr>` — cross-references to address
- `GET /xrefs_from?address=<addr>` — cross-references from address
- `GET /strings` — all defined strings
- `GET /searchFunctions?query=<name>` — search by name
- `GET /exports` — exported symbols (JNI functions)
- `GET /imports` — imported functions

Note: `/decompile?name=<name>` uses the old endpoint. Prefer `/decompile_function?address=<addr>` for reliability.

## Workflow: Analyzing Native Libraries in Mobile Apps

### 1. Identify JNI bridge (jadx-mcp-server)

Search for `System.loadLibrary` or `native` method declarations:
- `search_method_by_name` with query containing the lib name
- `search_classes_by_keyword` for `loadLibrary`
- Check exports in Ghidra: `GET /exports` shows `Java_<package>_<class>_<method>` symbols

### 2. Map JNI exports to Java methods (GhidraMCP)

```
GET /exports → Java_com_example_NativeClass_methodName
GET /decompile_function?address=<export_addr>
```

### 3. Trace interesting patterns

Common targets in security-sensitive native libs:
- **Certificate pinning**: look for `sha256//`, `X509`, `SSL_CTX`, curl vtls paths
- **Root/jailbreak detection**: `su`, `/system/app/Superuser`, `MobileSubstrate`
- **Encryption**: `AES`, `EVP_`, key derivation functions
- **Anti-tampering**: signature verification, checksum validation
- **Obfuscation**: string decryption routines (called before any meaningful string use)

### 4. Source path hints

Decompiled native code often reveals original source paths in debug strings:
```
../../../../src/main/cpp/mobile_sdk/thirdparty/http/lib/curl/vtls/vtls.c
```
These reveal the SDK structure and help identify which third-party libraries are embedded.

## Pitfalls

- GhidraMCP only lists functions that Ghidra has **defined**. If auto-analysis hasn't run, most of .text is undefined. Run Analysis > Auto Analyze first.
- The `/methods` endpoint may only return ~100 functions initially. After full analysis, thousands appear.
- Address format: use bare hex without `0x` prefix for GhidraMCP endpoints (e.g., `0043d9c8` not `0x0043d9c8`).
- jadx-mcp-server requires JADX GUI to be open — it communicates with the plugin, not standalone jadx CLI.
- For large .so files, Ghidra analysis can take 10+ minutes. Wait for it to complete before querying.

## Fallback: radare2 (r2) When Ghidra MCP is Unavailable

When GhidraMCP isn't running (port 8080 refused), use `r2` for quick native analysis:

### Find JNI Functions

```bash
r2 -q -c 'aa;afl~Java' lib/arm64-v8a/libutils.so
# Output: address, size, name for each JNI export
```

### Decompile/Disassemble a Function

```bash
# Disassemble (pdf = print disassembly function)
r2 -q -c 'aa;s sym.Java_com_pkg_Class_method;pdf' lib.so 2>&1 | grep -v "^INFO\|^WARN\|^ERROR"

# For pseudo-decompilation (if r2ghidra plugin installed):
r2 -q -c 'aa;s sym.Java_com_pkg_Class_method;pdg' lib.so
```

### Resolve String References in Disassembly

When r2 shows `adrp + add` loading an address, resolve the string at that offset:

```bash
# Print string at specific offset
r2 -q -c 'aa;ps @ 0xe4f1' lib.so

# Batch resolve multiple offsets
r2 -q -c 'aa;ps @ 0xe4f1; ps @ 0xe4e5; ps @ 0xf631' lib.so
```

### Quick String Analysis (No r2 Needed)

```bash
# Find JNI exports
strings lib.so | grep "Java_"

# Find method signatures (JNI type descriptors)
strings lib.so | grep -E "^\(L|^\(\[|^\(Z|^\(I"

# Find interesting strings near function code
strings -t x lib.so | grep -iE "flag|valid|intent|extra|scheme|key|password|token"
```

### Interpreting JNI Offsets in r2 Disassembly

Key JNI function table offsets (arm64, JNIEnv* in x0):
- `[x8, 0xf8]` → `GetObjectClass`
- `[x8, 0x108]` → `GetMethodID`
- `[x8, 0x2f0]` → `GetObjectField` (field access)
- `[x8, 0x2f8]` → `GetBooleanField`
- `[x8, 0x538]` → `NewStringUTF`
- `[x8, 0x558]` → `GetArrayLength`
- `[x8, 0x568]` → `GetObjectArrayElement`

When you see `ldr x8, [x8, 0x108]; blr x8` — that's calling `GetMethodID`. The next arguments (x2, x3) are the method name and signature strings.

### Decision: r2 vs Ghidra

| Scenario | Use |
|----------|-----|
| Quick JNI function overview (what does it call?) | r2 |
| Need full decompilation with types/variables | Ghidra |
| Resolve string references from disassembly | r2 (`ps @ offset`) |
| Complex control flow / loops / crypto | Ghidra |
| Ghidra not installed or not running | r2 (always available via brew) |

## Example: Liveness SDK Cert Pinning (libaailiveness)

1. In Ghidra: `GET /exports` → find `Java_*_Oo0O0` (obfuscated JNI names)
2. `GET /strings` → search for `sha256//` → find address in .rodata
3. `GET /xrefs_to?address=<string_addr>` → find the function using it
4. `GET /decompile_function?address=<func_addr>` → reveals pinning logic
5. In jadx: `search_classes_by_keyword` for the class that loads the native lib
6. Map the Java `native` method to the Ghidra export for full call chain
