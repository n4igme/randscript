---
name: retools
version: 1.0.1
description: "Reverse engineering tooling skill covering Ghidra, radare2, IDA, and Binary Ninja workflows. Setup, scripting, plugin management, and integration with MCP for automated analysis."
tags: [reverse-engineering, ghidra, radare2, ida, binary-ninja, re, disassembly, decompilation]
trigger: "ghidra setup, ghidra extension, r2 analysis, radare2, ida script, binary ninja, reverse engineering tools, RE tooling, ghidra mcp, decompile binary"
argument-hint: "<context: setup|ghidra|r2|ida|binja|mcp>"
metadata:
  hermes:
    tags: [reverse-engineering, tooling, ghidra, radare2]
    related_skills: [xdev, mtest, ptest]
---

# Reverse Engineering Tooling (retools)

Utility skill for RE tool setup, scripting, and integration. Supports xdev (exploit dev), mtest (mobile native RE), and ptest (binary analysis during pentests).

## Commands

| Command | Action |
|---------|--------|
| `setup` | Environment setup and verification |
| `ghidra` | Ghidra-specific workflows (extensions, MCP, scripting) |
| `r2` | radare2 workflows (quick analysis, scripting, automation) |
| `ida` | IDA Pro workflows (IDAPython, plugins, remote debug) |
| `binja` | Binary Ninja workflows (API, plugins, IL) |
| `mcp` | MCP bridge setup and usage |
| `malware` | Malware deobfuscation, implant analysis, IOC extraction |

---

## Environment (macOS)

### Ghidra
- Binary: `/opt/homebrew/bin/ghidraRun`
- Install: `/opt/homebrew/Cellar/ghidra/<version>/libexec/`
- System extensions: `/opt/homebrew/Cellar/ghidra/<version>/libexec/Ghidra/Extensions/`
- User extensions: `~/Library/ghidra/ghidra_<version>_PUBLIC/Extensions/`
- Logs: `~/Library/ghidra/ghidra_<version>_PUBLIC/application.log`
- Java: `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`

### radare2
- Binary: `r2` (Homebrew or source build)
- Config: `~/.radare2rc`
- Plugins: `~/.local/share/radare2/plugins/`
- r2pipe: `pip install r2pipe` (Python scripting)

### IDA Pro
- Binary: `/Applications/IDA Pro/ida64.app` (macOS)
- Plugins: `~/.idapro/plugins/`
- IDAPython: built-in Python 3 environment
- Remote debug: `linux_server64`, `android_server64`

### Binary Ninja
- Binary: `/Applications/Binary Ninja.app`
- Plugins: `~/Library/Application Support/Binary Ninja/plugins/`
- API: `import binaryninja` (headless scripting)

---

## Quick Start Decision Tree

```
What do you have?
│
├── APK/DEX (Android Java/Kotlin)
│   ├── JADX MCP (preferred) — decompile + navigate via MCP tools
│   ├── APKEditor (~/PenTest/Tools/APKEditor-1.4.7.jar) — repack/patch
│   └── Fallback: apktool d + dex2jar + jd-gui
│
├── .so / ELF (native library)
│   ├── Quick triage: r2 -q -c 'aaa; afl; iz' ./lib.so (5 min)
│   ├── JNI functions: r2 -q -c 'aa; afl~Java_' ./lib.so
│   ├── Deep analysis: Ghidra (import → auto-analyze → decompile)
│   └── If ARM64 + stripped: Ghidra > r2 (better decompilation)
│
├── PE / Windows binary
│   ├── IDA Pro (best decompilation for x86/x64)
│   ├── Ghidra (free alternative, good enough for most)
│   └── Quick strings: strings + FLOSS (for obfuscated strings)
│
├── iOS binary (Mach-O)
│   ├── Ghidra (ARM64 support, free)
│   ├── IDA (better if available)
│   └── class-dump / dsdump for ObjC headers
│
├── Firmware / embedded
│   ├── binwalk (extract filesystem)
│   ├── r2 (MIPS/ARM analysis)
│   └── Ghidra (best for unknown architectures)
│
└── Obfuscated script (JS/Python/PS)
    └── Manual deobfuscation — see Malware section below
```

---

## JADX / APK Tooling (Android Java/DEX RE)

### JADX MCP (preferred — integrated with Hermes)

JADX GUI with MCP plugin provides decompilation tools directly:
```
mcp_jadx_mcp_server_get_class_source(class_name)
mcp_jadx_mcp_server_search_classes_by_keyword(search_term, search_in="code")
mcp_jadx_mcp_server_get_android_manifest()
mcp_jadx_mcp_server_get_methods_of_class(class_name)
mcp_jadx_mcp_server_get_xrefs_to_method(class_name, method_name)
```

### APKEditor (repack/patch)
```bash
java -jar ~/PenTest/Tools/APKEditor-1.4.7.jar d -i app.apk -o decoded/
java -jar ~/PenTest/Tools/APKEditor-1.4.7.jar b -i decoded/ -o patched.apk
apksigner sign --ks debug.keystore --ks-pass pass:android patched.apk
```

### Quick APK Triage (5 min)
```bash
unzip -q app.apk -d extracted/
grep -rn "AIza\|AKIA\|sk_live\|api_key\|secret" extracted/
find extracted/lib/ -name "*.so" | sort
aapt dump xmltree app.apk AndroidManifest.xml
```

---

## Ghidra Workflows

### Extension Management

**Debugging startup failures:**
```bash
JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
  /opt/homebrew/Cellar/ghidra/<ver>/libexec/support/launch.sh fg jdk Ghidra "" "" ghidra.GhidraRun 2>&1
```

**Common errors:**
- "Multiple modules collided" — extension in BOTH system and user dirs. Remove one.
- "Invalid line encountered" in Module.manifest — Ghidra 12+ only accepts `MODULE FILE LICENSE:` lines or empty manifest.
- "ghidraVersion" mismatch — extension.properties must match installed Ghidra exactly.

**Building extensions from source:**
1. Clone extension source
2. Copy required JARs from Ghidra install (`Generic.jar`, `SoftwareModeling.jar`, `Base.jar`, `Docking.jar`, `Decompiler.jar`, `Utility.jar`)
3. Update `extension.properties` — set `version` and `ghidraVersion`
4. Build: `mvn clean package -q`
5. Install to `~/Library/ghidra/ghidra_<version>_PUBLIC/Extensions/`

**Pitfalls:**
- Homebrew upgrades change Cellar path — system extensions get wiped. User dir persists.
- Extension JAR must be recompiled against new Ghidra JARs (patching version string alone causes runtime errors).
- Module.manifest format changed across versions. Empty file is safe for simple extensions.

### GhidraMCP Integration

- Source: https://github.com/LaurieWired/GhidraMCP
- Plugin starts HTTP server on port 8080 when enabled in CodeBrowser
- Enable: File > Configure > Miscellaneous > GhidraMCP
- Bridge: `python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/`
- Bridge deps: `requests>=2,<3` and `mcp>=1.2.0,<2`

**Key MCP operations:**
```
mcp_ghidra_list_segments()
mcp_ghidra_search_functions_by_name("target")
mcp_ghidra_decompile_function_by_address(addr)
mcp_ghidra_get_function_xrefs(addr)
mcp_ghidra_list_imports()
mcp_ghidra_list_exports()
```

**Pitfalls:**
- REST API (port 8080) ONLY starts when a binary is opened in CodeBrowser — just launching Ghidra GUI is not enough. Double-click a binary in the project to open it.
- Duplicate extension in BOTH system (`/opt/homebrew/Cellar/ghidra/.../Extensions/`) AND user (`~/Library/ghidra/.../Extensions/`) dirs causes crash: "Multiple modules collided with same name". Remove one.
- `Module.manifest` format: Ghidra 12+ only accepts `MODULE DIR: lib` style lines. Arbitrary key-value pairs cause parse errors.
- Headless mode (`analyzeHeadless`) does NOT start the REST server. Use headless Java scripts for automated analysis, GUI+MCP for interactive exploration.

**Reference:** `references/ghidramcp-api.md`

### Ghidra Scripting (Headless)

```bash
# Import + analyze + run script (one-shot)
/opt/homebrew/Cellar/ghidra/<ver>/libexec/support/analyzeHeadless \
  /tmp/ghidra_project proj_name \
  -import ./binary \
  -processor AARCH64:LE:64:v8A \
  -postScript MyScript.java \
  -scriptPath /tmp \
  -overwrite 2>&1 | tail -20

# Re-run script on already-imported binary (no re-analysis)
analyzeHeadless /tmp/ghidra_project proj_name \
  -process binary_name \
  -noanalysis \
  -postScript MyScript.java \
  -scriptPath /tmp
```

**Headless script pattern (Java):**
```java
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class MyScript extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        // Get function at address (add 0x100000 for Ghidra's default image base)
        Address addr = currentProgram.getAddressFactory()
            .getDefaultAddressSpace().getAddress(0x581938);
        Function func = funcMgr.getFunctionContaining(addr);
        println("Function: " + func.getName() + " at " + func.getEntryPoint());
        println("Size: " + func.getBody().getNumAddresses());
        // Count BLR (indirect calls)
        InstructionIterator iter = currentProgram.getListing()
            .getInstructions(func.getBody(), true);
        int blr = 0;
        while (iter.hasNext()) {
            if (iter.next().getMnemonicString().equals("blr")) blr++;
        }
        println("BLR count: " + blr);
    }
}
```

**Pitfalls:**
- Class name MUST match filename (e.g., `FindVerify.java` → `public class FindVerify`)
- `getReferencesTo()` returns `ReferenceIterator`, NOT `Reference[]` (Ghidra 12+)
- Default image base for shared libs is 0x100000 — add this to file offsets for Ghidra addresses
- Headless mode does NOT start the GhidraMCP REST server — use headless scripts OR open GUI for MCP
- Parse output with `grep -E "(pattern)"` since headless prints INFO/WARN noise

---

## radare2 Workflows

### Plugin Setup
```bash
# Decompiler plugins (required for `pdg` and `pdd` commands)
r2pm -ci r2ghidra    # Ghidra decompiler in r2 (pdg command)
r2pm -ci r2dec       # Alternative decompiler (pdd command)

# Useful extras
r2pm -ci r2frida     # Frida integration (=!i, =!ic, =!ii)
r2pm -ci r2yara      # YARA rule matching
```

### Quick Binary Analysis
```bash
# Auto-analyze and list functions
r2 -q -c 'aaa; afl' ./binary

# Decompile function (with r2ghidra or r2dec)
r2 -q -c 'aaa; s sym.main; pdg' ./binary

# Find strings
r2 -q -c 'iz~password' ./binary

# Cross-references to function
r2 -q -c 'aaa; axt @sym.vulnerable_func' ./binary

# Disassemble specific function
r2 -q -c 'aaa; s sym.target; pdf' ./binary
```

### JNI Native Analysis (Android)
```bash
# Quick JNI function analysis
r2 -q -c 'aa;s sym.Java_pkg_Class_method;pdf' lib.so

# JNI call offsets (ARM64):
# 0xf8  = GetObjectClass
# 0x108 = GetMethodID
# 0x538 = NewStringUTF
# 0x2f0 = GetFieldID
# 0x2f8 = GetObjectField
# 0x558 = GetArrayLength
# 0x568 = GetObjectArrayElement
```

### r2pipe Scripting (Python)
```python
import r2pipe

r2 = r2pipe.open('./binary')
r2.cmd('aaa')

# List all functions
funcs = r2.cmdj('aflj')
for f in funcs:
    print(f"{f['offset']:#x} {f['name']} ({f['size']} bytes)")

# Find dangerous imports
imports = r2.cmdj('iij')
dangerous = [i for i in imports if i['name'] in ['system', 'exec', 'strcpy', 'sprintf']]

# Decompile function
r2.cmd(f's {addr}')
decomp = r2.cmd('pdg')

r2.quit()
```

### Binary Diffing
```bash
# Compare two binaries (patch analysis)
r2 -q -c 'aaa' -A old_binary
radiff2 -g main old_binary new_binary | dot -Tpng > diff.png

# Or use r2diaphora plugin for function-level diffing
```

---

## IDA Pro Workflows

### IDAPython Quick Scripts
```python
# Find all calls to a function
import idautils, idc

target = idc.get_name_ea_simple("system")
for xref in idautils.XrefsTo(target):
    print(f"{xref.frm:#x}: {idc.generate_disasm_line(xref.frm, 0)}")

# Rename functions by pattern
for func_ea in idautils.Functions():
    name = idc.get_func_name(func_ea)
    if name.startswith("sub_"):
        # Check for specific patterns to auto-rename
        pass

# Extract all strings matching pattern
import re
for s in idautils.Strings():
    if re.search(r'(password|secret|key)', str(s), re.I):
        print(f"{s.ea:#x}: {s}")
```

### Remote Debugging (Android)
```bash
# Push debug server to device
adb push android_server64 /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/android_server64"
adb shell "su -c '/data/local/tmp/android_server64 -p23946'"

# Forward port
adb forward tcp:23946 tcp:23946

# IDA: Debugger > Attach > Remote ARM Linux/Android
# Host: localhost, Port: 23946
```

### IDA Plugins (Useful)
```
# Keypatch: assembler/patcher
# Findcrypt: identify crypto constants
# LazyIDA: copy/paste improvements
# HexRaysPyTools: structure reconstruction
# FLARE: FireEye's RE tools collection
```

---

## Binary Ninja Workflows

### Headless Scripting
```python
import binaryninja as bn

bv = bn.open_view('./binary')
bv.update_analysis_and_wait()

# Find functions calling dangerous APIs
for func in bv.functions:
    for callee in func.callees:
        if callee.name in ['system', 'exec', 'strcpy']:
            print(f"{func.name} calls {callee.name}")

# Get IL for analysis
for func in bv.functions:
    for block in func.medium_level_il:
        for instr in block:
            if instr.operation == bn.MediumLevelILOperation.MLIL_CALL:
                print(f"{func.name}: {instr}")

bv.file.close()
```

---

## Cross-Tool Patterns

### Architecture Identification
```bash
# Quick arch check
file ./binary
readelf -h ./binary | grep Machine
r2 -q -c 'iI~arch' ./binary
```

### Symbol Recovery (Stripped Binaries)
```
# Ghidra: auto-analysis + Function ID (FIDB) databases
# r2: aaa (aggressive analysis) + aaaa (experimental)
# IDA: FLIRT signatures + Lumina server
# BinaryNinja: signature libraries + type propagation
```

### String Extraction Strategy
```bash
# Basic strings
strings -n 6 ./binary | sort -u

# Wide strings (UTF-16)
strings -el ./binary

# r2 (categorized)
r2 -q -c 'iz' ./binary        # data section strings
r2 -q -c 'izz' ./binary       # all strings (including code section)

# Specific patterns
strings ./binary | grep -iE 'http|api|key|secret|password|token'
```

---

## Malware Deobfuscation & Implant Analysis

For in-the-wild malware samples, obfuscated loaders, and supply chain implants.

**Reference:** `references/malware-deobfuscation.md`

### Quick Workflow
```
1. Triage — identify language, encoding layers, entry point
2. Map layers — list each obfuscation stage (permutation, base64, compression)
3. Decode outside-in — reimplement each layer's algorithm in Python (DON'T execute malware)
4. Extract IOCs — C2 IPs, wallets, tokens, campaign markers, paths
5. Document — architecture diagram, decoded config, attribution indicators
```

### Key Patterns
- **Seed-based string permutation** — deterministic char swap, fully reversible with known seed
- **Function constructor abuse** — `NVu['constructor']` = `Function()` for dynamic exec
- **Dictionary compression** — positional encoding referencing previously decoded strings
- **Per-machine tokens** — 256-byte RSA-like signatures for C2 auth (blocks sandbox retrieval)
- **Multi-tier C2 routing** — campaign version string selects primary vs fallback infrastructure

### Supported Targets
- JavaScript loaders (Node.js supply chain, trojanized configs)
- Python RATs/stealers (urllib + exec pattern)
- PowerShell downloaders
- .NET obfuscated assemblies
- Multi-stage implants (JS → Python, PS → .NET → shellcode)

---

## Pitfalls

- Ghidra auto-analysis on large binaries (>50MB) takes 30+ min — disable unused analyzers
- radare2 `aaa` on stripped binaries misidentifies functions — use `aaaa` or manual `af` on known entry points
- IDA Free doesn't support ARM64 — use Ghidra or Binary Ninja for mobile native libs
- Frida on rooted Android: SELinux enforcing blocks injection — `setenforce 0` or use Magisk Hide
- Stripped Go binaries: use `GoReSym` to restore symbol table before loading in Ghidra
- JNI native methods: match `Java_package_Class_method` naming or you'll miss the bridge functions
- Anti-debug checks (ptrace, timing): patch them out early or you'll waste hours on false behavior

## Verification

After tool setup, verify with:
```bash
# Ghidra
ghidraRun  # should launch GUI without errors

# r2
r2 -v  # version info
r2 -q -c 'e asm.arch=arm; e asm.bits=64; pa mov x0, 0' --  # test ARM64 assembly

# GhidraMCP
curl http://localhost:8080/methods  # should return JSON (when Ghidra + plugin running)
```

**References:**
- `references/ghidramcp-api.md` — GhidraMCP REST API endpoints
- `references/native-ssl-pinning-analysis.md` — SSL pinning RE in native libs
- `references/frida-scripting.md` — Frida patterns: Java hooks, native intercept, SSL bypass, root bypass, Python API
- `references/debugger-workflows.md` — LLDB, GDB, remote debugging (Android/iOS), pwndbg/GEF
- `references/unknown-binary-triage.md` — 15-min triage: identify, metadata, strings, dynamic, tool selection, `references/frida-scripting.md`, `references/debugger-workflows.md`, `references/unknown-binary-triage.md`

---

## Additional References

- `references/frida-scripting.md` — Frida hook patterns (Java, native, SSL bypass, root bypass, Python API)
- `references/debugger-workflows.md` — LLDB, GDB, GEF/pwndbg, remote debugging (Android/iOS)
- `references/unknown-binary-triage.md` — 15-min methodology for approaching unfamiliar binaries, `references/frida-scripting.md`, `references/debugger-workflows.md`, `references/unknown-binary-triage.md`
