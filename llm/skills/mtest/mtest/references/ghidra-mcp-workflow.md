# Ghidra MCP Workflow for AppFence RE

## Prerequisites

- Ghidra open with `libaf-android.so` loaded (ARM64/AARCH64)
- Auto-analysis complete
- GhidraMCP plugin active on port 8080

## Address Mapping

Ghidra default base for ELF: `0x100000`
- File offset `0xa9bd8` → Ghidra address `0x1a9bd8`
- Always verify: `readelf -s lib.so | grep JNI_OnLoad` gives file offset, add 0x100000 for Ghidra

## Step-by-Step MCP Workflow

### 1. Verify connection and orientation

```
mcp_ghidra_list_segments()          # Confirm binary loaded
mcp_ghidra_search_functions_by_name("JNI_OnLoad")  # Find entry point
```

### 2. Trace from JNI_OnLoad

```
mcp_ghidra_decompile_function_by_address(JNI_ONLOAD_ADDR)
# Look for: RegisterNatives call, class name string, method count
# Pattern: FindClass("com/pkg/ClassName") → RegisterNatives(env, class, methods, count)
```

### 3. Decompile kill functions (from binary analysis offsets)

```
# Convert file offsets to Ghidra addresses (+0x100000)
mcp_ghidra_decompile_function_by_address(0x1a9b80)  # Kill thread
mcp_ghidra_decompile_function_by_address(0x1a9cbc)  # Kill orchestrator
mcp_ghidra_decompile_function_by_address(0x1a9800)  # Thread spawner
```

### 4. Trace callers via xrefs

```
mcp_ghidra_get_function_xrefs("FUN_001a9800")  # Who spawns kill threads?
mcp_ghidra_get_xrefs_to(0x1a9b80)              # Who references kill thread func?
```

### 5. Find detection scanner

```
# Search for functions in the detection zone
mcp_ghidra_search_functions_by_name("FUN_001b0")  # Maps scanner area
mcp_ghidra_decompile_function_by_address(0x1b01b4) # Main detection function
```

### 6. Identify dlsym wrapper

```
# The kill orchestrator uses dlopen/dlsym to resolve kill/_exit at runtime
# Look for: dlopen("libc.so", 1) → dlsym(handle, "_exit") pattern
mcp_ghidra_decompile_function_by_address(0x1a9dd0)  # dlsym wrapper
```

## Key Patterns to Recognize in Decompilation

### Kill thread (FUN_001a9b80 pattern)
```c
usleep(param[1] * 1000000);   // Configurable delay
CallSupervisor(0);             // Inline SVC #0 = exit_group
FUN_kill_orchestrator(0);      // Fallback via libc
FUN_cleanup(&ptr);             // Cleanup (never reached)
```

### Kill orchestrator (FUN_001a9cbc pattern)
```c
pcVar2 = dlsym_wrapper("libc.so", "_exit");
pcVar3 = dlsym_wrapper("libc.so", "kill");  // DAT_00140f77 = "kill"
getpid();
syscall(0x5e, 0);              // exit_group via libc
if (failed) kill(pid, 9);     // SIGKILL fallback
if (failed) _exit(0);         // _exit fallback
abort();                       // Final fallback
```

### Thread spawner (FUN_001a9800 pattern)
```c
arg = malloc(0x10);
arg[0] = some_ptr;
arg[1] = delay_seconds;       // param_9 from caller
pthread_create(&thread, NULL, kill_thread_func, arg);
// ... cleanup after thread starts
```

### Maps scanner (FUN_001b01b4 pattern)
```c
getPackageName();
build_allowlist("/data/data/<pkg>", "/data/user/0/<pkg>", ...);
open_stream("/proc/self/maps");  // via fopen or ifstream
while (read_line()) {
    extract_path_from_mapping();
    if (!matches_allowlist(path)) {
        trigger_detection();    // → spawns kill thread
    }
}
```

## Pitfalls with Ghidra MCP

1. **Functions not auto-created** — Ghidra may not create functions at all addresses. If `decompile_function_by_address` returns "No function found", the address is in an unanalyzed region. Try nearby addresses or use `get_xrefs_to` to find references.

2. **Obfuscated names** — All internal functions are `FUN_XXXXXXXX`. Use xrefs and string references to identify purpose.

3. **Varargs decompilation** — Functions with variable arguments (like the detection scanner) produce messy decompilation with many `param_N` parameters. Focus on the control flow and string constants, not parameter types.

4. **Virtual calls** — `(**(code **)(*param + offset))()` patterns are JNI env calls. Common offsets: 0x30=FindClass, 0x6b8=RegisterNatives, 0x548=GetStringUTFChars, 0xb8=DeleteLocalRef.
