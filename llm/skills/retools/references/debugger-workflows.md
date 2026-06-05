# Debugger Workflows Reference

Quick reference for GDB, LLDB, and remote debugging setups.

## LLDB (macOS native)

### Basic Commands

```bash
# Attach to process
lldb -p <pid>
lldb -n "process_name"

# Launch binary
lldb ./binary
(lldb) run arg1 arg2

# Breakpoints
(lldb) b main
(lldb) b 0x100001234
(lldb) br set -n functionName
(lldb) br set -f file.c -l 42
(lldb) br set -r "regex_pattern"    # regex on symbol names

# Execution
(lldb) c          # continue
(lldb) n          # next (step over)
(lldb) s          # step into
(lldb) finish     # step out
(lldb) ni         # next instruction
(lldb) si         # step instruction

# Inspection
(lldb) bt                    # backtrace
(lldb) fr v                  # frame variables (locals)
(lldb) p expression          # print expression
(lldb) po object             # print object (ObjC/Swift)
(lldb) x/16xg $rsp           # examine memory (16 giant hex from RSP)
(lldb) dis -p                # disassemble at PC
(lldb) dis -n functionName   # disassemble function
(lldb) reg read              # all registers
(lldb) reg read rax rbx      # specific registers

# Memory
(lldb) memory read 0x1234 --count 64
(lldb) memory write 0x1234 0x41414141
(lldb) memory find 0x1000 0x2000 -s "pattern"
```

### Scripting (Python)

```python
# In LLDB console
(lldb) script
>>> target = lldb.debugger.GetSelectedTarget()
>>> process = target.GetProcess()
>>> thread = process.GetSelectedThread()
>>> frame = thread.GetSelectedFrame()
>>> print(frame.FindVariable("local_var").GetValue())

# Or as a command script
import lldb

def hook_function(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    bp = target.BreakpointCreateByName("target_func")
    print(f"Breakpoint set: {bp}")

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f script.hook_function hook')
```

## GDB

### Basic Commands

```bash
# Launch
gdb ./binary
gdb -p <pid>                # attach
gdb -ex "target remote :1234" ./binary  # remote

# Breakpoints
(gdb) b *0x401234
(gdb) b main
(gdb) b file.c:42
(gdb) watch *0x601000       # watchpoint (break on write)
(gdb) rwatch *0x601000      # read watchpoint

# Execution
(gdb) r                     # run
(gdb) c                     # continue
(gdb) ni / si               # next/step instruction
(gdb) finish                # step out

# Inspection
(gdb) bt                    # backtrace
(gdb) info reg              # registers
(gdb) x/32xg $rsp           # examine stack
(gdb) x/10i $rip            # disassemble at RIP
(gdb) p/x variable          # print hex
(gdb) info proc mappings    # memory map
(gdb) vmmap                 # (with gef/pwndbg)

# Heap (with gef/pwndbg)
(gdb) heap chunks
(gdb) heap bins
(gdb) heap tcache
```

### GEF / pwndbg (exploit dev extensions)

```bash
# Install GEF
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# Install pwndbg
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

# Key commands (pwndbg)
(gdb) checksec              # binary mitigations
(gdb) rop --grep "pop rdi"  # find gadgets
(gdb) cyclic 200            # generate pattern
(gdb) cyclic -l 0x41416141  # find offset
(gdb) got                   # GOT table
(gdb) plt                   # PLT entries
(gdb) search -s "flag{"     # search memory
```

## Remote Debugging

### GDB Remote (Linux target)

```bash
# On target
gdbserver :9999 ./binary
gdbserver --attach :9999 <pid>

# On host
gdb ./binary
(gdb) target remote <target-ip>:9999
```

### LLDB Remote (iOS/macOS)

```bash
# On device (iOS via SSH)
debugserver *:1234 --attach=<pid>

# On host
(lldb) platform select remote-ios
(lldb) process connect connect://<device-ip>:1234
```

### Android Native (GDB via adb)

```bash
# Push gdbserver
adb push gdbserver /data/local/tmp/
adb shell chmod 755 /data/local/tmp/gdbserver

# Attach on device
adb shell "su -c '/data/local/tmp/gdbserver :5039 --attach <pid>'"

# Forward port
adb forward tcp:5039 tcp:5039

# Connect from host
gdb-multiarch ./lib.so
(gdb) set architecture aarch64
(gdb) target remote :5039
```

## Pitfalls

- LLDB on macOS requires code-signing or SIP disabled for debugging system processes
- GDB on macOS is painful — use LLDB unless you specifically need GEF/pwndbg features
- `debugserver` on iOS needs developer disk image mounted (Xcode does this)
- Android gdbserver must match target arch (use gdbserver from NDK matching device ABI)
- ptrace-based debuggers fail if app has anti-debug (`prctl(PR_SET_DUMPABLE, 0)`) — patch or use Frida instead
- ASLR makes breakpoints on absolute addresses unreliable — use symbol names or offsets from base
- Core dumps: `ulimit -c unlimited` before crash, then `gdb binary core` for post-mortem
- Stripped binaries: load symbols from debug build separately with `add-symbol-file`
