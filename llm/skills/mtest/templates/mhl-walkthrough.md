# Challenge: MHL [AppName] (Android)
## Vulnerability: [Vuln Class] → [Impact]

---

## Summary

[2-3 sentences: what the app does wrong, the attack chain, and the end result. Written for someone who hasn't seen the app.]

---

## Step 1: Identify the Attack Surface

[AndroidManifest.xml excerpts, exported components, permissions. Show the entry point.]

```xml
<!-- Relevant manifest snippet -->
```

[Additional attack surface: native lib loading, content providers, etc.]

```java
// Relevant code showing the vulnerable pattern
```

## Step 2: Understand the [Vulnerable Logic]

[Decompiled source showing the bug. Explain the flow numbered 1-N.]

From `ClassName.java`:
1. [First thing that happens]
2. [Second thing]
3. [The unsafe operation]

```java
// Key vulnerable code snippet
```

## Step 3: [Build/Extract/Calculate Attack Prerequisites]

[Any crypto parameters to extract, paths to calculate, configs to read.]

```bash
# Commands to extract what's needed
```

## Step 4: [Build the Exploit]

[Payload code — Python PoC, malicious .so, Frida script, etc. Full working code.]

```python
#!/usr/bin/env python3
# Full exploit code here
```

[Compile/run instructions:]
```bash
# Build/run commands
```

## Step 5: [Deliver/Trigger the Exploit]

[The actual exploitation command. Explain what each part does.]

```bash
# The money shot — adb command, curl, intent URI, etc.
```

**What happens:**
1. [Chain of events from trigger to impact]
2. ...
N. [Final state — code executed, data leaked, etc.]

## Step 6: [Verify Exploitation]

```bash
# Commands to confirm success
```

**Output:**
```
[Actual output showing success — logcat, file contents, etc.]
```

## Notes

- [Timing considerations, 1-visit vs 2-visit, async behavior]
- [Why specific protections don't block this (SELinux, permissions)]
- [No root/Frida required — or what IS required]
- [Real-world delivery variant (browser intent://, phishing)]
- [Any interesting technical details about WHY it works]

## Flag

`[FLAG{...}]`

---

## Template Notes (remove before publishing)

- Flag value MUST come from actual execution (device run, Frida hook, or native disassembly). NEVER fabricate a flag value — if you can't extract it, write "Flag returned by native `getflag()` — run on device to capture" and show the Frida hook to grab it.
- For native flags: run `strings lib*.so | grep -iE "MHL|flag|CTF|{.*}"` first. If not in plaintext, the flag is constructed at runtime via XOR/arithmetic on .rodata arrays — reverse the native function with objdump/Ghidra and emulate in Python. See `references/native-flag-extraction.md`.
- CRITICAL: If `strings` only shows "Success" or a generic string, that is NOT the flag — MHL labs always use `MHL{...}` format. The real flag is hidden in native XOR routines. Never assume "Success" is the flag.
- Common MHL native pattern: helper functions XOR int32 arrays from .rodata with formulas like `arr[i] ^ (i*constant + offset)`, writing results to .bss buffers. Use objdump to identify the formula, then emulate in Python.
- Steps should be 5-8 total. Combine trivial steps, split complex ones.
- The reference format is the DocumentViewer gist: https://gist.github.com/n4igme/6d69ce5bd360189212cee8c40b5ff363
- Output path: `<challenge>/mtest-output/report/<challenge-lowercase>-walkthrough.md`
