---
name: xdev
version: 1.0.1
description: "System-level exploit development framework covering Linux, Windows, macOS, Android, iOS, and firmware. 5 gated phases from vulnerability analysis through reliable exploit delivery."
tags: [exploit, exploitation, shellcode, rop, heap, kernel, firmware, arm64, mitigation-bypass]
trigger: "exploit dev, exploit development, write exploit, build exploit, shellcode, rop chain, heap exploitation, kernel exploit, privilege escalation exploit, firmware exploit"
argument-hint: "<command: start|status|resume|next|report|abort|cleanup>"
metadata:
  hermes:
    tags: [exploit, development, shellcode, kernel, firmware, offensive]
    related_skills: [ptest, mtest, ctest]
---

# Exploit Development Framework

Structured 5-phase workflow for developing working exploits from known vulnerabilities. Takes a crash/bug and produces a reliable exploit with documentation. Covers Linux, Windows, macOS, Android, iOS, and firmware targets.

## Quick Reference

```
Phases:  1.VulnAnalysis → 2.PrimitiveDev → 3.MitigationBypass → 4.ExploitConstruction → 5.Documentation
States:  LOCKED → OPEN → PASSED (sequential)
Commands: start | status | next | resume | report | abort | cleanup

Key rules:
  • Understand the bug FULLY before writing exploit code
  • Each phase builds on primitives from the previous
  • Reliability > speed — a 90% reliable exploit beats a 50% one
  • Document every dead end (saves time on retry)
  • Test on exact target version (mitigations vary by patch level)
```

## Architecture

```
Phase 1: Vuln Analysis → Phase 2: Primitive Dev → Phase 3: Mitigation Bypass → Phase 4: Exploit Construction → Phase 5: Documentation
```

## Commands

| Command | Action |
|---------|--------|
| `start` | Initialize engagement — define target, vulnerability class, platform |
| `status` | Show current phase, progress, primitives developed |
| `resume` | Resume interrupted engagement from last checkpoint |
| `next` | Advance to next phase (runs exit criteria check) |
| `report` | Generate final exploit write-up |
| `abort` | Terminate development — target patched, approach infeasible, or deprioritized |
| `cleanup` | Archive engagement output, remove temporary exploit artifacts |

If no command is given, show current status and suggest next action.

### Command Procedures

**`start`:**
1. Collect: platform, architecture, vuln class, trigger (PoC/crash), target version, known mitigations, goal.
2. Create output directory (`./xdev-output/` with subdirs for each phase).
3. Write `state.yaml` with engagement metadata.
4. Write `target.md` with version details, compile flags, mitigation state.
5. Load platform decision tree → identify which reference file to use.
6. Begin Phase 1 analysis (crash triage, root cause identification).

**`status`:** Output current phase, gateway states, primitives developed so far (read/write/exec), mitigations bypassed, reliability estimate. If no engagement, suggest `start`.

**`resume`:**
1. Read `state.yaml` to determine active phase and primitives.
2. **Staleness:** >7 days → re-verify target hasn't been patched (check CVE status, vendor advisories). >30 days → re-assess if exploit is still relevant (may be patched or superseded).
3. Re-read findings-log for dead ends already explored.
4. Report status and suggest next action.

**`next`:**
1. Verify current phase gate is satisfied.
2. If NOT met: list unmet criteria (e.g., "no write primitive yet"), suggest approaches.
3. If met: update state.yaml, advance phase.
4. Override allowed with justification (e.g., "skipping mitigation bypass — target has no ASLR").

**`abort`:**
1. Record reason in state.yaml (target patched, approach infeasible, deprioritized, time budget exceeded).
2. Document what was achieved (primitives, partial chains) — may be useful for future targets.
3. Run cleanup.

**`cleanup`:**
1. Archive `./xdev-output/` to `xdev-output-{target}-{date}.tar.gz`.
2. Remove compiled exploit binaries (keep source).
3. Print summary: primitives achieved, mitigations bypassed, reliability.

---

## Initialization (`start`)

Collect before development:

1. **Target Platform** — Linux, Windows, macOS, Android, iOS, firmware/embedded
2. **Architecture** — x86_64, ARM64, ARM32, MIPS, RISC-V
3. **Vulnerability Class** — UAF, OOB R/W, type confusion, integer overflow, race condition, format string, logic bug, JIT/engine bug (JSC/V8)
4. **Trigger** — PoC crash, fuzzer output, code audit finding, CVE without public exploit, captured in-the-wild sample
5. **Target Version** — exact kernel/OS/binary version, compile flags, patch level
6. **Mitigations Known** — ASLR, DEP, CFI, CET, PAC, MTE, SMEP/SMAP, sandbox, SELinux
7. **Goal** — LPE, RCE, sandbox escape, kernel code exec, info leak chain

Create output directory:

```
./xdev-output/
├── state.yaml
├── target.md
├── findings-log.md
├── phase1-analysis/
│   ├── crash-triage.md
│   └── root-cause.md
├── phase2-primitives/
├── phase3-mitigations/
├── phase4-exploit/
│   ├── exploit.py (or .c)
│   └── payload/
└── phase5-report/
```

Write `state.yaml`:

```yaml
engagement:
  name: ""
  started: ""
  platform: ""       # linux, windows, macos, android, ios, firmware
  architecture: ""   # x86_64, arm64, arm32, mips
  vuln_class: ""     # uaf, oob, type_confusion, integer_overflow, race, format_string, logic
  target_version: ""

gateways:
  1_analysis: OPEN
  2_primitives: LOCKED
  3_mitigations: LOCKED
  4_construction: LOCKED
  5_documentation: LOCKED

primitives:
  info_leak: false
  arb_read: false
  arb_write: false
  code_exec: false

mitigations_bypassed: []
reliability: ""      # percentage or description
current_phase: 1
```

---

## Platform Decision Tree

Based on platform + vuln class, load the right reference and use the right technique:

```
Linux userland (glibc heap)
├── UAF/OOB → tcache poisoning, fastbin dup, house of * techniques
├── Format string → stack read/write, GOT overwrite
└── Reference: references/linux-userland.md

Linux kernel (SLUB allocator)
├── UAF → cross-cache attack (msg_msg, pipe_buffer, sk_buff)
├── OOB → adjacent object corruption (tty_struct, seq_operations)
├── Race → userfaultfd/FUSE page fault stalling
└── Reference: references/linux-kernel.md

Windows userland (LFH/segment heap)
├── UAF → LFH bucket spray, nt heap manipulation
├── Type confusion → vtable hijack, COM object abuse
└── Reference: references/windows-userland.md

Windows kernel (pool allocator)
├── UAF/OOB → pool spray (named pipes, IoCompletionPort)
├── Race → TOCTOU on shared memory
└── Reference: references/windows-kernel.md

Browser (PartitionAlloc / jemalloc)
├── Type confusion → addrof/fakeobj via TypedArray/ArrayBuffer
├── UAF → bucket spray with same-size objects
├── JIT → JIT spray, bounds check elimination
└── Reference: references/ios-webkit-chain.md

Android native (jemalloc / scudo)
├── UAF → jemalloc region spray, scudo quarantine bypass
├── Kernel → same as Linux kernel (SLUB)
└── Reference: references/android-native.md

iOS/macOS (kalloc / zone allocator)
├── UAF → zone spray (mach messages, IOKit objects)
├── PAC bypass → signing gadgets, PAC-less code, PACDA/PACDB confusion
└── Reference: references/macos-ios.md, references/arm64-exploitation.md

Firmware/embedded (no allocator / flat memory)
├── Stack overflow → direct ROP (often no ASLR/DEP)
├── Command injection → UART/serial shell
└── Reference: references/firmware-embedded.md
```

**Load the matching reference file when entering Phase 2.**

---

## Phase 1: Vulnerability Analysis

### Gate: root cause identified, trigger conditions documented, exploitability assessed

**Techniques:**

1. **Crash Triage:**
   ```bash
   # ASAN output analysis
   # Register state at crash (RIP/PC, RSP/SP, controlled registers)
   # Signal type: SIGSEGV (read/write?), SIGBUS, SIGABRT
   # Faulting instruction context
   ```

2. **Root Cause Classification:**
   - UAF: object freed, dangling pointer dereferenced — what allocator? what size?
   - OOB: buffer bounds exceeded — by how much? controlled length?
   - Type confusion: wrong vtable/type used — what types are confused?
   - Integer overflow: arithmetic wraps — where does the result flow?
   - Race condition: TOCTOU window — how wide? can it be widened?
   - Format string: user input as format — stack read/write primitive?

3. **Constraint Mapping:**
   - What bytes are controlled in the overflow/write?
   - What's the allocation size? (heap exploitation strategy depends on this)
   - What's the time window? (race conditions)
   - What code paths reach the vulnerability from attacker input?
   - Are there size/character/alignment restrictions?

4. **Exploitability Assessment:**
   | Rating | Criteria |
   |--------|----------|
   | Trivial | Direct PC control, no mitigations, large controlled buffer |
   | Moderate | Requires info leak + heap shaping, standard mitigations |
   | Complex | Tight constraints, multiple bugs needed, modern mitigations |
   | Theoretical | Proven vulnerable but no practical path to exploitation |

**Reference:** `references/linux-userland.md`, `references/windows-userland.md` (crash triage sections)

---

## Phase 2: Primitive Development

### Gate: at least one useful primitive demonstrated (read, write, or exec)

**Techniques:**

1. **Info Leak (ASLR/KASLR Defeat):**
   - Heap spray + OOB read to leak adjacent object pointers
   - UAF: read freed object's fd/bk pointers (heap base), vtable pointers (code base)
   - Side channels: timing, cache, branch prediction (speculative execution)
   - Partial overwrite: corrupt low bytes of pointer (no ASLR on low 12 bits)
   - `/proc/self/maps` if accessible (Android pre-hardening, debug builds)

2. **Arbitrary Read:**
   - Corrupted length field → OOB read
   - Fake object with controlled data pointer → read through object interface
   - Format string `%s` with controlled pointer on stack

3. **Arbitrary Write:**
   - Heap overflow into adjacent object's function pointer
   - UAF: replace freed object with controlled data, trigger virtual call
   - Format string `%n` with controlled pointer
   - Integer overflow in size → undersized allocation → heap overflow

4. **Code Execution:**
   - Overwrite return address (stack overflow)
   - Overwrite vtable/function pointer (heap corruption)
   - Overwrite GOT entry (format string / arbitrary write)
   - JIT spray (browser/JS engine targets)

5. **Heap Shaping (allocator-specific):**

   **Linux glibc (ptmalloc2):**
   - tcache: LIFO, per-thread, no integrity checks (< 2.32) → tcache poisoning trivial
   - fastbin: single-linked, size check only → fastbin dup, double-free
   - Unsorted bin: fd/bk leak → libc base. Corrupt bk → unsorted bin attack (write)

   **Linux kernel (SLUB):**
   - Cross-cache attack: free target object, reclaim slab page with different cache
   - Spray objects: `msg_msg` (variable size), `pipe_buffer` (1024), `sk_buff`, `tty_struct`
   - `userfaultfd` / `FUSE`: stall page faults to widen race windows

   **Windows (LFH / Segment Heap):**
   - LFH: randomized within bucket, spray heavily (256+ objects) for adjacency
   - Segment heap (Win10+): VS/LFH subsegments, less predictable → need larger spray
   - Pool (kernel): `NtCreateNamedPipeFile`, `IoCompletionPort` for pool spray

   **Browser (PartitionAlloc / jemalloc):**
   - PartitionAlloc (Chrome/WebKit): bucket-based, same-size guarantee → spray same-type objects
   - jemalloc (Firefox): region-based, predictable adjacency with large sprays
   - ArrayBuffer/TypedArray for controlled data placement

   **iOS/macOS (kalloc / zone):**
   - Zone allocator: spray with mach messages (`mach_msg` OOL descriptors)
   - kalloc zones: size-segregated, spray IOKit objects or `ipc_kmsg`
   - Cross-zone: free in one zone, reclaim from another (harder post-iOS 15)

   ```
   # General strategy:
   # 1. Spray objects of target size to fill holes
   # 2. Free strategic objects to create holes
   # 3. Trigger vulnerable allocation into the hole
   # 4. Adjacent object is now your target for corruption
   ```

**Reference:** `references/linux-userland.md`, `references/linux-kernel.md`, `references/arm64-exploitation.md`, `references/ios-webkit-chain.md`

---

## Phase 3: Mitigation Assessment & Bypass

### Gate: all relevant mitigations identified, bypass strategy selected

**Techniques:**

1. **Mitigation Enumeration:**
   ```bash
   # Linux
   checksec --file=./binary
   cat /proc/sys/kernel/randomize_va_space  # ASLR level
   cat /proc/sys/kernel/kptr_restrict       # KASLR leak protection
   dmesg | grep -i "SMEP\|SMAP\|CET"
   
   # Windows
   # Check PE headers: ASLR, DEP, CFG, CET, ACG
   # Process mitigation policies via Get-ProcessMitigation
   
   # macOS/iOS
   # PAC (arm64e), PPL, AMFI, sandbox profile
   ```

2. **Bypass Selection Matrix:**
   | Mitigation | Bypass Strategy |
   |-----------|-----------------|
   | ASLR | Info leak, partial overwrite, brute force (32-bit) |
   | DEP/NX | ROP/JOP chain, mprotect/VirtualProtect, JIT page abuse |
   | Stack canary | Info leak canary, overwrite past canary to other target, format string |
   | CFI | Counterfeit objects (COOP), valid-but-wrong targets, JIT |
   | CET (shadow stack) | Overwrite non-return control flow, signal frame abuse |
   | SMEP/SMAP | Kernel ROP, physmap spray, ret2dir |
   | PAC (ARM64) | PAC oracle, signing gadgets, PAC-less code paths, dyld interposing abuse |
   | MTE (ARM64) | Brute force (16 tags), use-before-tag-check, speculative bypass |
   | Sandbox | Escape via IPC, shared memory, permitted syscalls, GPU process pivot |
   | SELinux | Transition to permissive domain, exploit allowed operations |

3. **Gadget Discovery:**
   ```bash
   # ROP gadgets
   ROPgadget --binary ./target --ropchain
   ropper -f ./target --search "pop rdi"
   # JOP gadgets
   ROPgadget --binary ./target --jop
   # Kernel gadgets
   ROPgadget --binary vmlinux --ropchain
   ```

**Reference:** `references/mitigation-bypass.md`, `references/arm64-exploitation.md`, `references/ios-webkit-chain.md`

---

## Phase 4: Exploit Construction

### Gate: working exploit with documented reliability

**Techniques:**

1. **Payload Development:**
   - ROP chain construction (stack pivot → mprotect → shellcode)
   - Kernel payload (commit_creds(prepare_kernel_cred(0)), namespace escape)
   - Shellcode (see `references/shellcode-dev.md`)
   - Return-to-libc / one_gadget (glibc)

2. **Reliability Engineering:**
   - Heap spray density calculation (target allocation probability)
   - Race condition timing (CPU pinning, priority manipulation, userfaultfd)
   - Retry logic (non-destructive failure mode → retry without crash)
   - Cross-version support (offset tables, heuristic-based offset finding)

3. **Post-Exploitation Stability:**
   - Fix corrupted heap metadata (prevent crash on next allocation/free)
   - Restore overwritten kernel structures
   - Clean up spray objects (prevent OOM)
   - Fork before exploit (parent survives crash)

4. **Target Adaptation:**
   ```python
   # Offset table pattern
   OFFSETS = {
       "5.15.0-generic": {"commit_creds": 0xdeadbeef, "prepare_kernel_cred": 0xcafebabe},
       "5.19.0-generic": {"commit_creds": 0x12345678, "prepare_kernel_cred": 0x87654321},
   }
   ```

**Reference:** `references/shellcode-dev.md`, `references/linux-kernel.md`, `references/windows-kernel.md`, `references/ios-webkit-chain.md`

---

## Phase 5: Documentation & Delivery

### Gate: complete write-up with PoC, impact demonstration, remediation

**Report Structure:**

```markdown
# Exploit Write-Up — {Target} {Vuln Class}

## 1. Executive Summary
- Target, version, architecture
- Vulnerability class and root cause
- Impact achieved (LPE/RCE/sandbox escape)
- Reliability and constraints

## 2. Vulnerability Analysis
- Root cause with code references
- Trigger conditions
- Affected versions

## 3. Exploitation Strategy
- Primitives developed (info leak, write, exec)
- Mitigations bypassed and how
- Exploitation flow diagram

## 4. Exploit Code
- Annotated PoC with usage instructions
- Dependencies and environment requirements
- Expected output on success/failure

## 5. Reliability
- Success rate (N/M attempts)
- Timing constraints
- Target-specific requirements
- Failure modes and recovery

## 6. Remediation
- Root cause fix (patch)
- Mitigation hardening
- Detection opportunities (crash patterns, anomalous allocations)

## Appendix
- Offset tables
- Gadget lists
- Shellcode source
```

---

## Mandatory Checks

| Category | Minimum |
|----------|---------|
| Root Cause | Identified with code reference, not just "it crashes" |
| Primitive | At least one demonstrated (even if info leak only) |
| Mitigations | All active mitigations enumerated for target |
| Reliability | Tested N≥5 times, success rate documented |
| Cleanup | Exploit doesn't crash target after success (or documents why) |
| Portability | Offset/version dependencies documented |

---

## Effort Allocation

| Phase | % | 8-hour target | 16-hour target | Rationale |
|-------|---|---------------|----------------|-----------|
| 1 Analysis | 15% | 75 min | 2.5 hr | Understand before building |
| 2 Primitives | 30% | 2.5 hr | 5 hr | Hardest creative work |
| 3 Mitigations | 20% | 100 min | 3 hr | Research-heavy |
| 4 Construction | 25% | 2 hr | 4 hr | Integration + reliability |
| 5 Documentation | 10% | 50 min | 1.5 hr | Write-up + PoC polish |

## Abandon & Pivot Heuristics

**Phase 1 (Analysis):**
- Can't reproduce crash after 1 hour → verify exact version/config, check if already patched
- Root cause unclear after 2 hours → try different analysis approach (dynamic vs static), or get help
- Bug is in unreachable code path → abort (no attacker-controlled trigger)

**Phase 2 (Primitives):**
- No info leak after 2 hours → try alternative leak sources (side channel, partial overwrite, brute force if 32-bit)
- No write primitive after 4 hours → reassess exploitability. If Theoretical → abort.
- Heap shaping fails consistently → try different spray object, different allocator path, or cross-cache technique

**Phase 3 (Mitigations):**
- Can't bypass ASLR + no leak source → check if partial overwrite is sufficient for the target
- CFI/PAC blocking all gadgets → look for PAC-less code paths, or pivot to data-only attack
- Sandbox too restrictive → assess if the bug alone (pre-sandbox-escape) has enough impact to report

**Phase 4 (Construction):**
- Reliability below 30% after 2 hours of tuning → document as "requires further work", report with current rate
- Exploit works on test VM but not real target → version/config mismatch, rebuild test environment
- Kernel exploit causes panic on failure → add fork-before-exploit or find non-destructive failure path

**Global abandon rules:**
- **Target patched mid-development** → document progress, archive. Primitives may apply to future bugs in same component.
- **Exploitability downgraded to Theoretical** → abort, document why. Don't spend 16 hours on a bug that can't be exploited.
- **3+ separate bugs needed for chain** → reassess ROI. Only continue if payout/impact justifies the complexity.
- **CTF/lab context** → time-box to competition duration. Partial progress (primitives without full chain) still earns points.

---

## Guardrails

- **Authorization** — only develop exploits for targets you have explicit authorization to test (pentest engagement, CTF, own systems, coordinated disclosure)
- **Containment** — test exploits in isolated environments (VMs, containers, dedicated hardware). Never run kernel exploits on production systems.
- **No Weaponization** — exploits are PoC-grade for demonstrating impact. Don't add persistence, lateral movement, or evasion unless specifically scoped.
- **Responsible Disclosure** — if developing for a real vulnerability, follow coordinated disclosure timelines. Don't publish before vendor patch.
- **Data Safety** — kernel exploits can corrupt filesystems. Always snapshot before testing. Document destructive failure modes.
- **Scope Creep** — if exploitation requires chaining 3+ separate bugs, reassess whether the complexity is justified for the engagement. Document the chain even if you can't complete it.
