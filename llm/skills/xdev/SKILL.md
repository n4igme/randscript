---
name: xdev
version: 1.1.0
description: "System-level exploit development framework covering Linux, Windows, macOS, Android, iOS, and firmware. 5 gated phases from vulnerability analysis through reliable exploit delivery."
tags: [exploit, exploitation, shellcode, rop, heap, kernel, firmware, arm64, mitigation-bypass]
trigger: "exploit dev, exploit development, write exploit, build exploit, shellcode, rop chain, heap exploitation, kernel exploit, privilege escalation exploit, firmware exploit"
argument-hint: "<command: start|status|resume|next|report|abort|cleanup>"
notes:
  - "v1.1.0: Added Phase Entry Protocol, time_tracking, findings.jsonl procedure, N/A phase guidance. Fixed stale cross-skill references (ptest/mtest phase numbers). Added retools to related_skills."
  - "v1.0.2: Current stable. Platform decision tree, mandatory checks, abandon heuristics."
metadata:
  hermes:
    tags: [exploit, development, shellcode, kernel, firmware, offensive]
    related_skills: [ptest, mtest, ctest, retools]
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

Quick Primitives (mid-engagement entry):
  - Crash PoC in hand → reproduce 3x, collect crash dump, identify crash type (SEGV/abort/assert)
  - Source code available → trace input to vulnerable sink, identify control flow
  - Patch/diff available → find root cause, check if fix is complete or bypassable
  - No crash yet → fuzz with AFL++/libFuzzer for 30min before static analysis
```

## Architecture

**state.yaml schema:**
```yaml
engagement:
  name: string
  started: ISO8601
  target_binary: string
  exploit_type: string
current_phase: int
gateways:
  1_analysis: OPEN|PASSED|LOCKED
  2_primitives: ...
  3_mitigations: ...
  4_construction: ...
  5_documentation: ...
findings_count: int
time_tracking:
  phase_1_start: ISO8601
  # ... per phase
notes: string
```

```
Phase 1: Vuln Analysis → Phase 2: Primitive Dev → Phase 3: Mitigation Bypass → Phase 4: Exploit Construction → Phase 5: Documentation
```

## Scripts

Scripts in `~/.hermes/skills/security/xdev/scripts/`:
- **state_manager.py**: `init_state()`, `status()`, `advance_phase()`, `set_primitive()`, `add_bypass()`, `add_dead_end()`, `set_reliability()`, `abandon()`
- **gate_check.py**: `check_gate(workdir, phase)`, `print_gate_status(result)` — run before advancing
- **rop_builder.py**: ROP chain construction helpers
- **heap_spray.py**: Heap spray primitives

### Gate Enforcement (MANDATORY before `next`)

```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/xdev/scripts"))
from gate_check import check_gate, print_gate_status

result = check_gate(".", phase=None)
print_gate_status(result)
```

## When to Use / When NOT to Use

**Use when:**
- Target matches skill scope (see Quick Reference phases)
- You have required access level (credentials, API token, device, etc.)
- Authorization is confirmed (written permission for pentest, own assets for research)

**Avoid when:**
- Target is explicitly out of scope
- No credentials/token/device available and skill requires authenticated testing
- Time budget is insufficient for minimum viable engagement (< 15 min)
- Legal/ToS constraints block required techniques
- No crash PoC or fuzzer output
- Target is userland app with no binary access (use ptest/scode)
- Bug is in unreachable code (no attacker-controlled trigger)

## Error Handling

| Failure Mode | Action |
|--------------|--------|
| Tool exits non-zero | Capture stderr, check if partial output is usable |
| API rate limit (429) | Back off, retry once. If persistent, document and pivot |
| Credential expired | Re-acquire or document as finding (credential rotation issue) |
| Target unreachable | Retry 3x with 30s gap. If still down, mark host UNREACHABLE |
| Permission denied | Try alternative auth method. If blocked, document scope gap |
| WAF blocking | Try 3 bypass techniques max, then document WAF and move on |
| Frida detach | Retry with `-f` spawn mode. 3 failures → anti-Frida, escalate |

**Rules:**
- Never retry blindly — understand the error first
- Save partial results before retrying (power loss, network drop)
- Document blocker findings with evidence (screenshot, HTTP status)
- On repeated failure (>3 attempts): mark as BLOCKED, continue to other surface

## Concurrent Execution Safety

See `../references/concurrent-execution-safety.md` for state locking, parallel scanning, and subagent handoff rules.

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

#### Postmortem

After engagement closes, run shared retrospective:
```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/scripts"))
from postmortem import run_postmortem
run_postmortem(workdir, "xdev")
```

## Command Procedures

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

time_tracking:
  phase_1_start: ""
  phase_1_end: ""
  phase_2_start: ""
  phase_2_end: ""
  phase_3_start: ""
  phase_3_end: ""
  phase_4_start: ""
  phase_4_end: ""
  phase_5_start: ""
  phase_5_end: ""
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

## Phases (load reference for full methodology)

| Phase | Gate | Reference |
|-------|------|-----------|
| 1 Vulnerability Analysis | root cause understood, crash PoC reproducible, exploitability assessed | `references/phase1-vuln-analysis.md` |
| 2 Primitive Development | at least one useful primitive (read/write/exec) achieved from the bug | `references/phase2-primitive-dev.md` |
| 3 Mitigation Assessment & Bypass | all relevant mitigations identified, bypass strategy documented | `references/phase3-mitigation-bypass.md` |
| 4 Exploit Construction | reliable exploit achieving target capability (code exec, priv esc, etc.) | `references/phase4-exploit-construction.md` |
| 5 Documentation & Delivery | full writeup + exploit code delivered | see below |

**Usage:** `skill_view(name='xdev', file_path='references/phase1-vuln-analysis.md')` when entering that phase.

### Phase Entry Protocol (ALL phases)

When entering ANY phase, before executing techniques:
1. **Load reference file** — per Phases table above (+ Platform Decision Tree reference for Phase 2)
2. **Record timestamp** — write `phase_N_start` in state.yaml
3. **Review primitives state** — check which primitives are achieved so far, plan what this phase needs to produce

### N/A Phases

If a phase is not applicable (firmware with no mitigations → Phase 3 N/A, info-leak-only scope → Phase 4 N/A), document justification in state.yaml and mark gateway `N/A`. Never skip silently.

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

## Cross-Skill Triggers

**Into xdev (from other skills):**
- ptest finds RCE primitive (deserialization, SSTI) needing reliability work → invoke xdev Phase 2+
- mtest finds native buffer overflow in .so → invoke xdev (Android native path)
- scode identifies exploitable UAF/OOB in source → invoke xdev for PoC development
- ctest finds container escape primitive needing kernel exploit → invoke xdev (Linux kernel path)

**Out of xdev (to other skills):**
- Working exploit achieves code exec → hand to ptest Phase 5 (Post-Exploit & Impact)
- Exploit targets mobile native lib → hand back to mtest Phase 5 (Runtime & Vuln)
- Exploit grants cloud credentials → hand to ctest Phase 2 (IAM escalation)
- Exploit needs RE work (stripped binary, unknown format) → hand to retools

| xdev Finding | Triggers | Action |
|--------------|----------|--------|
| LPE achieved on target host | ptest | Post-exploitation: pivot, dump creds, lateral |
| Sandbox escape from app | mtest | Chain with app-layer findings for full impact |
| Kernel code exec | ctest | Test if cloud metadata/K8s SA accessible |
| Info leak primitive only | ptest/mtest | Report as-is, chain with other vulns for severity |

---

## Guardrails

- **Authorization** — only develop exploits for targets you have explicit authorization to test (pentest engagement, CTF, own systems, coordinated disclosure)
- **Containment** — test exploits in isolated environments (VMs, containers, dedicated hardware). Never run kernel exploits on production systems.
- **No Weaponization** — exploits are PoC-grade for demonstrating impact. Don't add persistence, lateral movement, or evasion unless specifically scoped.
- **Responsible Disclosure** — if developing for a real vulnerability, follow coordinated disclosure timelines. Don't publish before vendor patch.
- **Data Safety** — kernel exploits can corrupt filesystems. Always snapshot before testing. Document destructive failure modes.
- **Scope Creep** — if exploitation requires chaining 3+ separate bugs, reassess whether the complexity is justified for the engagement. Document the chain even if you can't complete it.

---

### Evidence Standards

All findings must follow `../references/evidence-standards.md` for required/optional evidence capture and redaction rules.

### Severity Mapping

Cross-skill severity normalization: `../references/severity-mapping.md`

## Pitfalls

- Kernel exploits: always check target kernel version + config (KASLR, SMEP, SMAP, kCFI) before investing time
- Heap exploits: glibc version matters enormously — tcache (2.26+), safe-linking (2.32+), per-thread cache changes
- Race conditions: timing windows vary wildly across hardware — PoC must demonstrate reliability percentage
- ASLR bypass: don't assume info leak exists — document the leak primitive separately from the main bug
- iOS: PAC bypass is mandatory for code exec on A12+ — budget time for this or downgrade scope to data-only

## Cross-Skill Chaining (findings.jsonl)

When recording a finding, append to `./xdev-output/findings.jsonl` for cross-skill consumption:

```python
import json
from datetime import datetime
finding = {
    "id": "XDEV-{count:03d}",
    "skill": "xdev",
    "severity": "{severity}",
    "type": "{vuln_type}",  # e.g., lpe, rce, sandbox_escape, info_leak, kernel_exec
    "target": "{binary_or_component}:{version}",
    "summary": "{one-line description}",
    "chain_potential": [],  # e.g., ["ptest:post_exploit", "mtest:mobile_chain", "ctest:cloud_pivot"]
    "timestamp": datetime.now().isoformat(),
    "phase": "{current_phase}",
    "confidence": "confirmed",  # confirmed / probable / theoretical
    "status": "confirmed",
    "reliability": "{percentage}"
}
with open("./xdev-output/findings.jsonl", "a") as f:
    f.write(json.dumps(finding) + "\n")
```

