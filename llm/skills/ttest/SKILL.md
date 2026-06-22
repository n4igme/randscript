---
name: ttest
version: 1.1.0
description: "Thick client (desktop application) penetration testing — .NET, Java, Electron, native Win/Mac apps. Proxy, local storage, business logic, DLL hijacking."
tags: [thick-client, desktop, pentest, dotnet, electron, java, windows]
trigger: "thick client pentest, desktop app test, .NET app test, Electron test, Java desktop test, WinForms test, WPF test"
argument-hint: "<command: start|status|resume|next|report|abort|cleanup>"
notes:
  - "v1.1.0: Added Phase Entry Protocol, findings.jsonl procedure, Abandon & Pivot Heuristics, N/A phase guidance. Aligned with skill family patterns."
  - "v1.0.1: Added command procedures, state.yaml schema, gate enforcement, script invocation, finding template."
metadata:
  hermes:
    tags: [thick-client, desktop, pentest, dotnet, electron, java, windows]
    related_skills: [ptest, retools, xdev, atest, scode]
---

# Thick Client Penetration Testing Framework

5-phase workflow for desktop application security testing. Fills the gap between web (ptest), mobile (mtest), and binary exploitation (xdev).

## Quick Reference

```
Phases:  1.Recon&Setup → 2.Traffic → 3.LocalAnalysis → 4.BusinessLogic → 5.Report
States:  LOCKED → OPEN → PASSED (sequential)
Commands: start | status | next | resume | report | abort | cleanup

Key rules:
  • Identify app type FIRST — .NET/Java/Electron/Native dictate toolchain
  • Traffic interception is harder than web — expect non-HTTP protocols
  • Local storage is the #1 source of findings in thick clients
  • Client-side logic bypass is almost always possible — prove it
  • DLL hijacking / sideloading = easy High finding on Windows

Cross-skill integration:
  • HTTP/API traffic found → hand to atest
  • Source code recovered (.NET/Java decompile) → hand to scode
  • Memory corruption found → hand to xdev
  • Binary RE needed → hand to retools
```

## Architecture

```
Phase 1: Recon & Setup → Phase 2: Traffic Analysis → Phase 3: Local Analysis → Phase 4: Business Logic → Phase 5: Reporting
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
- No app binary or installer
- App is web-only (use ptest/atest)
- Thin wrapper around web app with no client-side logic

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

## Retry / Timeout Patterns

| Operation | Timeout | Retry | Backoff |
|-----------|---------|-------|---------|
| HTTP requests | 30s | 3x | 5s linear |
| nuclei scan | 300s | 2x | 30s |
| Frida attach | 10s | 3x | 5s |
| Burp request | 60s | 2x | 10s |
| Cloud CLI | 120s | 2x | 30s |
| Git clone | 60s | 2x | 10s |

**Rules:**
- On timeout: wait for backoff, retry once. If persistent, document as blocker.
- On 429/503: exponential backoff (5s → 25s → 125s), max 3 attempts.
- On partial output: save what you have, note the gap, continue.
- Long-running scans: use background terminal with `notify_on_complete=true`.

| Command | Action |
|---------|--------|
| `start` | Initialize engagement — identify app type, setup proxy, create output dir |
| `status` | Show current phase, progress, findings count |
| `resume` | Resume interrupted engagement from last checkpoint |
| `next` | Advance to next phase (runs exit criteria check) |
| `report` | Generate final report |
| `abort` | Terminate engagement early |
| `cleanup` | Archive output, remove test artifacts |

## App-Type Decision Tree

```
What type of thick client?
│
├── .NET (WinForms / WPF / MAUI)
│   ├── Decompile: dnSpy, ILSpy, dotPeek
│   ├── Patch: dnSpy (edit + recompile IL)
│   ├── Proxy: Fiddler (auto .NET proxy), Burp (manual proxy settings)
│   ├── Local: %AppData%/Local, registry, SQLite, ProtectedData (DPAPI)
│   └── Key findings: hardcoded creds, DPAPI blobs, DLL hijack, license bypass
│
├── Java (Swing / JavaFX / Eclipse RCP)
│   ├── Decompile: JADX, JD-GUI, CFR, Procyon
│   ├── Patch: recaf, reassemble JAR
│   ├── Proxy: -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=8080
│   ├── Local: ~/.app/, preferences API, serialized objects
│   └── Key findings: hardcoded keys, deserialization, trust-all-certs, license bypass
│
├── Electron (Node.js + Chromium)
│   ├── Decompile: asar extract (plaintext JS/HTML/CSS)
│   ├── Patch: modify app.asar directly
│   ├── Proxy: --proxy-server="http://127.0.0.1:8080" flag
│   ├── Local: %AppData%/{app}/, IndexedDB, localStorage, keytar
│   ├── Key findings: nodeIntegration XSS→RCE, preload script abuse, IPC abuse, contextIsolation bypass
│   └── Reference: `references/electron-testing.md`
│
├── Native (C/C++ / Delphi / Qt)
│   ├── Decompile: Ghidra, IDA, x64dbg
│   ├── Patch: binary patching (x64dbg, Ghidra)
│   ├── Proxy: Proxifier (system-wide), custom hosts file
│   ├── Local: registry, AppData, custom file formats
│   └── Key findings: buffer overflow, DLL hijack, hardcoded crypto keys
│
└── Hybrid (CEF / WebView2 / Qt WebEngine)
    ├── Treat as web app in a shell — Chrome DevTools often available
    ├── Proxy: Proxifier or --proxy-server flag
    ├── DevTools: --remote-debugging-port=9222
    └── Key findings: same as web (XSS, CSRF) + local file access escalation
```

## Phase Routing

| Phase | Gate | Reference |
|-------|------|-----------|
| 1 Recon & Setup | App type identified, proxy working, tools ready | `references/phase1-recon-setup.md` |
| 2 Traffic Analysis | All protocols intercepted, API surface mapped | `references/phase2-traffic.md` + `references/non-http-protocol-testing.md` |
| 3 Local Analysis | Storage audited, secrets scanned, DLL hijack tested | `references/phase3-local-analysis.md` |
| 4 Business Logic | Client-side controls bypassed, license/auth tested | `references/phase4-business-logic.md` |
| 5 Reporting | All findings documented with PoCs | (inline below) |

### Phase Entry Protocol (ALL phases)

When entering ANY phase, before executing techniques:
1. **Load reference file** — per Phase Routing table above
2. **Record timestamp** — write `phase_N_start` in state.yaml
3. **Confirm app type context** — verify toolchain matches app type from Phase 1

### N/A Phases

If a phase is not applicable (offline app → Phase 2 Traffic minimal, simple utility → Phase 4 Business Logic N/A), document justification in state.yaml and mark gateway `N/A`. Never skip silently.

## Effort Allocation

| Phase | % | 4-hour engagement | 8-hour engagement |
|-------|---|-------------------|-------------------|
| 1 Recon & Setup | 15% | 35 min | 70 min |
| 2 Traffic | 25% | 60 min | 120 min |
| 3 Local Analysis | 25% | 60 min | 120 min |
| 4 Business Logic | 25% | 60 min | 120 min |
| 5 Reporting | 10% | 25 min | 50 min |

## Cross-Skill Triggers

| Signal | Target Skill | Action |
|--------|-------------|--------|
| HTTP/REST API traffic captured | atest | Full API pentest Phase 2+ |
| .NET/Java source recovered | scode | Code review (scope_type: desktop) |
| Buffer overflow in native lib | xdev | Exploit development |
| Binary needs deep RE | retools | Ghidra/IDA analysis |
| Web endpoints discovered | ptest | Standard web pentest |
| Cloud storage/API keys found | ctest | Cloud access testing |

## Abandon & Pivot Heuristics

**Phase 1 (Recon & Setup):**
- Proxy can't intercept after 30 min (custom protocol, cert issues) → Wireshark passive capture + proceed to Phase 3 (local analysis)
- App type unclear (heavily obfuscated native) → cap RE at 45 min, focus on traffic and storage

**Phase 2 (Traffic):**
- No HTTP traffic after 20 min → check for non-HTTP protocols (Wireshark). If custom binary protocol → document structure, move to Phase 3
- All traffic is encrypted with pinned cert and unpatchable → document, shift time to Phase 3/4
- Rich REST API discovered → hand to atest, focus ttest on local/logic

**Phase 3 (Local Analysis):**
- Storage encrypted and undecryptable → document, move to Phase 4
- No local storage at all (cloud-only app) → mark Phase 3 N/A after 15 min, expand Phase 4
- DLL hijack testing blocked by admin environment → document, continue with other checks

**Phase 4 (Business Logic):**
- App is simple utility with no business logic → mark N/A, proceed to reporting
- Client-side checks all properly server-validated → document "client hardened", move to report
- Memory corruption found during patching → hand to xdev, don't chase in ttest scope

**Global:**
- **75% budget, zero findings** → focus remaining time on DLL hijack + secrets scan (highest probability quick wins)
- **App auto-updates mid-test** → document version change, re-verify findings still reproduce
- **Source fully recovered (.NET/Java)** → hand to scode, shift ttest focus to runtime behavior only

### Severity Mapping

Cross-skill severity normalization: `../references/severity-mapping.md`

## Pitfalls

- .NET `ProtectedData` (DPAPI): decryptable only as same user on same machine — prove it, don't assume
- Electron `app.asar`: NOT encrypted. `npx asar extract app.asar ./extracted/` gives full source
- Java `-Djavax.net.ssl.trustStore`: custom trust stores bypass system proxy — find and add your CA
- DLL hijacking: test in ISOLATED environment — wrong DLL path can crash production systems
- Proxifier: process-level rules, not system-wide. Match exact executable name.
- Non-HTTP protocols: Wireshark first to identify, THEN choose interception tool
- License bypass alone is often "accepted risk" for internal apps — chain with data access for impact
- Windows modern protections: WDAG (Defender Application Guard) and Smart App Control block untrusted installers and scripts. Test in VM first; check `windefend` service status + `AppLocker`/`Windows Defender Application Control` policies before DLL/sideload tests.

### Postmortem

After engagement closes, run shared retrospective:
```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/scripts"))
from postmortem import run_postmortem
run_postmortem(workdir, "ttest")
```

## Command Procedures

**`start`:**
1. Collect: app name, version, app type (dotnet/java/electron/native/hybrid), platform (windows/macos/linux), rules of engagement.
2. Run `state_manager.init_state(workdir, name, app_type, platform, proxy_port)` — creates output dirs + state.yaml + scope.md + findings-log.md.
3. Identify proxy strategy based on app type (see App-Type Decision Tree).
4. Verify proxy intercepts traffic. Begin Phase 1 immediately.

**`status`:** Output current phase, gateway states (5 phases), findings by severity, time elapsed, abandon check. If no engagement, suggest `start`.

**`resume`:**
1. Read `state.yaml` to determine active phase.
2. **Staleness:** >7 days → re-verify app version unchanged (auto-updates). >30 days → treat as fresh.
3. Report status and suggest next action.

**`next`:**
1. Run gate check (see Gate Enforcement below).
2. If NOT met: list unmet criteria, suggest what to test.
3. If met: `state_manager.advance_phase(workdir)`.
4. Override allowed with justification.

**`abort`:** `state_manager.abandon(workdir, reason)` — marks remaining ABANDONED, generates partial report.

**`cleanup`:** Archive `./ttest-output/` to `ttest-output-{app}-{date}.tar.gz`. Remove test artifacts (patched binaries, injected DLLs). Print summary.

## State Schema

```yaml
engagement:
  name: ""
  started: ""
  app_type: ""      # dotnet, java, electron, native, hybrid
  platform: ""      # windows, macos, linux, cross-platform
  proxy_port: 8080

gateways:
  1_recon_setup: OPEN
  2_traffic: LOCKED
  3_local_analysis: LOCKED
  4_business_logic: LOCKED
  5_reporting: LOCKED

findings_count: 0
findings_by_severity: {critical: 0, high: 0, medium: 0, low: 0, info: 0}
current_phase: 1
time_tracking:
  phase_1_start: ""
  phase_1_end: ""
  # ...through phase_5...
notes: ""
```

## Gate Enforcement (MANDATORY before `next`)

```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/ttest/scripts"))
from gate_check import check_gate, print_gate_status

result = check_gate(".", phase=None)
print_gate_status(result)
```

### Evidence Standards

All findings must follow `../references/evidence-standards.md` for required/optional evidence capture and redaction rules.

## Script Invocation

```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/scripts"))
from config import SKILL_CONFIG
import state_manager

workdir = "."
state_manager.init_state(workdir, "CorpApp", app_type="electron", platform="windows", proxy_port=8080)

state_manager.status(workdir)
state_manager.advance_phase(workdir)
state_manager.add_finding(workdir, "TTEST-001", "Hardcoded API key in app.asar", "High", "Secrets", "renderer/config.js")
state_manager.abandon(workdir, "App removed from scope")
```

## Finding Template

```markdown
## [TTEST-{ID}] {Title}

**Severity:** Critical / High / Medium / Low / Info
**Category:** Secrets / Traffic / Storage / Logic / DLL / Config
**Component:** `{file path or module within the application}`

### Description
{What the vulnerability is}

### Reproduction
{Steps to reproduce — app version, OS, tools used}

### Evidence
{Screenshot, extracted data, or command output}

### Impact
{What an attacker gains — data access, code execution, privilege escalation}

### Remediation
{Fix with priority}
```

### Cross-Skill Chaining (findings.jsonl)

When recording a finding, append to `./ttest-output/findings.jsonl` for cross-skill consumption:

```python
import json
from datetime import datetime
finding = {
    "id": "TTEST-{count:03d}",
    "skill": "ttest",
    "severity": "{severity}",
    "type": "{vuln_type}",  # e.g., dll_hijack, hardcoded_secret, license_bypass, insecure_storage, rce_electron
    "target": "{component_or_file}",
    "summary": "{one-line description}",
    "chain_potential": [],  # e.g., ["atest:api_testing", "scode:code_review", "xdev:exploit_dev"]
    "timestamp": datetime.now().isoformat(),
    "phase": "{current_phase}",
    "confidence": "confirmed",  # confirmed / probable / theoretical
    "status": "confirmed"
}
with open("./ttest-output/findings.jsonl", "a") as f:
    f.write(json.dumps(finding) + "\n")
```
