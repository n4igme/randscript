---
name: mtest
version: 1.0.1
description: "Structured mobile application penetration testing framework with 10 gated phases for Android and iOS"
tags: [mobile, pentest, android, ios, frida, security]
trigger: "mobile pentest, mobile app test, APK test, IPA test, android security, ios security, dexguard bypass, appfence bypass, libaf-android, native root detection, inline svc bypass"
argument-hint: "<command: start|status|next|resume|report|abort|cleanup>"
notes:
  - "v3.0.0: Hub model — SKILL.md is routing + framework rules. All phase content in references/phase*.md"
  - "scripts/ contains Frida bypass scripts and phase automation"
  - "NEVER rewrite full SKILL.md in one tool call — use strReplace for edits"
metadata:
  hermes:
    tags: [mobile, pentest, android, ios, frida, security]
    related_skills: [ptest, retools, scode, atest]
---

# Mobile Application Penetration Testing (mtest)

## Quick Reference

```
Phases:  1.Preflight → 2.Static → 3.Bypass → 4.Traffic → 5.AttackSurface → 6.Runtime → 7.VulnAnalysis → 8.API → 9.Exploit → 10.Report
States:  LOCKED → OPEN → PASSED → N/A (sequential, no skipping)
Commands: start | status | next | resume | report | abort | cleanup

Key rules:
  • Feature-driven testing (by app feature, not by vuln class)
  • Production Validation: Critical requires non-rooted device proof
  • Bypass decision tree: 5 attempts → assess, 10 → hard stop
  • Confidence: Confirmed > Probable > Theoretical (never Critical + Theoretical)
  • Phase 3 is a MEANS to validate findings, not a finding itself
  • N/A phases must be documented with justification (not skipped silently)

Time caps (for 2-day/16hr engagement):
  P1: 45min  P2: 2.5hr  P3: 1.5hr  P4: 1.5hr  P5: 45min
  P6: 2.5hr  P7: 3hr    P8: 1.5hr  P9: 45min  P10: 45min
```

## Commands

| Command | Action |
|---------|--------|
| `start` | Begin new engagement — create output dir, define scope |
| `status` | Show current phase, progress, findings count |
| `resume` | Resume interrupted engagement — read state and continue |
| `next` | Advance to next phase (requires current phase gate satisfied) |
| `report` | Generate findings report (available from Phase 7+) |
| `abort` | Terminate engagement early (device bricked, app removed, client revokes access) |
| `cleanup` | Archive output, sanitize sensitive data |

---

## Phase Routing

When entering a phase, load the corresponding reference file:

| Phase | File | Gate Summary |
|-------|------|-------------|
| 1 | `references/phase1-preflight.md` | scope.md exists, target app identified, tools verified |
| 2 | `references/phase2-static-core.md` + `references/phase2-extended-checks.md` | decompilation complete, secrets scanned, endpoints extracted |
| 3 | `references/phase3-bypass.md` | protections bypassed or documented; Frida attaches |
| 4 | `references/phase4-traffic.md` | proxy intercepting, API mapped, auth flow documented (or N/A) |
| 5 | `references/phase5-attack-surface.md` | feature map with entry points, prioritized by risk |
| 6 | `references/phase6-runtime.md` + `references/phase6-test-categories.md` | Data Storage tested + 2 others; deep links tested |
| 7 | `references/phase7-vuln-analysis.md` + `references/phase7-execution-procedures.md` | all features from attack surface map tested |
| 8 | `references/phase8-api.md` | BOLA + auth bypass + injection tested (or N/A) |
| 9 | `references/phase9-exploitation.md` | all Critical/High have PoC or documented limitation |
| 10 | `references/phase10-reporting.md` | all findings documented, report generated |

**Load only the active phase file(s).** Each contains: gate, steps, commands, references.

---

## Framework Rules

### State Tracking

On `start`, create `state.yaml` in `<workdir>/mtest-output/`:

```yaml
engagement:
  name: ""
  target_app: ""
  package_id: ""
  bundle_id: ""
  started: ""
  platforms: []  # android, ios, or both

platform_progress:  # Only used when platforms has both
  android: {phase: 1, findings: 0, bypass_working: false}
  ios: {phase: 1, findings: 0, bypass_working: false}

gateways:
  1_preflight: OPEN
  2_static_analysis: LOCKED
  3_protection_bypass: LOCKED
  4_traffic_analysis: LOCKED
  5_attack_surface: LOCKED
  6_runtime_testing: LOCKED
  7_vulnerability_analysis: LOCKED
  8_api_testing: LOCKED
  9_exploitation: LOCKED
  10_reporting: LOCKED

findings_count: 0
current_phase: 1
notes: ""
```

### Finding ID Assignment

1. Read `findings_count` from `state.yaml`
2. Increment by 1 → `MTEST-{count:03d}`
3. Write updated count back immediately

### Command Procedures

**`start`:**
1. Define scope: app name, package/bundle ID, platform(s), version, engagement type (internal/bounty).
2. Create `<workdir>/mtest-output/` with subdirs for each phase.
3. Run `state_manager.init(workdir, name, package_id, platforms)` → creates state.yaml + scope.md.
4. Verify tools: Frida server running, proxy configured, device connected (`adb devices` / `ideviceinfo`).
5. Begin Phase 1 preflight immediately.

**`status`:** Show current phase, gateway states, findings count by severity, bypass status, time elapsed.

1. Verify phase gate criteria met (see phase file's Gate section)
2. Ask user: "Phase X complete. N findings. Advance to Phase Y?"
3. Update `state.yaml`: mark current PASSED, unlock next, record timestamps

**If gate NOT met:** list unmet criteria, suggest actions. Allow override with justification.

### Resume (`resume`)

1. Read `state.yaml` to determine active phase
2. **Staleness check:**
   - **>3 days:** Re-verify bypass still works (apps push silent updates)
   - **>7 days:** Re-pull APK (version may have changed). Re-run Phase 2 fast-path.
   - **>30 days:** Treat as near-fresh engagement.
3. Report status and suggest next action

### Abort (`abort`)

**Valid reasons:** device bricked/lost, app removed, client revokes access, legal concern.

1. Record reason in state.yaml, mark remaining gateways `ABORTED`
2. Generate partial report if findings exist
3. Run cleanup

### Cleanup (`cleanup`)

1. Archive `./mtest-output/` to `mtest-output-{app}-{date}.tar.gz`
2. Remove YOUR credentials — keep found credentials as evidence
3. Print summary: findings by severity, phases completed, duration

### Script Failure Protocol

| Exit Condition | Action |
|----------------|--------|
| Exit 0 / script runs | Parse output, continue |
| Frida crash / detach | Retry with `-f` (spawn). If 3 crashes → anti-Frida, escalate to Phase 3 |
| Script timeout | Kill, restart app, retry once |
| Total failure | Fall back to manual (adb, objection, or static evidence) |

Phase gates are NOT satisfied by failed scripts.

### N/A Phases

If a phase is not applicable (no API for Phase 8, no pinning for Phase 3), document justification and mark gateway `N/A`. Never skip silently.

### Offline/No-Network App

When app has no internet permission and no HTTP URLs: Phase 4 → N/A, Phase 8 → N/A. Detect in Phase 2.

### Exploit Validation

Critical/High findings MUST be validated dynamically in Phase 9 before final reporting. If not possible, document limitation explicitly.

### When to Stop Chasing a Bypass

1. **5 failed attempts:** Assess — is the finding worth validating?
2. **10 failed attempts:** Hard stop. Submit with static evidence at Probable/Theoretical.
3. **Bypass works but finding doesn't:** Re-analyze code path, identify mitigating control, downgrade.
4. **Cost-benefit:** Time on bypass ∝ finding value. Theoretical Medium ≠ 20+ iterations.
5. **Alternatives:** Non-rooted device, emulator, Frida Gadget (no server), accept static evidence.

---

## Effort Allocation

| Phase | % | Time Cap (16hr) | Rationale |
|-------|---|-----------------|-----------|
| 1 Preflight | 5% | 45 min | Setup |
| 2 Static | 15% | 2.5 hr | Foundation |
| 3 Bypass | 10% | 1.5 hr | Means to an end (cap at decision tree) |
| 4 Traffic | 10% | 1.5 hr | Baseline capture |
| 5 Attack Surface | 5% | 45 min | Organize |
| 6 Runtime | 15% | 2.5 hr | Dynamic validation |
| 7 Vuln Analysis | 20% | 3 hr | Core testing |
| 8 API | 10% | 1.5 hr | Server-side |
| 9 Exploitation | 5% | 45 min | Chain and prove |
| 10 Reporting | 5% | 45 min | Write-up |

**Move-on rule:** Phase exceeds time cap with no findings → advance. Exception: Phase 7 can extend if actively finding bugs.

**Adjustments:**
- Bug bounty: compress P1/4/5/10, expand P7
- Banking app: expand P3 (bypass) + P8 (attestation APIs)
- Offline app: skip P4/P8, expand P6

---

## Dual-Platform Engagement (Android + iOS)

**Execution order:** Android first (easier instrumentation), then iOS (Android findings guide where to look).

**Phase sharing:**
- **Per-platform (run twice):** Phase 2, Phase 3, Phase 6
- **Shared (run once):** Phase 4, Phase 5, Phase 7, Phase 8
- **Merge:** Phase 9 (per-finding per-platform), Phase 10 (unified report)

**Rules:**
- API-level findings only need testing once (same backend)
- Platform-specific findings get separate MTEST-XXX entries tagged `[Android]` or `[iOS]`
- Attack surface map (Phase 5) is unified, entries tagged per platform
- Time adjustment: +40% (not +100%) because shared phases

---

## App-Type Decision Tree

Load full decision tree: `references/app-type-decision-tree.md`

**Quick:** Banking (heavy bypass + IDOR) | Social (deep links + WebView + API) | Utility (local storage + IPC) | Game/Unity (metadata + native RE) | Flutter (libapp.so strings + BoringSSL bypass)

---

## Bug Bounty Fast-Path

Load: `references/bug-bounty-fast-path.md`

**TL;DR:** Static (30min) → Bypass (if pinned) → Traffic (15min) → Skip to Phase 7 highest-value features → Exploit → Submit. Budget: 4-8 hours.

---

## Output Structure

```
<workdir>/mtest-output/
├── state.yaml
├── scope.md
├── phase1-preflight/
├── phase2-static/
├── phase3-protection/
│   └── scripts/
├── phase4-traffic/
├── phase5-attack-surface/
│   └── attack-surface-map.md
├── phase6-runtime/
├── phase7-vuln-analysis/
│   └── per-feature/
├── phase8-api/
├── phase9-exploitation/
│   ├── poc/
│   └── evidence/
├── phase10-reporting/
├── findings/
│   └── MTEST-001.md
└── report.md
```

---

## Pitfalls

### Mobile-Specific
- **`allowBackup=true` is Info, not Medium** — Android 12+ encrypts backups by default. Only escalate if sensitive data in plaintext SharedPreferences AND targetSdk < 31.
- **WebView `loadUrl()` ≠ XSS** — unless `setJavaScriptEnabled(true)` AND user-controlled URL/content reaches it. Check both conditions before reporting.
- **Root/jailbreak detection bypass is NOT a finding** — it's a means to test. Phase 3 is a tool, not a result. Only report if bypass enables a real attack chain.
- **Frida on KernelSU 0.7.1 (kernel 4.4)** — too old for Zygisk/Shamiko. Use hluda-server at `/data/local/tmp/`, not regular frida-server. Spawn mode (`-f`) more reliable than attach.
- **Certificate pinning bypass alone is Medium at best** — only escalates if you can demonstrate real API abuse (IDOR, auth bypass) through the unpinned traffic.
- **`exported=true` on activities ≠ vulnerability** — only if the activity handles sensitive data without re-authentication or accepts untrusted input that leads to harm.
- **Don't report debug/test code in release builds as High** — unless it's actually reachable (check if BuildConfig.DEBUG gates it). Unreachable dead code is Info.

### Workflow
- **NEVER sync FROM randscript/myherms TO Hermes skills without explicit user confirmation.** Hermes is source of truth.
- **Scripts from delegate_task subagents are not recoverable from state.db** — rebuild from scratch if lost.
- **Before bulk file operations, verify backup exists.**

## Cross-Skill Triggers

| Signal | Trigger |
|--------|---------|
| API endpoints in traffic | `atest` |
| Cloud storage URLs (S3/GCS) | `ctest` |
| Web endpoints found | `ptest` |
| Hardcoded secrets/source code | `scode` |
| Web3/smart contract SDK | `w3hunt` |
| API geo-blocked | ptest `references/geo-restriction-bypass.md` |
| Large app (50K+ classes) | delegate Phase 2 to subagent |

## Operational Notes

> Full notes: `references/operational-notes.md`
