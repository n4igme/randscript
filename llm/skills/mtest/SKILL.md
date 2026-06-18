---
name: mtest
version: 4.0.0
description: "Structured mobile application penetration testing framework with 7 gated phases for Android and iOS"
tags: [mobile, pentest, android, ios, frida, security]
trigger: "mobile pentest, mobile app test, APK test, IPA test, android security, ios security, dexguard bypass, appfence bypass, libaf-android, native root detection, inline svc bypass"
argument-hint: "<command: start|status|next|resume|report|abort|cleanup|preflight|static|bypass|traffic-surface|runtime-vuln|api-exploit>"
notes:
  - "v4.0.0: Compressed 10 phases → 7. Merged Traffic+Surface, Runtime+VulnAnalysis, API+Exploitation. Added Phase Entry Protocol, time_tracking, discovery loop-back. Reference files unchanged — routing remapped."
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
Phases:  1.Preflight → 2.Static → 3.Bypass → 4.Traffic&Surface → 5.Runtime&Vuln → 6.API&Exploit → 7.Report
States:  LOCKED → OPEN → PASSED → N/A (sequential, no skipping)
Commands: start | status | next | resume | report | abort | cleanup
Phases:   preflight | static | bypass | traffic-surface | runtime-vuln | api-exploit | report

Key rules:
  • Feature-driven testing (by app feature, not by vuln class)
  • Production Validation: Critical requires non-rooted device proof
  • Bypass decision tree: 5 attempts → assess, 10 → hard stop
  • Confidence: Confirmed > Probable > Theoretical (never Critical + Theoretical)
  • Phase 3 is a MEANS to validate findings, not a finding itself
  • N/A phases must be documented with justification (not skipped silently)

Time caps (for 2-day/16hr engagement):
  P1: 45min  P2: 2.5hr  P3: 1.5hr  P4: 1.5hr  P5: 4hr  P6: 2.5hr  P7: 45min

Discovery loop-back:
  • P5/P6 findings revealing new endpoints/creds → append to discovery-queue.md
  • At phase exit, drain queue with targeted re-testing before advancing
```

## Commands

| Command | Action |
|---------|--------|
| `start` | Begin new engagement — create output dir, define scope |
| `status` | Show current phase, progress, findings count |
| `resume` | Resume interrupted engagement — read state and continue |
| `next` | Advance to next phase (requires current phase gate satisfied) |
| `report` | Generate findings report (available from Phase 5+) |
| `abort` | Terminate engagement early (device bricked, app removed, client revokes access) |
| `cleanup` | Archive output, sanitize sensitive data |

---

## Phase Routing

When entering a phase, load the corresponding reference file(s):

| Phase | Files | Gate Summary |
|-------|-------|-------------|
| 1 | `references/phase1-preflight.md` | scope.md exists, target app identified, tools verified |
| 2 | `references/phase2-static-core.md` + `references/phase2-extended-checks.md` | decompilation complete, secrets scanned, endpoints extracted |
| 3 | `references/phase3-bypass.md` | protections bypassed or documented; Frida attaches |
| 4 | `references/phase4-traffic.md` + `references/phase5-attack-surface.md` | proxy intercepting, API mapped, auth flow documented, attack surface map built and prioritized |
| 5 | `references/phase6-runtime.md` + `references/phase6-test-categories.md` + `references/phase7-vuln-analysis.md` + `references/phase7-execution-procedures.md` | all features from attack surface map tested dynamically; Data Storage + 2 others tested; deep links tested; discovery queue drained |
| 6 | `references/phase8-api.md` + `references/phase9-exploitation.md` | BOLA + auth bypass + injection tested; all Critical/High have PoC; chains documented |
| 7 | `references/phase10-reporting.md` | all findings documented, report generated |

**Load only the active phase file(s).** Each contains: gate, steps, commands, references.

### Phase Entry Protocol (ALL phases)

When entering ANY phase, before executing techniques:
1. **Load reference file(s)** — per Phase Routing table above
2. **Create/verify checklist** — `mtest-output/phase{N}-{name}/checklist.md` must exist with all techniques listed as PENDING
3. **Record timestamp** — write `phase_N_start` in state.yaml

### Discovery Loop-Back (Phase 5 & 6)

When runtime testing or API exploitation reveals NEW endpoints, credentials, or attack surface:
1. Append to `./mtest-output/discovery-queue.md` with source finding ID
2. At phase exit, before advancing: drain queue with targeted re-testing
3. Prevents "found creds during runtime testing but never tested the API with them" pattern

**Cross-skill references:**
- Attack recipes (mobile-specific): load ptest `references/attack-recipes.md` — includes deeplink hijacking, exported component abuse, cert pinning bypass patterns
- Severity escalation: load ptest `references/severity-escalation.md` after every finding

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
  4_traffic_surface: LOCKED
  5_runtime_vuln: LOCKED
  6_api_exploit: LOCKED
  7_reporting: LOCKED

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
  phase_6_start: ""
  phase_6_end: ""
  phase_7_start: ""
  phase_7_end: ""
  total_duration: ""  # Calculated at cleanup

findings_count: 0
current_phase: 1
notes: ""
```

### Finding ID Assignment

1. Read `findings_count` from `state.yaml`
2. Increment by 1 → `MTEST-{count:03d}`
3. Write updated count back immediately
4. **Append to `findings.jsonl`** for cross-skill chaining:
```python
import json
from datetime import datetime
finding = {
    "id": "MTEST-{count:03d}",
    "skill": "mtest",
    "severity": "{severity}",
    "type": "{vuln_type}",  # e.g., ssl_bypass, deeplink_hijack, insecure_storage, webview_rce
    "target": "{package_id} / {endpoint_if_applicable}",
    "summary": "{one-line description}",
    "chain_potential": [],  # Fill if applicable: ["atest:api_testing", "ptest:ssrf", "ctest:credential_access"]
    "timestamp": datetime.now().isoformat(),
    "phase": "{current_phase}",
    "status": "confirmed"
}
with open("./mtest-output/findings.jsonl", "a") as f:
    f.write(json.dumps(finding) + "\n")
```

**Cross-skill chain triggers from mtest findings:**
| mtest Finding | Triggers | Action |
|---------------|----------|--------|
| API endpoint without cert pinning | atest | Full API security testing on that endpoint |
| Hardcoded API key/secret in APK | ctest/ptest | Test key scope and access |
| WebView loading arbitrary URLs | ptest | XSS/phishing on trusted app context |
| Insecure deeplink handling | ptest | Open redirect / account takeover chain |
| Backend URL discovered in strings | ptest | Add to attack surface |
| OAuth token in local storage | atest | Token scope testing, replay attacks |

### Command Procedures

**`start`:**
1. Define scope: app name, package/bundle ID, platform(s), version, engagement type (internal/bounty).
2. Create `<workdir>/mtest-output/` with subdirs for each phase.
3. Run `phase1_preflight.run(workdir, target_apk, package_id, platform, engagement_name)` → creates output dirs + state.yaml.
4. Verify tools: Frida server running, proxy configured, device connected (`adb devices` / `ideviceinfo`).
5. Begin Phase 1 preflight immediately.

**`status`:** Show current phase, gateway states, findings count by severity, bypass status, time elapsed.

1. Verify phase gate criteria met (see phase file's Gate section)
2. Ask user: "Phase X complete. N findings. Advance to Phase Y?"
3. Update `state.yaml`: mark current PASSED, unlock next, record timestamps

**If gate NOT met:** list unmet criteria, suggest actions. Allow override with justification.

### Gate Enforcement (MANDATORY before `next`)

Before advancing any phase, run the gate checker:

```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/mtest/scripts"))
from gate_check import check_gate, print_gate_status

result = check_gate(".", phase=None)  # checks current phase from state.yaml
print_gate_status(result)
# Only advance if result["passed"] is True
```

If gate check fails, fix unmet items before advancing. Override only with explicit user justification.

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

If a phase is not applicable (no API for Phase 6, no pinning for Phase 3), document justification and mark gateway `N/A`. Never skip silently.

### Offline/No-Network App

When app has no internet permission and no HTTP URLs: Phase 4 scope reduced (no traffic), Phase 6 → N/A. Detect in Phase 2.

### Exploit Validation

Critical/High findings MUST be validated dynamically in Phase 6 before final reporting. If not possible, document limitation explicitly.

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
| 2 Static | 15% | 2.5 hr | Foundation — intelligence for all later phases |
| 3 Bypass | 10% | 1.5 hr | Means to an end (cap at decision tree) |
| 4 Traffic & Surface | 10% | 1.5 hr | Capture + organize attack map |
| 5 Runtime & Vuln | 25% | 4 hr | Core testing — dynamic per-feature analysis |
| 6 API & Exploit | 15% | 2.5 hr | Server-side + prove chains |
| 7 Reporting | 5% | 45 min | Write-up |

**Move-on rule:** Phase exceeds time cap with no findings → advance. Exception: Phase 5 can extend if actively finding bugs.

**Adjustments:**
- Bug bounty: compress P1/P4/P7, expand P5. Phase jumping allowed (see below).
- Banking app: expand P3 (bypass) + P6 (attestation APIs). For apps with Eversafe + Flutter BoringSSL (no known pattern), P3 cap = 3-4hr: root bypass 30min, Flutter SSL RE 2hr, anti-tampering 1hr. If not resolved in 4hr → accept partial bypass and advance.
- Offline app: P4 scope reduced (no traffic), P6 → N/A, expand P5

**Bug bounty phase jumping:** When a high-value lead is found during any phase (e.g., promising deep link in Phase 2), validate immediately — don't wait for sequential gate progression. Track the finding under the phase where it was proven. Resume sequential flow after the lead is resolved.

---

## Dual-Platform Engagement (Android + iOS)

**Execution order:** Android first (easier instrumentation), then iOS (Android findings guide where to look).

**Phase sharing:**
- **Per-platform (run twice):** Phase 2, Phase 3, Phase 5
- **Shared (run once):** Phase 4, Phase 6
- **Merge:** Phase 7 (unified report)

**Rules:**
- API-level findings only need testing once (same backend)
- Platform-specific findings get separate MTEST-XXX entries tagged `[Android]` or `[iOS]`
- Attack surface map (Phase 4) is unified, entries tagged per platform
- Time adjustment: +40% (not +100%) because shared phases

---

## App-Type Decision Tree

Load full decision tree: `references/app-type-decision-tree.md`

**Quick:** Banking (heavy bypass + IDOR) | Social (deep links + WebView + API) | Utility (local storage + IPC) | Game/Unity (metadata + native RE) | Flutter (libapp.so strings + BoringSSL bypass) | TWA/WebView wrapper (`references/twa-webview-apps.md`) | Meta apps (`references/meta-instagram-bypass.md`)

---

## Bug Bounty Fast-Path

Load: `references/bug-bounty-fast-path.md`

**TL;DR:** Static (30min) → Bypass (if pinned) → Traffic (15min) → Skip to Phase 5 highest-value features → Exploit → Submit. Budget: 4-8 hours.

---

## Output Structure

```
<workdir>/mtest-output/
├── state.yaml
├── scope.md
├── discovery-queue.md
├── phase1-preflight/
├── phase2-static/
├── phase3-bypass/
│   └── scripts/
├── phase4-traffic-surface/
│   └── attack-surface-map.md
├── phase5-runtime-vuln/
│   └── per-feature/
├── phase6-api-exploit/
│   ├── poc/
│   └── evidence/
├── phase7-reporting/
├── findings/
│   └── MTEST-001.md
└── report.md
```

---


## Pitfalls

> Full pitfalls: `references/pitfalls.md` (mobile-specific, Frida, Flutter, Meta apps, Eversafe, Ghidra, Burp integration)

### Behavioral Rules (always active)

- **Root/jailbreak bypass is NOT a finding** — Phase 3 is a means, not a result
- **Certificate pinning bypass alone is Medium at best** — needs real API abuse to escalate
- **Check `overridePins="true"` in NSC before spending hours on Frida bypass** — saves hours of wasted Phase 3 work
- **Don't over-engineer Frida when you have keys** — write standalone Python instead
- **Flutter 3.22+ breaks ALL known SSL bypass patterns** — needs Ghidra RE approach (see `references/flutter-ssl-bypass.md`)
- **Eversafe TLV token is forgeable (no crypto)** — full API testing without real device possible (see `references/eversafe-attestation.md`)
- **QUIC (UDP 443) bypasses HTTP proxies** — block with iptables to force TCP fallback
- **CRITICAL: Do NOT block `bindService` to EversafeService** — backend requires `x-eversafe-token` for auth. Blocking causes "Sorry, we can't log you in" with zero traffic.

### Technical Quick-Reference (load references/ for details)

- Burp invisible proxy pitfalls (upstream proxy pollution, hostname resolution, Host header with port): see `references/burp-mcp-integration.md`
- Eversafe debugger alert bypass (msg.what=84/100 suppress): see `references/eversafe-bypass.md`
- Eversafe PROD encrypt_token rejection: see `references/eversafe-attestation.md`
- Flutter + redsocks = no HTTP history (use Frida connect() redirect instead): see `references/redsocks-transparent-proxy.md`
- Flutter SSL pattern matching (r-x only, skip wrong functions): see `references/flutter-ssl-bypass.md`
- KernelSU root hiding (no DenyList, needs Frida hooks): see `references/kernelsu-root-hiding.md`
- Magisk systemless CA install path: `/data/adb/modules/*/system/etc/security/cacerts/`
- Burp MCP disconnected → raw socket SSE on port 9876: see `references/burp-mcp-raw-socket.md`

## Cross-Skill Triggers

| Signal | Trigger |
|--------|---------|
| Eversafe/Everspin detected (kr.co.everspin) | `references/eversafe-frida-bypass.md` + `references/eversafe-attestation.md` + `templates/flutter_eversafe_intercept.py` |
| KernelSU root detection (KSU overlay in mounts, /data/adb/ksu) | `references/kernelsu-root-hiding.md` + `templates/flutter_eversafe_full_bypass.js` |
| Flutter + Eversafe + root detection combined | `templates/flutter_eversafe_full_bypass.js` (all-in-one) |
| macOS Burp + DNAT not working | `references/redsocks-transparent-proxy.md` |
| Flutter SSL bypass hooks never trigger | `references/phase3-bypass.md` → fallback approaches |
| MHL/CTF challenge walkthrough write-up | `templates/mhl-walkthrough.md` |
| Native .so flag extraction (no plaintext in strings) | `references/native-flag-extraction.md` |
| BROWSABLE deep link with create/compose host | `scripts/deeplink_browsable_chain_test.sh` |
| API endpoints in traffic | `atest` — see Phase 6 → atest decision criteria below |
| Flask passive analyzer needed | `references/passive-traffic-analyzer.md` |
| Flutter app entering Phase 4 (traffic) | Skip redsocks→Burp. Use Frida Dart-layer HTTP dumper. See `references/redsocks-transparent-proxy.md` |
| Cloud storage URLs (S3/GCS) | `ctest` |
| Web endpoints found | `ptest` |
| Hardcoded secrets/source code | `scode` |
| Web3/smart contract SDK | `w3hunt` |
| API geo-blocked | ptest `references/geo-restriction-bypass.md` |
| Large app (50K+ classes) | delegate Phase 2 to subagent |
| Thick client companion app | `ttest` |
| AD/domain credentials in app | `adtest` — if domain is in scope |
| Meta/Instagram/Facebook app | `references/meta-instagram-bypass.md` + `references/meta-instagram-testing.md` |
| Meta Threads (barcelona) app | `references/meta-instagram-testing.md` → "Threads Specifics" |

### Phase 6 → atest Decision Criteria

**Stay in mtest Phase 6 (quick 2.5hr):**
- ≤10 API endpoints discovered in traffic
- Simple auth model (single bearer token, no multi-role)
- No GraphQL/gRPC — just REST
- API is secondary — mobile-specific surface is higher value
- Time budget remaining < 2hr

**Switch to full atest:**
- >10 endpoints with object IDs (BOLA surface)
- Complex auth: multi-role, tenant isolation, or undocumented privilege levels
- GraphQL or gRPC detected (needs specialized testing)
- Mobile app is a thin client — API IS the app
- Eversafe/attestation already bypassed — full API access available

**Handoff procedure:**
1. Complete mtest Phase 4 (traffic captured, endpoints mapped)
2. Start atest at Phase 2 — skip Phase 1, gate satisfied by mtest traffic analysis
3. Carry over: endpoint list from `mtest-output/phase4-traffic-surface/`, auth tokens from intercepted traffic
4. Findings tag with `source: "atest"` and flow back to mtest findings.jsonl
5. After atest completes, return to mtest Phase 6 for mobile-specific chains

## Operational Notes

> Full notes: `references/operational-notes.md`

