---
name: ptest
description: "Structured penetration testing framework with gated phases. Guides methodical progression from recon through exploitation to reporting."
version: 5.0.0
author: n4igme
license: MIT
trigger: "pentest, penetration test, web pentest, infrastructure pentest, network pentest, external pentest, internal pentest, red team"
argument-hint: "<command: start|preflight|status|resume|next|escalate|abort|cleanup|recon-passive|recon-active|enumerate-confirm|assess-exploit|post-exploit|report>"
notes:
  - "v5.0.1: Added mandatory self-check rule: before declaring any phase PASSED, re-read the phase reference checklist and verify every row. LoanPlatform (June 2026): user caught missed port scan (P2) and missed Prometheus URI batch test (P1) on review — both yielded critical findings."
  - "v5.0.0: Compressed 8 phases → 6. Merged Enumerate+AttackSurface into 'Enumerate & Confirm'. Merged VulnAssess+Exploit into 'Assess & Exploit'. PostExploit+Chain&Escalate merged. Discovery loop-back mechanism added. Reference files unchanged — routing remapped."
  - "v5.0.1: Added references/engagement-loanplatform-jfs.md — Prometheus URI batch testing, SPA proxy bypass, Spring Security filter gap pattern, Conductor workflow exposure."
  - "v4.7.0: Trigger table extracted to references/vulnerability-trigger-index.md. Pitfalls deduplicated. New attack recipes."
  - "RULE: Before declaring any phase PASSED, re-read that phase's reference file checklist. Verify every row has status DONE/SKIPPED(reason)/N/A(reason). Never declare phase complete from memory alone."
  - "v4.6.0: Hub model — SKILL.md handles routing + framework rules. Phase techniques in references/phase*.md."
  - "scripts/ contains hermes_tools-based phase scripts; see references/execute-code-integration.md for tier definitions and usage"
  - "TOKEN OPTIMIZATION: Gate Enforcement + Script Invocation appear once each (bottom of file). Do NOT duplicate them during future patches."
metadata:
  hermes:
    tags: [pentest, penetration-testing, security, recon, exploitation, post-exploitation, red-teaming, offensive-security]
    related_skills: [godmode, mtest, scode, osint, xdev, atest, ctest, w3hunt]
---

# Penetration Testing Framework

Structured pentest engagement with mandatory quality gates preventing premature phase advancement.

## Quick Reference

```
Phases:  1.Passive → 2.Active → 3.Enumerate&Confirm [STOP] → 4.Assess&Exploit → 5.PostExploit&Impact → 6.Report
States:  LOCKED → OPEN → PASSED (sequential, no skipping)
Commands: start | preflight | status | resume | next | escalate | abort | cleanup
Phases:   recon-passive | recon-active | enumerate-confirm | assess-exploit | post-exploit | report

Mandatory tools by phase:
  P1: dig, curl, whois          P2: nmap              P3: gobuster/feroxbuster, ffuf
  P4: nuclei, (vector-dependent) P5: (access-dependent)

Key guardrails:
  • Authorization required before ANY testing
  • Human sign-off required at every gateway transition
  • Phase 3 EXIT = MANDATORY STOP — present full inventory to user, get explicit "proceed to exploit?" before Phase 4
  • Every finding needs reproducible evidence (not theoretical)
  • SPA catch-all: if 5+ paths return identical status+size → frontend routing, not real endpoints (see `references/spa-recon-techniques.md`)
  • Pre-Report Gate 0: (1) attacker can do this NOW? (2) victim loses WHAT? (3) reproducible in 10 min?
  • Environment tag required on all findings (prod/nonprod/experiment)
  • Never skip phases — even for bug bounties

Discovery loop-back:
  • Phase 4/5 findings that reveal NEW attack surface (new hosts, creds, paths) → append to discovery-queue.md
  • At phase exit, drain discovery-queue: quick-enum new targets (P3 techniques) before advancing
  • Prevents "found creds in Phase 4 but never tested them" pattern
```

## Architecture


**state.yaml schema:**
```yaml
engagement:
  name: string
  started: ISO8601
  scope: string
current_phase: int
gateways:
  1_passive_recon: OPEN|PASSED|LOCKED
  2_active_recon: ...
  3_enumerate_confirm: ...
  4_assess_exploit: ...
  5_post_exploit_impact: ...
  6_reporting: ...
time_tracking:
  phase_1_start: ISO8601
  phase_6_end: ISO8601
findings_count: int
notes: string
```


`Gateway (Quality Gate)` → `Phase (Pentest Stage)` → `Tasks (Techniques)`

### Postmortem

After engagement closes, run shared retrospective:
```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/scripts"))
from postmortem import run_postmortem
run_postmortem(workdir, "ptest")
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
- Target is API-only (use atest)
- Target is mobile app (use mtest)
- Target is pure cloud infra with no network layer (use ctest)
## Commands

| Command | Action |
|---------|--------|
| **Lifecycle** | |
| `start` | Initialize a new engagement — prompt for scope, targets, and authorization |
| `preflight` | Check mandatory tool availability and install missing tools |
| `status` | Show current gateway state, progress, and pending techniques |
| `resume` | Resume from most recent phase |
| `next` | Advance to next phase after gate check |
| `report` | Generate final report |
| `abort` | Abandon engagement with reason |
| `cleanup` | Archive output and reset state |
| **Phase Execution** | |
| `recon-passive` | Execute passive recon techniques |
| `recon-active` | Execute active recon techniques |
| `enumerate-confirm` | Enumerate applications + confirm attack surface with user [MANDATORY STOP at exit] |
| `assess-exploit` | Threat model, vuln scan, and exploit top vectors |

## Error Handling

| Failure Mode | Action |
|--------------|--------|
| Tool exits non-zero | Capture stderr, check if partial output is usable |
| API rate limit (429) | Back off, retry once. If persistent, document and pivot |
| Credential expired | Re-acquire or document as finding (credential rotation issue) |
| Target unreachable | Retry 3x with 30s gap. If still down, mark host UNREACHABLE |
| Permission denied | Try alternative auth method. If blocked, document scope gap |
| WAF blocking | Try 3 bypass techniques max, then document WAF and move on |

**Rules:**
- Never retry blindly — understand the error first
- Save partial results before retrying (power loss, network drop)
- Document blocker findings with evidence (screenshot, HTTP status)
- On repeated failure (>3 attempts): mark as BLOCKED, continue to other surface

If no command is given, show current status and suggest next action.

## Phase Completion Criteria (Large Scope)

> Full criteria: `references/large-scope-guidance.md` — load for 50+ subdomain engagements.

Quick rule: ALL subdomains must be resolved, probed, tech-stacked, and JS-analyzed before Phase 1 exits. ALL accessible targets need path fuzzing + credential testing before Phase 2 exits.

## Preflight Check (`preflight`)

> Full tool tables, wordlist setup, and procedure: `references/preflight.md`

Verifies mandatory and recommended tools are available, installs missing ones, resolves SecLists path, and writes preflight report to `./ptest-output/preflight.md`.

If `./ptest-output/` doesn't exist, `preflight` runs in report-only mode (prints to stdout). It only writes `preflight.md` when called during or after `start`.

---

## Status (`status`)

Output:
1. Current phase and gateway state (OPEN/LOCKED/PASSED/ABORTED for all 6)
2. Active phase checklist summary: X/Y techniques done, Z findings in this phase
3. Total findings count and breakdown by severity (Critical/High/Medium/Low/Info)
4. Time elapsed since engagement start
5. Discovery queue items pending (if any)
6. Suggested next action

If no engagement exists (`./ptest-output/state.yaml` not found), report "No active engagement" and suggest `start`.

---

## Initialization (`start`)

Before any testing begins, collect and document:

1. **Preflight Check** — automatically run `preflight` to verify tool availability. Install missing mandatory tools before proceeding.
2. **Target Scope** — domains, IPs, applications, exclusions
3. **Scope Type** — determines which techniques apply:
   - `web` — web applications, APIs
   - `network` — infrastructure, hosts, services
   - `cloud` — AWS/GCP/Azure resources
   - `mobile` — iOS/Android applications
   - `mixed` — combination (default)
4. **Rules of Engagement** — testing hours, restricted techniques, notification requirements
5. **Authorization** — confirm written authorization exists (do NOT proceed without it)
6. **Output Directory** — create `./ptest-output/` with subdirectories:

```
./ptest-output/
  state.yaml            # Gateway state tracker
  scope.md              # Scope, type, and authorization record
  findings-log.md       # Running log of all findings
  discovery-queue.md    # Loop-back targets discovered during P4/P5
  recon-passive/        # Phase 1 results
    checklist.md
  recon-active/         # Phase 2 results
    checklist.md
  enumerate-confirm/    # Phase 3 results (enum + attack surface confirmation)
    checklist.md
  assess-exploit/       # Phase 4 results (vuln assessment + exploitation)
    checklist.md
    credential-inventory.md
  post-exploit/         # Phase 5 results (post-exploit + chain & escalate)
    checklist.md
  report/               # Phase 6 — Final report
  escalations/          # Critical finding escalations
```

Write initial `state.yaml`:

```yaml
engagement:
  name: ""
  started: ""
  scope_type: ""

config:
  seclists_path: ""  # Resolved during preflight

gateways:
  1_passive_recon: OPEN
  2_active_recon: LOCKED
  3_enumerate_confirm: LOCKED
  4_assess_exploit: LOCKED
  5_post_exploit: LOCKED
  6_reporting: LOCKED

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
  total_duration: ""  # Calculated at cleanup

findings_count: 0
escalations_count: 0
```

**Time tracking:** Timestamps are recorded automatically as part of the Phase Entry Protocol:
- `phase_N_start` — written when the phase checklist is created (Phase Entry Protocol step 4)
- `phase_N_end` — written when the gateway is set to PASSED (Gateway Transition step 7)
- `total_duration` — calculated at cleanup from first start to last end

Do NOT rely on the operator to manually fill these. The mechanical gates (create checklist → record start, write PASSED → record end) handle it. If timestamps are empty at cleanup, it means the Phase Entry Protocol was not followed — flag as a process gap.

---

## Re-assessment (`resume` with phases reopened)

When re-opening ALL phases for re-assessment (user says "re-open all phases and start from phase 1"):

1. Reset all gateways to LOCKED except Phase 1 → OPEN.
2. Keep existing `findings-log.md` as reference (don't delete prior findings).
3. **Treat every Phase 1 checklist row as PENDING** — do NOT carry over "DONE" status from prior run.
4. Re-run ALL techniques fresh: Wayback re-query, Shodan on ALL IPs (not just originals), web_search for GitHub/dorks, TLS cert analysis, JS bundles on new hosts.
5. Suffix new output files with `-v2` to distinguish from original engagement data.
6. New findings get sequential IDs continuing from the last (e.g., F-24 if prior had F-23).

**Key lesson (BlueSpider, June 2026):** Re-assessment that "carried over" old Wayback data and only Shodan-checked original IPs missed MariaDB exposure, 4 new Ignition hosts, and a 6.7MB PII dump on a previously-unknown host.

---

## Resume (`resume`)

When resuming an interrupted engagement:

1. Read `./ptest-output/state.yaml` to determine active gateway.
2. Read the active phase's `checklist.md` to see which techniques are done vs. pending.
3. Read `./ptest-output/findings-log.md` for context on what's been found.
4. **Re-orient (if >24h since last activity):**
   - Re-read `scope.md` to refresh scope boundaries and exclusions
   - Re-read `enumerate-confirm/checklist.md` (if exists) for target priority
   - Summarize to operator: "You're in Phase X, Y findings so far, last technique was Z. Next up: W."
5. Report status to user and suggest next technique to execute.

### Recovery (if state.yaml is missing or corrupted)

If `state.yaml` cannot be read:
1. Scan `./ptest-output/*/checklist.md` files to determine which phases have been started.
2. Find the last phase with a checklist containing `DONE` or `FAILED` entries.
3. Count findings in `./ptest-output/findings-log.md` to reconstruct `findings_count`.
4. Count files in `./ptest-output/escalations/` to reconstruct `escalations_count`.
5. Rebuild `state.yaml` — mark completed phases as `PASSED`, current phase as `OPEN`, remaining as `LOCKED`.
6. Inform user of reconstructed state and ask for confirmation before proceeding.

### Reference Files
- `references/ptest-tool-architecture.md` — Architecture doc for the ~/Project/ptest automated scanner tool (modules, pipeline, OOB, auth, evidence, WAF feedback, roadmap status)
- `references/xss-csp-bypass-techniques.md` — CSP nonce bypass research, null-byte search oracle, meta refresh exfil constraints, dangling markup patterns

### Staleness Check

| Inactivity | Action |
|------------|--------|
| >7 days | Flag all existing findings as `STALE — re-verify before report`. Re-probe key targets to confirm they're still alive and unchanged. |
| >30 days | Treat as a new engagement. Prior findings are reference only — re-verify everything before inclusion in any report. |

Staleness is calculated from the most recent timestamp in `state.yaml` (last phase transition or `time_tracking` entry).

---

# ═══════════════════════════════════════════════════════════════
# FRAMEWORK — Gateway system, quality gates, effort allocation
# ═══════════════════════════════════════════════════════════════

## Gateway Map

| Gateway | Phase | Reference Files | Exit Criteria |
|---------|-------|-----------------|---------------|
| 1 | Passive Reconnaissance | `references/phase1-passive-recon.md` | Attack surface mapped, subdomains validated, technologies identified. OSINT completeness verified. **Env-prefix quick-win check completed.** No packets sent to target. **Scope Viability Assessment completed.** |
| 2 | Active Reconnaissance | `references/phase2-active-recon.md` | All hosts HTTP-probed, port-scanned, technology-fingerprinted, path discovery on every live host, services detected. **AD environment flag:** if DC identified → flag for adtest at Phase 3 entry. |
| 3 | Enumerate & Confirm [MANDATORY STOP] | `references/phase3-enumeration.md` + `references/phase4-attack-surface.md` | Applications enumerated, APIs mapped, parameters discovered. Asset inventory confirmed with user (≥80% individually listed). Scope finalized, entry points mapped. **User explicitly approves advancing to exploitation.** |
| 4 | Assess & Exploit | `references/phase5-vuln-assessment.md` + `references/phase6-exploitation-framework.md` | Attack trees documented, vuln scans complete, top vectors exploited, credential inventory validated, attack chains documented. **Discovery queue drained.** **Local verification passed.** |
| 5 | Post-Exploit & Impact | `references/phase7-post-exploitation-framework.md` + `references/chain-and-escalate-phase.md` | Access type classified, playbook completed, data scope documented, all finding pairs evaluated for chains, severity upgraded where applicable. **Discovery queue drained.** |
| 6 | Reporting | `references/phase8-reporting-process.md` | Final report delivered, pre-delivery checklist passed |

---

## Mandatory Quality Gates

See `references/quality-gates.md` for full gate criteria per phase. Key rules:
- Every phase exit requires documented evidence (not just "tested")
- Findings must have PoC before phase advances
- Phase 4 requires credential-inventory.md + checklist.md BEFORE exploitation

## Effort Allocation

**Time-box enforcement:** See `references/time-box-enforcement.md` for budget calculation, alert levels, over-budget decision tree, per-technique time caps, and scope adjustment triggers.

| Phase | % of Total Time | Rationale |
|-------|----------------|-----------|
| 1 Passive Recon | 15% | Thorough passive discovery prevents blind spots in later phases |
| 2 Active Recon | 20% | Full host/service/tech coverage — foundation for everything |
| 3 Enumerate & Confirm | 15% | Deep enumeration + user confirmation before offensive work |
| 4 Assess & Exploit | 30% | Highest-value work — scanning, verification, and exploitation in one flow |
| 5 Post-Exploit & Impact | 15% | Demonstrate full blast radius, chain findings for real severity |
| 6 Reporting | 5% | Findings documented throughout — final assembly only |

Adjust based on scope size:
- **50+ hosts:** P1 → 20% (+5%), P2 → 25% (+5%), P3 → 10% (-5%), P4 → 25% (-5%)
- **Single app:** P1 → 10% (-5%), P2 → 15% (-5%), P4 → 40% (+10%)
- **API-only:** P3 → 20% (+5%), P4 → 25% (-5%)

**Continuous/internal engagements:** Set `time_budget.mode: "continuous"` in state.yaml. Track time for reporting only — no budget enforcement.

**Move-on heuristic:** If a technique yields no new results after 15–20 minutes of active work, mark it `DONE` (no findings) or `FAILED (diminishing returns)` and proceed. Exception for continuous engagements: vectors showing partial progress deserve extended time.

**Early-finding fast-track (bug bounty):** When a confirmed High/Critical finding is discovered during Phase 1-3, the operator may fast-track: (1) document the finding fully, (2) complete current phase's mandatory checks, (3) skip remaining low-priority techniques, (4) proceed to reporting. Mark skipped phases as "PASSED (fast-tracked — confirmed High finding)". Continue probing other live hosts briefly (10-15 min) for additional quick wins before closing.

---

### Evidence Standards

All findings must follow `../references/evidence-standards.md` for required/optional evidence capture and redaction rules.

## Finding Template

> Full template, ID assignment, and deduplication rules: `references/finding-template-full.md`

Cross-skill findings chaining (JSONL schema): `../references/findings-jsonl-convention.md`

When recording a finding, append to `./ptest-output/findings.jsonl`:
```python
import json
from datetime import datetime
finding = {
    "id": "PTEST-{count:03d}",
    "skill": "ptest",
    "severity": "{severity}",
    "type": "{vuln_type}",  # e.g., xss, sqli, ssrf, auth_bypass, idor
    "target": "{affected_host_or_endpoint}",
    "summary": "{one-line description}",
    "chain_potential": [],
    "timestamp": datetime.now().isoformat(),
    "phase": "phase{current_phase}",
    "confidence": "confirmed",
    "status": "confirmed"
}
with open("./ptest-output/findings.jsonl", "a") as f:
    f.write(json.dumps(finding) + "\n")
```

Every finding uses `FINDING-{ID}` (auto-incremented from `state.yaml`). Must include: severity, CVSS, affected asset, environment tag, steps to reproduce, evidence, impact, and remediation. Only **Confirmed** findings (with direct proof) go into the final report.

### Out-of-Scope Validation (MANDATORY before marking any finding as Confirmed)

**Before adding a finding to findings-log.md, cross-reference it against `scope.md` Out of Scope section.**

**WinTicket lesson (June 2026):** Two findings (Firebase email enumeration, DMARC p=none) were investigated, PoC'd, and documented as "Confirmed" before realizing both were explicitly listed in the program's Out of Scope exclusions. This wasted significant exploitation time.

**Procedure:**
1. Before marking a finding Confirmed, re-read the "Out of Scope" section in `scope.md`
2. Check if the finding's CLASS is excluded (e.g., "Vulnerabilities allowing enumeration of usernames and emails" excludes ALL email enum regardless of technique)
3. If excluded → mark as `OUT_OF_SCOPE` in findings-log, do NOT invest exploitation time
4. If borderline → document WHY it's different from the exclusion before proceeding

---

## Operational Lifecycle

See `references/operational-lifecycle.md` for full protocol. Summary:
- State tracked in `state.yaml` (phase, findings, timestamps, coverage)
- Each host gets coverage table + attack chains + re-enum loops at phase end
- Host timeout: document, retry 30min, mark unreachable
- Per-phase: load reference → execute → document → gate check → advance

## Escalation Protocol

Triggered by `escalate` command OR automatically when a Critical/P1 finding is discovered.

**ID relationship:** An escalation is also a finding. It gets both:
- A **finding ID** from `findings_count` (e.g., `FINDING-5`) — used in findings-log.md and the final report.
- An **escalation ID** from `escalations_count` (e.g., `escalation-1`) — used for the escalation file name and urgent notification.

1. Document finding fully using the Finding Template (assigns a finding ID).
2. Classify severity (CVSS 3.1).
3. Increment `escalations_count` in `state.yaml` (1-indexed — first escalation = `escalation-1`).
4. Write to `./ptest-output/escalations/escalation-{escalations_count}.md`, referencing `FINDING-{ID}`.
5. Alert user for immediate client communication.
6. Current gateway pauses until escalation is acknowledged.

See `references/escalate-finding.md` for full procedure.

---

## Cleanup (`cleanup`)

Post-engagement housekeeping:

1. **Archive** — compress `./ptest-output/` to `./ptest-output-{engagement-name}-{date}.tar.gz`.
2. **Sanitize** — remove credentials *you used* during testing. Do NOT remove credentials *you found* as findings — those are evidence.
3. **Verify** — confirm report is complete and all findings are documented.
4. **Summary** — print engagement stats (findings by severity, phases completed, duration).

---

## Abort (`abort`)

Terminate an engagement early when it cannot or should not continue.

**Valid reasons:** authorization revoked, target decommissioned, client request, scope invalidated, legal concern.

**Procedure:**
1. **Prompt for reason** — require explicit justification.
2. **Mark phases** — current `OPEN` phase → `ABORTED (reason)`, all `LOCKED` phases → `ABORTED`.
3. **Set state** — write `engagement.status: ABORTED` and `engagement.aborted_at: {timestamp}` to `state.yaml`.
4. **Generate partial report** — if any findings exist, produce a summary report noting the engagement was terminated early and why.
5. **Run cleanup** — archive and sanitize as normal.

---

# ═══════════════════════════════════════════════════════════════
# PHASES — Phase-specific techniques, checklists, and procedures
# ═══════════════════════════════════════════════════════════════

## Scope-Aware Checklist Generation

> Full technique-by-scope matrix: `references/scope-matrix.md`

When generating phase checklists during `start`, filter techniques by scope type. Techniques that don't apply to the engagement's scope type should be pre-marked as `N/A (scope: {type})` instead of `PENDING`. When scope type is `mixed`, all techniques are `PENDING`.

---

## Phase Entry Protocol (ALL phases)

When entering ANY phase, before executing techniques:
1. **Load reference file** — `skill_view(name='ptest', file_path='references/<phase-file>')`
2. **Create/verify checklist** — `ptest-output/<phase-dir>/checklist.md` must exist with all techniques listed as PENDING
3. **Create phase-specific mandatory files** — each phase has required output files (see Output File Gate). Create empty templates at entry, populate during execution.
4. **Record timestamp** — write `phase_N_start` in state.yaml when creating the checklist. Write `phase_N_end` when PASSED is written. This is automatic bookkeeping — no separate action needed.

This prevents the pattern of "execute first, document later" that caused gaps in LINE WORKS (Phases 3-6 all had missing documentation despite work being done). Creating the structure upfront ensures nothing is forgotten.

## Scope Viability Assessment (Phase 1 Exit)

> Full assessment framework: `references/large-scope-guidance.md`

At Phase 1 exit, classify expected yield (HIGH/MEDIUM/LOW). If LOW → flag to user before investing full effort. Document in scope.md.

## Phase Routing

When entering a phase, load the corresponding reference file(s) with `skill_view(name='ptest', file_path='references/<file>')`:

| Phase | Files | Load When |
|-------|-------|-----------|
| 1 | `references/phase1-passive-recon.md` | Entering passive recon |
| 2 | `references/phase2-active-recon.md` | Entering active recon |
| 3 | `references/phase3-enumeration.md` + `references/phase4-attack-surface.md` | Entering enumerate & confirm |
| 4 | `references/phase5-vuln-assessment.md` + `references/phase6-exploitation-framework.md` | Entering assess & exploit |
| 5 | `references/phase7-post-exploitation-framework.md` + `references/chain-and-escalate-phase.md` | Entering post-exploit & impact |
| 6 | `references/phase8-reporting-process.md` | Entering reporting |
| — | `references/escalate-finding.md` | Critical finding discovered (any phase) |

**Load only the active phase files.** Each contains: full technique checklist, procedures, commands, exit criteria, and pitfalls specific to that phase.

### Discovery Loop-Back (Phase 4 & 5)

When exploitation or post-exploitation reveals NEW attack surface (credentials, hosts, API keys, internal URLs):
1. Append to `./ptest-output/discovery-queue.md` with source finding ID
2. At phase exit, before advancing: drain the queue by running Phase 3 enumeration techniques against new targets
3. New findings from loop-back get their own IDs and feed back into the current phase

This prevents the pattern of "found creds during exploit but never tested them" (LINE WORKS, June 2026).

---

# ═══════════════════════════════════════════════════════════════
# OPERATIONAL — Multi-target, guardrails, cross-skill, pitfalls
# ═══════════════════════════════════════════════════════════════

## Multi-Target Engagement Structure

> Directory layout, rules, and fast-exit heuristics: `references/multi-target-structure.md`

Each target gets independent state tracking. Finding IDs are unique per-target. Reference findings by `{target}:{finding-id}` when submitting.

---

## Exploitation Mindset & Post-Exploitation Rules

> Full content: `references/exploitation-mindset.md` — load when entering Phase 4-5.

Key rules:
- Phase 4 objective is TAKEOVER, not proving individual vulnerabilities — chain ALL findings
- Don't ask "want me to continue?" — always continue until blocked
- THEORETICAL IS NOT HACKABLE: if a finding needs a prerequisite you haven't proven (XSS for token theft, MitM for header injection), report at severity of what you actually proved, not the full chain. "I need hackable things, not theoricality things."
- SHELL IS THE STARTING LINE: upon any access → `printenv | sort` → test every credential → document each as separate finding
- Never stop at less than full blast radius

## Guardrails

See `references/guardrails.md` for full rules. Critical:
- No destructive operations without explicit authorization
- Write Access Response Protocol for proving write without modifying
- PoC scripts must contain real tested values, never placeholders
- Scope enforcement: confirm before testing undocumented assets

## Cross-Skill Triggers

See `references/cross-skill-triggers.md` for full decision tree. Quick ref:
- API-heavy target → `atest` | Mobile app → `mtest` | Cloud/K8s → `ctest`
- Source code available → `scode` | Exploit dev needed → `xdev`
- Web3/smart contracts → `w3hunt` | RE binary → `retools`
- Thick client (desktop app) → `ttest` | AD/domain scope → `adtest`
- **SYSTEM on domain-joined Windows host → IMMEDIATELY load `adtest`** — don't waste cycles on ad-hoc AD attacks. The adtest skill has structured delegation/relay/ADCS/ACL workflows that are far more effective than guessing.

## Cross-Skill Triggers — Bug Bounty Target Selection

When selecting bug bounty targets from platforms (Intigriti, HackerOne, YesWeHack):
- Load `intigriti-programs-enumeration` for Intigriti Algolia enumeration
- Filter by: wildcard scope + bounty range + industry match to operator's experience
- Engagement intel files: `references/intel-{target}-{platform}.md` — load when resuming

## Finding More Vulnerabilities

> **Full trigger→reference mapping (80+ entries):** `references/vulnerability-trigger-index.md` — load at phase transitions to identify which technique references apply to the current target.

Quick-access patterns:
- Tomcat Manager RCE (WAR deploy): `references/tomcat-manager-rce.md`
- Tomcat manager (default creds/WAR deploy): `references/tomcat-manager-exploitation.md`
- Tomcat WAR deploy (GUI-only): `references/tomcat-war-deploy-rce.md`
- Windows hash exfil (webshell, no SMB): `references/windows-hash-exfiltration-webshell.md`
- AD lateral movement/privesc: `references/ad-lateral-movement-checklist.md`
- DPAPI credential decryption: `references/dpapi-credential-decryption.md`
- Docker breakout via host mount: `references/docker-breakout-host-mount.md`
- Snowplow collector event injection + stored XSS: `references/snowplow-collector-exploitation.md`
- MCP/Agent protocol unauthenticated exploitation (Mintlify docs): see Phase 1 `references/phase1-passive-recon.md` §"MCP/Agent Protocol Files"
- MCP server discovery & exploitation (.well-known/mcp): `references/mcp-server-exploitation.md`
- CDN-fronted targets: `references/cdn-aware-phase5.md`
- Firebase auth: `references/firebase-auth-bypass.md`
- SQLi with WAF: `references/sqli-payloads-and-bypass.md`
- XSS filter bypass: `references/xss-filter-bypass-techniques.md`
- CSP nonce bypass + blind search oracle: `references/blind-search-oracle-html-injection.md`
- Spring Boot unauth recon (actuator, user enum, JS extraction, broken-auth): `references/spring-boot-unauth-recon.md`
- File upload RCE: `references/attack-recipes.md` §"Avatar Upload Path Traversal"
- XXE in SPA: `references/attack-recipes.md` §"Base64-Encoded XML Submission"
- DOM XSS cipher: `references/attack-recipes.md` §"DOM XSS via Client-Side Cipher"
- SPA proxy path prefix bypass (Istio/K8s): `references/attack-recipes.md` §"SPA Proxy Path Prefix Bypass"
- Webhook signature bypass (Prometheus→route leak→forge): `references/webhook-signature-bypass.md`
- Prometheus→webhook endpoint discovery: `references/prometheus-webhook-discovery.md`
- Istio 400 "Bad Request" ≠ auth failure: `references/istio-mesh-assessment.md`
- K8s/Istio internal enumeration (path routing, Prometheus URI, VPN DNS): `references/k8s-istio-internal-enumeration.md`
- Predictable reset token: `references/predictable-token-patterns.md`
- Lambda SSRF (file:// + IAM creds): `references/lambda-ssrf-credential-theft.md`
- GraphQL introspection bypass (error message enumeration): `references/graphql-introspection-bypass.md`
- GraphQL schema enumeration via error messages: `references/graphql-schema-enumeration-via-errors.md`
- SPA proxy auth bypass (jfs-client pattern): `references/spa-proxy-auth-bypass.md`
- Rate limit bypass via X-Forwarded-For + device-id rotation: `references/rate-limit-bypass-header-rotation.md`
- Uphold (Intigriti bounty): `references/intel-uphold-intigriti.md`
- Stuck at 40-50% budget: `references/stuck-playbook.md`
- Capital.com (Intigriti bounty): `references/intel-capital-com-program.md`
- Monzo (Intigriti bounty): `references/intel-monzo-intigriti.md`
- Next.js __NEXT_DATA__ runtimeConfig extraction: `references/nextjs-runtime-config-extraction.md`
- Next.js source maps + runtimeConfig extraction: `references/nextjs-source-map-recon.md`
- Docker breakout (disk mount, socket, cgroup, nsenter): `references/docker-breakout-techniques.md`

- Client presentation / verbal delivery: `references/client-presentation-storytelling.md`
- **Recipe feedback loop:** Before closing any engagement, ask: "Does this finding generalize into a reusable pattern?" If yes → patch `references/attack-recipes.md` with new recipe (trigger + technique + yield).

## Webhook Signature Bypass Pattern (Capital.com, June 2026)

When target uses third-party webhook callbacks (Sumsub KYC, Stripe, AppsFlyer, etc.):
1. Find callback endpoints via Prometheus metrics (`uri=` labels reveal all routes)
2. Test signature verification: send valid JSON with `X-Payload-Digest: INVALID` header
3. Differential validation: 415 (wrong content-type) + 400 (empty body) + 500 (bad route) + 200 (valid JSON) = app processes input but doesn't check signature
4. Confirm processing via Prometheus counters (if available): `callback_produce_success_total` incrementing = events reach Kafka/downstream
5. Impact multiplier: financial/regulated platform + KYC bypass = Critical

**Trigger:** target has `/callback/*` or `/webhook/*` endpoints, especially for KYC providers (Sumsub, Jumio, Onfido)

## File Naming Convention

Reference files use prefixes to indicate loading rules:
- **`engagement-*`** — target-specific engagement docs. Only load when testing that specific target. Excluded from public repos via gitignore.
- **`intel-*`** — program recon/infrastructure intel. Only load during target selection or when hitting that infrastructure stack. Excluded from public repos via gitignore.
- **`phase*`** — phase methodology docs. Load when entering that phase.
- Everything else — reusable technique references. Load based on cross-skill-triggers signal matching.

**Public repo safety:** engagement/intel files contain extracted API keys, auth tokens, and target-specific secrets. Always gitignore: `**/engagement-*`, `**/intel-*`, and any file with auth flow captures (e.g., `jago-auth-flow.md`).

### Severity Mapping

Cross-skill severity normalization: `../references/severity-mapping.md`

## Pitfalls

> **Full pitfalls list with engagement-specific details:** `references/pitfalls.md` — load when entering Phase 4+ or when a pattern below triggers.

### Checklist Atomicity Rule (MANDATORY)
Split compound items into atomic rows. Every DONE needs an output artifact reference. No artifact = not done. Self-review each row before `next`.

### Key Behavioral Rules (always active)
- **Engagement/intel file naming:** prefix with `engagement-` or `intel-` (gitignored)
- TOKEN ≠ ATO — prove victim data access, not just token possession
- SHELL IS THE STARTING LINE — dump env vars, test every credential upon any access
- EXPLOIT FIRST, THEORIZE NEVER — test before documenting
- PROVE END-TO-END — walk full path from attacker action → victim impact
- "Theoretical" ≠ "Finding" — unproven prerequisites = lower severity
- IDOR FALSE CONFIRMATION — `errorCode: 0` ≠ IDOR. Prove DIFFERENTIAL data (victim's content, not yours)
- NEVER USE CURL FOR SYSTEMATIC TESTING — Python scripts only. 4+ targets → delegate_task; 20+ → execute_code
- NEVER SKIP PHASES BECAUSE "BORING" — completeness, not cherry-picking
- RE-ASSESSMENT ≠ SHORTCUT — when reopening phases, LOAD the phase reference file and execute ALL checklist rows fresh. Never carry over old data. See `references/reassessment-protocol.md`
- BLOCKERS ARE THE START — 5+ bypass techniques before moving on
- NEVER CLAIM COMPLETION FROM SUMMARIES — verify against disk/reference files
- TOOL FAILURE ≠ SKIP — use alternatives before marking SKIPPED
- PREMATURE ABANDONMENT — test ALL endpoints before conclusions
- HTTP STATUS ≠ ATO PROOF — prove identity + victim data access, not just 204/302
- TEST WRITE METHODS ON PROD UNAUTH — POST/DELETE on action endpoints without cookies
- PREDICTABLE RESET TOKEN — TEST SIMPLEST HYPOTHESIS FIRST — register 2+ accounts, get real tokens, check length (32=MD5, 40=SHA1, 64=SHA256, 128=SHA512), test `hash(email)` BEFORE trying Host header/IDOR. Takes 10 seconds, catches the most common pattern.

### Situational Pitfalls

> **Full situational pitfalls with engagement-specific details:** `references/pitfalls.md`
>
> Load at Phase 4+ entry or when a technique is failing. Contains engagement lessons from
> LoanPlatform, Capital.com, Monzo, Uphold, BlueSpider, WinTicket, SecOps exams.

Key one-liners (see reference for full context):
- TRANSPARENT PROXY FALSE POSITIVES — Shodan InternetDB as ground truth
- NUCLEI TIMEOUT — tag-specific scans, never mark DONE on 0-result timeout
- SUBDOMAIN ENUM — multiple sources (subfinder + crt.sh)
- SHODAN ON ALL IPs — every unique IP, not just primary
- GOOGLE/GITHUB NEVER "N/A" — execute the search, mark DONE with "0 results"
- OPENAPI SPEC IS THE WORDLIST — batch-test all paths unauth
- SPRING BOOT CONTEXT PATH — probe outside /api/** filter
- POST+JSON+XHR BYPASSES 302 — Java/JBoss session redirect
- SPA CATCH-ALL — baseline with random UUID first
- WEBPACK CHUNKS — business logic in lazy-loaded chunks
- JS BUNDLE DIFF — dev vs prod early in Phase 3
- SQLi DECOY DATA — enumerate ALL rows with LIMIT N,1
- CHAIN PoCs MANDATORY — no diagrams without executable proof
- CREDENTIAL INVENTORY BEFORE PHASE 6 — or wasted exploits
- JWT BRUTE FALSE POSITIVES — re-verify 3x, network flakes cause hits
- UNAUTH WRITE ON PROD — verify login after reset before claiming ATO
- AJAX LOGIN + CURL — use browser for page access, curl for API only
- CORS RE-TEST IN PHASE 6 — new backends found during exploit
- WEAK CSRF — empty rejected but random accepted = not session-tied
- FORGOT-PW FLOODING — 20+ rapid = DoS finding
- n8n OAUTH SCOPE ESCALATION — test arbitrary scopes on registration
- OAUTH PARAM TESTING — bare GET 302 ≠ gated
- VPN SPLIT-TUNNEL — separate .ovpn, delete stale manual routes
- TLS CIPHER TESTING — pin `-tls1_2` or server upgrades to 1.3
- PARAM TYPE BRUTE-FORCE — config endpoint wildcard values
- RATE-LIMITED TARGETS — JS route extraction over ffuf
- ANGULAR PRE-RENDERED — ng-version without bundles = server-side
- SKIPPED ≠ DONE (0 RESULTS) — execute and mark with result, never skip
- OPENSSH KEY FORMAT — re-wrap base64, verify with ssh-keygen before use
- DOCKER HOST MOUNT — /mnt/host/ = instant root via SSH key injection
- MIMIKATZ UPLOAD VIA WEBSHELL — PowerShell AppendAllText + certutil -decode

## Gate Enforcement (MANDATORY before `next`)

**Self-Review Protocol (SoundOn, June 2026):**
Before running the gate checker, manually verify:
1. Every DONE row has evidence (file path or output reference). No evidence = not done.
2. Compound checklist items (e.g., "OSINT (WHOIS, Wayback, GitHub, dorks, Shodan)") — confirm EACH sub-technique was executed, not just some. If template groups them, split into atomic rows before advancing.
3. Ask: "If the user asks 'did we do all activities on all subdomains?' can I say YES with proof?" If no → phase incomplete.

Before advancing any phase, run the gate checker:

```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/ptest/scripts"))
from gate_check import check_gate, print_gate_status

result = check_gate(".", phase=None)  # checks current phase from state.yaml
print_gate_status(result)
# Only advance if result["passed"] is True
```

If gate check fails, fix the unmet items before calling `advance_phase()`. Override only with explicit user justification documented in state.yaml notes.

---

## Automation Scripts (execute_code integration)

> Full tier definitions, script table, and usage patterns: `references/execute-code-integration.md`

Phase scripts live in `scripts/`. Two tiers: **Tier 1** (phase setup, run once at entry) and **Tier 2** (batch execution for 20+ targets). Decision heuristic: 1-3 targets → direct calls, 4-6 → delegate_task, 10+ → execute_code with batch script.

**state_manager.py — engagement lifecycle:**
```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/scripts"))
from config import SKILL_CONFIG
import state_manager

workdir = "."
state_manager.init_state(workdir, "Target Corp", scope_type="web",
    targets=["example.com", "api.example.com"], budget_hours=16)
state_manager.status(workdir)
state_manager.advance_phase(workdir)  # NOTE: at final phase (6), returns "Already at final phase" — manually set 6_reporting: PASSED + phase_6_end in state.yaml
state_manager.add_finding(workdir, "FINDING-1", "Stored XSS", "High", "app.example.com")
state_manager.escalate(workdir, "FINDING-2", "RCE via SSTI", "Critical", "api.example.com")
should, reason = state_manager.should_abandon(workdir, budget_hours=16)
state_manager.abandon(workdir, "Authorization revoked")
```

### Script Failure Protocol

| Exit Condition | Action |
|----------------|--------|
| Exit 0 | Parse output, continue normally |
| Exit 1 (partial) | Parse successful results, log failures, continue manually for failed targets |
| Exit 2+ (total failure) | Fall back to manual execution of the technique |
| Timeout | Kill process, log partial results, split into smaller batches and retry |

**Never mark a technique as DONE based solely on a failed script.** If the script fails, the technique remains PENDING until manually completed or explicitly SKIPPED with documented reason.

> **Execution pitfalls (parallel probing, terminal backgrounding, tool workarounds):** See `references/operational-pitfalls.md`

