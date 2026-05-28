---
name: ptest
description: "Structured penetration testing framework with gated phases. Guides methodical progression from recon through exploitation to reporting."
version: 4.6.0
author: n4igme
license: MIT
argument-hint: "<command: start|preflight|status|resume|next|escalate|abort|cleanup|recon-passive|recon-active|enumerate|attack-surface|vuln-assess|exploit|post-exploit|report>"
notes:
  - "v4.6.0: Hub model — SKILL.md handles routing + framework rules. Phase techniques in references/phase*.md. Tool tables, scope matrix, finding template, heuristics extracted to references/."
  - "scripts/ contains hermes_tools-based phase scripts for all 8 phases; see references/execute-code-integration.md for tier definitions and usage"
  - "Shell scripts (bulk-actuator-scan.sh, http-probe-parallel.sh) still usable via terminal() for standalone runs"
metadata:
  hermes:
    tags: [pentest, penetration-testing, security, recon, exploitation, post-exploitation, red-teaming, offensive-security]
    related_skills: [godmode, mtest, scode, osint, xdev]
---

# Penetration Testing Framework

Structured pentest engagement with mandatory quality gates preventing premature phase advancement.

## Quick Reference

```
Phases:  1.Passive → 2.Active → 3.Enumerate → 4.AttackSurface → 5.VulnAssess → 6.Exploit → 7.PostExploit → 8.Report
States:  LOCKED → OPEN → PASSED (sequential, no skipping)
Commands: start | preflight | status | resume | next | escalate | abort | cleanup
Phases:   recon-passive | recon-active | enumerate | attack-surface | vuln-assess | exploit | post-exploit | report

Mandatory tools by phase:
  P1: dig, curl, whois          P2: nmap              P3: gobuster/feroxbuster, ffuf
  P5: nuclei                    P6: (vector-dependent) P7: (access-dependent)

Key guardrails:
  • Authorization required before ANY testing
  • Human sign-off required at every gateway transition
  • Every finding needs reproducible evidence (not theoretical)
  • Pre-Report Gate 0: (1) attacker can do this NOW? (2) victim loses WHAT? (3) reproducible in 10 min?
  • Environment tag required on all findings (prod/nonprod/experiment)
  • Never skip phases — even for bug bounties
```

## Architecture

`Gateway (Quality Gate)` → `Phase (Pentest Stage)` → `Tasks (Techniques)`

## Commands

$ARGUMENTS
<!-- ↑ Runtime token: the skill framework substitutes this with the user's actual command argument -->

| Command | Action |
|---------|--------|
| **Lifecycle** | |
| `start` | Initialize a new engagement — prompt for scope, targets, and authorization |
| `preflight` | Check mandatory tool availability and install missing tools |
| `status` | Show current gateway state, progress, and pending techniques |
| `resume` | Resume an interrupted engagement — read existing output and continue from last checkpoint |
| `next` | Attempt to advance to the next phase (runs exit criteria check) |
| `escalate` | Trigger critical finding escalation |
| `abort` | Terminate engagement early — records reason, generates partial report |
| `cleanup` | Archive engagement output, sanitize sensitive data |
| **Phase Execution** | |
| `recon-passive` | Execute passive recon techniques |
| `recon-active` | Execute active recon techniques |
| `enumerate` | Execute application-layer enumeration |
| `attack-surface` | Map and confirm attack surface with user |
| `vuln-assess` | Execute threat modeling and vulnerability assessment |
| `exploit` | Execute exploitation techniques |
| `post-exploit` | Execute post-exploitation techniques |
| `report` | Generate final pentest report |

If no command is given, show current status and suggest next action.

---

# ═══════════════════════════════════════════════════════════════
# SETUP — Tool preparation, engagement initialization, resumption
# ═══════════════════════════════════════════════════════════════

## Preflight Check (`preflight`)

> Full tool tables, wordlist setup, and procedure: `references/preflight.md`

Verifies mandatory and recommended tools are available, installs missing ones, resolves SecLists path, and writes preflight report to `./ptest-output/preflight.md`.

If `./ptest-output/` doesn't exist, `preflight` runs in report-only mode (prints to stdout). It only writes `preflight.md` when called during or after `start`.

---

## Status (`status`)

Output:
1. Current phase and gateway state (OPEN/LOCKED/PASSED/ABORTED for all 8)
2. Active phase checklist summary: X/Y techniques done, Z findings in this phase
3. Total findings count and breakdown by severity (Critical/High/Medium/Low/Info)
4. Time elapsed since engagement start
5. Suggested next action

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
  recon-passive/        # Phase 1 results
    checklist.md
  recon-active/         # Phase 2 results
    checklist.md
  enumeration/          # Phase 3 results
    checklist.md
  attack-surface/       # Phase 4 results
    checklist.md
  vuln-assessment/      # Phase 5 results
    checklist.md
  exploit/              # Phase 6 results
    checklist.md
  post-exploit/         # Phase 7 results
    checklist.md
  report/               # Phase 8 — Final report
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
  3_enumeration: LOCKED
  4_attack_surface: LOCKED
  5_vuln_assessment: LOCKED
  6_exploitation: LOCKED
  7_post_exploitation: LOCKED
  8_reporting: LOCKED

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
  phase_8_start: ""
  phase_8_end: ""
  total_duration: ""  # Calculated at cleanup

findings_count: 0
escalations_count: 0
```

**Time tracking:** Record ISO timestamps when each phase starts and ends. At cleanup, calculate total duration and per-phase time.

---

## Resume (`resume`)

When resuming an interrupted engagement:

1. Read `./ptest-output/state.yaml` to determine active gateway.
2. Read the active phase's `checklist.md` to see which techniques are done vs. pending.
3. Read `./ptest-output/findings-log.md` for context on what's been found.
4. **Re-orient (if >24h since last activity):**
   - Re-read `scope.md` to refresh scope boundaries and exclusions
   - Re-read `attack-surface/checklist.md` (if exists) for target priority
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

| Gateway | Phase | Reference File | Exit Criteria |
|---------|-------|-----------|---------------|
| 1 | Passive Reconnaissance | `references/phase1-passive-recon.md` | Attack surface mapped, subdomains validated, technologies identified. OSINT completeness verified. **Env-prefix quick-win check completed.** |
| 2 | Active Reconnaissance | `references/phase2-active-recon.md` | Subdomain list expanded via active DNS techniques, all hosts port-scanned, services detected, network topology mapped |
| 3 | Enumeration | `references/phase3-enumeration.md` | Applications enumerated, APIs mapped, parameters discovered, Prometheus metrics mined for hidden services |
| 4 | Attack Surface Mapping | `references/phase4-attack-surface.md` | Asset inventory confirmed with user, scope finalized, entry points mapped |
| 5 | Threat Modeling & Vuln Assessment | `references/phase5-vuln-assessment.md` | Attack trees documented, vuln scans complete, CORS reflection tested on all auth endpoints, vectors prioritized |
| 6 | Exploitation | `references/phase6-exploitation-framework.md` | All mandatory techniques executed, credential inventory validated, top 5 vectors attempted, attack chains documented. **Local verification passed.** |
| 7 | Post-Exploitation | `references/phase7-post-exploitation-framework.md` | Access type classified, appropriate playbook completed, data scope documented, attack path diagram created, credentials added to inventory |
| 8 | Reporting | `references/phase8-reporting-process.md` | Final report delivered, pre-delivery checklist passed |

---

## Mandatory Quality Gates

### Pre-Report Gate 0 (MANDATORY before writing any finding)

Before drafting any finding report, answer these 3 questions. One NO = KILL the finding and move on.

1. **Can the attacker do this RIGHT NOW with a real HTTP request?**
   - Not "theoretically possible" — demonstrate with an actual request/response
   - If it requires external conditions outside attacker control (Chainlink malfunction, sequencer downtime, specific server load), it's borderline

2. **What does the victim LOSE?**
   - Map to CIA triad: confidentiality (data exposed), integrity (data modified), availability (data deleted/DoS)
   - "The server responds differently" is NOT impact. Quantify: how many users, what data, what dollar value
   - If the answer is only "information disclosure of non-sensitive data" — severity is Low at best

3. **Can it be reproduced in 10 minutes from scratch?**
   - Fresh browser, no prior state, following only your written steps
   - If it requires lucky timing, specific victim behavior beyond "click a link", or network position — document those dependencies explicitly
   - If you can't demo it reproducibly at least 3/5 attempts, do not file

**Kill signals (instant NO):**
- Finding requires privileged access an attacker can't obtain
- Finding is already known/documented behavior (check program policy)
- Finding is on the program's "never submit" list (self-XSS, logout CSRF, missing headers without impact)
- Impact is purely theoretical with no concrete demonstration

### Local Exploit Verification Gate (Phase 6 → 7 transition, MANDATORY)

Before advancing from Phase 6, every confirmed exploit MUST be locally verified when possible.

**Verification procedure:**
1. **Re-read the actual source/target behavior** — don't rely on notes from earlier analysis. Re-fetch/re-read the code.
2. **Simulate the environment locally** — install the same libraries (yauzl, express, spring-boot, etc.), replicate the file structure, run the exploit against your local simulation.
3. **Verify each chain link independently** — test validation bypass, test payload delivery, test execution separately before combining.
4. **Compare your assumptions vs actual code** — check function signatures, required interfaces, return value handling, error paths.
5. **Document verification result** — add "Locally verified: YES/NO (reason)" to the finding.

**When local verification is NOT possible:**
- Target uses proprietary/closed-source backend (no source available)
- Environment requires specific cloud services that can't be replicated
- Exploit depends on race conditions or timing that can't be simulated

In these cases, document: "Local verification not possible: {reason}. Confidence level: HIGH/MEDIUM/LOW based on {evidence}."

**Real-world save (Dojo #51, May 2026):** Initial exploit had wrong plugin interface (`module.exports = { result: flag }` instead of required `get()`, `getName()`, `run()` methods). Also had wrong first-nibble constraint (`0xA || 0xB` instead of actual `0xA || 0xC`). Local simulation caught both before submission.

---

## Effort Allocation

**Time-box enforcement:** See `references/time-box-enforcement.md` for budget calculation, alert levels, over-budget decision tree, per-technique time caps, and scope adjustment triggers.

| Phase | % of Total Time | Rationale |
|-------|----------------|-----------|
| 1–2 Recon (Passive + Active) | 15% | Discovery, not exploitation |
| 3 Enumeration | 15% | Deep enough to find entry points |
| 4 Attack Surface | 5% | Planning — consolidation only (elastic: takes as long as user needs to confirm) |
| 5 Vuln Assessment | 20% | Scanning + manual verification |
| 6 Exploitation | 25% | Highest-value work |
| 7 Post-Exploitation | 10% | Demonstrate impact |
| 8 Reporting | 10% | Write-up (findings documented throughout) |

Adjust based on scope size:
- **50+ hosts:** P1-2 → 25% (+10%), P3 → 10% (-5%), P6 → 20% (-5%)
- **Single app:** P1-2 → 10% (-5%), P3 → 10% (-5%), P6 → 35% (+10%)
- **API-only:** P3 → 20% (+5%), P5 → 15% (-5%)

**Continuous/internal engagements:** Set `time_budget.mode: "continuous"` in state.yaml. Track time for reporting only — no budget enforcement.

**Move-on heuristic:** If a technique yields no new results after 15–20 minutes of active work, mark it `DONE` (no findings) or `FAILED (diminishing returns)` and proceed. Exception for continuous engagements: vectors showing partial progress deserve extended time.

**Early-finding fast-track (bug bounty):** When a confirmed High/Critical finding is discovered during Phase 1-3, the operator may fast-track: (1) document the finding fully, (2) complete current phase's mandatory checks, (3) skip remaining low-priority techniques, (4) proceed to reporting. Mark skipped phases as "PASSED (fast-tracked — confirmed High finding)". Continue probing other live hosts briefly (10-15 min) for additional quick wins before closing.

---

## Finding Template

> Full template, ID assignment, and deduplication rules: `references/finding-template-full.md`

Every finding uses `FINDING-{ID}` (auto-incremented from `state.yaml`). Must include: severity, CVSS, affected asset, environment tag, steps to reproduce, evidence, impact, and remediation. Only **Confirmed** findings (with direct proof) go into the final report.

---

## Operational Lifecycle

### Execution Loop

1. **Read State** — check `./ptest-output/state.yaml` to determine active gateway.
2. **Read Checklist** — check the phase's `checklist.md` for pending techniques.
3. **Pick Technique** — select next pending technique.
4. **Execute** — run the technique using the tools specified in the phase skill file.
5. **Document** — record findings using the Finding Template above.
6. **Update Checklist** — mark technique status in `checklist.md`:
   - `DONE` — technique executed successfully (findings or no findings)
   - `SKIPPED (reason)` — technique not applicable or tool unavailable
   - `FAILED (reason)` — technique attempted but did not succeed
7. **Update Findings Log** — append to `./ptest-output/findings-log.md`.
8. **Repeat** until phase exit criteria are met.

### Gateway Transition (`next`)

1. **Coverage Audit** — verify checklist shows sufficient technique coverage.
2. **Mandatory Tool Check** — confirm all mandatory tools for the phase were executed.
3. **Evidence Check** — confirm all findings have supporting evidence.
4. **Exit Criteria** — evaluate against the phase's exit criteria (see Gateway Map).
5. **Sign-off** — ask user: *"Phase [X] complete. [N] findings documented. Ready to advance to [next phase]?"*
6. **Update State** — update `./ptest-output/state.yaml`: mark gateway as PASSED, unlock next.

**If exit criteria are NOT met:**
1. List specific unmet criteria.
2. Suggest which techniques to run to satisfy them.
3. Do NOT advance — gateway remains OPEN.
4. Ask: *"Want to address these gaps, or override with justification?"*
5. If user overrides, record justification in checklist and proceed.

If no sign-off response within the session, continue executing remaining techniques in the current phase rather than blocking.

---

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

## Phase Routing

When entering a phase, load the corresponding reference file with `skill_view(name='ptest', file_path='references/<file>')`:

| Phase | File | Load When |
|-------|------|-----------|
| 1 | `references/phase1-passive-recon.md` | Entering passive recon |
| 2 | `references/phase2-active-recon.md` | Entering active recon |
| 3 | `references/phase3-enumeration.md` | Entering enumeration |
| 4 | `references/phase4-attack-surface.md` | Entering attack surface mapping |
| 5 | `references/phase5-vuln-assessment.md` | Entering vuln assessment |
| 6 | `references/phase6-exploitation-framework.md` | Entering exploitation |
| 7 | `references/phase7-post-exploitation-framework.md` | Entering post-exploitation |
| 8 | `references/phase8-reporting-process.md` | Entering reporting |
| — | `references/escalate-finding.md` | Critical finding discovered (any phase) |

**Load only the active phase file.** Each contains: full technique checklist, procedures, commands, exit criteria, and pitfalls specific to that phase.

---

# ═══════════════════════════════════════════════════════════════
# OPERATIONAL — Multi-target, guardrails, cross-skill, pitfalls
# ═══════════════════════════════════════════════════════════════

## Multi-Target Engagement Structure

> Directory layout, rules, and fast-exit heuristics: `references/multi-target-structure.md`

Each target gets independent state tracking. Finding IDs are unique per-target. Reference findings by `{target}:{finding-id}` when submitting.

---

## Guardrails

### Disclosure & Platform Rules

- **Public Disclosure Prohibition** — NEVER publish PoCs on public URLs before vendor fix (or 90-day deadline). Keep PoCs local in `ptest-output/report/`. See `references/bug-bounty-submission-guide.md`.
- **YesWeHack Dojo Challenges** — See `references/yeswehack-dojo-interaction.md` for UI interaction patterns.

### Scope Rules

- **Scope Type Interpretation** — "Web application" (e.g., `mokapos.com`) means ONLY that domain, NOT `*.mokapos.com`. Only "Wildcard" targets include subdomains. Confirm BEFORE Phase 1.
- **Related-Domain Scope Risk** — findings on same-company different-root-domain are borderline. Submit clear-scope findings first, borderline last with scope note.
- **Scope Enforcement** — never test targets outside defined scope. Re-read `scope.md` before each technique.
- **Program Exclusion Cross-Check (Phase 4, MANDATORY)** — cross-reference ALL vectors against the program's exclusion list BEFORE scoring them.

### Evidence Rules

- **Evidence Required** — every finding must have reproducible proof.
- **Verified Findings Only** — DNS resolution or CT log presence alone does NOT constitute a finding. Must include proof of current exploitability.
- **Environment Tagging** — every finding MUST be tagged: `prod`, `nonprod`, `experiment`, or `all`.

### Workflow Rules

- **Strict Sequence & Self-Audit** — never skip a phase. Before requesting gateway sign-off, proactively review what was missed — list gaps honestly and offer to fill them.
- **Phase 1 OSINT Completeness** — verify ALL 10 techniques attempted: (1) WHOIS/DNS/TXT, (2) subdomain enum, (3) Wayback Machine, (4) GitHub/GitLab search, (5) Google dorking, (6) Shodan/Censys, (7) JS bundle analysis, (8) Mobile app identification, (9) Docker Hub check, (10) dark web & breach data OSINT.
- **Mandatory Tool Execution** — mandatory tools per phase must be run. If unavailable, document the gap explicitly.
- **Human Sign-off** — always request user confirmation before passing a gateway.
- **No Time/Schedule Commentary** — never comment on the time or suggest stopping. The operator decides their schedule.
- **Authorization First** — refuse to begin without confirmed authorization.
- **No Deployed Persistence** — document persistence techniques but do not deploy backdoors without explicit authorization.
- **ALWAYS do post-exploitation.** See `references/post-exploitation-rules.md`. Never stop at "proved access exists" — demonstrate actual impact.
- **Scope Type Awareness** — skip techniques that don't apply to the engagement's scope type.

### Target Assessment Heuristics

> Fast-exit rules, blocker handling, false positive detection: `references/target-heuristics.md`

### CTI & Legal

- **CTI-Sourced Credentials** — credentials from breach databases require EXPLICIT authorization to test against production. Document the risk without logging in. May violate local law (e.g., UU ITE in Indonesia) even with general pentest authorization.

---

## Cross-Skill Triggers

See `references/cross-skill-triggers.md` for full table and chains.

| Signal | Trigger Skill |
|--------|--------------|
| Cloud infrastructure (AWS/GCP/Azure) | `ctest` |
| API-heavy target | `atest` |
| Mobile app discovered | `mtest` |
| Web3/blockchain | `w3hunt` |
| Source code available | `scode` |
| Istio/service mesh detected | `references/istio-mesh-assessment.md` |
| Geo-restricted target | `references/geo-restriction-bypass.md` |

Cross-skill work runs **parallel** to the current phase (doesn't block gateway). Findings tagged with `source: "{skill-name}"` in findings-log.md. Each skill maintains its own state; only findings flow back to ptest.

---

## Automation Scripts (execute_code integration)

> Full tier definitions, script table, and usage patterns: `references/execute-code-integration.md`

Phase scripts live in `scripts/`. Two tiers: **Tier 1** (phase setup, run once at entry) and **Tier 2** (batch execution for 20+ targets). Decision heuristic: 1-3 targets → direct calls, 4-6 → delegate_task, 10+ → execute_code with batch script.

### Script Failure Protocol

| Exit Condition | Action |
|----------------|--------|
| Exit 0 | Parse output, continue normally |
| Exit 1 (partial) | Parse successful results, log failures, continue manually for failed targets |
| Exit 2+ (total failure) | Fall back to manual execution of the technique |
| Timeout | Kill process, log partial results, split into smaller batches and retry |

**Never mark a technique as DONE based solely on a failed script.** If the script fails, the technique remains PENDING until manually completed or explicitly SKIPPED with documented reason.

> **Execution pitfalls (parallel probing, terminal backgrounding, tool workarounds):** See `references/operational-pitfalls.md`
