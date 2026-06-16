---
name: ptest
description: "Structured penetration testing framework with gated phases. Guides methodical progression from recon through exploitation to reporting."
version: 1.0.1
author: n4igme
license: MIT
trigger: "pentest, penetration test, web pentest, infrastructure pentest, network pentest, external pentest, internal pentest, red team"
argument-hint: "<command: start|preflight|status|resume|next|escalate|abort|cleanup|recon-passive|recon-active|enumerate|attack-surface|vuln-assess|exploit|post-exploit|report>"
notes:
  - "v4.7.0: Trigger table (80+ entries) extracted to references/vulnerability-trigger-index.md. Pitfalls deduplicated and trimmed to one-liners in SKILL.md (details in references/pitfalls.md). New attack recipes: avatar upload path traversal RCE, base64 XXE in SPAs, DOM XSS cipher reversal. SKILL.md 717→~590 lines (~18% reduction)."
  - "v4.6.2: Deduplicated pitfalls — 19 entries consolidated into 6. When adding new pitfalls, SEARCH for existing entries on the same topic before appending."
  - "v4.6.0: Hub model — SKILL.md handles routing + framework rules. Phase techniques in references/phase*.md. Tool tables, scope matrix, finding template, heuristics extracted to references/."
  - "scripts/ contains hermes_tools-based phase scripts for all 8 phases; see references/execute-code-integration.md for tier definitions and usage"
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
  • Phase 4 = MANDATORY STOP — present full inventory to user, get explicit "proceed?" before Phase 5
  - Every finding needs reproducible evidence (not theoretical)
  - SPA catch-all: if 5+ paths return identical status+size → frontend routing, not real endpoints (see `references/spa-recon-techniques.md`)
  • Pre-Report Gate 0: (1) attacker can do this NOW? (2) victim loses WHAT? (3) reproducible in 10 min?
  • Environment tag required on all findings (prod/nonprod/experiment)
  • Never skip phases — even for bug bounties
```

## Architecture

`Gateway (Quality Gate)` → `Phase (Pentest Stage)` → `Tasks (Techniques)`

## Commands

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
| 1 | Passive Reconnaissance | `references/phase1-passive-recon.md` | Attack surface mapped, subdomains validated, technologies identified. OSINT completeness verified. **Env-prefix quick-win check completed.** No packets sent to target — only third-party sources (DNS records, Shodan InternetDB, GitHub, Google, CT logs). **Scope Viability Assessment completed.** |
| 2 | Active Reconnaissance | `references/phase2-active-recon.md` | All hosts HTTP-probed, port-scanned, technology-fingerprinted, path discovery on every live host, services detected, network topology mapped. **AD environment flag:** if DC identified (ports 88/389/636/3268) + domain-joined hosts found → flag for adtest loading at Phase 3 entry. |
| 3 | Enumeration | `references/phase3-enumeration.md` | Applications enumerated, APIs mapped, parameters discovered, Prometheus metrics mined for hidden services. **ALL subdomains from master list probed (not just Phase 2 live-hosts.txt).** |
| 4 | Attack Surface Mapping | `references/phase4-attack-surface.md` | Asset inventory confirmed with user (≥80% of live hosts individually listed — no wildcard grouping for accessible hosts), scope finalized, entry points mapped |
| 5 | Threat Modeling & Vuln Assessment | `references/phase5-vuln-assessment.md` | Attack trees documented, vuln scans complete, CORS reflection tested on all auth endpoints, vectors prioritized |
| 6 | Exploitation | `references/phase6-exploitation-framework.md` | All mandatory techniques executed, credential inventory validated, top 5 vectors attempted, attack chains documented. **Local verification passed.** |
| 7 | Post-Exploitation | `references/phase7-post-exploitation-framework.md` | Access type classified, appropriate playbook completed, data scope documented, attack path diagram created, credentials added to inventory |
| 7.5 | Chain & Escalate | `references/chain-and-escalate-phase.md` | All finding pairs evaluated, chains documented, severity upgraded where applicable |
| 8 | Reporting | `references/phase8-reporting-process.md` | Final report delivered, pre-delivery checklist passed |

---


## Mandatory Quality Gates

See `references/quality-gates.md` for full gate criteria per phase. Key rules:
- Every phase exit requires documented evidence (not just "tested")
- Findings must have PoC before phase advances
- Phase 6 requires credential-inventory.md + checklist.md BEFORE exploitation

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


## Exploitation Mindset & Post-Exploitation Rules

> Full content: `references/exploitation-mindset.md` — load when entering Phase 6-7.

Key rules:
- Phase 6 objective is TAKEOVER, not proving individual vulnerabilities — chain ALL findings
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



## Finding More Vulnerabilities

> **Full trigger→reference mapping (80+ entries):** `references/vulnerability-trigger-index.md` — load at phase transitions to identify which technique references apply to the current target.

Quick-access patterns:
- Tomcat Manager RCE (WAR deploy): `references/tomcat-manager-rce.md`
- Windows hash dump via webshell (no SMB): `references/windows-hash-extraction-via-webshell.md`
- Tomcat manager RCE: `references/tomcat-manager-exploitation.md`
- Windows hash dump via webshell: `references/windows-hash-exfiltration-webshell.md`
- AD lateral movement/privesc: `references/ad-lateral-movement-checklist.md`
- DPAPI credential decryption: `references/dpapi-credential-decryption.md`
- Tomcat WAR deploy (GUI-only): `references/tomcat-manager-war-deploy.md`
- Docker breakout via host mount: `references/docker-breakout-host-mount.md`
- Tomcat WAR deploy (GUI-only): `references/tomcat-war-deploy-rce.md`
- CDN-fronted targets: `references/cdn-aware-phase5.md`
- Firebase auth: `references/firebase-auth-bypass.md`
- SQLi with WAF: `references/sqli-payloads-and-bypass.md`
- XSS filter bypass: `references/xss-filter-bypass-techniques.md`
- Tomcat manager (default creds/WAR deploy): `references/tomcat-manager-exploitation.md`
- Windows hash exfil (webshell, no SMB): `references/windows-hash-exfiltration-webshell.md`
- File upload RCE: `references/attack-recipes.md` §"Avatar Upload Path Traversal"
- XXE in SPA: `references/attack-recipes.md` §"Base64-Encoded XML Submission"
- DOM XSS cipher: `references/attack-recipes.md` §"DOM XSS via Client-Side Cipher"
- Predictable reset token: `references/predictable-token-patterns.md`
- Lambda SSRF (file:// + IAM creds): `references/lambda-ssrf-credential-theft.md`
- Stuck at 40-50% budget: `references/stuck-playbook.md`
- Docker breakout (disk mount, socket, cgroup, nsenter): `references/docker-breakout-techniques.md`

**Recipe feedback loop:** Before closing any engagement, ask: "Does this finding generalize into a reusable pattern?" If yes → patch `references/attack-recipes.md` with new recipe (trigger + technique + yield).

## File Naming Convention

Reference files use prefixes to indicate loading rules:
- **`engagement-*`** — target-specific engagement docs. Only load when testing that specific target. Excluded from public repos via gitignore.
- **`intel-*`** — program recon/infrastructure intel. Only load during target selection or when hitting that infrastructure stack. Excluded from public repos via gitignore.
- **`phase*`** — phase methodology docs. Load when entering that phase.
- Everything else — reusable technique references. Load based on cross-skill-triggers signal matching.

**Public repo safety:** engagement/intel files contain extracted API keys, auth tokens, and target-specific secrets. Always gitignore: `**/engagement-*`, `**/intel-*`, and any file with auth flow captures (e.g., `jago-auth-flow.md`).

## Pitfalls

> **Full pitfalls list with engagement-specific details:** `references/pitfalls.md` — load when entering Phase 5+ or when a pattern below triggers.

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

### Situational Pitfalls (one-liners — see `references/pitfalls.md` for details)
- TRANSPARENT PROXY FALSE POSITIVES — Shodan InternetDB as ground truth
- NUCLEI TIMEOUT — tag-specific scans, never mark DONE on 0-result timeout
- SUBDOMAIN ENUM — multiple sources (subfinder + crt.sh)
- SHODAN ON ALL IPs — every unique IP, not just primary
- GOOGLE/GITHUB NEVER "N/A" — even for internal apps
- PHASE 4 CHECKLIST ≠ REFERENCE — diff before advancing
- PHASE 2 ≠ JUST PORT SCAN — brute-force, vhost, zone xfer, methods, headers
- SPRING BOOT CONTEXT PATH — probe outside /api/** filter
- OPENAPI SPEC IS THE WORDLIST — batch-test all paths unauth
- n8n OAUTH SCOPE ESCALATION — test arbitrary scopes on registration
- OAUTH PARAM TESTING — bare GET 302 ≠ gated
- POST+JSON+XHR BYPASSES 302 — Java/JBoss session redirect
- CORS RE-TEST IN PHASE 6 — new backends found during exploit
- SPA CATCH-ALL — baseline with random UUID first
- WEBPACK CHUNKS — business logic in lazy-loaded chunks
- JS BUNDLE DIFF — dev vs prod early in Phase 3
- PARAM TYPE BRUTE-FORCE — config endpoint wildcard values
- RATE-LIMITED TARGETS — JS route extraction over ffuf
- ANGULAR PRE-RENDERED — ng-version without bundles = server-side
- VPN SPLIT-TUNNEL — separate .ovpn, delete stale manual routes
- TLS CIPHER TESTING — pin `-tls1_2` or server upgrades to 1.3
- WEAK CSRF — empty rejected but random accepted = not session-tied
- FORGOT-PW FLOODING — 20+ rapid = DoS finding
- PREDICTABLE RESET TOKEN — test hash(email) FIRST: sha512, md5, sha256. Token length reveals algo (128=SHA512, 64=SHA256, 40=SHA1, 32=MD5). 10 seconds to verify.
- NO RATE LIMIT — test ALL auth endpoints
- AJAX LOGIN + CURL — use browser for page access, curl for API only
- SQLi DECOY DATA — enumerate ALL rows with LIMIT N,1
- CHAIN PoCs MANDATORY — no diagrams without executable proof
- CREDENTIAL INVENTORY BEFORE PHASE 6 — or wasted exploits
- JWT BRUTE FALSE POSITIVES — re-verify 3x, network flakes cause hits
- UNAUTH WRITE ON PROD — verify login after reset before claiming ATO
- PREDICTABLE RESET TOKEN — test SHA-512/256/1/MD5(email) FIRST
- EXAM KALI BOX AS PIVOT — when an exam provides a dedicated Kali system on the target subnet, ALL scanning MUST be done from Kali. Target hosts may firewall traffic from outside the /28. SecOps (June 2026): external nmap found only 2 hosts (.9, .10); Kali nmap with -Pn found 4 hosts including .7 (DC, RDP 3389) and .8 (Tomcat 8080, RDP 3389). Always `nmap -Pn -sV` the full /28 from Kali before concluding host count.
- VPN-GATED EXAM TARGETS: BROWSER VS CURL DIVERGENCE — when targets are behind VPN (exam/lab), the browser tool may resolve DNS differently than manual `curl --resolve`. If curl shows one app (e.g., OpenVPN-AS) but the browser shows a completely different app (e.g., "SecOps Labs"), it means the VPN pushes DNS or the target uses vhost routing. ALWAYS verify with `browser_navigate` first before spending time on curl-based discovery. SecOps exam (June 2026): curl to 172.27.224.1:443 hit OpenVPN-AS; browser hit a web app with XSS/SQLi labs and robots.txt with `/supersecret/` containing the flag.
- EXAM KALI BOX — check available tools on Kali IMMEDIATELY after getting creds. Install impacket (`pip3 install impacket`) early. Scripts at `/usr/share/doc/python3-impacket/examples/`. Kali may lack xfreerdp, evil-winrm, crackmapexec — plan accordingly.

- UNAUTH WRITE ENDPOINTS ON PROD — verify login works BEFORE claiming ATO after reset
- DOCKER/CONTAINER BREAKOUT PATTERNS — when SSH leads to a container (hostname looks like hex, /proc/1/cgroup shows docker): (1) check for host filesystem mounts: `find / -name "mnt" -o -name "host" 2>/dev/null`, look for /mnt/host or /host. (2) check docker socket: `ls -la /var/run/docker.sock`. (3) check SUID binaries: `find / -perm -4000 2>/dev/null` for custom binaries. (4) If host FS mounted + root in container → write SSH key to /mnt/host/root/.ssh/authorized_keys for host access. SecOps exam (June 2026): container had /mnt/host mount + SUID PATH hijack → host root.
- DOMAIN-JOINED WINDOWS SYSTEM SHELL → LOAD ADTEST — when you get SYSTEM on a domain-joined host, immediately load the adtest skill. Ad-hoc AD attacks (trying RBCD, DCSync, password guessing) without the structured adtest workflow wastes hours. SecOps exam (June 2026): spent 2+ hours on ad-hoc AD escalation before loading adtest which identified unconstrained delegation + LDAP signing disabled as the correct relay path.
- NTLM RELAY TOOLING FAILURES — impacket ntlmrelayx v0.13.x segfaults on some systems. Fallback: downgrade to v0.10.0 (`pip3 install impacket==0.10.0`). Always validate coercion FIRST with smbserver.py capture, THEN set up relay. Never assume coercion worked without proof.
- DPAPI CREDENTIAL DECRYPTION DECISION TREE — Domain user masterkey: needs domain backup key (DC admin) OR user's password. Local user masterkey: needs user's cleartext password (NTLM hash alone insufficient on newer Windows with SHA-512/AES-256 masterkeys). If neither available, SKIP after 30 min and find another path. Tools: mimikatz dpapi::masterkey (/rpc, /system, /password, /hash, /sid). Check dwDomainKeyLen: if 0 = local-only (no domain backup possible).
- LAB/EXAM PASSWORD CRACKING STRATEGY — when rockyou fails: (1) online lookup (hashes.com, crackstation.net, ntlm.pw), (2) context-based wordlist (company name + year + symbols: "SecOps2023!", "Evident@2023"), (3) rule-based: john --rules=best64/dive, (4) if still fails after 15 min → MOVE ON, find another path. Machine account hashes (120+ char random) are NEVER crackable.
- EXAM/LAB TIME MANAGEMENT — if blocked on a single escalation path for >45 min after trying 3+ techniques, STOP. Enumerate OTHER paths before continuing. Common trap: spending 2+ hours on DPAPI/NTLM relay when an easier path exists elsewhere.
- SSH NON-STANDARD PORT (2222) + KEY-ONLY ON 22 = DOCKER — this pattern strongly suggests a container. Check: hostname (hex-like), /proc/1/cgroup, /mnt/host or /host mounts, docker.sock, SUID binaries. Container root + host FS mount = host root via SSH key injection.
- PIVOT HOST TOOLING READINESS — when gaining access to multiple hosts (Kali, Linux pivot, Windows), run a quick tool inventory on EACH before deciding where to launch attacks: `python3 -c "import impacket; print(impacket.__version__)"`, `which smbclient ntlmrelayx.py secretsdump.py nmap responder crackmapexec certipy`. Choose the host with best tooling for relay/exploitation. Don't discover tool gaps mid-attack.
- BLOCKED PATHS DOCUMENTATION — when an escalation path is exhausted (3+ techniques tried, all failed), add a "BLOCKED" entry to findings-log.md: path name, techniques tried, evidence of failure, reason blocked. Prevents re-attempting the same dead end after context compaction or session resume.
- TOMCAT MANAGER TEXT 403 — if /manager/text returns 403 (manager-gui only, no manager-script), use HTML multipart upload with CSRF nonce in same session (requests.Session + regex CSRF_NONCE + POST multipart)
- OPENSSH KEY FORMAT — leaked keys from pastebin/web often have broken line wrapping. Decode full base64, re-wrap at 70 chars, add proper BEGIN/END headers. Verify with `ssh-keygen -y -f key` before use.
- DOCKER HOST MOUNT — containers with host filesystem at `/mnt/host/` = instant root on host. Write attacker SSH key to `/mnt/host/root/.ssh/authorized_keys`, then SSH to port 22 as root.
- DPAPI DOMAIN USER CREDS — for domain users, masterkey decryption requires: domain backup key (via DC RPC), OR user's cleartext password + SID. Machine DPAPI_SYSTEM keys only decrypt the BACKUP portion (not usable for credential blob decryption). Don't waste time with backup key on the credential blob.
- EXAM KALI BOX — check Kali tool availability FIRST (impacket, crackmapexec, xfreerdp). Install missing tools early. Kali may have limited impacket; use `pip3 install impacket` + scripts at `/usr/share/doc/python3-impacket/examples/`.
- MIMIKATZ UPLOAD VIA WEBSHELL — use PowerShell `[IO.File]::AppendAllText()` in 8KB chunks via POST, then `certutil -decode`. Verify file size matches before decoding. `Add-Content -NoNewline` doesn't work reliably for large binary base64.


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
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/ptest/scripts"))
import state_manager

workdir = "."
state_manager.init_state(workdir, "Target Corp", scope_type="web",
    targets=["example.com", "api.example.com"], budget_hours=16)
state_manager.status(workdir)
state_manager.advance_phase(workdir)
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

