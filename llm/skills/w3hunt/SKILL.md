---
name: w3hunt
version: 1.4.0
description: "Web3 bug bounty hunting on Immunefi and similar platforms. Target selection, scope verification, DeFi-specific recon, and attack vector prioritization for hybrid web+contract programs."
tags: [web3, bug-bounty, immunefi, defi, smart-contract, recon]
trigger: "immunefi, web3 hunting, defi bug bounty, smart contract bounty, web3 recon"
argument-hint: "<command: start|next|recon|scope|targets|status|resume|report|abort|cleanup>"
notes:
  - "v2.1.0: Hub model — SKILL.md is routing + strategy + framework. Phase content in references/phase*.md"
  - "NEVER rewrite full SKILL.md in one tool call — use strReplace/patch for edits. Large write_file calls hit output token limits and get truncated."
metadata:
  hermes:
    tags: [web3, bug-bounty, immunefi, defi, smart-contract]
    related_skills: [ptest, scode, atest]
---

# Web3 Bug Bounty Hunting Framework

Optimized for hunters with strong web pentest backgrounds targeting DeFi protocol web+contract hybrid programs.

## Quick Reference

```
Phases:  1.Triage(15m) → 2.Recon(1h) → 3.Web(30m-2h) → 4.SC(2-3h,conditional) → 5.Exploit+Submit(30m)
Default: WEB-FIRST (Phase 3 always runs, Phase 4 only if web is dead)
Budget:  4-8 hours per target. No High+ by hour 6 → move on.

Key rules:
  • 15-min triage BEFORE deep-dive (verify live, check C4/Sherlock, check scope)
  • NEVER claim impact you haven't proven end-to-end
  • Verify exploit output BEFORE writing report
  • Asset scope is STRICTLY enforced — check before submitting
  • PoC in Python only (requests + eth_account), NEVER curl
  • Submit immediately — sitting on findings risks duplicates

Oracle prerequisite check (all 3 required — see Strategy section):
  If ANY fails → pivot to web scope or different bug class
```

## Commands

| Command | Action |
|---------|--------|
| `start` | Initialize new target — create working directory, save scope, run Phase 1 triage |
| `next` | Check gate condition and advance to next phase |
| `recon` | Phase 2: Subdomain enum, GitHub repos, frontend analysis, API mapping |
| `scope` | Re-verify program scope mid-engagement (check for changes since start) |
| `targets` | Research and shortlist suitable programs from Immunefi |
| `status` | Show current target, phase, findings, time spent |
| `resume` | Resume interrupted hunting session from last checkpoint |
| `report` | Generate finding report in platform-specific format (Immunefi/YesWeHack) |
| `abort` | Terminate hunt early — external reason (program paused, legal, scope invalidated) |
| `cleanup` | Archive engagement output, sanitize sensitive data |
| `postmortem` | Record engagement outcome: hours, payout, lessons, update ROI metrics |

### `start` Procedure

1. **Create working directory** — `~/PenTest/Hunting/Immunefi/<target>/`
2. **Save scope** — extract ALL assets into `scope.txt`. Include: rules, targets, impacts, payout structure, severity version, FULL asset list.
3. **Initialize state.yaml** — `state_manager.init_state(workdir, name, slug, platform, scope_type)`
4. **Run Phase 1 triage** — `phase1_triage.run(workdir, slug, platform)`
5. If GO → `state_manager.advance_phase(workdir)` to enter Phase 2. If NO-GO → `state_manager.abandon(workdir, reason)`.

### `next` Procedure

1. Read state.yaml → determine `current_phase`.
2. Run gate check:
```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/w3hunt/scripts"))
from gate_check import check_gate, print_gate_status

result = check_gate(os.path.expanduser("~/PenTest/Hunting/Immunefi/<target>"), phase=None)
print_gate_status(result)
```
3. Verify gate condition:

**Gate Enforcement (run before advancing):**
```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/w3hunt/scripts"))
from gate_check import check_gate, print_gate_status

result = check_gate(os.path.expanduser("~/PenTest/Hunting/Immunefi/<target>"), phase=None)
print_gate_status(result)
# Only advance if result["passed"] is True
```

Gate conditions per phase:
   - Phase 1: GO/NO-GO decision documented
   - Phase 2: minimum viable recon checklist complete (5 items)
   - Phase 3: quick-kill checklist done, OR "web layer hardened" documented
   - Phase 4: at least one batch tested with PoC, OR "SC dead/skipped" documented
   - Phase 5: PoC validated + report submitted
3. If NOT met: list what's missing, suggest actions.
4. If met: `state_manager.advance_phase(workdir)`, report advancement.
5. Override: record justification in `notes` and proceed.

### `resume` Procedure

1. Read `state.yaml` to determine current phase and time spent.
2. Re-verify program is still live.
3. Re-check scope hasn't changed.
4. **Staleness:** >3 days → re-verify findings. >14 days → re-run Phase 2 recon (10 min).
5. Report status and suggest next action.

### `report` Procedure

1. Load finding from `findings/finding-NNN.md`.
2. Format per platform template (see `references/immunefi-report-template.md`).
3. Verify: PoC runs, output matches claimed impact, asset is in scope.
4. Output formatted report ready for submission.

### `abort` Procedure

**Valid reasons:** program paused/removed, scope invalidated, legal concern, platform dispute.

1. Record reason in state.yaml: `status → "aborted"`, mark gateways `ABORTED`.
2. If findings exist but unsubmitted → ask user: submit now or discard?
3. Run cleanup.

### `cleanup` Procedure

1. Archive target directory to `<target>-<date>.tar.gz`.
2. Remove any mainnet private keys or tokens from PoC files.
3. Update state.yaml: `status → "closed"`.
4. Print summary: time spent, findings submitted, outcomes.

### `postmortem` Procedure

Run after every engagement closes (accepted, rejected, abandoned, duplicate).

1. Run `scripts/postmortem.py` — auto-calculates hours, payout, $/hr, phase found, time-to-first.
2. Answer lessons: what worked, what wasted time, transferable pattern?, skill gaps?
3. Script appends to `references/engagement-roi-metrics.md` automatically.
4. If new pitfall discovered → patch `references/operational-rules.md`.
5. If finding generalizes → patch ptest `references/attack-recipes.md` with new recipe.

## Cross-Skill Handoffs

**Into w3hunt (from other skills):**
- atest finds smart contract interaction via API → invoke w3hunt
- scode finds Solidity/Vyper code in repo → invoke w3hunt + scode (web3 scope)
- ptest discovers DeFi webapp → invoke w3hunt for contract-level testing

**Out of w3hunt (to other skills):**
- Web frontend found on DeFi app → hand to ptest (standard web pentest)
- API layer between frontend and contracts → hand to atest
- Contract source code needs review → hand to scode (web3 scope type)
- Off-chain oracle/keeper exploitable → hand to ctest (if cloud-hosted)

### `scope` Procedure

Use when: resuming after >24h, before submitting, or when unsure about asset coverage.

1. Re-fetch program page — check if assets were added/removed.
2. Diff against saved `scope.txt` — flag changes.
3. Update `scope.txt` with changes and timestamp.

### Gate Enforcement (MANDATORY before `next`)

```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/w3hunt/scripts"))
from gate_check import check_gate, print_gate_status

result = check_gate(os.path.expanduser("~/PenTest/Hunting/Immunefi/<target>"), phase=None)
print_gate_status(result)
```

### Target Refresh

```bash
python3 ~/.hermes/skills/security/w3hunt/scripts/target_refresh.py \
  --min-payout 10000 \
  --output ~/.hermes/skills/security/w3hunt/references/immunefi-targets-v3.md
```

### Postmortem

```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/w3hunt/scripts"))
import postmortem
postmortem.run(os.path.expanduser("~/PenTest/Hunting/Immunefi/<target>"), lessons={
    "what_worked": "...", "what_wasted_time": "...",
    "transferable": "yes/no — ...", "hunt_again": "yes/no — ..."
})
```

### `status` Procedure

1. Read state.yaml → extract target name, current phase, status.
2. Calculate elapsed time from `target.started`.
3. Show gateway states (OPEN/LOCKED/PASSED/ABANDONED).
4. Count findings by status (draft/validated/submitted).
5. Run `state_manager.should_abandon(workdir)` — display result.
6. Output:
```
─── w3hunt status ───────────────────────────
Target:   <name> (<platform>)
Phase:    <N> (<phase_name>) — <gateway_status>
Elapsed:  <X.X>h / 8h budget
Findings: <N> total (<N> draft, <N> submitted)
Abandon:  <yes/no> — <reason if yes>
─────────────────────────────────────────────
```

### `targets` Procedure

**Data source (try in order):**
1. arkadiyt/bounty-targets-data repo (structured JSON, updated daily):
   `curl -s "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/immunefi_data.json"`
2. Immunefi explore page (fallback): `https://immunefi.com/explore/`

**Steps:**
1. Fetch + filter: "Websites and Applications" scope, active, $10K+ Critical payout.
2. Apply selection criteria: hybrid web+SC, mid-tier, EVM chains.
3. Apply ROI-weighted scoring (from `references/engagement-roi-metrics.md`):
   ```
   Score = base_payout × type_multiplier × freshness_bonus × negative_signals

   type_multiplier:  consumer_app=1.5, security_co=1.4, infra=1.3, defi_hybrid=1.0, defi_vault_sc=0.4
   freshness_bonus:  <30d=1.3, <90d=1.1, >1yr=0.8
   negative_signals: prior_c4/sherlock=×0.6, no_web_scope=×0.3, api_dead=×0.0
   ```
4. Quick-check top 5 candidates (2 min per): web scope? fresh? prior contest? payout?
5. Output ranked shortlist with: slug, payout, scope type, score, rationale.
6. Suggest `start <slug>` for top pick.

**Staleness:** Cached shortlist in `references/immunefi-targets-v3.md` — refresh when >7 days old.

See `references/immunefi-targets-v3.md` for current shortlist.

---

## Phase Routing

When entering a phase, load the corresponding reference file:

| Phase | File | Gate Summary |
|-------|------|-------------|
| 1 | `references/phase1-triage.md` | GO/NO-GO decision made, prerequisites checked |
| 2 | `references/phase2-recon.md` | Subdomains mapped, GitHub cloned, APIs discovered, framework identified |
| 3 | `references/phase3-web-assessment.md` | Quick-kill checklist done, OR "web layer hardened" |
| 4 | `references/phase4-sc-audit.md` | At least one batch tested with PoC, OR "SC dead/skipped" |
| 5 | `references/phase5-exploit.md` | PoC validated + report submitted |

**Load only the active phase file.**

---

## Strategy

**Core edge:** Most Immunefi hunters are Solidity-focused. Web pentest skills applied to DeFi frontends, APIs, and off-chain components face far less competition.

**Target selection criteria:**
- BOTH web/app scope AND smart contract scope (hybrid programs)
- Mid-tier payout: $10K-$100K for Critical (avoid over-audited top-tier)
- Protocols with: DeFi frontends, admin panels, APIs, off-chain components
- Active programs on EVM chains (Ethereum, Arbitrum, Optimism, Base, Polygon, BSC)
- Multi-chain deployments preferred (larger attack surface, inconsistency bugs)

**Priority by web pentest edge:**
- HIGH: CeFi/DeFi hybrids, multi-chain aggregators, platforms with complex APIs
- MEDIUM: Trading UIs, yield farming dashboards, DCA/scheduling frontends
- LOWER: Pure contract protocols with minimal web layer

**Pattern transferability prerequisite check (MANDATORY before SC source review):**
All THREE required for oracle bug class:
1. ✅ Permissionless trigger function (harvest, compound, rebase callable by anyone)
2. ✅ On-chain oracle-dependent swap (not just transfer to strategist)
3. ✅ Slippage/minAmountOut calculated FROM oracle price (not user-supplied)
If ANY is missing → pivot to web scope or switch bug class.

**Decision tree:**
- Web scope exists → WEB-FIRST (default)
- No web, SC prerequisites pass → SC-FIRST
- $50K+ program with both surfaces → PARALLEL (delegate_task)

**Effort:** Total 4-8 hours. P1: 15m, P2: 1h, P3: 30m-2h, P4: 2-3h (conditional), P5: 30m.

**Early-finding fast-track:** Critical/High during Phase 2/3 → skip to Phase 5 immediately. Submit → return for more.

---

## Framework

### State Tracking

```yaml
target:
  name: ""
  slug: ""
  platform: "immunefi"
  url: ""
  started: ""
  status: "active"
  scope_type: "hybrid"

current_phase: 1

gateways:
  1_triage: OPEN
  2_recon: LOCKED
  3_web_assessment: LOCKED
  4_sc_audit: LOCKED
  5_exploit_submit: LOCKED

scope:
  has_web: false
  has_sc: false
  web_targets: []
  sc_addresses: []
  max_payout_web: ""
  max_payout_sc: ""

prerequisites:
  program_live: false
  prior_contest: false
  oracle_permissionless: null
  oracle_swap_onchain: null
  oracle_slippage_derived: null

findings_count: 0
submitted_count: 0

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

notes: ""
```

**Time enforcement:** Elapsed > 8 hours + no findings → trigger abandon. Use `state_manager.should_abandon()`.

### Output Structure

```
~/PenTest/Hunting/Immunefi/<target>/
├── state.yaml
├── scope.txt
├── submissions.yaml       # Created on first submit
├── subdomains.txt
├── frontend-recon.txt
├── recon-summary.txt
├── github-repos.txt
├── api-endpoints.txt
├── findings/
│   └── finding-001.md
└── poc/
    └── poc_001.py
```

### Finding Template

```markdown
# Finding-NNN: {Title}

**Severity:** Critical / High / Medium
**Impact Category:** {Exact Immunefi category wording}
**Affected Asset:** {Contract address or URL — MUST be in scope list}
**Chain:** {Ethereum / Arbitrum / Polygon / etc.}
**Phase Discovered:** {2/3/4}
**Status:** draft / validated / submitted / accepted / rejected

## Description
## Steps to Reproduce
## PoC
File: `../poc/poc_NNN.py`
Output: {actual execution output}
## Impact
## Fix Suggestion
## Scope Proof
```

### Script Failure Protocol

| Exit Condition | Action |
|----------------|--------|
| Exit 0 | Parse output, continue |
| Exit 1 (partial) | Parse successful results, continue manually for failed items |
| Exit 2+ (total failure) | Fall back to manual execution |
| Timeout | Retry once. If persistent, execute manually. |

Phase gates are NOT satisfied by failed scripts.

### Severity & Reporting

See `references/immunefi-severity-v2.2.md` for severity tables and decision tree.
See `references/immunefi-report-template.md` for report format and impact framing.

---

## Operational

### Post-Submission Protocol

| Response | Action |
|----------|--------|
| "Needs more info" | Respond within 24hr with exact evidence |
| "Not reproducible" | Re-run PoC, provide updated output with timestamps |
| "Duplicate" | Accept gracefully. Move on. |
| "Out of scope" | Check if reframeable (frontend bundle proof). If not, lesson learned. |
| "Accepted" | 🎉 Note pattern. Look for same bug class on similar targets. |

### Abandon Decision

**Triggers:** hour 6 with no High+, OR Phase 3 yields nothing and SC prerequisites fail.

1. `state_manager.abandon(workdir, reason)`
2. Document in `recon-summary.txt`: what was tested, why it's hardened/dead
3. Move to Next Target Decision Tree (fresh target criteria: payout × novelty × recency × hybrid)

## Pitfalls

> Full pitfalls and operational rules: `references/operational-rules.md`

**Engagement file naming:** ALWAYS prefix target-specific references with `engagement-` (e.g., `engagement-ens.md`, `engagement-grab-ovo.md`). These patterns are gitignored from public backup repos via `llm/skills/**/engagement-*`. Files without the prefix trigger GitHub secret scanning alerts when they contain contract addresses, API keys, or wallet details found during testing.

**Top 5 instant-rejection rules:**
1. **NEVER claim impact you haven't proven end-to-end** — theoretical = rejected
2. **VERIFY EXPLOIT OUTPUT BEFORE WRITING REPORT** — run full chain, confirm output matches claim
3. **Asset scope is STRICTLY enforced** — verify address in scope list before submitting
4. **Submit immediately** — sitting on findings risks duplicates
5. **PoC in Python only** — never curl. Include `Origin` header matching in-scope app URL

### References

- `references/sc-audit-patterns.md` — DeFi SC audit patterns
- `references/platform-operational-notes.md` — Platform-specific notes
- `references/immunefi-severity-v2.2.md` — Severity tables
- `references/immunefi-report-template.md` — Report format
- `references/operational-rules.md` — Full operational rules
- `references/immunefi-targets-v3.md` — Target shortlist
- `references/engagement-stakewise.md` — Signature replay (Critical)
- `references/engagement-ens.md` — CSP bypass via stale PostHog (Critical)
- `references/engagement-hacken.md` — SSRF bypassing Cloudflare Access
- `references/engagement-beefy-lessons.md` — Scope rejection lesson
