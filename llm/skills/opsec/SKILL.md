---
name: opsec
description: "Defensive OPSEC self-assessment framework — exposure scoring, identity compartmentalization, remediation playbook, and periodic audit methodology."
version: 1.2.0
author: n4igme
license: MIT
trigger: "opsec, operational security, exposure check, identity compartment, privacy audit, digital footprint"
argument-hint: "<command: start|status|resume|next|assess|score|chain|remediate|audit|report|abort|cleanup>"
notes:
  - "v1.2.0: Added Phase Entry Protocol, time_tracking, deduplicated Gate Enforcement. Aligned with skill family patterns."
  - "v1.1.0: Extracted to hub model — Phase 2, 4, 5, 6, Report Template, Pitfalls → references/. SKILL.md reduced from 515 to 227 lines."
metadata:
  hermes:
    tags: [opsec, privacy, defensive, security, exposure, compartmentalization]
    related_skills: [osint, ptest]
---

# OPSEC Self-Assessment Framework

Structured methodology for assessing and reducing your own digital exposure. Think of it as pentesting yourself — finding leaks in your personal digital footprint before adversaries do.

## Quick Reference

```
Phases:  1.Inventory → 2.Exposure → 3.Scoring → 4.Chain → 5.Remediation → 6.Audit
Flow:    What exists → What's exposed → How bad → How linked → Fix it → Maintain
Commands: start | assess | score | chain | remediate | audit | report
Lifecycle: status | resume | next | abort | cleanup

Key rules:
  • Git commit history is the #1 source of identity leaks for developers
  • Deleted content persists in Wayback Machine — request explicit removal
  • 3+ hops between public persona and real identity = good compartmentalization
  • Quarterly audits catch new exposure before adversaries do
  • Don't overreact — focus on what enables real attacks, not theoretical exposure
```

## Architecture

`Inventory (What exists)` → `Assessment (What's exposed)` → `Scoring (How bad)` → `Remediation (Fix it)`

## Scripts

Scripts in `~/.hermes/skills/security/opsec/scripts/`:
- **state_manager.py**: `init_state()`, `status()`, `advance_phase()`, `add_finding()`, `set_chain_hops()`, `add_remediation()`, `abandon()`
- **gate_check.py**: `check_gate(workdir, phase)`, `print_gate_status(result)` — run before advancing
- **exposure_check.py**: Automated git email audit + platform presence check

```bash
# Quick exposure check
python3 ~/.hermes/skills/security/opsec/scripts/exposure_check.py --github-user <handle> --check-platforms
```

## Commands

| Command | Action |
|---------|--------|
| **Lifecycle** | |
| `start` | Initialize self-assessment — collect all known identifiers |
| `status` | Show progress: phases completed, findings by severity |
| `resume` | Resume interrupted assessment |
| `next` | Advance to next phase (check gate) |
| `abort` | Terminate assessment |
| `cleanup` | Archive output, sanitize sensitive data |
| **Phase Execution** | |
| `assess` | Phase 2: Run full exposure assessment |
| `score` | Phase 3: Rate findings by severity |
| `chain` | Phase 4: Map identity cross-reference chains |
| `remediate` | Phase 5: Generate remediation plan |
| `audit` | Phase 6: Periodic audit checklist |
| `report` | Compile full OPSEC assessment report |

### Command Procedures

**`start`:** Collect ALL identifiers → create `./opsec-output/` → write `state.yaml` + `inventory.md` → advance to Phase 2.

**`status`:** Current phase, findings by severity (🔴🟠🟡🟢), chain hops to real identity, remediation items pending.

**`resume`:** Read state.yaml. Staleness: >30 days → re-run Phase 2 (new breaches). >90 days → fresh assessment.

**`next`:** Verify gate (inventory complete / all checks run / findings scored / chain mapped / remediation written). If unmet, list gaps.

**`abort`:** Record reason, mark remaining ABORTED, cleanup.

**`cleanup`:** Archive `./opsec-output/` → `opsec-output-{date}.tar.gz`. Remove discovered credentials (document first).

### Output: `./opsec-output/`

```
state.yaml | inventory.md | exposure.md | scoring.md | chain-map.md | remediation-plan.md | audit-checklist.md | report.md
```
## Phase 1: Identity Inventory

### Phase Entry Protocol (ALL phases)

When entering ANY phase, before executing techniques:
1. **Load reference file** — per phase (Phase 2+: load from `references/`)
2. **Record timestamp** — track phase start time for budgeting

Collect ALL known identifiers (be honest — adversaries will find them anyway):

```markdown
## My Identifiers
- Real name:
- Aliases/nicknames:
- Handles (list all):
- Email addresses (list all):
- Phone numbers:
- Domains owned:
- Employer/org:
- Location (city/region):
- Profiles (list URLs):
```

## Phase 2: Exposure Assessment

> Full methodology (sections 2.1-2.9): `references/phase2-exposure.md`

## Phase 3: Severity Scoring

### 🔴 CRITICAL
- Real name + home address publicly linked
- Bank account numbers exposed
- Work credentials or internal domains in public repos
- Single profile that chains to full real identity in 1 hop
- Family member names + relationship exposed

### 🟠 HIGH
- Real name linked to security handle (targeted attack risk)
- Employer clearly identifiable from public data
- Multiple emails exposed enabling credential stuffing
- Cross-links between professional and personal personas on profile pages

### 🟡 MEDIUM
- Handle exists on platform but minimal info exposed
- Location narrowed to city/region level
- Professional role/skills visible (enables targeted phishing)
- Secondary/old accounts still active

### 🟢 LOW
- Alias-only presence with no real identity link
- Generic bio/about info
- Inactive accounts with no content
- Public SSH keys (low risk unless combined with other data)

## Phase 4: Cross-Reference Chain Analysis

> Chain mapping methodology: `references/phase4-chain.md`

## Phase 5: Remediation Playbook

> Priority 1-6 remediation steps: `references/phase5-remediation.md`

## Phase 6: Periodic Audit Checklist

> Quarterly checklist: `references/phase6-audit.md`

## Report Template

> Full template: `references/report-template.md`

## Pitfalls

> All pitfalls: `references/pitfalls.md`

## Time Budgets

| Assessment Type | Total | Inventory | Exposure | Scoring | Chain | Remediation |
|----------------|-------|-----------|----------|---------|-------|-------------|
| First full assessment | 3-4 hr | 30 min | 1.5-2 hr | 30 min | 30 min | 30 min |
| Quarterly audit | 1 hr | skip | 30 min | 15 min | skip | 15 min |
| Post-incident (breach/dox) | 2 hr | 15 min | 1 hr | 15 min | 15 min | 15 min |

**Abandon triggers:**
- No new exposure found after 1 hour of Phase 2 → your OPSEC is good, move to scoring
- All findings are 🟢 Low → skip remediation, schedule next quarterly audit
- Assessment reveals 🔴 Critical → stop assessment, remediate immediately, then resume

## Gate Enforcement (MANDATORY before `next`)

```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/opsec/scripts"))
from gate_check import check_gate, print_gate_status

result = check_gate(".", phase=None)
print_gate_status(result)
```

## Cross-Skill Integration

- **Validate your own exposure:** Run `osint` skill against your handles — `handle_check.py` from osint scripts checks 12+ platforms in one call
- **After remediation:** Re-run osint to verify fixes worked (profile removed, email no longer discoverable)
- **For team assessments:** Use osint on team members (with authorization) to find org-wide patterns
- **Domain recon overlap:** osint `references/domain-recon.md` has DNS/WHOIS/crt.sh methodology — use it in Phase 2 for your own domains
- **Breach correlation:** osint `references/breach-correlation.md` covers HIBP/DeHashed techniques — use in Phase 2.5
- **Proven patterns:** osint `references/proven-patterns.md` has handle/email discovery patterns — reverse them to find YOUR leaks

## Script Invocation

Scripts are in `~/.hermes/skills/security/opsec/scripts/`. Invoke via `execute_code`.

**state_manager.py — assessment lifecycle:**
```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/opsec/scripts"))
import state_manager

workdir = "."
state_manager.init_state(workdir, "n4igme",
    handles=["n4igme", "maurha"], emails=["test@proton.me"],
    domains=["example.com"])

state_manager.status(workdir)
state_manager.advance_phase(workdir)
state_manager.add_finding(workdir, "high", "Work email in git commits", source="github")
state_manager.set_chain_hops(workdir, 2)
state_manager.add_remediation(workdir, 1, "Remove cross-links from GitHub sidebar")
state_manager.abandon(workdir, "All findings are Low")
```

**gate_check.py — phase gate enforcement:**
```python
# See Gate Enforcement section above for usage
```

**exposure_check.py — automated audit:**
```bash
python3 ~/.hermes/skills/security/opsec/scripts/exposure_check.py --github-user <handle> --check-platforms --output ./opsec-output/exposure-auto.md
```
