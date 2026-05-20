# Time-Box Enforcement Mechanism

## Overview

Pentests are time-constrained. Without enforcement, early phases consume disproportionate time (recon is comfortable; exploitation is uncertain). This mechanism forces prioritization decisions when time runs out.

## Setup: At Engagement Start

When `start` is called, calculate time budgets:

```yaml
# Add to state.yaml during initialization
time_budget:
  total_hours: 40  # User provides this (engagement days × 8)
  phase_budgets:
    phase_1_2: 6.0   # 15% — Recon (passive + active)
    phase_3: 6.0      # 15% — Enumeration
    phase_4: 2.0      # 5%  — Attack Surface
    phase_5: 8.0      # 20% — Vuln Assessment
    phase_6: 10.0     # 25% — Exploitation
    phase_7: 4.0      # 10% — Post-Exploitation
    phase_8: 4.0      # 10% — Reporting
  phase_spent:
    phase_1_2: 0.0
    phase_3: 0.0
    phase_4: 0.0
    phase_5: 0.0
    phase_6: 0.0
    phase_7: 0.0
    phase_8: 0.0
  alerts_triggered: []
```

## Budget Calculation Table

| Engagement Length | Total Hours | Ph 1-2 | Ph 3 | Ph 4 | Ph 5 | Ph 6 | Ph 7 | Ph 8 |
|-----------------|-------------|--------|------|------|------|------|------|------|
| 1 day | 8h | 1.2h | 1.2h | 0.4h | 1.6h | 2.0h | 0.8h | 0.8h |
| 2 days | 16h | 2.4h | 2.4h | 0.8h | 3.2h | 4.0h | 1.6h | 1.6h |
| 3 days | 24h | 3.6h | 3.6h | 1.2h | 4.8h | 6.0h | 2.4h | 2.4h |
| 5 days | 40h | 6.0h | 6.0h | 2.0h | 8.0h | 10.0h | 4.0h | 4.0h |
| 10 days | 80h | 12.0h | 12.0h | 4.0h | 16.0h | 20.0h | 8.0h | 8.0h |

## Tracking: During Execution

### Per-Technique Time Logging

Every technique in the checklist tracks time spent:

```markdown
| # | Technique | Status | Time Spent | Budget | Over? |
|---|-----------|--------|------------|--------|-------|
| 3.1 | Directory Brute-Force | DONE | 1.5h | 1.0h | ⚠️ YES |
| 3.2 | API Endpoint Discovery | DONE | 0.5h | 1.0h | No |
| 3.3 | Parameter Discovery | IN PROGRESS | 0.3h | 0.5h | No |
```

### Phase Budget Check

At the start of each technique, check remaining budget:

```
Phase budget remaining = phase_budget - phase_spent

If remaining <= 0:
  → TRIGGER: Over-budget decision (see below)

If remaining < estimated_technique_time:
  → WARN: "~{X}min remaining in phase budget. This technique typically takes {Y}min."
  → Ask: "Continue with reduced scope, skip, or borrow time from next phase?"
```

## Alerts & Decisions

### Alert Levels

| Level | Trigger | Action |
|-------|---------|--------|
| 🟢 On Track | Spent < 75% of phase budget | Continue normally |
| 🟡 Warning | Spent 75-100% of phase budget | Prioritize remaining techniques, skip low-value ones |
| 🔴 Over Budget | Spent > 100% of phase budget | Force decision: stop phase or borrow time |
| ⚫ Critical | Total engagement > 90% spent, phases remaining | Emergency triage — skip to highest-value remaining work |

### Over-Budget Decision Tree

```
Phase budget exhausted. What now?

├── Are mandatory techniques still PENDING?
│   ├── YES → Can they be done in reduced scope? (quick scan vs deep scan)
│   │         ├── YES → Execute reduced scope, mark as "DONE (reduced — time constraint)"
│   │         └── NO → Mark as "SKIPPED (time constraint)" — document in report
│   └── NO → All mandatory done. Mark remaining optional as "SKIPPED (time constraint)"
│
├── Is this phase producing high-value findings?
│   ├── YES → Borrow up to 25% from the NEXT phase
│   │         Update state.yaml: reduce next phase budget
│   │         Log: "Borrowed {X}h from Phase {N+1} — high-value findings in progress"
│   └── NO → Stop immediately. Diminishing returns confirmed.
│
└── Is the engagement total budget at risk?
    ├── YES → Force phase completion NOW. No borrowing.
    └── NO → Borrow is acceptable.
```

### Borrowing Rules

- Can borrow up to **25%** from the next phase
- Can borrow up to **50%** from Phase 8 (reporting) if findings are documented throughout
- **Cannot** borrow from Phase 6 or 7 to fund earlier phases (exploitation time is sacred)
- **Cannot** borrow more than once from the same phase
- All borrowing is logged in `state.yaml` under `alerts_triggered`

## Per-Technique Time Caps

Default maximum time per individual technique before forcing a move-on decision:

| Phase | Default Cap | Exception |
|-------|------------|-----------|
| Phase 1-2 (Recon) | 30 min/technique | Subdomain enum: 45 min |
| Phase 3 (Enumeration) | 45 min/technique | Full JS analysis: 60 min |
| Phase 4 (Attack Surface) | 20 min/technique | Planning phase — should be fast |
| Phase 5 (Vuln Assessment) | 30 min/technique | Nuclei full scan: 60 min |
| Phase 6 (Exploitation) | 60 min/technique | Credential chaining: 90 min |
| Phase 7 (Post-Exploitation) | 30 min/technique | Data classification: 45 min |
| Phase 8 (Reporting) | N/A | Time-box the whole phase, not techniques |

### Move-On Heuristic (Enhanced)

```
Technique running > time cap. Decision:

1. Has it produced ANY results in the last 10 minutes?
   → NO → Mark DONE or FAILED, move on immediately
   → YES → Continue for 10 more minutes max, then force stop

2. Is this a mandatory technique?
   → YES → Try one alternative approach (5 min), then mark FAILED if still nothing
   → NO → Mark SKIPPED (diminishing returns), move on

3. Is this the last technique before a gateway?
   → YES → Complete it (gateway transition is more important than time cap)
   → NO → Move on, come back if time permits at end of phase
```

## Status Command Integration

When `status` is called, include time tracking:

```markdown
## Engagement Status

**Phase:** 5 — Vulnerability Assessment (OPEN)
**Time Budget:**
- Phase 5: 4.2h spent / 8.0h budget (52%) 🟢
- Total: 18.5h spent / 40.0h budget (46%) 🟢
- Borrowed: 0.5h from Phase 4 → Phase 3

**Current Technique:** 5.3 — SSL/TLS Assessment
- Time on technique: 15 min
- Technique cap: 30 min
- Remaining in phase: 3.8h

**Projection:**
- At current pace: Phase 5 will complete in ~3.5h (within budget)
- Remaining phases need: 18h (budget available: 21.5h) ✅
```

## End-of-Engagement Triage

When total engagement time > 85% spent:

```
EMERGENCY TRIAGE:

1. What phases are incomplete?
2. What's the minimum viable deliverable for each?
   - Phase 6 minimum: Top 3 vectors attempted, credential inventory validated
   - Phase 7 minimum: Data scope documented, attack path diagram created
   - Phase 8 minimum: Executive summary + findings + remediation roadmap
3. Skip everything else. Focus on report quality over coverage.

Document in report: "Due to time constraints, the following techniques were not executed: {list}. 
These are recommended for a follow-up engagement."
```

## Scope Adjustment Triggers

Sometimes the scope is too large for the time budget. Recognize this early:

| Signal | When | Action |
|--------|------|--------|
| >200 live subdomains | Phase 1-2 | Reduce to top 50 by priority matrix |
| >20 unique services | Phase 3 | Focus enumeration on top 10 |
| >15 exploitable vectors | Phase 5 | Prioritize top 5 for Phase 6 |
| Multiple environments all accessible | Phase 6 | Focus on prod only, note others |

**Communicate to client:** "The scope contains {X} assets. With the current time budget of {Y} days, we can achieve {depth} coverage on {Z} priority targets, or {breadth} coverage across all targets. Recommend: {your suggestion}."

## Integration with state.yaml

```yaml
# Updated state.yaml structure
time_budget:
  total_hours: 40
  started: "2024-01-15T09:00:00+07:00"
  deadline: "2024-01-19T17:00:00+07:00"
  phase_budgets:
    phase_1_2: 6.0
    phase_3: 6.0
    phase_4: 2.0
    phase_5: 8.0
    phase_6: 10.0
    phase_7: 4.0
    phase_8: 4.0
  phase_spent:
    phase_1_2: 5.5
    phase_3: 6.8  # Over budget
    phase_4: 1.5
    phase_5: 0.0  # Current phase
    phase_6: 0.0
    phase_7: 0.0
    phase_8: 0.0
  borrowing:
    - from: phase_4
      to: phase_3
      amount: 0.5
      reason: "JS analysis yielding API keys — high value"
  alerts_triggered:
    - phase: 3
      level: "over_budget"
      time: "2024-01-16T14:30:00+07:00"
      decision: "Borrowed 0.5h from Phase 4. Skipped CMS enum (no CMS detected)."
  scope_adjustments:
    - time: "2024-01-15T11:00:00+07:00"
      adjustment: "Reduced subdomain scope from 270 to top 50 by priority"
      reason: "Time budget insufficient for full coverage"
```

## Pitfalls

- **Don't track time to the minute.** Round to 15-minute increments. The overhead of precise tracking defeats the purpose.
- **Borrowing is a slippery slope.** One borrow is fine. Three borrows means your initial estimate was wrong — communicate to client.
- **Phase 8 always takes longer than expected.** Never borrow more than 50% from reporting. A pentest without a good report is wasted effort.
- **Time pressure causes mistakes.** When over-budget, the temptation is to rush. Rushed exploitation = missed findings AND potential damage. Better to test fewer vectors thoroughly than many vectors sloppily.
- **Document what you DIDN'T test.** This is as valuable as what you did test. It sets expectations and justifies follow-up engagements.
