# Bounty Target Selection Heuristic

Decision framework for "which program is worth my time this week?"

---

## Scoring Matrix

Rate each program 1-5 on these factors:

| Factor | Weight | What to assess |
|--------|--------|----------------|
| Payout/Effort ratio | 3x | Min payout for Medium vs typical hours to find one |
| Scope freshness | 2x | New assets added recently? Unaudited code? |
| Triage speed | 2x | Days to first response? Backlog? |
| Rejection rate | 2x | Your personal rejection history on this program |
| Stack familiarity | 1x | Do you know the tech? (Java/Go/Node/Mobile) |
| Competition level | 1x | Public vs private? Recent payouts = crowded? |

**Score = sum(factor × weight). Highest score wins the week.**

---

## Quick Decision Tree

```
1. Any NEW scope added to existing program?
   → YES → Test that first (lowest competition, fresh surface)
   → NO → continue

2. Any private invite pending?
   → YES → Prioritize (limited hunters = less competition)
   → NO → continue

3. Which program has best payout-per-hour from YOUR history?
   → Pick that one unless rejection rate > 50%

4. Tie-breaker: pick the one where you have unused recon data
   (endpoints mapped but not fully tested)
```

---

## Red Flags (deprioritize)

- Triage takes >14 days consistently
- >50% of your reports rejected on this program
- Very narrow scope with many active hunters
- Low payouts relative to complexity (e.g., $50 for Critical)
- Program paused/unresponsive

## Green Flags (prioritize)

- New scope added in last 30 days
- Private invite (limited hunter pool)
- Fast triage (<3 days to first response)
- High min payout (Critical >$5K)
- Stack you've found bugs in before
- Program accepts chained findings

---

## Your Active Programs (update as needed)

| Program | Platform | Stack | Min Critical | Notes |
|---------|----------|-------|-------------|-------|
| GoPay | YWH | Go/Java | TBD | Rejection history — needs chain narrative |
| Bank Jago | Internal | Java/Mobile | N/A | Full access, attestation forge proven |
| BFI Finance | Internal | TBD | N/A | Phase 4 done, 7 findings |
| BitBank | IssueHunt | Angular/Node | TBD | Japanese, CloudFront+nginx |
| ENS | Immunefi | Solidity | $25K | contracts-v2 role persistence confirmed |

---

## Weekly Routine

Monday: 15 min to score programs → pick focus for the week.
Don't context-switch mid-week unless a Critical drops in your lap.
