# Target Selection Scoring

Quick rubric for deciding whether to invest time in a bug bounty program. Score ≥ 7 → engage. Score < 4 → skip.

## Scoring Matrix

| Factor | +3 | +2 | +1 | 0 | -1 | -2 |
|--------|----|----|----|----|----|----|
| **Critical payout** | >$20k | >$10k | >$3k | >$500 | <$500 | Points only |
| **Program age** | <3 months | <6 months | <1 year | 1-3 years | >3 years | — |
| **Scope size** | >100 assets | >50 assets | >20 assets | 5-20 | <5 | 1 asset |
| **Tech stack match** | Exact match to expertise | Strong overlap | Partial overlap | New but learnable | Completely foreign | — |
| **Last paid bounty** | <7 days | <30 days | <90 days | <1 year | >1 year (dead) | — |
| **Competition** | — | <10 researchers | 10-50 | 50-100 | 100-500 | >500 |
| **Response time** | — | <24h avg | <3 days | <1 week | >2 weeks (slow) | Unresponsive |

## Quick Decision

```
Score ≥ 10  →  Priority target. Deep engagement (8-16 hours).
Score 7-9   →  Good target. Standard engagement (4-8 hours).
Score 4-6   →  Marginal. Quick-scan only (1-2 hours max).
Score < 4   →  Skip. Move to next program.
```

## Red Flags (Auto-Skip)

- Program has history of marking valid bugs as "informative"
- Requires NDA just to view scope
- "We'll decide severity" with no published severity table
- Only accepts findings through their custom portal (not standard platforms)
- Scope is a single production app with no staging/sandbox mentioned

## Green Flags (Bonus Points)

- Program publishes response statistics (transparency = good faith)
- Multiple asset types (web, mobile, API, cloud) = more attack surface
- Recent scope expansion = fresh unexplored surface
- "Safe harbor" language explicitly included
- Managed by reputable platform (HackerOne, Bugcrowd, Intigriti, YesWeHack)

## ROI Tracking

After each engagement, record:
```
target: {name}
hours: {total}
payout: ${amount}
findings: {count submitted}
accepted: {count accepted}
roi: ${payout/hours}/hr
```

Over time, this reveals:
- Which tech stacks yield best $/hour for you
- Which platforms pay fastest
- Which scope types match your skillset
- Optimal time investment before diminishing returns (usually 6-8 hours)

## Integration with w3hunt

w3hunt's `targets` command already does platform-specific triage. This scoring rubric complements it for programs found outside of w3hunt's scope (Intigriti, YesWeHack, self-hosted programs, VDPs that convert to paid).
