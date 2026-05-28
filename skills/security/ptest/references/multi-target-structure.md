# Multi-Target Engagement Structure

When a bug bounty program has multiple in-scope assets, organize per-target:

```
./ptest-output/                    # Primary target (first tested)
  state.yaml
  scope.md                         # FULL program scope (all assets)
  findings-log.md
./target2.domain/
  ptest-output/
    state.yaml                     # Independent state per target
    scope.md                       # Target-specific scope subset
    findings-log.md
```

## Rules

1. The primary `scope.md` documents ALL program assets and their status (tested/dead/RBAC-blocked/pending)
2. Each target gets its own `state.yaml` with independent phase tracking
3. Finding IDs are unique per-target (F-1 in target A ≠ F-1 in target B)
4. When submitting, reference findings by `{target}:{finding-id}` (e.g., `findaya.co.id:F-4`)
5. Cross-target findings go in the target where they have highest impact
6. Mark targets as completed: `tested (N findings)`, `dead (decommissioned)`, `RBAC-blocked`, `hardened (0 findings)`

## Fast-Exit Heuristics

- Identical Istio RBAC 403 on all paths → "RBAC-blocked", move on (5 min max)
- All subdomains don't resolve → "dead/decommissioned", move on (2 min max)
- Well-known hardened service, all endpoints return proper 401 → "hardened", move on (10 min max)
- Prioritize targets sharing infrastructure with already-vulnerable targets
