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

## Coverage Tracking (Large Scope Engagements)

For engagements with 50+ subdomains/hosts, maintain a coverage matrix in `scope.md` or a dedicated `coverage.md`. Without this, it becomes impossible to reconstruct what was tested at what depth across sessions.

### Coverage Depth Levels

| Level | Label | Meaning |
|-------|-------|---------|
| 0 | `dns-only` | DNS record exists, no HTTP probe |
| 1 | `status-checked` | One HTTP request for status code |
| 2 | `quick-probe` | 2-5 manual requests (login page, common paths) |
| 3 | `path-discovery` | Gobuster/feroxbuster/ffuf run |
| 4 | `vuln-tested` | Technology-specific tests, parameter fuzzing, auth testing |
| 5 | `exploited` | Active exploitation attempted |

### Coverage Matrix Format

```markdown
## Coverage Matrix (updated: YYYY-MM-DD)

| Host | Level | Phase | Protection | Notes |
|------|-------|-------|------------|-------|
| api.target.com | 3 | P2-3 | CF API Shield | MISSING_API_TOKEN, no creds |
| admin.target.com | 4 | P3+ | None (direct) | SQLi tested, clean |
| bibit.target.com | 2 | P2 | CF IP Allowlist | All bypass failed |
| sftp.target.com | 0 | P1 | None (direct) | UNTESTED — priority |
```

### Rules

- Update coverage matrix at end of each session (before context loss)
- Mark untested high-value targets explicitly so next session knows where to start
- Group hosts by protection type (CF-proxied, IAP, Direct, Dead) for efficient batch testing
- When resuming, read coverage matrix FIRST to avoid re-testing or missing gaps

### Pitfall (Bank Jago lesson)

Without coverage tracking, a 221-subdomain engagement resulted in only 13% active testing coverage with no record of what was done where. Reconstructing this required parsing zone files and relying on compacted session memory — unreliable. Always maintain the matrix.

## Fast-Exit Heuristics

- Identical Istio RBAC 403 on all paths → "RBAC-blocked", move on (5 min max)
- All subdomains don't resolve → "dead/decommissioned", move on (2 min max)
- Well-known hardened service, all endpoints return proper 401 → "hardened", move on (10 min max)
- Prioritize targets sharing infrastructure with already-vulnerable targets
