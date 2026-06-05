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

### Pitfall (BFI Finance lesson)

186 live hosts but nuclei only ran on 15 (8% coverage). Discovered only when manually checking `nuclei-targets.txt` vs `live-subs.txt`. The phase checklist said "DONE" because the tool was executed — but not against all hosts. **Tool execution ≠ full coverage.**

### Mandatory Coverage Verification (Phase 5/6 Exit Gate)

Before signing off Phase 5 or Phase 6, run this diff:

```bash
# Generate untested hosts list
comm -23 \
  <(cat live-subs.txt | awk -F'|' '{print $1}' | sort) \
  <(cat nuclei-targets.txt | sed 's|https\?://||' | sort) \
  > untested-hosts.txt

# If non-empty → phase is NOT complete
wc -l untested-hosts.txt
# Must be 0 before sign-off
```

**Exit criteria addition:**
- Phase 5: `diff(master_live_hosts, nuclei_targets) == 0`
- Phase 5: `diff(master_live_hosts, cors_tested_hosts) == 0`
- Phase 6: `diff(accessible_hosts, exploitation_tested_hosts) == 0`

If any diff is non-zero, batch-test the remaining hosts before requesting gateway sign-off. Use:

```bash
# Batch nuclei on missed hosts
nuclei -l untested-hosts.txt -severity critical,high,medium -o nuclei-remaining.txt -rate-limit 50

# Batch CORS on missed hosts
cat untested-hosts.txt | while read host; do
  cors=$(curl -sk --max-time 3 -H "Origin: https://evil.com" "https://$host/" -D- 2>/dev/null | grep -i "access-control-allow-origin")
  [ -n "$cors" ] && echo "$host | $cors"
done > cors-remaining.txt
```

## Fast-Exit Heuristics

- Identical Istio RBAC 403 on all paths → "RBAC-blocked", move on (5 min max)
- All subdomains don't resolve → "dead/decommissioned", move on (2 min max)
- Well-known hardened service, all endpoints return proper 401 → "hardened", move on (10 min max)
- Prioritize targets sharing infrastructure with already-vulnerable targets
