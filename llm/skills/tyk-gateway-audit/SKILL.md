---
name: tyk-gateway-audit
version: 1.1.0
description: "Tyk API gateway policy analysis: whitelist/blacklist extraction, OJK audit cross-referencing, prefix mismatch detection for exposure verification."
tags: [tyk, api-gateway, audit, ojk, whitelist, blacklist, exposure-analysis]
triggers:
  - user asks to compare API paths against Tyk gateway configs
  - user asks about whitelist/blacklist status of an endpoint
  - user needs to cross-reference audit spreadsheets with gateway definitions
  - user asks to determine if an API is exposed or blocked
  - OJK or regulatory audit endpoint verification
---

# Tyk Gateway Audit — Exposure Verification

## When to Use / When NOT to Use

**Use when:**
- Auditing API gateway exposure against whitelist/blacklist
- Cross-referencing OJK audit sheets with Tyk configs
- Verifying prefix mismatch due to listen_path stripping

**Avoid when:**
- No Tyk gateway config or OJK audit sheets
- Target uses different API gateway (Kong, Apigee, AWS API Gateway)
- Scope is endpoint behavior, not gateway policy

## Purpose

Cross-reference API endpoint inventories (OJK audit lists, pentest scope sheets) against Tyk API gateway whitelist/blacklist configurations to determine actual exposure status.

## Key Concepts

**state.yaml schema:**
```yaml
engagement:
  name: string
  started: ISO8601
  target: string
current_phase: int
gateways:
  1_load: OPEN|PASSED|LOCKED
  2_match: ...
  3_verify: ...
  4_report: ...
findings_count: int
time_tracking:
  phase_1_start: ISO8601
notes: string
```

- **Whitelist** = endpoint IS reachable through the gateway (exposed). Column F = "No" (not exposed via blacklist).
- **Blacklist** = endpoint IS blocked by the gateway. Column F = "Yes" (exposed via blacklist mechanism, meaning it needed explicit blocking).
- **listen_path** = the prefix Tyk strips before matching whitelist/blacklist paths. This causes prefix mismatches between audit sheets and configs.

## Repository Structure (tyk-api-policy)

```
api/           — One YAML per API definition (e.g., bff-jawara.yaml, bff-mobile-v2.yaml)
policy/        — Access control policies
assessment/    — Extracted CSVs:
  whitelist-endpoints.csv  — columns: api_file, listen_path, auth_type, whitelisted_path, allowed_methods, ignore_case, env
  blacklist-endpoints.csv  — columns: api_file, listen_path, auth_type, blocked_path, blocked_methods, ignore_case, env, notes
```

## Concurrent Execution Safety

See `../references/concurrent-execution-safety.md` for state locking, parallel scanning, and subagent handoff rules.

## Workflow

### Phase Entry Protocol (ALL phases)

When entering ANY phase:
1. **Load reference file** — `skill_view(name='tyk-gateway-audit', file_path='references/<phase-file>')`
2. **Record timestamp** — write `phase_N_start` in state.yaml
3. **Check prerequisites** — verify prior phase gate is PASSED
4. **Review findings** — check `findings.jsonl` for chain opportunities before starting

## Retry / Timeout Patterns

| Operation | Timeout | Retry | Backoff |
|-----------|---------|-------|---------|
| CSV parse | 10s | 2x | 5s |
| Python script | 60s | 2x | 10s |
| Web fetch | 30s | 2x | 5s |

**Rules:**
- On parse error: check file encoding (UTF-8 vs Latin-1), retry once
- On empty CSV: verify header matches expected schema, document deviation
- On timeout: save partial matches, document as incomplete audit


## Findings (findings.jsonl)

**Format:** JSONL, one JSON object per line.

**Required fields:** `finding_id`, `title`, `severity`, `category`, `target`, `confidence` (0.0-1.0), `timestamp`

**Example:**
```json
{"finding_id": "RETOOLS-001", "title": "Hardcoded API key", "severity": "High", "category": "secrets", "target": "app.apk", "confidence": 0.95, "timestamp": "2026-06-22T10:00:00Z"}
```

## Error Handling

| Failure Mode | Action |
|--------------|--------|
| CSV missing | Check path; if truly missing, document as blocker |
| Path mismatch | Log unmatched paths to `prefix-mismatch-endpoints.csv` |
| Stale values | Clear column F for unmatched paths (see Phase 5 Cleanup) |
| Encoding error | Re-read with `encoding='latin-1'` or skip BOM |

**Rules:**
- Never silently skip a path — log it as unmatched, N/A, or blocker
- After all matching passes, clear stale values from prior runs

### Step 1: Load both assessment CSVs
Read `whitelist-endpoints.csv` (col D = path) and `blacklist-endpoints.csv` (col D = path).

### Step 2: Clean paths for comparison
- Strip regex anchors: `$` suffix, `^` prefix
- Strip escape chars: `\\/` → `/`, `\\?` → `?`
- Strip trailing `/*` wildcards
- Skip placeholder entries (`/black-list-url`)
- Normalize path params: `{anything}` → `{id}` for matching

### Step 3: Match OJK paths against configs
For each audit path (column B):
1. Direct match against whitelist/blacklist paths
2. Parameter-normalized match (`{customerId}` == `{id}`)
3. Suffix match (OJK path ends with config path) — handles prefix stripping

### Step 4: Set exposure status
- Whitelist match → col F = "No", col G = source YAML filename
- Blacklist match → col F = "Yes", col G = source YAML filename
- Blacklist takes precedence when path appears in both

### Step 5: Detect prefix mismatches for unmatched paths
Compare trailing segments (≥2 matching) to find paths that differ only by prefix due to `listen_path` stripping. Mark col G with `source.yaml (prefix-mismatch: /tyk/config/path)` so reviewer can distinguish direct vs inferred matches.

### Step 6: Clean stale values
After all matching, clear column F for any row where column G is empty. This prevents false positives from prior runs or partial executions.

### Recommended: Single-pass script
Run all three matching approaches (direct, param-normalized, prefix-mismatch) in ONE script execution rather than separate whitelist-then-blacklist passes. This avoids stale state issues entirely.

## Pitfalls

1. **Stale column values from previous runs**: When running multiple passes (whitelist-only, then blacklist, then prefix-mismatch), earlier passes can set column F values that later passes don't clear. After all matching is complete, ALWAYS clear column F for any row where column G (source) is empty — those are false positives from a prior run. The user caught `/card/accounts/multiple-cifs` showing "No" with no source backing it.

2. **listen_path prefix stripping**: The OJK sheet uses full logical paths (e.g., `/jaguard-retail/retail/v1/customers/auth/login`), but the Tyk config stores paths relative to listen_path (e.g., `/retail/v1/customers/auth/login` under listen_path `/jaguard-retail`). This is the #1 source of "no match" results.

2. **Missing leading slash**: Some bff-mobile-v2 whitelist entries omit the leading `/` (e.g., `loan-offer/offers` instead of `/loan-offer/offers`, `transaction/status` instead of `/transaction/status`). Handle both forms.

3. **Dual presence**: Some endpoints appear on BOTH whitelist and blacklist (whitelisted in one gateway, blocked in another or same). Blacklist takes precedence for the "exposed via blacklist" column.

4. **Version differences**: OJK may list `/kyc/v3/...` while Tyk config has `/kyc/v2/...` — same endpoint, different version prefix. These show up in suffix matching but need manual review.

5. **Wildcard patterns**: Blacklist entries like `/private*` block entire subtrees. Don't try to match individual paths against these — note them as glob blocks.

## Common Prefix Mapping

| OJK Prefix | Tyk listen_path | Config-relative path starts with |
|---|---|---|
| `/api/...` | `/bff-jawara` | `/...` (bare) |
| `/jaguard-retail/retail/...` | `/jaguard-retail` | `/retail/...` |
| `/loan-platform/loan-processing/...` | `/loan-platform/` | `/loan-processing/...` |
| `/loan-platform/loan-transaction/...` | `/loan-platform/` | `/loan-transaction/...` |
| `/payment-and-cms-mediator/...` | `/payment-and-cms-mediator/` | `transfers/...` (no slash) |
| `/sprint/...` | `/sprint/` | `/v1/...` |
| `/transfer/admin/...` | `/transfer/` | `/admin/...` |

## Output Artifacts

- Updated OJK worksheet with col F (Yes/No) and col G (source file)
- `prefix-mismatch-endpoints.csv` — unmatched paths with closest config match, prefix diff, source file

## Quick Wins

| Signal | Action | Expected Yield |
|--------|--------|---------------|
| Wildcard listen_path (`/`) | Check if ALL paths are exposed | High — broad exposure |
| Blacklist with no entries | All paths pass through | High — missing controls |
| Whitelist with `*` pattern | Effectively no restriction | Medium |
| Path prefix mismatch | Endpoints may bypass policy | Medium — false sense of security |

### Evidence Standards

All findings must follow `../references/evidence-standards.md` for required/optional evidence capture and redaction rules.

### Severity Mapping

Cross-skill severity normalization: `../references/severity-mapping.md`

### Postmortem

After engagement closes, run shared retrospective:
```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/scripts"))
from postmortem import run_postmortem
run_postmortem(workdir, "tyk-gateway-audit")
```

### Gate Enforcement (MANDATORY before `next`)

```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/tyk-gateway-audit/scripts"))
from gate_check import check_gate, print_gate_status

result = check_gate(".", phase=None)
print_gate_status(result)
```

## References

See `references/path-matching-script.md` for the reusable Python pattern.
