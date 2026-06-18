---
name: tyk-gateway-audit
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

## Purpose

Cross-reference API endpoint inventories (OJK audit lists, pentest scope sheets) against Tyk API gateway whitelist/blacklist configurations to determine actual exposure status.

## Key Concepts

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

## Workflow

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

## References

See `references/path-matching-script.md` for the reusable Python pattern.
