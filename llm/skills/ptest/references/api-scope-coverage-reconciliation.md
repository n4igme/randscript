# API Scope Coverage Reconciliation

Cross-reference multiple API inventory documents to validate pentest coverage. Common in regulated environments (OJK audit, ISO 27001) where governance docs and vendor execution trackers must align.

## When to Use

- Pre-engagement: verify vendor scope completeness against governance/regulator list
- Post-engagement: validate all in-scope APIs were actually tested
- Audit preparation: prove coverage to regulators (OJK, BI, etc.)
- Multiple vendor coordination: Horangi vs Bitdefender scope overlap analysis

## The Problem

API paths in different documents rarely match exactly due to:
1. **BFF prefixes** — vendor tests via gateway (`/account/accounts/auth-transaction-amount`) while governance doc lists service path (`/accounts/auth-transaction-amount`)
2. **Path param styles** — `{accountId}` vs `<account_id>` vs `:accountId` vs `*`
3. **HTTP method granularity** — vendor list has per-method entries, governance has path-only
4. **Service-level vs route-level** — one doc groups by service, other by full path

## Matching Strategy (Python)

```python
import re

def normalize_params(path):
    """Normalize all path parameter styles to a common placeholder."""
    path = re.sub(r'\{[^}]+\}', '{p}', path)   # {accountId} -> {p}
    path = re.sub(r'<[^>]+>', '{p}', path)      # <account_id> -> {p}
    path = re.sub(r':\w+', '{p}', path)         # :accountId -> {p}
    path = path.replace('/*', '/{p}')           # wildcard
    return path.strip().rstrip('/')

def build_suffix_index(paths):
    """Build suffix set to handle BFF prefix differences.
    
    E.g., /account/accounts/auth-transaction-amount generates:
      - /account/accounts/auth-transaction-amount (exact)
      - /accounts/auth-transaction-amount (suffix)
      - /auth-transaction-amount (suffix)
    """
    exact = set()
    suffixes = set()
    for p in paths:
        norm = normalize_params(p)
        exact.add(norm)
        segments = norm.split('/')
        for i in range(1, len(segments)):
            suffixes.add('/' + '/'.join(segments[i:]))
    return exact, suffixes

def match_path(ojk_path, bd_exact, bd_suffixes):
    """Three-tier matching: exact -> suffix -> endswith."""
    norm = normalize_params(ojk_path)
    # Tier 1: exact match
    if norm in bd_exact:
        return True
    # Tier 2: OJK path is a suffix of some BD path
    if norm in bd_suffixes:
        return True
    # Tier 3: tail match (last 2+ segments)
    for bd_p in bd_exact:
        if len(bd_p) > 10 and (bd_p.endswith(norm) or norm.endswith(bd_p)):
            return True
    return False
```

## Typical Document Shapes

### Governance/Regulator Doc (OJK Audit)
- Columns: api_group, api_path, category (Internal/External), AppSec Analysis, Remarks
- One row per path (no HTTP method)
- Contains exclusion reasons ("not exposed", "decommissioned", "pending verification")

### Vendor Execution Tracker (Bitdefender/Horangi)
- Columns: Service, Method, Full External path, Full Link, Status
- One row per method+path combination
- Contains real testing status with HTTP response codes
- Points to actual staging URLs

## Output

Update the governance doc's coverage column (Yes/No) based on whether each path exists in the vendor tracker. Report:
- Total match rate
- Breakdown by category (which API groups have gaps)
- Expected 0% categories (decommissioned, not exposed, different vendor scope)

## Bank Jago Specifics (2026)

- OJK file: 862 endpoints across 13 API groups
- Bitdefender scope: bff-mobile-v2, loan-platform, partner-gateway, ms-* services
- Horangi scope: tested via Postman collections (separate from Bitdefender)
- Jago Bisnis endpoints tested separately (not in Bitdefender mobile scope)
- SNAP APIs behind partner IP whitelist (separate scope)
- JAWA /company/* prefix = decommissioned, expect 0%
- Key domains: stg-mobile.jago.com, stg-api.jago.com, stagingcards.jago.com

## Pitfalls

- Don't assume 0% match = problem — some categories are intentionally out of vendor scope
- Suffix matching can over-match on short paths (e.g., `/accounts` matches many things) — filter by minimum path length
- Some vendors list the same endpoint multiple times (per HTTP method) — deduplicate before counting
- CSV parsing: some Remarks fields contain commas inside quotes — use proper CSV parser for production
