# Tyk API Gateway Config-as-Code Parsing

When you have access to Tyk API definition YAML files (common in internal pentests where source/config repos are in scope), extract the full API surface programmatically before testing.

## What to Extract

1. **Auth type per API**: `use_keyless`, `enable_jwt`, `use_standard_auth`
2. **Listen paths**: `proxy.listen_path` — the public-facing route
3. **Target URLs**: `proxy.target_url` — reveals internal service topology
4. **White list paths**: Only these paths are accessible (strict)
5. **Black list paths**: These are blocked, everything else passes (permissive)
6. **Environment overrides**: Dev/stg/prod may have different rules
7. **Tags**: `internal`/`external`/`partner` — may indicate network segmentation
8. **Rate limits**: Policy-level `rate` and `per` values
9. **JWT config**: `jwt_signing_method`, JWKS source URLs, `jwt_identity_base_field`
10. **URL rewrites**: `tyk://` internal forwarding rules

## Python Parser (run in api/ directory)

```python
import yaml, glob, csv, sys

files = sorted(glob.glob("*.yaml"))
writer = csv.writer(sys.stdout)
writer.writerow(["api_file","listen_path","auth_type","path","allowed_methods","ignore_case","env"])

for fname in files:
    try:
        with open(fname) as f:
            data = yaml.safe_load(f)
    except:
        continue
    if not isinstance(data, dict):
        continue

    lp = data.get('proxy', {}).get('listen_path', '?')
    if data.get('use_keyless'):
        auth = 'keyless'
    elif data.get('enable_jwt'):
        auth = 'JWT'
    elif data.get('use_standard_auth'):
        auth = 'auth_token'
    else:
        auth = 'unknown'

    # Change 'white_list' to 'black_list' for blacklist extraction
    def find_list(obj, list_type='white_list', env='all'):
        found = []
        if isinstance(obj, dict):
            if list_type in obj:
                wl = obj[list_type]
                if isinstance(wl, list):
                    for item in wl:
                        path = item.get('path', '?')
                        methods = list(item.get('method_actions', {}).keys())
                        mstr = "|".join(methods) if methods else "ALL"
                        ic = item.get('ignore_case', False)
                        found.append((path, mstr, str(ic).lower(), env))
            for k, v in obj.items():
                if k in ('dev','stg','pt','prod') and isinstance(v, dict):
                    found.extend(find_list(v, list_type, k))
                else:
                    found.extend(find_list(v, list_type, env))
        elif isinstance(obj, list):
            for item in obj:
                found.extend(find_list(item, list_type, env))
        return found

    entries = find_list(data, 'white_list')  # or 'black_list'
    for path, methods, ic, env in entries:
        writer.writerow([fname, lp, auth, path, methods, ic, env])
```

## Security Analysis Priorities

### Black list APIs (higher bypass potential):
- `ignore_case: false` everywhere → test `/Private/*` vs `/private/*`
- Wildcard patterns without regex anchoring → test URL encoding (`%70rivate`)
- Missing leading slash (e.g., `payment-instructions/mobile-app-direct-execution`) → path confusion
- Regex anchors (`$`) only on some paths → test without anchor on others
- Environment flips (white→black in prod) → prod may be MORE permissive for unlisted paths

### Key patterns to flag:
- **Keyless + financial ops**: partner-gateway, SWIFT, Visa — no gateway auth
- **Identity services keyless**: Hydra/Kratos/Keto public endpoints
- **Env-specific blocks**: paths blocked only in prod → exposed in non-prod (which may have real data)
- **Black list on root listen_path `/`**: only a few paths blocked on a catch-all route
- **SSL skip**: `ssl_insecure_skip_verify: true` between gateway and backends
- **Unlimited rate limiting**: `rate: -1, per: -1` on policies

### Bypass testing vectors for black_list:
1. Case variation: `/Private/` vs `/private/`
2. URL encoding: `/%70rivate/` for `/private/`
3. Double slash: `//private/`
4. Trailing dot/slash: `/private./`, `/private//`
5. Unicode normalization: fullwidth characters
6. Path parameter injection: `/private;param/`
7. Null byte: `/private%00/`

## Output Files

Generate two CSVs in `assessment/` directory:
- `blacklist-endpoints.csv` — all blocked paths (everything else is accessible)
- `whitelist-endpoints.csv` — all allowed paths (everything else is blocked)

These feed directly into Phase 2 testing scope.

## Audit Cross-Referencing (OJK / Regulatory Compliance)

When an external audit spreadsheet (e.g., OJK annual pentest scope) needs exposure status populated, cross-reference against the extracted CSVs programmatically.

**Pattern:** Compare audit spreadsheet column (api_path) against whitelist/blacklist column D (whitelisted_path / blocked_path), then set an exposure flag.

**Key implementation details:**
1. Clean whitelist paths: strip regex anchors (`$`, `^`), escaped slashes (`\/`), trailing wildcards (`/*`)
2. Skip blacklist placeholder entries (`/black-list-url`)
3. Normalize path parameters for matching: `re.sub(r'\{[^}]+\}', '{id}', path)` — handles `{customerId}` vs `{id}` mismatches
4. Run order matters: whitelist pass FIRST (set "No" = not exposed via blacklist), then blacklist pass SECOND (set "Yes" = exposed via blacklist). Blacklist overwrites whitelist because endpoints can appear on both (whitelisted for access but also on the block list)
5. Endpoints appearing on BOTH lists means: they're routed through the blacklist mechanism (exposed via blacklist), so final answer is "Yes"

**Python recipe (execute_code):**
```python
import csv, re

def clean_path(path):
    clean = path.strip().rstrip('$').lstrip('^')
    clean = clean.replace('\\/', '/').replace('\\?', '?')
    if clean.endswith('/*'):
        clean = clean[:-2]
    return clean

def match_paths(source_path, target_paths):
    """Check if source_path matches any path in target_paths set."""
    if source_path in target_paths:
        return True
    src_norm = re.sub(r'\{[^}]+\}', '{id}', source_path)
    for tp in target_paths:
        tp_norm = re.sub(r'\{[^}]+\}', '{id}', tp)
        if src_norm == tp_norm:
            return True
    return False

# Load paths from assessment CSV (column D = index 3)
paths = set()
with open('assessment/whitelist-endpoints.csv', 'r') as f:
    reader = csv.reader(f)
    next(reader)
    for row in reader:
        if len(row) > 3:
            paths.add(clean_path(row[3]))

# Read audit file, match column B, set column F
rows = []
with open('audit.csv', 'r') as f:
    rows = list(csv.reader(f))

for i in range(1, len(rows)):
    if match_paths(rows[i][1].strip(), paths):
        rows[i][5] = 'No'  # or 'Yes' for blacklist pass

with open('audit.csv', 'w', newline='') as f:
    csv.writer(f).writerows(rows)
```

**Typical results (Bank Jago 2026):**
- ~650 whitelist paths, ~50 blacklist paths (excl placeholders)
- ~230 OJK audit endpoints match whitelist
- ~13 OJK audit endpoints match blacklist
- 3-5 endpoints appear on BOTH (these get "Yes" = exposed via blacklist mechanism)
