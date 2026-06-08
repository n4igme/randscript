# SPA False Positive Detection in Web Enumeration

## Problem
Modern SPAs (Single Page Applications) using client-side routing return HTTP 200 with the same HTML shell for ALL paths. This causes massive false positives when:
- Checking for .git/HEAD exposure
- Scanning for actuator/admin endpoints
- Directory brute-forcing
- Checking for config files

## ByteDance/TikTok "Goofy Deploy" SPA Pattern (SoundOn, June 2026)

ByteDance products (SoundOn, TikTok Music) serve **two separate SPA apps from the same domain**:
- **client-main** (authenticated dashboard) — catches all non-API, non-public routes, returns React shell HTML
- **client_seo** (public SSR) — serves `/bio/*` routes with full SSR + `__MODERN_ROUTER_DATA__`

**Detection signals:**
- Response contains `goofy-deploy-app-{id}` in script tags
- Inline `<script id="gfdatav1">` JSON with `env`, `idc`, `region`, `ver`, `canary` fields
- `x-ggw-config-version` response header (on SSR routes)
- Title is generic "SoundOn" (not page-specific) → SPA shell, not real content

**Key implication:** ALL path fuzzing returns 200 with identical body size for non-existent paths. Only `/api/` routes return distinct responses (JSON "Unauthorized", "ROUTE_NOT_FOUND", or actual data).

**Intel extraction from SPA shell:**
- `gfdatav1` JSON → deployment version, IDC, region, canary status
- `pumbaa-rule` base64 → full privacy/network interception ruleset
- Script `project-id` attribute → Argus SecSDK project identifier
- `data-business` attribute on PPF loader → internal app identifier

---

## Detection Method

**Always establish a baseline first:**
```bash
# Get response size for a known-nonexistent path
baseline=$(curl -sk --max-time 3 "https://target.com/nonexistent-xyz-baseline-12345" 2>/dev/null | wc -c)
echo "Baseline: $baseline bytes"
```

**Then compare:**
```bash
# Only flag if response size DIFFERS from baseline
size=$(curl -sk --max-time 3 "https://target.com/.git/HEAD" 2>/dev/null | wc -c)
if [ "$size" != "$baseline" ] && [ "$size" -gt 5 ]; then
    echo "[DIFF] .git/HEAD -> $size bytes (vs baseline $baseline)"
fi
```

**For .git specifically, check content:**
```bash
resp=$(curl -sk --max-time 3 "https://target.com/.git/HEAD" 2>/dev/null)
if echo "$resp" | grep -q "ref: refs/"; then
    echo "[VULN] .git exposed"
fi
```

## Common SPA Frameworks and Their Baseline Sizes
- Goofy Deploy (ByteDance/TikTok): 30-90KB HTML shell
- Next.js: Variable, check for `__NEXT_DATA__` in all responses
- Create React App: ~2-5KB shell with `<div id="root"></div>`
- Vue/Nuxt: Similar pattern

## Real vs Fake Endpoint Indicators

| Signal | Real Endpoint | SPA Catch-All |
|--------|--------------|---------------|
| Response size | Different from baseline | Same as baseline |
| Content-Type | application/json | text/html |
| Response body | JSON/text error | Full HTML page |
| Status code | 401/403/500 | 200 |

## Key Insight: Different Error Codes = Real Backend
When testing APIs behind SPAs:
- `{"code":98001002,"message":"You must log in"}` → Real auth gate
- `{"code":60000,"message":"content length not empty"}` → Real validation
- `{"code":10000}` → Real but generic error
- Full HTML page → SPA catch-all (false positive)

## Technique: POST vs GET Differentiation
SPAs only catch-all on GET. POST to the same path often reveals real backend:
```bash
# GET returns SPA shell (false positive)
curl -sk "https://target.com/api/v1/endpoint" | wc -c  # Same as baseline

# POST reveals real backend
curl -sk -X POST "https://target.com/api/v1/endpoint" \
  -H "Content-Type: application/json" -d '{}'
# Returns: {"code":98001002,"message":"You must log in"}
```
