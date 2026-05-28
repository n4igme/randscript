# Google Pitchfork Framework Testing

## Overview
Google's Pitchfork (boq-pitchfork) is the standard SPA framework for Google web apps. Products using it: Jules (Swebot), Gemini (BardChatUi), AI Studio (MakerSuite), Illuminate (Roma), NotebookLM (LabsTailwindUi), IDX (MonospaceNgUI).

## Architecture
- All routes return same SPA shell (~100-110KB) — client-side routing
- Backend API: `/_/<ProductName>/data/batchexecute` (POST only)
- CSP report: `/_/<ProductName>/cspreport`
- Config embedded in `window.WIZ_global_data` object in page source
- Server: ESF (Google Edge Server Frontend)

## Key Config Fields in WIZ_global_data
| Field | Purpose |
|-------|---------|
| `SNlM0e` | XSRF/AT token (required for API calls, short-lived) |
| `FdrFJe` | Request ID (changes per page load) |
| `Im6cmf` | Backend API path (e.g., `/_/Swebot`) |
| `MUE6Ne` | Internal server name |
| `cfb2h` | Build version with date |
| `b5W2zf` | Default config name |
| `S06Grb` | User's Google ID (authenticated only) |
| `oPEP7c` | User's email (authenticated only) |
| `nflpzd` | Feed polling Basic Auth token — INTENTIONAL, not a vuln |
| `mNXx4` | Feed endpoint path |
| `hsFLT` | Rate limit config |
| `iCzhFc` | GitHub connected status (Jules-specific) |
| `TSDtV` | Feature flags array (100+ experiment IDs) |
| `WZsZ1e` | SAPISID value (for SAPISIDHASH auth) |

## IMPORTANT: `nflpzd` is NOT a vulnerability
The `nflpzd` field contains a Basic Auth token (e.g., `Basic anVsZXM6b2lxUWlZdnlhX1dxbnNX` → `jules:oiqQiYvya_WqnsW`). This is **intentionally embedded** for client-side notification feed polling. Present in both authenticated and unauthenticated pages. Google uses these lightweight tokens across all Pitchfork apps for their internal pubsub/notification feeds. Do NOT report as a finding.

## batchexecute RPC Format

### Request
```
POST /_/<ProductName>/data/batchexecute
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
X-Same-Domain: 1
Origin: https://<host>
Cookie: <google auth cookies>

f.req=[[[\"<RPC_ID>\",\"<JSON_PARAMS>\",null,\"generic\"]]]&at=<AT_TOKEN>
```

### URL-encoded example
```
f.req=%5B%5B%5B%22RPCName%22%2C%22%5B%5D%22%2Cnull%2C%22generic%22%5D%5D%5D&at=<AT_TOKEN>
```

### Response format
```
)]}'

[["wrb.fr","RPCName","<JSON_RESPONSE>",null,null,null,"generic"],["di",N],["af.httprm",N,"requestId",N]]
```

### Error codes in response
- `[3]` = wrong parameter format/count
- `[5]` = wrong parameter count (needs more params)
- `[7]` = requires authentication or missing permission
- `[9]` = invalid parameter value
- `[16]` = wrong parameter format (different from [3])
- `400` with `"xsrf"` = missing or invalid AT token

## RPC Discovery Methodology
1. Extract AT token: `grep -o 'SNlM0e":"[^"]*' page.html | cut -d'"' -f3`
2. Find RPC ID candidates from JS bundle: `grep -oE '"[A-Za-z][a-zA-Z0-9]{4,6}"' app.js | sort -u`
3. Fuzz each candidate with empty params `"[]"`:
```bash
curl -s "https://host/_/Product/data/batchexecute" \
  -H "Cookie: $COOKIES" \
  -H "Content-Type: application/x-www-form-urlencoded;charset=UTF-8" \
  -H "X-Same-Domain: 1" \
  --data 'f.req=%5B%5B%5B%22RPCID%22%2C%22%5B%5D%22%2Cnull%2C%22generic%22%5D%5D%5D&at=TOKEN'
```
4. If response contains `"wrb.fr"` → valid RPC
5. If `[3]`/`[5]` → valid but needs correct params
6. If `400` → invalid RPC name

## CSRF Testing
- AT token is the only CSRF protection (embedded in page HTML)
- `X-Same-Domain` header is NOT validated
- `Origin` header is NOT validated  
- Only `application/x-www-form-urlencoded` POST works
- GET requests rejected
- `text/plain` and `multipart/form-data` rejected
- No CORS headers returned
- Conclusion: CSRF protection relies solely on AT token (which requires same-origin read to extract) — this is secure by design

## IDOR Testing
- Session/resource IDs are large numeric values (uint64)
- RPCs that accept resource IDs may be user-scoped (ignore the ID, return authenticated user's data)
- Must verify with two accounts to confirm true IDOR
- Empty response `"[]"` for non-owned resources could mean either "access denied" or "resource deleted"

## Jules (Swebot) — Discovered RPCs

| RPC ID | Function | Params |
|--------|----------|--------|
| `IjaU6c` | List sessions/tasks | `[null,null,1]` |
| `gV7IZe` | Get quota | `[]` → `[[15000,remaining,[timestamp]],100]` |
| `DrvqKc` | Generate correlation ID | `[]` → `["id",[timestamp]]` |
| `y0MC8` | Feature flag check | `[]` → `[false]` |
| `G6wZ6` | Get GitHub org/user | `["sessionId"]` → `[[["ghId","username"]]]` |
| `INUsod` | List workspaces/repos | `["sessionId"]` → workspace + repo details |
| `nQkxVe` | Get org details | `[]` → org/repo data |
| `n0WcTc` | Session data (unknown) | `["sessionId"]` or `[null,null,1]` |
| `GCDTBd` | Session data (unknown) | needs correct params |
| `ZVF6Ae` | Session data (unknown) | needs correct params |

Note: `G6wZ6` and `INUsod` are **user-scoped** — they return the authenticated user's data regardless of which session ID is passed. This is secure (no IDOR).

## Google Maps — Tested Endpoints

| Endpoint | Result |
|----------|--------|
| `/maps?q=XSS` | URL-encoded in output, not exploitable |
| `/maps/embed?pb=` | 400 on injection |
| `/maps/api/js?callback=X` | JSONP reflected, but strict validation (alphanum+dots only), nosniff header |
| `/maps/vt?pb=` | Tile proxy ignores injected URLs |
| `/maps/preview/place?q=` | Returns JSON data, no injection |
| `/maps/reserve/` | Public partner page, bookings/settings need auth |
| `/maps/reserve/partners` | 200 without auth (~400KB), no sensitive data |
| `/maps/rpc/search` | 405 (GET only?) |

## Pitfalls
- AT tokens expire quickly — always fetch fresh before each test batch
- macOS grep doesn't support `-P` (PCRE) — use `-o` with basic patterns
- `shuf` not available on macOS — use `sort -R` or `gshuf`
- Google cookies alone don't work for Colab (TornadoServer) — different auth mechanism
- The SPA returns 200 for ALL paths — can't use HTTP status for path discovery
- Feature flags in `TSDtV` contain internal URLs, model names, codenames — useful for recon but mostly informational
