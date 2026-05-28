# Google SPA Reconnaissance Patterns

When targeting Google products (*.google.com), their SPAs leak significant internal data in the initial page load without authentication.

## WIZ_global_data Extraction

Google's frontend framework embeds configuration in `window.WIZ_global_data` on every product page. Extract with:

```bash
curl -sk "https://TARGET.google.com/" | grep -oP "WIZ_global_data = \K{.*?};" | python3 -m json.tool
```

**What it reveals:**
- Internal app/service name (e.g., `Swebot`, `BardChatUi`, `LabsTailwindUi`)
- Service identifier (e.g., `labs-language-aida-swebot-uiserver`)
- Auth endpoints (ServiceLogin continue URL, SignOut URL)
- API prefix patterns (e.g., `/_/Swebot`)
- Feature flags (numeric IDs with boolean/string values)
- Internal model names/codenames
- Available countries list
- Privacy notice dates
- Internal bug tracker URLs (b.corp.google.com)
- Internal code paths (google3/...)
- Demo/staging endpoints (*.appspot.com)

## CSP Header Intelligence

Google products use detailed CSP headers that reveal:

```bash
curl -sk -I "https://TARGET.google.com/" | grep -i "content-security-policy"
```

**Extract from CSP:**
- `report-uri /_/APPNAME/cspreport` → internal app identifier
- `form-action` → staging/sandbox endpoints (onegoogle-autopush, onegoogle-staging)
- `connect-src` → allowed API backends, CDN origins
- `frame-src` → embedded services, picker URLs

## Google App Identifiers (Known)

| Subdomain | App Name | CSP Report Path | Server | Notes |
|-----------|----------|----------------|--------|-------|
| gemini.google.com | BardChatUi | `/_/BardChatUi/cspreport` | ESF | Pitchfork |
| jules.google.com | Swebot | `/_/Swebot/cspreport` | ESF | Pitchfork, AI coding agent |
| notebooklm.google.com | LabsTailwindUi | `/_/LabsTailwindUi/cspreport` | ESF | Pitchfork |
| idx.google.com | MonospaceNgUI | `/_/MonospaceNgUI/cspreport` | ESF | Redirects to firebase.google.com/studio |
| geminidataanalytics.cloud.google.com | ConversationalAnalyticsUi | `/_/ConversationalAnalyticsUi/cspreport` | ESF | Very new, minimal footprint |
| illuminate.google.com | Roma | `/_/Roma/cspreport` | ESF | Pitchfork, build 20260318.07 |
| aistudio.google.com | MakerSuite | `/_/MakerSuite/cspreport` | ESF | Pitchfork, X-Frame-Options: DENY |
| colab.research.google.com | — | — | TornadoServer/6.5.5 | NOT Pitchfork, Python Tornado, Jupyter-style API |
| privacysandbox.google.com | — | devsite/v2 | Google Frontend | Static devsite |
| firebase.google.com | — | devsite/v2 | Google Frontend | Static devsite |

## Non-Pitchfork Targets (Higher Priority)

`colab.research.google.com` runs **TornadoServer/6.5.5** (Python) — not Google's standard ESF/Pitchfork infra. All Jupyter-style API endpoints exist but return 403 without proper auth:
- `/api/sessions`, `/api/kernels`, `/api/contents/`, `/api/kernelspecs`, `/api/config`, `/api/status`
- `/hub/api`, `/user`, `/socketio`, `/socket.io`, `/ws`
- `/tun/` returns 401 (tunnel to runtime, needs runtime-specific token)
- `/drive/` returns 307 → `/drive/`
- Standard Google cookies are NOT sufficient — needs Colab-specific session or OAuth token
- Contains multiple API keys in page source (referer-restricted, standard for browser use)

## Google Internal RPC Format (batchexecute)

Google SPAs use a proprietary RPC mechanism at `/_/APPNAME/data/batchexecute`. This requires auth cookies but the endpoint pattern is predictable:

```
POST /_/Swebot/data/batchexecute
Content-Type: application/x-www-form-urlencoded

f.req=[[["RPC_METHOD_NAME","[\"param1\",\"param2\"]",null,"generic"]]]
```

RPC method names can sometimes be found in the JS bundles (look for arrays of strings near `batchexecute` references).

## SPA Catch-All Detection

All Google SPAs serve the same HTML shell (~100KB) for every route. Verify before reporting "200 on /admin":

```bash
# These will ALL return 200 with same size — it's the SPA shell, not real endpoints
curl -sk -o /dev/null -w "%{size_download}" "https://jules.google.com/api"
curl -sk -o /dev/null -w "%{size_download}" "https://jules.google.com/admin"
curl -sk -o /dev/null -w "%{size_download}" "https://jules.google.com/nonexistent12345"
# All ~102KB = SPA catch-all, NOT real endpoints
```

## Feature Flag Extraction

Feature flags in WIZ_global_data follow this pattern:
```javascript
// [flagID, null, boolValue, null, stringValue, null, "internalName"]
[45724102, null, null, null, null, null, "emcavb", ["[[...]]"]]
[45791091, null, false, null, null, null, "IQaf8b"]
```

These can potentially be toggled via API manipulation when authenticated (pass flag IDs in request parameters).

## App Engine Demo Endpoints

Google Labs products often have demo instances on App Engine:
```
https://demo-external-dot-{SERVICE}.{REGION}.r.appspot.com/
```

These serve the frontend shell without auth but typically don't expose backend APIs on the same host. The frontend calls back to the main product domain for API requests.

## Prototype Pollution Monitoring

Google products actively monitor `__proto__` access via Object.prototype sealing. They report violations to:
```
https://csp.withgoogle.com/csp/proto/APPNAME
```

This means:
1. They're aware of prototype pollution as a vector
2. Monitoring != blocking — the pollution may still work
3. Any successful pollution will be logged (consider this for stealth)
