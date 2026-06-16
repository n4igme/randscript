# SPA Backend Discovery via Browser Network Interception

## When to Use
- Target is a Single Page Application (SPA) served from CDN/OSS
- API calls from curl hit static file hosting (OSS MethodNotAllowed, HTML instead of JSON)
- The SPA's real API backend is on a different subdomain than the frontend

## Problem
Modern SPAs (Umi, React, Vue) serve static HTML/JS from CDN (e.g., marmot-cloud.com, AliyunOSS).
The `/api/*` paths in the JS source are relative — they get proxied through the SPA's serving
infrastructure (TERN gateway, Nginx, etc.) in-browser, but curl to the same origin hits the
static file server directly.

## Discovery Technique

### Method 1: Browser Performance API (fastest)
```javascript
// In browser console after triggering an API call (login, register, etc.)
performance.getEntriesByType('resource')
  .filter(r => r.name.includes('/api/'))
  .map(r => r.name + ' | ' + r.responseStatus)
```
This reveals the ACTUAL backend URL the browser connected to.

### Method 2: JS Bundle URL Extraction
```bash
# Download main JS bundle
curl -sk --compressed "https://TARGET/" | grep -o 'src="[^"]*\.js"'
# Then search bundle for full backend URLs
curl -sk --compressed "$BUNDLE_URL" | grep -o '"https://[^"]*alipay[^"]*"' | sort -u
```

### Method 3: Browser Fetch Interceptor
```javascript
const origFetch = window.fetch;
window._apiResponses = [];
window.fetch = async function(...args) {
  const resp = await origFetch.apply(this, args);
  if (args[0] && args[0].toString().includes('/api/')) {
    const clone = resp.clone();
    const body = await clone.text();
    window._apiResponses.push({url: args[0].toString(), status: resp.status, body: body.substring(0, 500)});
  }
  return resp;
};
```

## Real-World Example: AntGroup GenAI Cockpit (June 2026)

- Frontend: `bot.alipayplus.com` (served from `webapp-origin.marmot-cloud.com`)
- Curl to `bot.alipayplus.com/api/v1/entrance/publicKey` → OSS XML MethodNotAllowed
- Browser Performance API revealed: `ilmprodmerchant.alipayplus.com/api/v1/entrance/*`
- Direct curl to `ilmprodmerchant.alipayplus.com` → real API responses

## Key Indicators of Hidden Backend
- `Server: AliyunOSS` or `marmot-cloud.com` in response headers for the frontend
- POST requests return XML `MethodNotAllowed` with `ResourceType: Object`
- JS bundles reference different hostnames (look for `https://` in bundle source)
- `window.injectInfo`, `window.__TERN__` variables in HTML suggest TERN gateway proxy

## Unauthenticated Endpoint Patterns (Alibaba/Ant Convention)

Alibaba/Ant SPAs use path naming conventions to mark intentionally unauthenticated endpoints. After discovering the real API backend, **filter for these patterns immediately** — they're high-value targets that bypass auth by design:

| Path Segment | Meaning | Example |
|-------------|---------|---------|
| `/unLogin/` | Explicitly unauthenticated | `/ighome/api/file/unLogin/upload.json` |
| `/noAuth/` | No auth required | `/api/noAuth/config.json` |
| `/pub/` | Public endpoint | `/pub/userNotLogin.htm` |
| `/open/` | Open/public API | `/open/api/v1/status` |

**Why these matter:**
- Developers mark them "unauthenticated by design" so they skip auth middleware
- But they often still perform sensitive operations (upload, download, send email/SMS, password reset)
- Secondary controls are usually weak: Referer-only check, no rate limit, no size limit
- Scanners ignore them ("no auth = health check") — but they're often overpowered

**Testing procedure:**
1. Extract all endpoints from JS bundles
2. Filter for `/unLogin/`, `/noAuth/`, `/pub/`, `/open/` segments
3. For each: test what operations are possible (file upload, data query, state change)
4. Check for weak secondary controls: Referer bypass, missing rate limit, no size cap

**Real-world finding (AntGroup, June 2026):**
- `/ighome/api/file/unLogin/upload.json` — unauthenticated file upload
- Only needed `Referer: https://connect.alipayplus.com/` to bypass
- Accepted PDF/PNG/JPG/ZIP/PEM, 5MB+, no rate limit, no auth
- Severity: Medium-High (CWE-434)

Also check the **auth gateway error messages** for internal service URLs:
```python
# When an auth-gated endpoint rejects you, the error often leaks the auth service:
# {"buserviceErrorCode": "USER_NOT_LOGIN",
#  "buserviceErrorMsg": "https://antbuservice.alipay.com/pub/userNotLogin.htm?appName=ilmprodmerchant&..."}
# This reveals: internal auth service URL, app name, redirect structure
```

## After Discovery
Once real backend is found, all API testing switches to direct requests against it.
No browser needed for subsequent exploitation — just use Python requests.
