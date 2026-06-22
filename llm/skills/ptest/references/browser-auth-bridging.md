# Browser-to-Curl Authenticated Resource Download

## When to use
- Target app serves PDFs, reports, or files behind auth
- You have an active browser session but need to download via curl/scripts
- PDF viewers (pdf.js) load resources via XHR that don't expose direct download links

## Technique: Extract JWT from Browser Cookies

### Step 1: Find the resource URL
Use `performance.getEntriesByType('resource')` in browser console to find loaded resources:
```javascript
performance.getEntriesByType('resource')
  .filter(e => e.name.includes('pdf') || e.name.includes('download'))
  .map(e => e.name);
```

### Step 2: Extract token from cookies
```javascript
document.cookie
// Look for JWT in cookie values (often URL-encoded JSON with a "token" field)
```

If the cookie contains URL-encoded JSON with a token field:
```javascript
JSON.parse(decodeURIComponent(document.cookie.match(/user=([^;]+)/)[1])).token
```

### Step 3: Download with Bearer token
```bash
curl -o output.pdf "<resource_url>" \
  -H "Authorization: Bearer <jwt_token>"
```

## Pitfalls
- Cookie-based auth (passing Cookie header) may not work if the API expects Authorization header — try Bearer first
- JWT may be URL-encoded in the cookie — decode before use
- `performance.getEntriesByType('resource')` only shows resources loaded AFTER navigation — trigger the PDF viewer first, then query
- Some platforms use httpOnly cookies not visible via `document.cookie` — in that case, use browser's Network tab or intercept via Burp

## Real example (CyberWarFare Labs)
- PDF loaded via pdf.js (22 canvas elements, no iframe/embed)
- Resource URL found: `/api/imgandpdf/pdf/<course>/<id>/<filename>.pdf`
- Token extracted from `user` cookie (URL-encoded JSON object with `token` field)
- Cookie header returned 401, Bearer header returned 200
