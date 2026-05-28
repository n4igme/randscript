# Next.js Server-Side Proxy Pattern (SSR API Routes)

Exploiting Next.js API routes that proxy to internal services.

---

### Next.js Server-Side Proxy Pattern (SSR API Routes)

Modern web apps (Next.js, Nuxt, SvelteKit) often proxy API calls through their own server-side routes. The frontend calls `/goid/token` on the SAME origin, and the Next.js server adds session tokens, CSRF validation, captcha verification, and internal headers before forwarding to the real backend.

**Detection signals:**
- API endpoints on the same domain as the frontend (not a separate api.* subdomain)
- `x-nextjs-cache` header in responses
- JS bundle references paths like `/goid/token` with `credentials: "include"` (cookie-based)
- Server returns "missing field" errors even when you provide all visible fields (server adds hidden ones)
- CSRF cookies (csrfSecret + XSRF-TOKEN) required for API calls

**Implications for testing:**
1. You CANNOT replicate the full request externally — the server adds fields from its session store
2. The captcha token is consumed server-side and converted to a session flag — you can't skip it
3. Browser-based testing is the ONLY way to trigger these flows (fetch interception)
4. Non-prod environments may have the same proxy but with relaxed WAF — test there first
5. The `/goid/token` endpoint may pass through without full proxy validation (refresh tokens don't need captcha)

**Testing strategy:**
- Use browser fetch interception to capture the FULL request (headers + body + cookies)
- If captcha blocks browser automation, document as blocker and assess close-out
- Focus on endpoints that bypass the proxy (direct backend access via gojekapi.com)
- Test grant_type variations on /goid/token (refresh_token, client_credentials) — these may not require captcha

**GoFood-specific patterns (May 2026):**
- Consumer web uses `x-user-type: customer` (vs `merchant` for GoBiz)
- Client ID: `gofood-web` (proxy-only, not registered on direct GoID API)
- Additional endpoints: `/v6/customers/newrequest`, `/v6/customers/phone/verify`, `/v6/customers/register`
- Field name difference: `phone` (with +62 prefix) vs GoBiz's `phone_number` + `country_code`
- `/v2/otp/retry` accepts `otp_token` field — validates token expiry without captcha
- 49 reCAPTCHA elements detected in login modal — heavy captcha protection
- Headers from JS: `x-user-type`, `x-user-locale`, `gojek-country-code`, `gojek-timezone`, `x-location`, `x-uniqueId`, `x-platform`, `x-appversion`, `gojek-service-area`, `gojek-service-type`, `x-captcha-token`, `x-captcha-appid`