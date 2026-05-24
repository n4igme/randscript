# GoTo/Gojek/GoBiz Authentication Patterns

## Overview
GoTo ecosystem (Gojek, GoBiz, GoFood Merchant) uses a shared auth system called "GoID" with specific patterns that differ from standard OAuth/OIDC.

## GoID Auth Flow (discovered May 2026)

### Endpoints
- `/goid/login/request` — OTP/password login initiation (unauthenticated)
- `/goid/token` — Token exchange (OTP verification, password auth, refresh)

### Required Headers (mandatory — API returns "user type cannot be empty" without these)
```
Authentication-Type: go-id
X-PhoneMake: <device info>
X-PhoneModel: <browser/device model>
x-DeviceOS: Web
X-User-Locale: en-US
X-AppVersion: <from $_ENV.REACT_APP_DOCKER_IMAGE_TAG>
Gojek-Country-Code: ID
Gojek-Timezone: Asia/Jakarta
X-Platform: Web
X-User-Type: merchant  (valid values: "merchant"; "admin" is rejected)
x-appId: go-biz-web-dashboard
x-uniqueid: <UUID v4>
Authorization: Bearer   (empty bearer — required header even without token)
Content-Type: application/json
```

### Login Request Payloads

**Email (password flow):**
```json
{"email":"user@example.com","login_type":"password","client_id":"go-biz-web-new"}
```

**Email (OTP flow):**
```json
{"email":"user@example.com","login_type":"otp","client_id":"go-biz-web-new"}
```

**Phone (OTP only):**
```json
{"client_id":"go-biz-web-new","phone_number":"81234567890","country_code":"62"}
```

### Token Exchange Payloads

**Password grant:**
```json
{"client_id":"go-biz-web-new","grant_type":"password","data":{"email":"user@example.com","password":"xxx"}}
```

**OTP grant:**
```json
{"client_id":"go-biz-web-new","grant_type":"otp","data":{"otp":"1234","otp_token":"<uuid from login/request>"}}
```

**Refresh token:**
```json
{"client_id":"go-biz-web-new","grant_type":"refresh_token","data":{"refresh_token":"<token>"}}
```

### Response Patterns (User Enumeration)

| Scenario | login_type=otp (email) | login_type=otp (phone) | login_type=password |
|----------|----------------------|----------------------|-------------------|
| Account exists | `{"success":true}` | `{"success":true, "data":{"otp_token":"...","otp_length":4}}` | `{"success":true}` |
| Account doesn't exist | `goid:error:unauthorized` "Email tidak valid" | `goid:error:internal` "Something went wrong" | `{"success":true}` (no differentiation!) |
| Rate limited | `goid:error:ratelimited` (15 min cooldown) | `goid:error:ratelimited` | N/A |

**Key insight:** Password flow returns success for ALL emails (no enumeration). OTP flow differentiates (enumeration possible). Test BOTH flows separately.

### Rate Limiting Behavior
- **OTP send (email):** 3 per email per 15 minutes. No IP limit.
- **OTP send (phone):** At least 2 consecutive allowed. No IP limit observed.
- **OTP verify:** 3 attempts per otp_token. New token = fresh 3 attempts (but new OTP code).
- **Password verify:** Returns "Forbidden" for all attempts (CAPTCHA likely required).

### OTP Characteristics
- Length: 4 digits (phone), unknown for email
- Validity: 720 seconds (12 minutes)
- Delivery: SMS (phone), email (email)
- Token rotation: Each new request generates new OTP + new otp_token

### GoFood Web (Consumer) — Differences from GoBiz

GoFood web (gofood.co.id) uses the same GoID system but with consumer-facing differences:

**Client ID:** `gofood-web` (vs `go-biz-web-new` for GoBiz)

**X-User-Type:** `customer` (vs `merchant` for GoBiz)

**Architecture:** Next.js server-side proxy — GoID endpoints are proxied through the Next.js backend, NOT called directly from the browser to gojekapi.com. Endpoints appear at:
- `https://gofood.co.id/goid/login/request` (WAF-blocked on prod, accessible on non-prod)
- `https://gofood.co.id/goid/token` (accessible on ALL environments including prod)
- `https://gofood.co.id/v2/otp/retry` (WAF-blocked on prod)
- `https://gofood.co.id/v6/customers/newrequest` (WAF-blocked on prod)

**WAF bypass via non-prod environments:** Tencent Cloud WAF blocks `/goid/login/request` on prod but NOT on alpha/q/integration. The `/goid/token` endpoint passes through WAF on ALL environments. This means:
- User enumeration testing → use alpha.gofood.co.id or q.gofood.co.id
- Token exchange testing → works on prod (gofood.co.id)

**Additional API routes (Next.js server-side):**
```
/api/orders              → 401 (needs auth)
/api/pricing/estimate    → 401 (needs auth)
/api/gopay/login         → 500 (server error — potential target)
/api/tiktok/login        → 403 (blocked)
/api/force-logout        → 404
/api/bonsai/app-links    → 404
/api/poi/reverse-geocode → 404
/api/poi/search          → 404
```

**Lens Analytics API Key (in JS bundle):**
- Endpoint: `https://lens-fc.golabs.io/collect/gofood_expansion`
- apiKey: `Basic <base64(0a85395a-3e53-4fc8-9e23-13bb505375e0)>`
- App name: `gofood_web_service`
- This is an analytics/telemetry key, not exploitable (program excludes public API keys)

**Environments discovered:**
| Host | BuildId | WAF strictness |
|------|---------|---------------|
| gofood.co.id | 18.0.1 (semver) | Full WAF |
| alpha.gofood.co.id | 18.0.1 (same as prod) | Relaxed — GoID accessible |
| q.gofood.co.id | 2ChQBOnJub4vEdVrnkoMB (hash) | Relaxed — GoID accessible |
| integration.gofood.co.id | 5uoCE_6IuCQWVX5uZbE-D (hash) | Relaxed — GoID accessible |

### Internal vs Merchant Auth
- **Merchant portal** (portal.gofoodmerchant.co.id): GoID auth, `ENABLE_REGISTRATION=true` (but no registration UI)
- **Internal portal** (internal.gobiz.com): Google Workspace SSO via OAuth, `ENABLE_REGISTRATION=false`
- **Zeus** (app.gobiz.co.id/zeus): Internal admin, Google OAuth only

### Environment Config Exposure Pattern
GoTo apps expose full `$_ENV` in inline `<script>` tag in HTML body. Check:
- Portal HTML for `$_ENV = {...}` or `window.__ENV = {...}`
- Different environments (prod, staging, internal) have different configs
- Config reveals: API hosts, client IDs, API keys, feature flags, build info, internal URLs

### GoFood Web — Captcha Gate (Critical Blocker)

**reCAPTCHA is mandatory for all pre-auth flows on GoFood web.** The login page loads 49 captcha-related elements. Without a valid captcha token, `/goid/login/request` cannot be called — even on non-prod environments.

The Next.js server-side proxy adds a server-generated field (likely the captcha validation result or a session nonce) before forwarding to the GoID backend. This means:
- Direct curl to `/goid/login/request` ALWAYS returns `"goid:error:missing_field"` regardless of headers/body
- The "missing field" is NOT any of: x-user-type, gojek-country-code, x-platform, x-appversion, x-uniqueId, x-captcha-token, captcha_response
- It's injected server-side by the Next.js API route handler
- **Implication:** Cannot test user enumeration or OTP flooding on GoFood web without solving captcha

**Workaround (not achieved):** Would need to either:
1. Solve reCAPTCHA programmatically (out of scope)
2. Use browser automation with manual captcha solving
3. Find a captcha bypass (none found)

### GoFood Web — Customer Registration Endpoints

The `/v6/customers/` endpoints use different field names than GoID:
```
Field name: "phone" (with +62 prefix, e.g., "+6281234567890")
NOT: "phone_number" + "country_code" (that's GoID format)
```

Response progression:
- `{"phone_number":"81234567890","country_code":"62"}` → `CO:CUST:param_missing`
- `{"phone":"+6281234567890"}` → `CO:CUST:user_consent_not_found` (PROGRESS — needs prior OTP step)
- `{"phone":"+6281234567890","name":"Test","email":"test@test.com"}` → same consent error

The "user_consent_not_found" error confirms the endpoint processes the request but requires a prior OTP verification step (which requires captcha).

### GoFood Web — Direct API Access (goid.gojekapi.com)

The `gofood-web` client_id is NOT registered on the direct GoID API (goid.gojekapi.com / api.gojekapi.com). All requests return:
```json
{"code": "GoPay-1000", "message": "Don't worry, we're fixing this."}
```

This means `gofood-web` is a **proxy-only client** — it only works through the Next.js server-side proxy which adds its own service credentials before forwarding to GoID. Unlike `go-biz-web-new` (GoBiz) which works directly against the API.

**Implication:** Cannot bypass the Next.js proxy by calling GoID directly for GoFood consumer flows.

### GoFood Web — /v2/otp/retry Behavior

The OTP retry endpoint is accessible on non-prod without WAF:
- Without `otp_token` → `otp:svc:bad_request`
- With any `otp_token` value → `otp:svc:expired` (validates token format)
- **No rate limiting observed** (5 rapid requests all processed)
- But useless without a valid otp_token (which requires captcha-gated login/request)

### Discovery Technique
When API requires undocumented custom headers, use browser fetch interception (see OTP/2FA section in main SKILL.md) rather than trying to reverse-engineer from minified JS.

### GoTo Ecosystem — Hardened Target Indicators

When encountering a GoTo/Gojek target with ALL of these, mark as "hardened — unauthenticated testing exhausted":
1. Tencent Cloud WAF on production (blocks dotfiles, actuator, GoID endpoints)
2. reCAPTCHA on login/signup flows (server-side validated, not bypassable)
3. Next.js server-side proxy (adds fields that can't be replicated)
4. Kong + Envoy auth enforcement on all API routes
5. No registration flow accessible without captcha

In this case, the only path forward is:
- Obtain a Gojek account via mobile app (requires Indonesian phone number)
- Extract Bearer token from mobile app or browser DevTools after manual login
- Then test authenticated API routes (/api/orders, /api/pricing/estimate, etc.)
