# Meta/Instagram Infrastructure Intelligence

## Collected: 2026-05-29 (Meta Bug Bounty engagement)

## Infrastructure Architecture

- **Edge network:** Meta's own (c10r PoPs — cgk1, cgk2, sin11, sin2)
- **Server:** proxygen-bolt (Meta's HTTP framework, internal variant)
- **Ports:** Only 80/443 exposed on all Meta-owned IPs (fully hardened)
- **CDN:** static.cdninstagram.com (rsrc.php pattern for JS bundles)
- **Email:** Proofpoint gateway (mxa/mxb-00082601.gslb.pphosted.com)
- **Corporate email:** Microsoft O365 (autodiscover.instagram.com → outlook.office365.com)

## Key Headers

| Header | Meaning |
|--------|---------|
| `x-ig-push-state: c2` | Instagram API endpoint (mobile) |
| `x-ig-server-region: vcn` | Server region identifier |
| `x-ig-cache-control: no-cache` | API response (not cached) |
| `x-fb-debug: <base64>` | Internal debug info (present on most hosts) |
| `x-fb-request-id` | Request tracing ID |
| `x-fb-trace-id` | Distributed trace ID |
| `x-fb-rev: 1040394193` | Build revision number |
| `x-fb-connection-quality` | Client connection quality assessment |
| `server: proxygen-bolt` | Meta's HTTP server (only on some hosts) |
| `proxy-status: proxy_internal_response` | Internal proxy (not reaching backend) |

## App IDs

| Platform | App ID | Context |
|----------|--------|---------|
| Instagram Web | 936619743392459 | X-IG-App-ID header for web requests |
| Instagram Android | 567067343352427 | X-IG-App-ID for mobile API |

## Authentication Architecture

- **Password encryption:** `#PWD_INSTAGRAM_BROWSER:0:0:<password>` (client-side, version 0 = plaintext, higher = RSA encrypted)
- **CSRF:** `csrftoken` cookie + `X-CSRFToken` header
- **Request signing:** `X-IG-Signature` header (mobile API)
- **Bloks framework:** Server-driven UI via `/api/v1/bloks/` (mobile)
- **OIDC:** `/.well-known/openid-configuration` exposed
  - Authorization: `https://www.instagram.com/oauth/dialog`
  - JWKS: `https://www.instagram.com/.well-known/oauth/openid/jwks/`
  - Signing: RS256, kid: `4e1390dc05a76677928682d72e002287cc0cd4f6`

## CORS Observations

26 hosts return `Access-Control-Allow-Origin: *` including:
- graph.instagram.com, z-p*.graph.instagram.com
- gateway.instagram.com, test-gateway.instagram.com, z-p42-gateway.instagram.com
- at-od.instagram.com (401 — internal proxy with CORS wildcard)
- edge-chat.instagram.com, web-chat-e2ee.instagram.com
- rupload.instagram.com, live-upload.instagram.com
- logger.instagram.com, shortwave.instagram.com

**Note:** CORS * on these endpoints is likely intentional (CDN/API design), but combined with auth bypass on any of them → exploitable cross-origin data access.

## Interesting Subdomains

| Subdomain | Status | Notes |
|-----------|--------|-------|
| at-od.instagram.com | 401 | Internal proxy, CORS *, auth bypass target |
| intern.instagram.com | 400 | Internal tools, x-fb-debug present |
| test-gateway.instagram.com | 404 | Internal proxy, CORS * |
| preprod.instagram.com | 404 | Pre-production environment |
| genai-graph.instagram.com | 200 | AI/ML GraphQL endpoint |
| payments-graph.instagram.com | 200 | Payment processing GraphQL |
| imagine.instagram.com | 200 | AI feature (no auth redirect!) |
| call.instagram.com | 302→login | Calling feature (requires auth) |
| autodiscover.instagram.com | 301→O365 | Microsoft IIS, potential takeover |

## Auth Endpoints (Mobile API — i.instagram.com)

| Endpoint | Behavior | Notes |
|----------|----------|-------|
| /api/v1/accounts/login/ | 400 (needs encrypted pwd) | Mobile login |
| /api/v1/accounts/two_factor_login/ | 400 "invalid_parameters" | Needs two_factor_identifier from login |
| /api/v1/accounts/send_two_factor_login_sms/ | 400 "missing_parameters" | With device_id → "invalid_identifier" |
| /api/v1/accounts/account_recovery_code_verify/ | fail (empty msg) | Recovery code validation |
| /api/v1/accounts/check_confirmation_code/ | fail (validates codes!) | No hard rate limit (15 req processed) |
| /api/v1/accounts/send_recovery_flow_email/ | rate_limit_error | Aggressively rate limited |

## Anti-Bot Protections

- `AuthPlatformAntiScriptingException` — triggered on login endpoint when bot detected
- Inconsistent `user` field in login response when anti-scripting active (randomizes true/false)
- Proper CSRF token required for web endpoints (get from cookie jar)
- Arkose Labs (FunCaptcha) on some flows

## DNS/Email Security

- SPF: `v=spf1 include:facebookmail.com include:_spf.fb.com -all` (strict)
- DMARC: `v=DMARC1; p=reject; pct=100` (fully enforced)
- No email spoofing possible
- No subdomain takeover via CNAME (all A records to Meta IPs)
- autodiscover.instagram.com → Microsoft IPs (40.99.x.x) — only non-Meta IP in scope
