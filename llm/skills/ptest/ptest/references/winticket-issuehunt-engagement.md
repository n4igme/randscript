# WinTicket / IssueHunt Engagement Intel

## Program
- Platform: IssueHunt
- URL: https://issuehunt.io/programs/72c9712d-1727-47a1-8b1e-e51940135e64
- Org: CyberAgent, Inc.
- Dir: ~/PenTest/Hunting/IssueHunt/WinTicket/

## Scope
- Web: https://www.winticket.jp
- API: *.winticket.jp
- iOS: id1455195128
- Android: jp.winticket.app

## Rewards (JPY)
Critical: ¥100k-300k | High: ¥30k-100k | Medium: ¥10k-30k | Low: ¥5k-10k

## Out of Scope (CRITICAL — check before reporting)
- Email/username enumeration
- SPF/DKIM/DMARC misconfig
- Brute force against passwords/tokens
- Missing CSRF tokens
- Missing security headers without direct vuln
- Server banner disclosure
- Stack traces / error messages

## Infrastructure
- CDN: Fastly (Varnish)
- Cloud: GCP (Compute, Cloud Storage, Cloud DNS, Istio/Envoy mesh)
- Auth: Firebase (winticket-firebase)
- Payment: GMO Multipayment
- Analytics: Datadog, Braze, Sentry
- Email: SparkPost
- SGTM: Server-side Google Tag Manager
- Outlier: dwuzxuvwlq.winticket.jp = A8.net affiliate tracker (CNAME trck.a8.net)

## GCS Bucket
- Name: billioon-image-prd (leaked via 403 XML on assets.winticket.jp)
- Objects publicly readable if path known, listing denied

## Key Technical Details
- SPA: Angular/webpack chunked JS
- API: api.winticket.jp/v1 (Istio/Envoy)
- CMS: cms.winticket.jp/api/v1 (Fastify)
- Auth paths: /my/* (authenticated prefix)
- Proxy: /z/* (ponta, surveys, offerwalls)
- Custom headers: X-WT-API-Origin, X-WT-Draft, X-WT-Mirror, X-WT-PR, etc.

## All Findings (June 2026)

### Reportable (IN SCOPE)
- FINDING-1: Login CSRF via /v1/auth/apple intent:// injection (Medium-High) — form-encoded bypasses CORS, no state param
- FINDING-2: Unrestricted Mobile Firebase API Key from APK (Medium) — no referer restriction unlike web key
- FINDING-3: Adjust production token leaked in APK (Medium) — event+revenue injection confirmed (rfw8aoe3ixog)
- FINDING-4: Firebase password provider on passwordless platform (Medium) — pre-registration ATO, mass squatting
- FINDING-5: No rate limit on POST /v1/auth/email/token (Medium)
- FINDING-6: Sentry DSN event injection (Low) — write confirmed with event_id
- FINDING-7: Datadog RUM+Logs write injection (Low) — 202 confirmed
- FINDING-8: SGTM fake analytics injection (Low) — 200 confirmed
- FINDING-9: Braze SDK content cards readable (Low)
- FINDING-10: GCS billioon-image-prd public object access (Low) — individual images 200 if path known
- FINDING-11: GMO Payment ShopID confirmed valid (Low) — tshop00066026, differential error oracle

### Out of Scope (do not report)
- Firebase email enumeration via PASSWORD_RESET (explicitly excluded)
- DMARC p=none (explicitly excluded)
- Missing security headers (explicitly excluded)

## Ruled Out (tested, not exploitable)
- X-WT-API-Origin reflection: unicode-escaped (\u003c), not XSS
- Cache poisoning: Vary keys on ALL custom headers (20+ in Vary)
- get.winticket.jp open redirect: always redirects to www regardless of params
- Firebase continueUrl: validated, rejects external domains (UNAUTHORIZED_DOMAIN)
- GraphQL/WebSocket: not present on any host
- Envoy CVEs: patched (path traversal, ext_authz bypass)
- GCS billioon-image-prd: listing denied, no sensitive objects found
- GMO Payment: decoded key doesn't match ShopPass format (E00000003)
- CORS: no reflection on any origin across 40+ tests
- SQLi/NoSQL/SSTI/XXE: all properly handled by Envoy+Fastify
- Firebase Firestore: Datastore mode (REST API unavailable)
- Braze SDK key: client-only, no admin access

## Auth Flow (confirmed Phase 6)
1. Firebase signUp (email+pw, needs Referer header) → idToken
2. POST /v1/auth/email/token (Bearer idToken) → WT token (timestamp.hmac)
3. POST /v1/auth/email (Bearer WT token) → 400 (needs "full registration")
4. Full registration requires additional fields (birthday? phone? KYC?)
5. Without full registration: /v1/users/me → 401, /v1/charges → 401

## API Method Discovery
- POST /v1/users (allows POST per OPTIONS, returns 400 - unknown required fields)
- GET+PUT /v1/users/me (needs full registration)
- POST /v1/users/me/email (400)
- POST /v1/auth/apple → 307 intent:// (reflects full JSON body)
- DELETE /v1/auth → 204 (always succeeds, doesn't revoke token)
- /my/settings → 403 from Google Frontend (SSR, auth-gated)

## Config Dump (from window.__CONFIG__)
- GMO_MP_API_KEY (base64): decodes to 78-char hex string
- GMO_MP_PUBLIC_KEY: RSA 3072-bit public key
- BRAZE_API_KEY: ce69e52b-4d15-4abe-ae44-71d038bcbcdc (SDK endpoint: fra-02)
- PONTA_WEB_CLIENT_ID: 0849b25e26ef3fb085f590d5af798e46
- AI_MESSENGER_TENANT: winticket-mx7bc
- HAYABUSA: winticket.hayabusa.dev (unreachable)
- ADX: adx.ameba.jp/v1/delivery (404)

## Lessons
- Target is well-hardened (Referer-restricted API key, Vary keyed cache, X-Frame-Options DENY)
- Firebase signUp NOT disabled — only restricted by Referer header (bypassable from curl/Python)
- Backend checks `sign_in_provider` claim — password tokens get 401 on protected endpoints
- Registration requires mobile app WebView bridge (`showRegisterPage` callback to native)
- Temp email interception works (api.tempmail.lol) — OOB codes retrievable in ~25s
- Even with emailLink provider token, still need native app to complete full registration
- Biggest untested surface: authenticated area (betting, payments, IDOR, race conditions)
- Form-encoded POST bypasses CORS preflight on /v1/auth/apple (intent:// injection confirmed)
- Datastore mode (not Firestore) means REST API queries require service account
- Token is deterministic: same second = same HMAC output (user-specific though)
- APK downloadable via `apkeep -a jp.winticket.app -d apk-pure .` — even TWA wrappers leak keys
- winticket.co.jp is a separate domain (Next.js corporate site on GFE) — NOT in *.winticket.jp scope
