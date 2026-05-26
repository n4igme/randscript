# Grab/OVO HackerOne Engagement (2026-05-26)

## Scope
- Platform: HackerOne (https://hackerone.com/grab)
- Critical: `*.grab.com`, `*.grabpay.com`, `*.grab-sure.com`, `*.myteksi.com`, `*.myteksi.net`, `*.ovofinansial.com`
- High: `*.ovo.id`
- Medium: `*.grabtaxi.com`, `*.grab.co`
- Specific Critical: jira.grab.com, wiki.grab.com, api.grabpay.com, gifts.grab.com, p.grabtaxi.com
- Mobile: Grab Passenger, Grab Driver, OVO, MoveIt

## Findings (unsubmitted — none reached proven-impact threshold)

### 1. OTP No Rate Limit on doc-stg.ovofinansial.com
- OVO Rampart File Service (lending document management)
- `/otp` accepts ANY email as `{identifier: "..."}`, returns `{"note":"success"}`
- `/otpcheck` has ZERO rate limiting (100+ attempts, no lockout)
- Cross-session verification works (OTP tied to email, not session)
- **NOT PROVEN:** actual account takeover. Can't confirm OTP is real (same response for nonexistent emails). At 14.7 req/s, full 1M keyspace takes ~19h single session.
- **Verdict:** Missing rate limiting = Low/Medium. Not submittable as High without proven login.

### 2. Config Leak Chain (dev-website + funding.ovofinansial.com)
- `dev-website.ovofinansial.com/assets/config.js` — staging OAuth client_id, K8s URLs, DataDog, Leanplum, LaunchDarkly
- `funding.ovofinansial.com/config.js` — PRODUCTION OAuth client_id, Griffin API URL
- **Exploitation attempted on ALL tokens:**
  - DataDog pub tokens → 403/401 on all API endpoints (read AND write)
  - Leanplum dev key → "Invalid access key" on all actions
  - LaunchDarkly client IDs → flags readable (but client-side by design)
  - OAuth client_ids → useless without client_secret (only authorization_code grant supported)
- **Verdict:** No exploitable access. Informational at best.

### 3. LaunchDarkly Feature Flags (staging + production)
- 35 flags exposed via client SDK endpoint
- Includes: admin panel module map (55+ modules), TinyMCE API key, env confirmation
- Production flags confirm `env: "prd"` and different values from staging
- **Reality:** Client-side SDK IDs are designed to be public. The flags are what any browser receives.
- **Verdict:** Not submittable. "Leakage of non-sensitive API keys" is typically OOS.

### 4. food.grab.com runtimeConfig Leak
- `__NEXT_DATA__` in production HTML exposes:
  - `APP_GRABID_PROXY_URL: https://food.grab.dev:3000/proxy/grabid`
  - `APP_PAYSDK_BASE_URL: https://food.grab.dev:3000/__local__/paysdk`
  - `APP_SENTRY_DSN: https://24c952955d1a419da9d8b1aaceae1ecc@sentry.io/1429894`
  - Internal architecture (portal.grab.com/foodweb, p.grab.com/delvplatformapi)
- food.grab.dev resolves (165.160.13.20), port 80 open but only health check stub
- Port 3000 (actual app) not accessible externally
- Sentry DSN writable (429 rate limit, not 401) — can inject fake error events
- **Verdict:** Dev URLs leaked but not accessible. Sentry write = data poisoning (Low). Not worth submitting alone.

## Infrastructure Map

### OVO Finansial
- auth.ovofinansial.com — Django OAuth Toolkit (authorization_code only)
- auth-stg.ovofinansial.com — staging auth (same behavior)
- griffin.ovofinansial.com — production lending API (401 on all paths)
- griffin-stg.taralite.com — staging lending API (401 on /apis/cepanel, /apis/fds)
- doc-stg.ovofinansial.com — Rampart File Service (OTP auth, Vue.js + Express)
- funding.ovofinansial.com — Lender dashboard (React SPA)
- settlement.ovo.id — ASP.NET 4.0 VisionRecon (login page exposed)

### Grab
- food.grab.com — Next.js, proxy endpoints (all 502 from external)
- gifts.grab.com — Next.js SSG, no real API backend
- api.ovo.id — PIN endpoints alive (`invalid request`), OTP verify deprecated (410)
- cb.ovo.id / cellblockui.ovo.id — OVO internal tools (SPA, no unauth access)
- Most *.grab.com behind CloudFront 403
- hungrygowhere.com — WordPress, WP REST API returns 500, xmlrpc blocked

## Key Lessons

1. **Grab is heavily hardened** — CloudFront on everything, envoy service mesh, proper auth on all APIs
2. **OVO staging is more exposed** but still requires valid credentials to exploit
3. **Config leaks are common but low-value** — client-side tokens are designed to be public
4. **Mobile app interception needed** — the real attack surface is the authenticated mobile API (OVO PIN, GrabPay transactions). Can't reach it from web-only testing.
5. **food.grab.com proxy endpoints** return 502 — likely geo-restricted or need specific internal routing
6. **Don't waste time on "almost" findings** — if you can't prove the full chain, move to next target

## Next Steps (if returning to Grab)
- Intercept OVO mobile app traffic (Frida + Mi MIX 2) to get proper auth tokens
- Test authenticated flows: IDOR on user endpoints, race conditions on payments
- Check GrabPay API with valid merchant session
- Revisit doc-stg with a real @grab.com email (if obtainable via OSINT)
