# Grab Infrastructure Patterns (HackerOne)

## Program Info
- Platform: HackerOne (`hackerone.com/grab`)
- Bounty: Low $50-750, Med $500-3000, High $2000-7500, Critical $5000-15000
- Mobile apps pay higher (Low $75-750, Critical $7500-15000)
- Scope updated: May 2026
- Note: `*.qms.grab.com` explicitly OUT OF SCOPE

## Scope (32 assets)

### Critical Severity (Wildcard)
- `*.grab.com` — main domain
- `*.grabpay.com` — payment platform
- `*.grab-sure.com` — insurance
- `*.myteksi.com` — legacy brand
- `*.myteksi.net` — legacy brand
- `*.ovofinansial.com` — OVO financial services (Indonesia)

### Critical Severity (Specific)
- `p.grabtaxi.com` — **Main API gateway** (Golang, auth via `X-mts-ssid` header)
- `api.grabpay.com` — GrabPay API
- `xtramile.grabpay.com` — GrabPay rewards
- `manage.grab.co` — Management portal
- `gifts.grab.com` — Gift cards
- `gamma.grab.co` → redirects to `gamma.grab.com`

### Mobile Apps (Critical)
- `com.grabtaxi.passenger` — Grab passenger (Android)
- `com.grabtaxi.driver2` — Grab driver (Android)
- `com.grab.merchant` — Grab merchant (Android)
- `com.moveit.app.customer` — MoveIt (Android)
- `ovo.id` — OVO wallet (Android)

### Medium Severity
- `*.grabtaxi.com`, `*.grab.co`
- `grab.careers`, `kartaview.org`
- `hungrygowhere.com` (High)
- `*.ovo.id` (High)

## Tech Stack

| Service | Stack |
|---------|-------|
| p.grabtaxi.com | Golang API gateway, returns 502 without proper routing |
| api.grab.com | Same as p.grabtaxi.com (502 on all paths) |
| finance.grab.com | Envoy proxy, CloudFront CDN, Go backend |
| doc.grab.com | Node.js (Express), Vue.js, "Rampart" file sharing |
| sandbox.grab.com | React SPA → p.grabtaxi.com |
| partner-api.grab.com | Next.js (GrabKiosk CMS) |
| omega-rtc.grab.com | React, campaigns/rewards/RTC system |
| drishti.grab.com | React + Ant Design, content moderation |
| cdp.grab.com | React, Customer Data Platform |
| consumer-ai.grab.com | WebView chatbot (auth from native app bridge) |
| vn.einvoice.grab.com | ASP.NET MVC, Vietnamese e-invoice portal |

## Internal Services Discovered

| Domain | Purpose | Source |
|--------|---------|--------|
| api-restricted.grab.com | Internal API gateway (Hedwig messaging) | config.json |
| api-restricted.stg-myteksi.com | Staging API | source map |
| cdp.grab.com | Customer Data Platform | config.json |
| cdp.stg-myteksi.com | CDP staging | page source |
| segmentation-platform.grab.com | User segmentation | config.json |
| hedwig-dash.grab.com | Notification dashboard (403) | config.json |
| sandbox-cms.grab.com | Feed CMS (403) | config.json |
| mystique-figma-be.mngd.int.engtools.net | Internal design tool | source map |
| wiki.grab.com | Internal Confluence (403) | source map |
| maptiles.grab.com | Map tiles server | config.json |
| grab.slack.com/archives/CDLNWK4EQ | Slack channel | source map |
| grabtaxi.atlassian.net/wiki/spaces/RTC/ | Atlassian wiki | source map |

## Authentication

### p.grabtaxi.com (Main API)
- Auth header: `X-mts-ssid` (session token from mobile app)
- Returns 401 on all endpoints without auth (properly enforced)
- API paths: `/api/passenger/v{1-3}/*`
- Discovered endpoints: safety/emergencycontacts, loyalty/points, grabfood/*, rides, profile, referral

### Internal Tools (drishti, omega-rtc, bolt, taxi)
- Auth: Google SSO via Concedo IAM (`api.grab.com/concedoiam`)
- Login library: `grab-login` (npm package)
- Role-based access (Admin role in drishti)

### doc.grab.com (Rampart File Sharing)
- Auth: Email OTP or Google SSO (internal)
- CSRF token in meta tag (rotates per request)
- OTP expires in 5 minutes

## Findings (May 2026)

### S3 Bucket Listing (Low)
- `huawei-image-ads-cms.grab.com` / `huawei-video-ads-cms.grab.com`
- Bucket: `prd-galaxy-assets`
- Public ListBucket, 1000+ ad images, write denied (403)

### Unauthenticated Financial API (Informational — downgraded)
- `finance.grab.com/api/v1/*`
- Endpoints: myloans/details, user/demographic_data, loan/restructure, ona/instalment-history, download_receipt, send_email_receipt, my/postal-codes, user/onboard
- Returns 400 (bad input) not 401 — no auth middleware
- Requires valid `msgID` parameter (format unknown, could not brute-force)
- Server: Envoy behind CloudFront (SIN2-P7)
- devMessage leak: `{"devMessage":"Bad Input.","arg":"Missing required field msg_id\n"}`
- **Downgrade reason:** Cannot prove data access without valid msgID. The 400 vs 401 signal suggests missing auth, but without demonstrating actual data retrieval, impact is unproven.

### Source Map Exposure (Low — downgraded from Medium)
- `drishti.grab.com/static/index.*.js.map` — 1.1MB, 47 app files (content moderation)
- `omega-rtc.grab.com/index.*.js.map` — 4.2MB, 503 app files (campaigns/rewards)
- Reveals: internal IAM client IDs, auth flows, moderation categories, internal URLs
- **Exploitation attempted:** Tried to use discovered internal API paths (`api-restricted.grab.com`, `api-restricted.stg-myteksi.com`), Concedo IAM client IDs, and Google SSO login flow (`/manual-moderation/v1/mobile/login`). All failed — gateway returns 403/502, OAuth requires @grab.com account.
- **Downgrade reason:** Information disclosure only. Could not chain into auth bypass or data access without an authenticated Grab internal account.

### Config.json Exposure (Low — downgraded from Medium)
- `omega-rtc.grab.com/config.json` — Sentry DSN, 6 Partner UIDs, Google OAuth, Concedo IAM, RUM token, internal APIs
- `bolt.grab.com/config.json` — Sentry DSN + Google OAuth client ID
- `taxi.grab.com/config.json` — Sentry DSN + GrabID + VAPID key
- All 3 Sentry DSNs confirmed active (accept events, dropped by quota)
- **Exploitation attempted:** Tried OAuth flows with exposed client IDs (strict redirect_uri + PKCE required), Concedo IAM auth (502/empty), Sentry event injection (quota-limited, no XSS vector). Partner UIDs alone don't enable access.
- **Downgrade reason:** Robust gateway protections prevent exploitation of exposed credentials without an authenticated session.

### CORS Misconfiguration (Low)
- `api.grab.com` returns `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`
- Browser-rejected combination (spec violation) — non-exploitable
- Indicates server-side misconfiguration but no practical attack vector

## Recon Stats
- 15,592 total subdomains (subfinder across 9 domains)
- 1,104 publicly-resolvable (filtered private IPs + OOS qms)
- 662 live HTTP hosts (137×200, 353×403, 77×404, 13×502)
- Most grab.com subdomains resolve to private IPs (10.x.x.x) — internal infra

## Geo-Blocking (Critical Obstacle)

`p.grabtaxi.com` (main API gateway) returns **502 on ALL paths** from outside Southeast Asia. This blocks all authenticated testing without a regional VPN. Affected:
- `p.grabtaxi.com` — 502 (Singapore AWS: 52.74.244.224, 3.1.150.128, etc.)
- `gifts.grab.com/v2/go` — CloudFront 403 (WAF blocks API calls, static assets OK)
- `manage.grab.co` — CloudFront 403
- `xtramile.grabpay.com` — CloudFront 403

**Still accessible globally:**
- `hungrygowhere.com` — WordPress blog (Apache, no CloudFront)
- `api.grab.com/manual-moderation/v1/mobile/login` — responds (needs Google auth code)
- S3 buckets via CNAME (`huawei-image-ads-cms.grab.com`)
- Static assets on CDN (JS, CSS, source maps)

## Leaked JWT (GitHub OSINT)

Found in `thgiang/omnichannel-now-grab-baemin` repo (GrabAPI.cs):
- Audience: `MEXUSERS` (merchant account)
- Subject: `ec687c0f-2933-452a-b986-78a4e3705ee2`
- Issued: 2021-06-08, Expires: **2038-07-19** (17-year lifetime)
- Login method: NATIVE
- **Status:** Cannot validate — `p.grabtaxi.com` geo-blocked. Needs SG/ID VPN to test.
- Header: `x-mts-ssid: <token>`
- User-Agent: `Grab Merchant/4.27.0 (android 5.1.1; Build 90)`

Also found: `AmrosoInfinity/GeneratorToken` — Python tool that validates Grab tokens via profile API.

## hungrygowhere.com (WordPress)

- **Stack:** WordPress 6.x, Apache/2.4.66 (Ubuntu), PHP 7.4+
- **Plugins:** Contact Form 7 v6.1.6, Yoast SEO v27.6, W3 Total Cache v2.9.4, WP Mail SMTP v4.8.0
- **Users (46+ via REST API):** grab_admin, stephzheng, hannahtan, shannonong, joeytan, changqi, angeline-ang, etc.
- **User enum:** `/wp-json/wp/v2/users?per_page=100` returns full user list (id, name, slug, description, avatar)
- **Author sitemap:** `/author-sitemap.xml` also exposes all usernames
- **Login:** wp-login.php redirects to homepage on failure (custom behavior, no error message enumeration)
- **XMLRPC:** Disabled (returns empty)
- **Registration:** Disabled (redirects to homepage)
- **Interesting pages:** `/ads-management/` (page ID 52025)
- **GTM:** GTM-N96PGHK, Google Optimize: OPT-TJV8CTT, AdSense: ca-pub-4638388957072306

## gifts.grab.com (Next.js)

- **Stack:** Next.js (SSG), CloudFront CDN
- **Routes:** `/`, `/404`, `/redeem`, `/[country]/[[...page]]`, `/[country]/[locale]/[[...page]]`
- **Redeem flow:** `/redeem?id=<giftID>` or `?code=<code>` → calls `/v2/go?id=<id>&format=json` → returns `redirectLink`
- **Source maps:** Return HTTP 200 but empty content (placeholder files, not real maps)
- **API calls:** All blocked by CloudFront WAF (403)
- **Scribe SDK:** `https://scribe-web-sdk.grab.com/scribe_bundle_v1.0.55.min.js`

## S3 Bucket Deep-Dive

### prd-galaxy-assets (via huawei-image-ads-cms.grab.com)
- **ListBucket:** Allowed via CNAME only (direct S3 URL returns AccessDenied)
- **GetObject:** 403 (CloudFront blocks individual file access)
- **PutObject/DeleteObject:** 403
- **Versioning/ACL/Policy:** All AccessDenied
- **Content:** Only `alice/images/` prefix — ad creative images (jpg/webp/png)
- **No sensitive data** — just marketing assets with obfuscated filenames
- **IsTruncated: true** — 1000+ objects but all same pattern

### Related buckets discovered
- `stg-galaxy-assets` — exists (403, fully locked)
- `dev-galaxy-assets` — exists (403, fully locked)
- `grab-data` — exists (403)
- No other Grab bucket names found via pattern testing

## Key Patterns
1. **SPA catch-all everywhere** — most *.grab.com apps return 200 HTML for all paths (React/Next.js client routing). Always verify with POST or check response size vs baseline.
2. **config.json is the goldmine** — runtime config at predictable path, rarely protected, contains Sentry DSNs, OAuth client IDs, partner UIDs, internal service URLs.
3. **Source maps not stripped** — multiple production apps serve .map files. Check every JS bundle URL + `.map`.
4. **Envoy + CloudFront** — finance/API services use Envoy proxy behind CloudFront. Look for missing auth (400 vs 401 signal).
5. **Google SSO (Concedo IAM)** — internal tools use Grab's custom IAM. Client IDs in config.json.
6. **Partner UIDs are production identifiers** — P2M, Transport, ONA, Food, Mart, Pay, Express UIDs exposed in omega-rtc config.
7. **Geo-blocking is the #1 obstacle** — without a SG/ID VPN, most API testing is impossible. Prioritize static asset recon and targets without CloudFront WAF (hungrygowhere.com).
8. **GitHub OSINT is productive** — `gh search code 'X-mts-ssid'` found valid long-lived JWTs in third-party repos. Always check for leaked tokens before giving up on authenticated testing.
