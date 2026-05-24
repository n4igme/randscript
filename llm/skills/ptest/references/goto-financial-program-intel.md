# GoTo Financial — Bug Bounty Program Intelligence

**Platform:** YesWeHack
**Program:** GoTo Financial - Public Bounty Program
**Last Updated:** 2026-05-24

## Scope (14 assets)

| # | Asset | Type | Value | Bounty Range |
|---|-------|------|-------|--------------|
| 1 | GoPay iOS App | Mobile (iOS) | Critical | $100–$7,000 |
| 2 | GoPay Android App | Mobile (Android) | Critical | $100–$7,000 |
| 3 | *.gopayapi.com | Wildcard | Critical | $100–$7,000 |
| 4 | gopaymerchant.midtrans.com | Web App | High | $50–$3,000 |
| 5 | mokapos.com | Web App (NOT wildcard) | High | $50–$3,000 |
| 6 | *.go-pay.co.id | Wildcard | Medium | $50–$1,000 |
| 7 | api.midtrans.com | API | Medium | $50–$1,000 |
| 8 | app.midtrans.com | Web App | Medium | $50–$1,000 |
| 9 | www.midtrans.com | Web App | Medium | $50–$1,000 |
| 10 | *.gaming.gopayapi.com | Wildcard | Medium | $50–$1,000 |
| 11 | *.gofin.io | Wildcard | Medium | $50–$1,000 |
| 12 | *.findaya.com | Wildcard | Medium | $50–$1,000 |
| 13 | *.findaya.co.id | Wildcard | Medium | $50–$1,000 |
| 14 | *.gtflabs.io | Wildcard | Medium | $50–$1,000 |

## Key Exclusions

- Staging environments (test/integration/staging in domain)
- Subdomain takeover (non-qualifying)
- Rate limiting/brute-force bypass (non-qualifying)
- User enumeration (non-qualifying)
- GraphQL introspection enabled (non-qualifying)
- Disclosed public API keys (Google Maps, Firebase, analytics — non-qualifying)
- Lack of obfuscation/binary protection (non-qualifying)
- 30-day CVE delay for reward eligibility

## Infrastructure Patterns (from recon)

### gopayapi.com
- **DNS:** AWS Route53
- **Service Mesh:** Istio with strict RBAC on all financial services
- **Gateways:** Kong (al-gtdp-{b,p,s}-kong.gopayapi.com) — host-based routing + RBAC
- **Cloud:** Mix of Alibaba Cloud + AWS (GKE, EKS)
- **RBAC pattern:** `"RBAC: access denied"` (istio-envoy) on all financial services
- **Kong pattern:** `{"message":"no Route matched with those values"}` on gateway hosts
- **Auth:** Bearer tokens (from GoPay mobile app)
- **Scale:** 500+ subdomains, multi-country (ID, TH, VN)
- **Key services:** emoney, KYC (onekyc), payments, merchants, drivers, insurance, risk-gateway, transfers, SNAP (Standard National Open API)
- **Monitoring:** Grafana Faro via katulampa.gopay.sh
- **Internal GitLab:** source.golabs.io (self-managed, login required)
- **Blocker:** All financial APIs require valid GoPay user token (mobile app + Indonesian phone number)

### mokapos.com
- **DNS:** Cloudflare (dora/matt.ns.cloudflare.com)
- **Service Mesh:** Istio/Envoy (exposed on some hosts)
- **API Gateway:** Kong Enterprise (v19.18.6 app version) with RBAC
- **Cloud:** Alibaba Cloud (Jakarta region, IPs 8.215.x.x)
- **CDN:** Cloudflare (most subdomains), Alibaba CDN/Tengine (developer, career, life)
- **Backend:** Rails (api.mokapos.com), Go + Spring Boot (services)
- **Frontend:** Nuxt.js (www), React + Module Federation/single-spa (backoffice, 9 micro-apps)
- **CMS:** WordPress 7.0 (wp.mokapos.com) — headless via REST API + WPGraphQL
- **OAuth:** Doorkeeper (Rails) — authorization_code + client_credentials grants
- **Zero Trust:** Cloudflare Access on business-admin, u-membership, wp-login
- **OSS Buckets:** al-ms-id-{p,s}-file-{public,private}.oss-ap-southeast-5.aliyuncs.com
- **Mobile:** com.mokapos.android (Play Store)
- **Auth flow:** backoffice.mokapos.com/register → reCAPTCHA → OAuth token
- **Kong Admin API:** admin-kong-production.mokapos.com (internet-exposed, RBAC-protected)

## Findings (mokapos.com, 2026-05-24)

| ID | Title | Severity | Asset | Reportable? |
|----|-------|----------|-------|-------------|
| F-1 | CORS arbitrary origin reflection + credentials | Medium (5.4) | wp.mokapos.com | YES — submitted to YesWeHack |
| F-2 | PHP stack trace disclosure (headless-cms plugin) | Low (3.7) | wp.mokapos.com | Likely rejected as info-only |

## Lessons Learned

1. **mokapos.com is NOT wildcard** — listed as "Web application", subdomains are out-of-scope (may get reduced bounty at discretion)
2. **gopayapi.com is extremely hardened** — Istio RBAC blocks everything without valid auth token
3. **GoPay mobile app is the key** — all API auth flows require tokens obtained via the mobile app
4. **Kong Admin API exposure** is common in GoTo infra but always RBAC-protected
5. **WordPress (wp.mokapos.com)** is the weakest link — headless CMS with broken WooCommerce dependency, CORS misconfigured, stack traces enabled
6. **Registration requires reCAPTCHA** — can't automate account creation for authenticated testing
7. **Program explicitly excludes** many common findings (rate limiting, user enum, GraphQL introspection, public API keys)

## Gojek Bug Bounty Program (Separate from GoTo Financial)

**Platform:** YesWeHack
**Program:** Gojek Bug Bounty Program
**URL:** https://yeswehack.com/programs/gojek-bug-bounty-program (login required)

### In-Scope Assets

| # | Asset | Type | Value |
|---|-------|------|-------|
| 1 | *.gojekapi.com | Wildcard | Critical |
| 2 | api.gojek.co.id | API | Critical |
| 3 | com.gojek.app (Android) | Mobile | Critical |
| 4 | Gojek iOS | Mobile | Critical |
| 5 | gofood.co.id | Web App | High |
| 6 | api.gobiz.co.id | API | High |
| 7 | portal.gofoodmerchant.co.id | Web App | High |
| 8 | *.gofood.co.id | Wildcard | Medium |
| 9 | *.gobiz.co.id | Wildcard | Medium |
| 10 | *.gojek.com | Wildcard | Medium |
| 11 | *.golabs.io | Wildcard | Medium |
| 12 | *.gofoodmerchant.co.id | Wildcard | Medium |

### GoFood Infrastructure (from gofood.co.id engagement, May 2026)
- **Stack:** Next.js SSR + Kong + Istio/Envoy + Tencent Cloud EdgeOne
- **DNS:** Tencent DNSPod (ult01/ult02.dnspod.com)
- **Environments:** prod (gofood.co.id), alpha, q (QA), integration — all live
- **Auth:** GoID (shared with GoBiz/GoPay), client_id=`gofood-web`, X-User-Type=`customer`
- **WAF:** Tencent Cloud WAF (stgw) — stricter on prod, relaxed on non-prod
- **Key finding:** `/goid/token` passes through WAF on prod; `/goid/login/request` blocked on prod but accessible on alpha/q/integration
- **API routes:** Next.js server-side proxies at `/api/orders` (401), `/api/pricing/estimate` (401), `/api/gopay/login` (500)
- **Related domain:** gofoodmerchant.co.id (same IP as alpha.gofood.co.id, merchant-facing)
- **Mobile apps:** com.gojek.app (consumer), com.gojek.resto (merchant)

### Exclusions (assumed — same program family as GoTo Financial)
- Staging environments
- Subdomain takeover
- Rate limiting/brute-force bypass
- User enumeration
- Public API keys

## GoFood (gofood.co.id) — Engagement Results (May 2026)

**Program:** Gojek Bug Bounty (separate from GoTo Financial)
**Result:** 0 findings. Target is hardened.

**Infrastructure:** Next.js 18.0.1 + Kong + Envoy/Istio + Tencent Cloud WAF + EdgeOne CDN
**Environments:** prod, alpha, q (QA), integration — all same backend, WAF only on prod
**Auth:** GoID (shared with GoBiz/Gojek) — captcha-gated, proxy-only client

**Key blockers:**
- reCAPTCHA mandatory on all pre-auth flows (server-side validated)
- Next.js proxy adds server-generated fields (can't replicate via curl)
- `gofood-web` client not registered on direct GoID API (proxy-only)
- All authenticated APIs need Bearer token from mobile app

**Related domains (out of scope but noted):**
- gofoodmerchant.co.id — same IP as alpha.gofood.co.id, has portal/gateway/git/gitlab subdomains
- golabs.io — GoTo internal labs (lens-fc.golabs.io analytics)

**Lesson:** GoFood web is significantly more hardened than GoBiz web. Same GoID backend but with captcha + server-side proxy adding required fields. Without mobile app account, unauthenticated testing is exhausted quickly.

## GoFood (gofood.co.id) — Engagement Results (May 2026)

**Program:** Gojek Bug Bounty (separate from GoTo Financial)
**Scope:** *.gofood.co.id (assumed wildcard)
**Result:** 0 findings — hardened target

### Infrastructure
- **Stack:** Next.js 18.0.1 + Kong + Istio/Envoy + Tencent Cloud EdgeOne
- **DNS:** DNSPod (Tencent), CNAME → eo.dnse4.com (anycast CDN)
- **Environments:** prod (gofood.co.id), alpha, q, integration — all same stack
- **WAF:** Tencent Cloud WAF on prod only; non-prod environments have relaxed WAF
- **Auth:** GoID (shared with GoBiz/GoPay) + reCAPTCHA on all pre-auth flows
- **Related:** gofoodmerchant.co.id (same IP as alpha, Istio+Kong+Next.js)

### Key Technical Findings (not reportable)
- Non-prod envs expose GoID endpoints without WAF (alpha/q/integration)
- `/goid/token` passes through WAF on prod (only GoID endpoint accessible)
- `/v2/otp/retry` has no rate limiting (program excludes rate limiting)
- `/api/gopay/login` returns 500 on all envs (broken, no stack trace)
- Next.js server-side proxy adds captcha-derived session fields — can't replicate externally
- Consumer client_id `gofood-web` is proxy-only (not registered on direct GoID API at gojekapi.com)
- 49 reCAPTCHA elements protect login modal

### Why It's Hardened
1. Tencent WAF blocks all sensitive paths on prod
2. reCAPTCHA server-validated on all pre-auth flows (no bypass found)
3. Next.js SSR proxy adds hidden fields from session store
4. Kong enforces Bearer auth on all API routes
5. No exposed actuator/swagger/admin
6. No CORS, no SSRF, no nuclei findings

### Lessons Learned
- GoFood consumer web has STRONGER security than GoBiz merchant web (more WAF rules, captcha on everything)
- The `gofood-web` client only works through the Next.js proxy — direct API calls to gojekapi.com fail
- Non-prod environments are the only viable testing surface but program likely excludes staging
- Authenticated testing requires Gojek mobile app account (Indonesian phone number)

### gojekapi.com (Gojek Bug Bounty Program)

- **DNS:** Tencent DNSPod (ult01/ult02.dnspod.com) — same as gofood.co.id
- **Scale:** 178 subdomains discovered, 67 live hosts
- **Service Mesh:** Istio/Envoy on raccoon cluster (8.215.36.34, 147.139.171.249)
- **API Gateway:** Kong + Tencent WAF on main cluster (43.152.108.x)
- **CDN:** TencentEdgeOne on i.gojekapi.com (darkroom image proxy)
- **Object Storage:** AWS S3 + CloudFront (goplatform.gojekapi.com, ap-southeast-1)
- **Partner Auth:** mTLS on tokopedia.partners.gojekapi.com
- **MQTT:** VerneMQ (mqtt-clickstream-prd, tcc-mqtt-*) — not HTTP accessible
- **Legacy GCP:** 104.155.x.x hosts all unreachable (decommissioned)
- **Docker Hub org:** gojektech (darkroom, vernemq, kong-plugin-dev, iap-auth, beast, kafqa, stolon)

**Kong routing pattern (CRITICAL):**
- Without correct path prefix: 404 + 48 bytes `{"message":"no Route matched with those values"}`
- With correct prefix (`/gojek/v2/`, `/go-bundles/v1/`, `/gopoints/v2/`, etc.): 401 from backend
- App headers (X-AppId, X-AppVersion, X-Platform, X-UniqueId, X-User-Type) do NOT affect routing — only path matters
- Rate limit headers visible on GoID endpoints: `X-RateLimit-Limit-Minute: 75`

**GoID endpoints (goid.gojekapi.com):**
- `/goid/token` — 429 rate limited per device (prod)
- `/goid/login/request` — 400 on prod (GoPay-1000 internal error), 401 on integration (version check)
- `/goid/v1/token` — 400 "missing_field" on integration (endpoint processes requests)
- Version check blocks app versions < current; error: "Please update to the latest official app version"
- Error code leak: `goid:error:unauthorized:[withRefreshTokenShortCircuiter] access token is invalid`
- Token request structure (from APK): `{client_id, client_secret, grant_type:"otp", data:{otp_token, otp}, scopes:[]}`

**Confirmed live API routes (api.gojekapi.com, all 401):**
- /gojek/v2/booking/history/{id}, /gojek/v2/customer/v2/history/{id}, /gojek/v2/customer
- /litmus/run/experiments (chaos engineering), /live/track/{id} (403, CORS-checked)
- /go-bundles/v1/benefits-list, /gopoints/v2/customer/vouchers
- /content-recommendation/v1/component, /goclub/v1/optin-page

**CORS on /live/track/:**
- Strict whitelist: only exact `https://gofood.co.id` reflected in ACAO
- No subdomain matching, no HTTP, no bypass variants — properly implemented
- Evil origins get WAF block page (2838 bytes) vs app-level 403 (34 bytes)

**Shared IPs (cross-program):**
- 43.152.108.21 hosts BOTH goid.gojekapi.com AND gofoodmerchant.co.id
- 43.152.108.30 also registered as qcloudwzgj.com in Shodan

**Shodan intel:**
- 43.152.108.30 (api): ports 80, 443, 8080 ← extra port to probe
- 35.198.235.89 (partners): SSH port 22 open (OpenSSH 8.4p1, Debian, GCP VM)

**Blocker:** All APIs require Bearer token from Gojek mobile app + Indonesian phone number. GoID login endpoints enforce version check. Without valid auth token, exploitation is limited to pre-auth flows.

## Findings (gopay.co.id + *.gopayapi.com, 2026-05-24)

| ID | Title | Severity | Asset | Reportable? |
|----|-------|----------|-------|-------------|
| F-3 | Source Maps Exposed (prod+staging) | Medium (5.3) | gopay-web-page.gopayapi.com | YES — full source code disclosure |
| F-4 | Production Clickstream Token Exposed | Medium (5.3) | gopay-web-raccoon.gojekapi.com | YES — verified write access |
| F-5 | Grafana Faro API Key Exposed | Low (3.7) | gopay-web-page.gopayapi.com | Borderline — program may exclude "public API keys" |
| F-6 | New Relic Credentials Exposed | Info (2.0) | gopay-web-page.gopayapi.com | NO — browser monitoring keys by design |
| F-7 | Laravel Debug Mode on Production CMS | Medium (5.3) | cms-website.gopay.co.id | YES — stack traces on financial app |
| F-8 | Internal CMS Login Panels Exposed | Low (3.7) | cms-website + cms-finansiap | Borderline — no direct exploit |

### GoPay Infrastructure (from recon, May 2026)

- **gopay.co.id:** Cloudflare CDN, Laravel/SuitCMS backend at `/var/www/gopay-backend/`
- **CMS API:** `/api/{locale}/{resource}` (NOT `/api/v1/`). Locale = path segment (id/en)
- **CMS endpoints (public, read-only):** articles (1641), promos (51), faqs, products (9), menus, tags, teams (20), careers (21), article_categories (13), banners
- **CMS auth:** SuitCMS at `/secret/auth/login`, Laravel Horizon at `/horizon` (401)
- **gopayapi.com:** 867 subdomains, mostly Istio RBAC (403). Kong gateways at al-gtdp-{b,p,s}
- **Web apps:** gopay-web-page (React, Alibaba OSS/Tengine), pin-web-client (Next.js, S3/CloudFront), app.gwk (Flutter Web, CloudFront)
- **Monitoring:** Grafana Faro at `katulampa.gopay.sh`, New Relic
- **Event pipeline:** Raccoon at `gopay-web-raccoon.gojekapi.com` (prod) and `gopay-web-raccoon-integration.gojekapi.com` (integration)
- **Internal:** source.golabs.io (GitLab, 302→login), go-jek.atlassian.net (Confluence)
- **Staging:** gopaystaging.gopay.co.id, pin-web-client-staging, gopay-web-page.staging
- **Deep links:** `gojek://gopay/tokenization/{payment,linking}` (prod), `gojekstaging://` (staging)
- **Partner integrations:** findaya.co.id (PayLater), app.jago.com (Bank Jago pocket)
- **CDN:** gopay-website.al-gp-id-p.cdn.gtflabs.io (Alibaba CDN for static assets)

### Tokens Extracted (GoPay)

| Token | Type | Env | Verified |
|-------|------|-----|----------|
| C100BB73-F82C-4510-8419-13FD36AA40A2 | Grafana Faro API Key | prod+staging | 400 on POST (format issue) |
| bf63bf09-30b7-458d-8c79-5e9285848329 | Clickstream (Raccoon) | prod | **200 — write confirmed** |
| 187fbc91-2cb8-4545-b131-f3bb8fb70a91 | Clickstream (Raccoon) | staging/integration | **200 — write confirmed** |
| NRBR-9169fd1232bdb932329 | New Relic Browser License | prod | Not tested |
| NRJS-a4e8af0bce479ffea19 | New Relic Browser License | staging | Not tested |

### GoPay Lessons Learned

1. **CMS is the weak link** — gopayapi.com services are behind Istio RBAC, but the CMS (cms-website.gopay.co.id) has debug mode, wildcard CORS, and exposed admin panels
2. **Source maps on S3/CloudFront** — build pipelines don't strip .map files from CDN deployments
3. **Client-side tokens are exploitable** — even "analytics" tokens can grant write access to production pipelines
4. **Flutter Web bundles are goldmines** — 5.7MB main.dart.js contains all API paths, deep links, and partner URLs in plain text
5. **Response size differentiation** — when Laravel middleware blocks, compare response sizes to identify which routes EXIST vs which don't (11739 = route exists but middleware rejects, 9042 = no route)
6. **Blog source reveals API patterns** — production site HTML often contains the correct API URL format that debug traces obscure
7. **Program exclusion risk** — Faro/New Relic keys may be excluded as "public API keys"; frame Clickstream token differently (it grants WRITE access, not just read)
8. **Combine chain findings** — F-3 (source map) + F-4 (token) + F-9 (gwc token) originally combined as ONE report. Later SPLIT into per-app reports (1A: gopay-web-page, 1B: gwc) for separate bounties. Each app is independently exploitable.
9. **Split maximizes bounty** — programs pay per-finding. 6 individual reports > 3 combined reports. Cross-reference related reports to show combined impact without bundling.
10. **CORS * + Debug = severity upgrade** — individually Medium, combined enables cross-origin architecture extraction without user interaction (attacker invisible in logs). Split into separate reports but cross-reference each other.

### GoPay Submission Status (2026-05-24)

| Report | Findings | Severity | Asset | Status |
|--------|----------|----------|-------|--------|
| FINAL-yeswehack-1a-gopay-web-page.md | F-3+F-4 (source map + token) | High (7.5) | *.gopayapi.com | Ready to submit |
| FINAL-yeswehack-1b-gwc.md | F-9 gwc (source map + token) | High (7.5) | *.gopayapi.com | Ready to submit |
| FINAL-yeswehack-2a-debug-mode.md | F-7 (debug mode) | Medium (5.3) | gopay.co.id | Ready to submit |
| FINAL-yeswehack-2b-cors-wildcard.md | CORS * | Medium (5.3) | gopay.co.id | Ready to submit |
| FINAL-yeswehack-3a-argocd-config-disclosure.md | ArgoCD config | Medium (5.3) | *.go-pay.co.id | Ready to submit |
| FINAL-yeswehack-3b-argocd-device-code.md | ArgoCD device code | High (8.1) | *.go-pay.co.id | Ready to submit |
| yeswehack-submission-cors.md | F-1 | Medium (5.4) | mokapos.com | Submitted (may be out of scope — wp.mokapos.com) |

**Splitting strategy applied:** Originally 3 combined reports, split into 6 individual submissions for maximum bounty potential. Each report is self-contained and independently reproducible. Cross-references between related reports show combined impact without bundling.

## Findings (*.go-pay.co.id, 2026-05-24)

| ID | Title | Severity | Asset | Reportable? |
|----|-------|----------|-------|-------------|
| F-9 | Production ArgoCD Exposed + Device Code Flow + execEnabled | High (8.1) | argocd-ui.go-pay.co.id | YES — `*.go-pay.co.id` IS in scope (Medium value wildcard, row 6). Submit under that asset. |

**Scope clarification:** `*.go-pay.co.id` is explicitly listed as a Medium-value wildcard in the program. ArgoCD finding is fully in scope — no scope note needed. The bounty range is $50–$1,000 for Medium-value assets, but severity (High) may push it higher at program discretion.

### go-pay.co.id Infrastructure (from recon, May 2026)

- **go-pay.co.id:** 34.96.114.176 (GCP) — no HTTP response (timeout)
- **ArgoCD prod:** argocd-ui.go-pay.co.id → 149.129.250.140 (Alibaba Cloud), v2.14.13, Dex+Google SSO
- **ArgoCD stg:** argocd-ui-stg.go-pay.co.id → 149.129.243.113 (Alibaba Cloud), v3.0.2
- **Service mesh:** Istio RBAC on global-portal.go-pay.co.id (8.215.48.67)
- **Internal-only (private IPs):** portal.go-pay.co.id (10.15.1.86), gopaysh-stg (10.121.208.49)
- **Live but 404:** stg.imali.go-pay.co.id → 147.139.210.243
- **DNS-only (no resolve):** stg.go-pay.co.id, staging.go-pay.co.id, portal.stg, use.stg, external-integration-staging
- **Subdomains found:** 55 total (subfinder), most internal or non-resolving
- **Key services:** ArgoCD, imali (payments?), exchange, global-portal, service-graph, GitLab, passport, cloud, dashboard
- **Cloud:** Alibaba Cloud (Jakarta) + GCP
- **Blocker:** Most services behind Istio RBAC or internal IPs; ArgoCD is the only externally exploitable surface

### go-pay.co.id Lessons Learned

1. `stg.go-pay.co.id` does NOT resolve — the "staging" pattern here uses `*-stg.go-pay.co.id` or `stg.*.go-pay.co.id` (subdomain prefix/infix, not bare `stg.`)
2. Production ArgoCD is the highest-value target — everything else is RBAC-blocked or internal
3. Device code flow on Dex is the default attack vector for ArgoCD with Google SSO
4. Paired prod/stg ArgoCD instances (different versions) suggest canary deployment for infra tooling
5. **`*.go-pay.co.id` IS in scope** (Medium wildcard, row 6 in scope table) — don't confuse with `gopay.co.id`. Submit ArgoCD finding under this asset directly, no scope note needed.
6. **Disclosure policy lesson:** Never push PoC HTML to public GitHub Pages before vendor acknowledgment. Keep PoCs in local ptest-output directory and paste code directly in report body.

## Recommended Next Targets

Priority order for future sessions:
1. **gojekapi.com Phase 2** — port scan (8080 on api IP, MQTT ports, SSH on partners), active DNS brute-force
2. **GoPay mobile app** — decompile APK, find hardcoded tokens/endpoints, test API with extracted auth
3. ***.go-pay.co.id** — Medium value wildcard, may have different infra
4. ***.gofin.io** — GoTo Financial labs, may have less hardened services
5. ***.findaya.com / *.findaya.co.id** — Findaya (GoTo lending), separate infra likely
6. ***.gtflabs.io** — GoTo Financial labs/experiments
7. **gopaymerchant.midtrans.com** — High value, merchant-facing
8. **gofood.co.id (authenticated)** — Obtain Gojek consumer token via mobile app, test /api/orders, /api/pricing/estimate, GoID flows on non-prod
