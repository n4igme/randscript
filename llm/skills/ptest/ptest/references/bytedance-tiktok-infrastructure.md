# ByteDance / TikTok Infrastructure Patterns

## Tech Stack Fingerprints

| Header/Signal | Meaning |
|---------------|---------|
| `Server: TLB` | TikTok Load Balancer (custom) |
| `X-Powered-By: Goofy Deploy` | ByteDance Node.js deployment framework |
| `X-Powered-By: Goofy Node` | ByteDance Node.js runtime |
| `X-Cache: ... AkamaiGHost/22.x` | Akamai CDN (primary) |
| `nonce="argus-csp-token"` | Argus anti-bot / CSP system |

## Frontend Architecture

- **UI Library:** Arco Design (ByteDance, `@arco-design/web-react`)
- **Micro-frontend:** Garfish (module federation, `garfishModuleInfo` in page source)
- **Framework:** React 18 + EdenX runtime
- **Build system:** VMOK (module federation variant)
- **Privacy:** Pumbaa privacy protection framework (loader in `<script>` tags)
- **Monitoring:** Slardar (ByteDance APM, `slardar-config` JSON in page)
- **Analytics:** Tea (ByteDance telemetry)
- **AB Testing:** LibraWeb (`libraweb-sg.tiktok.com`)
- **i18n:** Starling (`starling-sg.tiktokv.com`)
- **Anti-bot SDK:** MSSDK (`webmssdk.js`, `mssdk-sg.tiktok.com`)

## Domain Ecosystem

| Domain | Purpose |
|--------|---------|
| tiktok.com | Main platform |
| tiktokv.com | Video CDN / MCS telemetry API |
| tiktokcdn-us.com | US CDN (lf16-cdn-tos, lf16-tiktok-web) |
| ttwstatic.com | Static assets (sf16-website-login.neutral) |
| byteoversea.com | ByteDance overseas infra (maliva-mcs) |
| byteintlapi.com | ByteDance international API (followme, frontier) |
| tiktokd.net | Internal dev/canary deployments |
| tiktokglobalshop.us | E-commerce (TikTok Shop geo/address API) |
| snssdk.com | SDK/telemetry |
| tiktokw.eu | EU region |
| tiktokv.us | US video/API |
| oecsccdn.com | E-commerce CDN |

## Subdomain Naming Patterns

```
{env}.{service}.tiktok.com
```

Environments: `dev`, `staging`, `test`, `internal`, `admin`, `monitor`, `grafana`, `prometheus`, `jenkins`, `gitlab`, `alpha`

Services discovered: `im-ws`, `libraweb`, `feelgood-api`, `consentapi16-normal`, `livecenter`, `live-backstage`, `getstarted`, `login-row`, `login-us`, `login-no1a`, `analytics`, `ads`, `affiliate`, `image`, `email`, `lp`

Regions: `sg`, `va`, `ru`, `us`, `eu`, `alisg`, `no1a`, `row`, `useast5`, `useastred`

## Recon Tips

1. **JS bundle config extraction:** Look for `<script id="gfdatav1">`, `<script id="garfishModuleInfo">`, `<script id="scmconfigv1">`, `<script id="tiktok-environment">`, `<script id="pumbaa-rule">` — these contain IDC, region, API endpoints, module versions, and sometimes API keys.

2. **Module federation manifests:** Garfish apps expose `asset-manifest.json` at canary domains like `{random-words}.tx.tiktokd.net/asset-manifest.json` — these are internal dev endpoints.

3. **MCS endpoints (telemetry):** `mcs-{region}.tiktok.com/v1/list` and `mcs-{region}.tiktokv.com/v1/list` — telemetry collection, may accept crafted payloads.

4. **Frontier API gateway:** `frontier.tiktokv.us` / `frontier-i18n.byteintlapi.com` — backend API gateway for e-commerce services.

5. **Most internal tools (gitlab/grafana/jenkins/prometheus) are dead DNS** — TikTok has cleaned up. Focus on live 200 OK targets.

6. **WebSocket endpoints (`im-ws*.tiktok.com`)** return 400 without upgrade headers — need proper WebSocket handshake for testing.

7. **DMARC is p=reject** — email spoofing is not viable.

8. **Wayback Machine times out** for tiktok.com (too large) — use targeted URL patterns instead of wildcard.

9. **crt.sh returns empty** for large domains — use subfinder (got 682 subs) as primary source.

## Authentication & Security Architecture

### Cookie Model
| Cookie | SameSite | HttpOnly | Purpose |
|--------|----------|----------|---------|
| `sessionid` | Lax | Yes | Primary session (not sent cross-site POST) |
| `sessionid_ss` | None | Yes | Cross-site variant — does NOT authenticate alone |
| `sid_tt` | Lax | Yes | Session token (same value as sessionid) |
| `tt_csrf_token` | Lax | Yes | CSRF token |
| `ttwid` | None | Yes | Device tracking |
| `msToken` | None/Lax | No | Per-request token (client-generated, rotates) |
| `uid_tt` | Lax | Yes | User ID hash |
| `odin_tt` | Lax | Yes | Device fingerprint |

### Defense Layers (ordered)
1. **Akamai CDN** — blocks requests with non-TikTok `Origin` header (403 "Access Denied")
2. **Argus/MSSDK** — client-side request signing (`X-Bogus`, `_signature`). Raw requests without signatures get 403 on most POST endpoints
3. **CSRF token** — `status_code: 10402 "invalid csrf token"` on follow, privacy, IM settings, profile updates
4. **SameSite=Lax** — session cookies not sent on cross-site POST (browser enforcement)
5. **`sessionid_ss` (SameSite=None)** — exists but does NOT authenticate alone (needs Argus + other validation)

### CSRF Findings
- Endpoints WITH CSRF enforcement: `/api/commit/follow/user/`, `/api/privacy/*/update/*`, `/api/im_setting/update/v1`
- Endpoints WITHOUT CSRF (but protected by Argus + SameSite): `/api/collection/create|delete|modify_info|modify_items|move_items/`, `/api/dislike/item/`, `/api/drama/collect/`, `/api/impression/write/`, `/api/commit/remove/`, `/api/share/settings/`
- Logout (`/passport/web/logout/`) — no CSRF, but evil origin blocked by CDN

### Testing Approach
- **Raw requests (curl/Python)** — blocked by Argus on most state-changing endpoints
- **Playwright browser context** — bypasses Argus (browser generates signatures automatically)
- **Session reuse** — save cookies after manual login (CAPTCHA), reuse via `context.add_cookies()`. Session lasts days.
- **JS bundle extraction** — works via curl (no Argus on static assets). Found 259 API endpoints from 86 bundles.

### Key API Endpoints (from JS bundles, 259 total)
- Auth (37): `/passport/web/logout/`, `/passport/web/auth/bind/`, `/passport/web/fido2/*`
- User (50): `/api/update/profile/`, `/api/privacy/*/update/*`, `/api/user/block/`
- Content (90): `/api/aweme/delete/`, `/api/comment/publish/`, `/api/collection/*`
- Social (9): `/api/commit/follow/user/`, `/api/commit/follow/request/approve|reject/`
- Messaging (6): `/api/im/chat/notice`, `/api/im/stranger/unlimit/`

### Internal API Domains
| Domain | Purpose |
|--------|---------|
| `im-api-sg.tiktok.com` | IM REST API |
| `im-ws-sg.tiktok.com` | IM WebSocket (`wss://*/ws/v2`) |
| `t.tiktok.com` | Metrics/telemetry API |
| `webcast.tiktok.com` | Live streaming API |
| `location-sg.tiktokv.com` | Geolocation API |

## E-commerce (SCM) Architecture

The supply chain management platform (`scm-us.tiktok.com`) uses:
- Garfish micro-frontend with 8 modules: account, goods, stockin, stockout, inventory, universal, settlement, analytics
- Each module has its own CDN-hosted JS bundle with version tracking
- Config exposes: Google Maps API key, App ID, region, Frontier API domain, Geo API domain
- Internal module names follow `@i18n-sc-merchant/{module}` pattern
- Canary deployments use `{random-words}.tx.tiktokd.net` domains
