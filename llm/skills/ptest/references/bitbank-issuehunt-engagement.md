# bitbank.cc — IssueHunt Bug Bounty Engagement Intel

## Program
- Platform: IssueHunt (Japanese #1 bug bounty platform)
- URL: https://issuehunt.io/programs/ff1efa2d-4f57-4a8b-95b9-19f0a3f40d75
- IssueHunt program URLs use UUID format: `/programs/{uuid}`
- Company: bitbank, inc. (Japanese crypto exchange, Kanto Finance Bureau #00004)

## Scope (STRICT — not wildcard)
- bitbank.cc (main site)
- app.bitbank.cc (trading app)
- api.bitbank.cc (private REST API)

## Rewards
- Low: ¥5,000–¥10,000
- Medium: ¥10,000–¥100,000
- High: ¥100,000–¥300,000
- Critical: ¥300,000–¥5,000,000

## Out of Scope (key exclusions)
- Automated scanner output without analysis
- Brute force credential attacks
- Login/Logout CSRF, missing CSRF tokens
- Missing security headers without direct vuln
- Username/email enumeration
- SPF/DKIM/DMARC misconfig
- Vuln from other domains than the 3 specified

## Infrastructure
- CDN: CloudFront (all targets) — no direct origin exposed
- DNS: AWS Route53
- Storage: S3 (static sites + bankmaster data)
- API: Node.js + nginx behind CloudFront
- Frontend: Angular SPA (app.bitbank.cc) with ngrx, chunk-based lazy loading
- Main site: Next.js SSG (static export to S3)
- Realtime: PubNub (sub-c-ecebae8e-dd60-11e6-b6b1-02ee2ddab7fe) + Socket.IO (stream.bitbank.cc)
- Monitoring: Sentry (project 294271)
- Anti-bot: Google reCAPTCHA v2
- Email: Google Workspace + Amazon SES + Zendesk + Marketo
- DMARC: p=reject (properly enforced)

## API Auth Mechanism
- HMAC-SHA256 signature (NOT cookie-based)
- Headers: ACCESS-KEY, ACCESS-SIGNATURE, ACCESS-NONCE (or ACCESS-REQUEST-TIME + ACCESS-TIME-WINDOW)
- Signature input (GET): `{nonce}{full_path_with_query}`
- Signature input (POST): `{nonce}{json_body}`
- HMAC key = API secret (generated in user's access key page)
- Official docs: github.com/bitbankinc/bitbank-api-docs

## Public Endpoints (no auth)
- api.bitbank.cc/v1/spot/pairs — trading pair config
- api.bitbank.cc/v1/spot/status — exchange status
- public.bitbank.cc/{pair}/ticker — market ticker
- public.bitbank.cc/{pair}/depth — order book
- public.bitbank.cc/{pair}/transactions — trade history
- bitbank.cc/api/app-campaign/banners — campaign banners
- bitbank.cc/api/app-campaign/internal-ads — internal ads
- bitbank.cc/api/blog/articles — blog articles
- bankmaster.bitbank.cc/banks — Japanese bank code list (gzip JS)

## CORS Behavior
- api.bitbank.cc reflects ANY *.bitbank.cc origin in Access-Control-Allow-Origin
- Does NOT set Access-Control-Allow-Credentials: true
- Auth is header-based (HMAC), not cookies → CORS reflection alone not exploitable
- Would become exploitable IF: (a) cookie/session auth added, (b) subdomain takeover achieved

## Discovered Subdomains (out of scope, informational)
- stream.bitbank.cc — Socket.IO realtime (nginx)
- bankmaster.bitbank.cc — bank code data (S3)
- stg.bitbank.cc — staging (CloudFront)
- dev.bitbank.cc — development (CloudFront)
- gitlab.p0fuy9f4prap28og.bitbank.cc — internal GitLab (35.79.34.56)
- regtest.bitbank.cc — Bitcoin regtest (54.144.34.208)
- support.bitbank.cc → bitbankcc.zendesk.com
- corporate.bitbank.cc → Vercel
- tech.bitbank.cc → Ghost on Fastly

## GitHub Presence (bitbankinc org)
- bitbank-api-docs (125 stars) — REST + streaming API docs
- bitbank-mcp-server — MCP integration (TypeScript)
- mock-bitbankcc — Docker mock API (reveals endpoint structure)
- exchangeDepositContract — Solidity deposit contract
- python/ruby/java/node-bitbankcc — official client libs

## Attack Vectors for Phase 3+
1. API HMAC signature — test replay, timing leakage, missing signature validation on specific endpoints
2. PubNub channels — check if private user data (orders, balances) leaks to any subscriber
3. Socket.IO stream — unauthorized channel subscription for private data
4. /account/ routes (96 discovered) — test each for auth enforcement without HMAC
5. Undocumented API routes — fuzz api.bitbank.cc/v1/
6. /announcement/draft/ — unpublished content exposure
7. token header in CORS allow-headers — may indicate alternate auth path
8. bankmaster.bitbank.cc — S3 bucket object listing (NoSuchKey on root = bucket exists)

## Mobile Apps
- iOS: cc.bitbank.mobile (v3.7.1, App Store ID 1352242602)
- Android: likely same bundle ID (unconfirmed)

## Related Domain
- bitcoinbank.co.jp (DMARC rua recipient — same company)
