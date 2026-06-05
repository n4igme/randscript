# Bitbank.cc Engagement Intel

## Program Details
- Platform: IssueHunt (UUID-based URL: https://issuehunt.io/programs/ff1efa2d-4f57-4a8b-95b9-19f0a3f40d75)
- Scope: bitbank.cc, app.bitbank.cc, api.bitbank.cc (NOT wildcard)
- Company: bitbank, inc. (Japanese crypto exchange, Kanto Finance Bureau #00004)
- Rewards: Low ¥5K-10K, Medium ¥10K-100K, High ¥100K-300K, Critical ¥300K-5M
- Related domain: bitcoinbank.co.jp (DMARC rua recipient)

## Infrastructure
- CDN: CloudFront (all targets). No direct origin IP exposed.
- DNS: AWS Route53
- Frontend (bitbank.cc): Next.js SSG → S3
- Trading app (app.bitbank.cc): Angular SPA → S3 (496KB)
- API (api.bitbank.cc): Node.js + nginx behind CloudFront
- Stream (stream.bitbank.cc): Socket.IO (WebSocket only, no HTTP fallback)
- Public API (public.bitbank.cc): S3 static market data
- Realtime: PubNub (sub-c-ecebae8e-dd60-11e6-b6b1-02ee2ddab7fe) — Access Manager enforced

## Auth Mechanism (HMAC-SHA256)
- Headers: ACCESS-KEY, ACCESS-SIGNATURE, ACCESS-NONCE (or ACCESS-REQUEST-TIME + ACCESS-TIME-WINDOW)
- Signature (GET): HMAC-SHA256(secret, nonce + full_path_with_query)
- Signature (POST): HMAC-SHA256(secret, nonce + JSON_body)
- Error codes: 20001 (auth failed), 20002 (invalid key format), 20003 (no key), 20005 (invalid sig), 20011 (MFA failed)
- No key enumeration oracle — all invalid keys return same code
- NOT cookie-based → CSRF not applicable, CORS without Allow-Credentials not exploitable

## CORS Behavior
- api.bitbank.cc reflects ANY *.bitbank.cc origin in Access-Control-Allow-Origin
- Does NOT return Access-Control-Allow-Credentials: true
- Without credentials header, browsers block cross-origin reads with cookies
- Since auth is HMAC (custom headers), not cookies, the CORS config is not exploitable
- Evil subdomain (e.g., evilapp.bitbank.cc) would be reflected but can't steal HMAC auth

## Hardened Vectors (tested, not exploitable)
- PubNub channels: 403 Forbidden without auth token (Access Manager)
- API key enumeration: uniform 20001 for all invalid keys
- Admin/debug paths: none exist (no actuator, swagger, graphql, admin)
- S3 bucket listing: bankmaster.bitbank.cc only serves /banks (bank code list)
- Rate limiting: ~30 req/s threshold (429), but lenient at 5 req/s

## GitHub Org: bitbankinc
- bitbank-api-docs (125 stars) — full REST + Stream API reference
- mock-bitbankcc — WireMock-based mock (confirms no hidden endpoints)
- bitbank-mcp-server — TypeScript MCP for public market data
- exchangeDepositContract — Solidity (on-chain deposit contract)
- Client libs: python/ruby/java/node-bitbankcc

## Remaining Attack Vectors (for Phase 5+)
1. HMAC timing attack on signature verification (no rate limit on auth attempts)
2. WebSocket stream auth token lifetime/reuse (from /v1/user/private_stream)
3. Business logic in order/withdrawal flow (requires valid account)
4. Account registration flow vulnerabilities (KYC bypass, 2FA enrollment)
5. Angular app client-side auth state manipulation
6. OAuth/EPOS card application callback flow (/account/epos/card-application/auth/callback)

## Out of Scope Exclusions (from program)
- Automated scanner output, brute force, social engineering
- Login/Logout CSRF, missing CSRF tokens, missing security headers
- Username/email enumeration, stack traces, server banners
- SPF/DKIM/DMARC misconfig, SSL cipher issues
