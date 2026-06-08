# ByteDance SoundOn — Target Intel

## Platform
- **Program:** HackerOne (TikTok)
- **Product:** SoundOn — music distribution platform for artists
- **Domain:** soundon.global (wildcard cert *.soundon.global)
- **Parent:** ByteDance/TikTok

## Infrastructure
- **CDN:** Akamai (edgekey.net, AkamaiGHost)
- **LB:** TLB (TikTok Load Balancer)
- **IDC:** sg1 (Singapore), alisg (Alibaba SG)
- **DNS:** Akamai NS (a1-156.akam.net, etc.)
- **Frontend:** React SPA with Modern.js (Rsbuild), two apps:
  - client-main: authenticated dashboard (CSR only)
  - client_seo: public pages with SSR (__MODERN_ROUTER_DATA__)
- **Anti-bot:** webmssdk (X-Bogus, _signature, msToken params)
- **Privacy:** Pumbaa (TikTok Privacy Protection Framework)
- **SecSDK:** Argus project-id 2382
- **Deploy:** Goofy Deploy (internal ByteDance CD system)

## Subdomains (4 total, tight scope)
- www.soundon.global — main app (200, TLB)
- soundon.global — same as www
- us.soundon.global — 301 redirect to www
- sf-soundon-ug.soundon.global — UGC CDN (403 Akamai)

## Unauthenticated API Endpoints
- /api/open/ping — env, version (1.0.2.5462), isProd
- /api/open/region — user region, available regions, login status
- /api/open/config — VOD/ImageX service IDs, upload hosts
- /api/open/feelgood/token — JWT with platform config (no auth!)
- /api/open/fg — feature gates

## JWT from /api/open/feelgood/token
- Algorithm: HS256, TTL: 7200s
- Leaks: artists-test.bytedance.net (internal, 10.179.156.79)
- Platform ID: 7231002700274647041
- Trigger events: aigcMVVideoTaskDone, ai_session_end, createArtistPage, etc.

## Authentication
- TikTok OAuth (login/oauth/middle)
- Google OAuth (accounts.google.com/o/oauth2/v2/auth)
- Session: cookie-based (Unauthorized on missing cookie)

## Key Attack Surface (authenticated)
- /api/user, /api/team/current — account info
- /api/album/list, /api/release — music management
- /api/contract/*, /api/revenue/balance — financial
- /api/royalty-splits — multi-party payment splitting
- /api/invite/code, /api/team-invite/confirm — team management
- /api/promo/* — promotional features
- /api/data/dsp/trend, /api/data/tt/trend — analytics (need msToken+X-Bogus)

## Security Posture
- Akamai WAF: blocks XSS/SQLi probes (403)
- CSP: report-only (unsafe-eval + unsafe-inline) — XSS CAN execute
- No X-Frame-Options, no HSTS, no X-Content-Type-Options
- CORS: not reflective (only expose-headers)
- No DMARC record (email spoofing possible but low impact for non-financial)
- TRACE: blocked (403)

## Priority Vectors for Exploitation
1. IDOR on artist/contract/release IDs (numeric IDs in API)
2. OAuth flow manipulation (state parameter, redirect_uri)
3. Bio page XSS (user-controlled content in SSR, CSP is report-only)
4. Team invite token prediction/reuse
5. Royalty split manipulation (financial impact)
6. msToken/X-Bogus bypass for data endpoints
