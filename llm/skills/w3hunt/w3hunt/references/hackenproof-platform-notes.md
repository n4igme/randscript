# HackenProof Platform Notes

## Platform Overview
- Web3-focused bug bounty platform (competitor to Immunefi)
- Run by Hacken (blockchain security/audit company, Estonian entity Hacken OÜ)
- Programs page: https://hackenproof.com/programs
- **Cloudflare blocks automated access** — can't curl/browse program pages programmatically

## Key Differences from Immunefi
- Generally smaller payouts but less competition
- More web/app scope programs
- Less strict PoC requirements than Immunefi
- Some programs accept Medium/Low findings that Immunefi wouldn't
- Submission rate limits: TBD (not yet confirmed)

## Hacken's Own Bug Bounty (*.hacken.io)

### Infrastructure
- Most subdomains behind Cloudflare CDN (same IPs: 172.67.75.194, 104.26.13.140, 104.26.12.140)
- GitHub orgs: `hackenproof` (5 repos), `hknio` (21 repos — main engineering), `hai-group` (1 repo)
- Tech stack: Next.js (main site), Rails (assets), Express.js (cmc-api), Supabase (scoping)

### Subdomains (19 discovered via HackerTarget, crt.sh was down)
- **scoping.hacken.io** — Vercel (NO Cloudflare WAF), Supabase backend, "Hacken Sharing Tool" for private repo access control
- **auth.scoping.hacken.io** — Supabase auth (project ref: znksrgcjncicswolrntc), CORS wildcard confirmed
- **assets.hacken.io** — Rails backend, .env blocked by WAF (403 vs normal 404 = file exists)
- **cmc-api.hacken.io** — Express.js, serves full audit database at root (public data)
- **hai.hacken.io** — $HAI token app, nginx/1.29.3 leaked
- **exchange-notifier.hacken.io** — dangling DNS (A record → 1.1.1.1)
- **wp.hacken.io** — WordPress behind Cloudflare Access (Zero Trust)
- **devwp.hacken.io** — parked/dead (redirects to dns.google)

### Findings (2026-05-25)
1. auth.scoping.hacken.io CORS wildcard (`Access-Control-Allow-Origin: *`) — Medium
2. exchange-notifier.hacken.io dangling DNS — Low-Medium
3. cmc-api.hacken.io X-Powered-By: Express — Info
4. hai.hacken.io nginx version disclosure — Info

### Best Attack Vector
**scoping.hacken.io** — needs authenticated testing:
- Supabase anon key not in client JS (server-side rendered)
- Need to sign up → capture anon key from network requests
- Then test: RLS bypass, IDOR on shared repos, auth bypass
- CORS * on auth endpoint becomes exploitable if anon key is found

### Working Directory
`/Users/nb-dk-0552/PenTest/Hunting/Hackenproof/Hacken/`

## Supabase Testing Methodology (reusable)

When a target uses Supabase:

1. **Find project ref** — look for `*.supabase.co` in JS bundles, DNS CNAMEs, or response headers (`sb-project-ref` header)
2. **Find anon key** — search JS chunks for `eyJ...` JWT tokens, check `__NEXT_DATA__`, RSC payloads, or capture from authenticated network requests
3. **Test without key** — all Supabase endpoints return 401 "No API key found" without it
4. **With anon key, test:**
   - `GET /rest/v1/<table>?select=*` — enumerate tables, check RLS
   - `POST /rest/v1/<table>` — test write access
   - `GET /auth/v1/admin/users` — admin endpoint (should be blocked by anon key)
   - `GET /storage/v1/bucket` — list storage buckets
   - `POST /auth/v1/signup` — can you create accounts?
   - `POST /auth/v1/token?grant_type=password` — test auth
5. **CORS on Supabase is always `*`** — this is by design (client-side SDK). The security is in RLS policies and API key scoping. CORS * alone on Supabase is NOT a finding unless combined with leaked service_role key or broken RLS.
6. **Key types matter:**
   - `anon` key — public, limited by RLS policies
   - `service_role` key — bypasses RLS, full access (finding this = Critical)
   - Check if service_role key is accidentally exposed in client JS or error messages
