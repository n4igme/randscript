# Hacken Engagement — HackenProof (2026-05-25)

## Target
- Program: Hacken (HackenProof — their own program)
- Scope: *.hacken.io (wildcard)
- Working dir: /Users/nb-dk-0552/PenTest/Hunting/Hackenproof/Hacken/

## Findings (1x High confirmed)

### Finding 1: SSRF via /api/download-file/ + /api/company-logo/ (High — CVSS 8.6)
**Pattern:** Next.js API routes that fetch arbitrary URLs server-side
- `/api/download-file/?url=` — restricted to `*.hacken.io` but bypasses Cloudflare Access on internal subdomains
- `/api/company-logo/?url=` — unrestricted outbound SSRF (fetches ANY external URL, returns response body as GIF)
**Impact:** Bypasses Cloudflare Access Zero Trust on portal.hacken.io, exposing:
- Full ABP Framework API service map (548KB, 150+ controllers, 500+ endpoints)
- Tenant configuration (GUID, ID, platform version, subscription)
- SAML metadata revealing real internal domain (hacken.cyver.io)
- CSRF tokens from login/callback pages
- Health endpoint (server status + timestamp)
**Report:** `findings/FINAL-hackenproof-ssrf.md`

## Recon Approach

### What worked:
1. Subdomain enumeration (HackerTarget) → 19 subdomains
2. GitHub org enumeration (hackenproof, hknio, hai-group) → 27 repos
3. Next.js JS chunk analysis → found Supabase anon key
4. robots.txt analysis → revealed blocked paths
5. Parallel sub-agents (3x) for recon → 5 min wall clock

### Key technique: SSRF as internal proxy
The `/api/download-file/` endpoint was the breakthrough. It only allows `*.hacken.io` URLs but:
- portal.hacken.io is behind Cloudflare Access (Zero Trust) — normally requires auth
- The SSRF originates from hacken.io's server → Cloudflare Access trusts it
- Result: full access to portal.hacken.io without any authentication

### Post-exploitation via SSRF:
1. Fetched `/AbpServiceProxies/GetAll` → 548KB API map (all controllers, endpoints, params)
2. Fetched `/AbpScripts/GetScripts` → 349KB config (permissions, localization, settings)
3. Fetched `/api/services/app/Session/GetCurrentLoginInformations` → tenant config without auth
4. Fetched `/saml-metadata` → real internal domain (hacken.cyver.io), SAML ACS endpoint
5. Fetched `/health` → server status confirmation
6. Extracted CSRF tokens from `/Account/Login` and `/App/Jira/Callback`
7. Confirmed Stripe callback reflects attacker URL in returnUrl field

## Tech Stack
- hacken.io: Next.js on Cloudflare
- portal.hacken.io: ASP.NET (ABP Framework / Cyver v11.0.0) on Azure (cyver.northeurope.cloudapp.azure.com)
- scoping.hacken.io: Next.js on Vercel + Supabase (znksrgcjncicswolrntc.supabase.co)
- cmc-api.hacken.io: Express.js on Cloudflare
- assets.hacken.io: Ruby on Rails on Cloudflare

## Reusable Patterns

### Next.js SSRF via API routes
Next.js apps often have `/api/` routes that fetch external resources (images, files, logos). Test:
- `/api/download-file/?url=`
- `/api/company-logo/?url=`
- `/api/og-image/?url=`
- `/api/proxy/?url=`
- `/api/fetch/?url=`

These are server-side fetches that bypass client-side restrictions (CORS, Cloudflare Access).

### ABP Framework enumeration (when identified)
ABP (ASP.NET Boilerplate) exposes these without auth by default:
- `/AbpServiceProxies/GetAll` — FULL API client JS (all endpoints)
- `/AbpScripts/GetScripts` — config, permissions, localization
- `/api/services/app/Session/GetCurrentLoginInformations` — tenant info
- `/api/TokenAuth/GetExternalAuthenticationProviders` — auth providers
- `/health` — server status
- `/saml-metadata` — SAML SP configuration

### Cloudflare Access bypass via SSRF
When a target has Cloudflare Access (Zero Trust) protecting internal apps:
1. Find an SSRF on a trusted origin (same domain/org)
2. The SSRF request originates from the trusted server IP
3. Cloudflare Access sees the request as coming from a trusted source
4. Result: bypass Zero Trust without any authentication

### Supabase enumeration
When Supabase project is identified:
- Anon key may be in JS chunks (search for `sb_publishable_` or `eyJ` patterns)
- `/auth/v1/settings` — reveals enabled OAuth providers
- `/rest/v1/<table>?select=*` — test RLS (returns [] if enforced, data if not)
- Try INSERT to test write RLS: POST with `Prefer: return=representation`
- RPC function names leak via error messages ("Perhaps you meant to call...")
- Column names leak via invalid filter errors

## Files
- `/Users/nb-dk-0552/PenTest/Hunting/Hackenproof/Hacken/findings/FINAL-hackenproof-ssrf.md`
- `/Users/nb-dk-0552/PenTest/Hunting/Hackenproof/Hacken/findings/findings-summary.md`
- `/Users/nb-dk-0552/PenTest/Hunting/Hackenproof/Hacken/recon/` (all recon data)
- `/Users/nb-dk-0552/PenTest/Hunting/Hackenproof/Hacken/findings/evidence-*.{json,xml}`
