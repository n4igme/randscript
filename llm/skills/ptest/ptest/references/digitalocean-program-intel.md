# DigitalOcean Bug Bounty Program Intel

## Program Details
- **Platform:** Intigriti
- **URL:** https://www.intigriti.com/programs/digitalocean/digitalocean/detail
- **Bounty:** $50 - $10,000
- **Started:** 2026-05-27

## Scope Summary

### In-Scope (Key Targets)
- `*.digitalocean.com` (wildcard, check OOS list)
- `169.254.169.254` (metadata service from Droplets — SSRF target)
- `api.digitalocean.com` (API)
- `cloud.digitalocean.com` (main panel, Arkose Labs captcha)
- `*.snapshooter.com` (cloud backup/recovery, Laravel app)
- `hacktoberfest.com` (Next.js)
- `do.co` (shortlink, nginx)
- GitHub: `digitalocean/do-agent`, `digitalocean/droplet-agent`, `digitalocean/doctl`

### Out-of-Scope Subdomains
anchor, brand, cloudsupport, deploy, email, events, go, groove, helpdesk, ideas, investor, investors, ir, mirrors, pilot, rewards, segment, status, tracking, waves

### Out-of-Scope Wildcards (Customer Resources)
- `*.db.ondigitalocean.com`
- `*.digitaloceanspaces.com`
- `*.doserverless.co`
- `*.k8s.ondigitalocean.com`
- `*.ondigitalocean.app`
- `registry.digitalocean.com/*`

## Infrastructure Map (Discovered 2026-05)

### Authentication
- **cloud.digitalocean.com:** Arkose Labs captcha + Cloudflare Bot Management + HSTS
- **api.digitalocean.com:** Bearer token (64 chars legacy OR 71 chars "do" prefix v1)
- **hackathon-tracker:** JWT (HS256, jsonwebtoken library, verbose errors)
- **app.snapshooter.com:** Laravel Sanctum (session-based), Livewire, registration open

### Key Findings (Unauthenticated)
1. **Stripe webhook bypass (HIGH)** — `app.snapshooter.com/stripe/webhook` processes events without signature verification
2. **Open S3 buckets (LOW)** — `repos-droplet.digitalocean.com` (eng-droplet-packages), `repos.insights.digitalocean.com` (rooster/do-agent)
3. **GenAI Agent API spec exposed (INFO)** — `agent-bb7c8e8f107ffaca00e0-zo6gz.ondigitalocean.app/openapi.json`
4. **CSP info leak (INFO)** — cloud.digitalocean.com leaks: `localdev.internal.digitalocean.com:4500/4501/9000`, `cloud.s2r1.internal.digitalocean.com`, `cims-stage2.s2r1.spaces.stage2gateway.com`, `*.do-ai.run`, `*.agents.do-ai.run`, Sentry DSN key

### Infrastructure Notes
- **MCP Platform:** 15+ `*.mcp.digitalocean.com` subdomains (apps, accounts, docs, docr, droplets, doks, functions, networking, spaces, databases) — all redirect to docs page currently
- **GlobalProtect VPN:** `clienteng-{nyc3,sfo2}`, `coffee-{fra1,syd1,sfo2,nyc3}` — PAN-OS version obfuscated ("1")
- **Sonar monitoring:** `{ams3,sfo2,nyc3,sgp1,lon1,fra1,blr1,syd1,tor1}.sonar.digitalocean.com` — all 307 redirect
- **Docker Registry:** `test-docr.digitalocean.com` — V2 API, auth enforced via `api.digitalocean.com/v2/registry/auth`
- **Salesforce staging:** `cloudsupport-full-staging.digitalocean.com` — sandbox `doinstance--dofull`, CSP leaks Ironclad CLM, DocuSign, Stripe, Adyen integrations

### Hardened Vectors (Don't Waste Time)
- `.env` on any DO subdomain → Cloudflare WAF blocks
- JWT brute-force on hackathon-tracker → 500+ secrets tested, none worked
- GenAI Agent API → properly auth-gated (403 "Not authenticated")
- Snapshooter Horizon → locked (403)
- Snapshooter Livewire upload → CSRF protected (419)
- DO API CORS → `Access-Control-Allow-Origin: *` but no credentials allowed (not exploitable)
- cloud.digitalocean.com/login?next= → renders login page, doesn't redirect (not open redirect)

### Next Steps (Authenticated Required)
1. Create DO account → test cloud panel API, IDOR on resources, SSRF via droplet metadata (169.254.169.254)
2. Register on snapshooter with verified email → IDOR, business logic, backup access, prove Stripe webhook upgrade
3. Test DO API with valid token → IDOR on droplet/volume/database IDs, privilege escalation
4. Test GenAI Agent API with DO token
5. Reverse-engineer droplet-agent binary for hardcoded secrets or SSRF vectors
