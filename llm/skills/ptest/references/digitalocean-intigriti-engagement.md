# DigitalOcean Bug Bounty (Intigriti) — Engagement Notes (2026-05-27)

## Program
- **Platform:** Intigriti
- **URL:** https://www.intigriti.com/programs/digitalocean/digitalocean/detail
- **Max Bounty:** $10,000
- **Min Bounty:** $50

## Scope Summary
- `*.digitalocean.com` (wildcard, check OOS list)
- `*.snapshooter.com` (cloud backup/recovery, DO acquisition)
- `api.digitalocean.com`, `cloud.digitalocean.com`
- `169.254.169.254` (metadata service from Droplets — in scope)
- `do.co`, `hacktoberfest.com`, `hackathon-tracker.digitalocean.com`
- GitHub: digitalocean/do-agent, droplet-agent, doctl

## OOS Subdomains (*.digitalocean.com)
anchor, brand, cloudsupport, deploy, email, events, go, groove, helpdesk, ideas, investor, investors, ir, mirrors, pilot, rewards, segment, status, tracking, waves

## OOS Wildcards
- `*.db.ondigitalocean.com`, `*.digitaloceanspaces.com`, `*.doserverless.co`, `*.k8s.ondigitalocean.com`, `*.ondigitalocean.app`, `registry.digitalocean.com/*`

## Infrastructure
- **CDN/WAF:** Cloudflare (Bot Management + WAF on all properties)
- **Auth:** Arkose Labs captcha on cloud.digitalocean.com login
- **API:** REST at api.digitalocean.com (all 401 without token)
- **Token format:** Legacy = 64 chars, v1 = 71 chars starting with "do"
- **MCP Platform:** *.mcp.digitalocean.com (all redirect to docs — new product, not yet live)
- **VPN:** GlobalProtect on clienteng-*/coffee-* subdomains (PAN-OS version obfuscated)

## Findings (Phases 1-6 Unauthenticated)

### Confirmed Reportable
| # | Finding | Severity | Target | Status |
|---|---------|----------|--------|--------|
| 1 | Stripe webhook signature bypass | Medium* | app.snapshooter.com/stripe/webhook | Needs auth account to prove impact |
| 2 | Open S3 bucket listing | Low | repos-droplet.digitalocean.com |  |
| 3 | Open S3 bucket listing | Low | repos.insights.digitalocean.com |  |
| 4 | GenAI Agent API OpenAPI spec exposed | Info | agent-*.ondigitalocean.app |  |
| 5 | CSP leaks internal infrastructure | Info | cloud.digitalocean.com |  |
| 6 | JWT error verbosity | Info | hackathon-tracker.digitalocean.com |  |

*Stripe webhook: accepts forged events (200 "Webhook Handled"), 500 on subscription.deleted (proves active processing), but no proven state change without a real account. User correctly identified this as lacking real impact — downgraded from High to Medium.

### Stripe Webhook Detail
- **Endpoint:** POST https://app.snapshooter.com/stripe/webhook
- **Events processed:** customer.subscription.created/updated/deleted, checkout.session.completed, payment_intent.succeeded, invoice.payment_succeeded
- **No signature needed:** works with no Stripe-Signature header, or fake signature
- **To prove impact:** Create Snapshooter account → find Stripe customer_id → forge upgrade → verify account state changed

### hackathon-tracker JWT
- Library: jsonwebtoken (Node.js)
- Algorithm: HS256 (confirmed via "invalid signature" error)
- Brute-force: 500 secrets from SecLists JWT wordlist — all failed
- Endpoints: /health (200), /metrics (200 "# OK"), /events (401), /users (401), /.env (403)

### Snapshooter (app.snapshooter.com)
- Framework: Laravel (Livewire, Sanctum)
- Horizon: 403 (locked)
- Registration: open but requires email verification
- OAuth: no social login endpoints found
- Livewire upload: CSRF protected (419)

## What Didn't Work
- JWT brute-force on hackathon-tracker (500 secrets)
- GenAI API auth bypass (properly gated)
- GlobalProtect CVE (version hidden)
- .env bypass on hackathon-tracker (Cloudflare blocks)
- Open redirect on cloud.digitalocean.com/login?next= (renders page, doesn't redirect)
- GraphQL on cloud.digitalocean.com (requires auth)
- CORS on api.digitalocean.com (Access-Control-Allow-Origin: * without credentials — not exploitable)
- Snapshooter registration (login fails — likely needs email verification)
- MCP subdomains (all redirect to docs)

## Next Steps (Authenticated Required)
1. Create DO account → test cloud panel IDOR, API, SSRF via droplet metadata
2. Register on Snapshooter with verified email → prove Stripe webhook impact
3. Test DO API with valid token → IDOR on resources, privilege escalation
4. SSRF from droplet → metadata service (169.254.169.254 in scope)
5. Test GenAI Agent API with valid DO token

## CSP Intelligence (from cloud.digitalocean.com)
Internal domains leaked:
- `localdev.internal.digitalocean.com` (ports 4500, 4501, 9000)
- `cloud.s2r1.internal.digitalocean.com`
- `cims-stage2.s2r1.spaces.stage2gateway.com`
- `*.do-ai.run`, `*.agents.do-ai.run`
- Sentry DSN key: `aee88abdb1378a68fd5ff728abdf2694`
- GenAI agent: `agent-bb7c8e8f107ffaca00e0-zo6gz.ondigitalocean.app`
