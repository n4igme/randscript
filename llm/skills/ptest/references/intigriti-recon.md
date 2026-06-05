# Intigriti Platform Recon Reference

## Scope Data Without Login

When Intigriti login is blocked (bot detection, CAPTCHA), use the community-maintained bounty targets dataset:

```bash
# Download Intigriti program data
curl -s "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json" -o /tmp/intigriti.json

# Parse programs with bounties
python3 -c "
import json
with open('/tmp/intigriti.json') as f:
    data = json.load(f)
# Sort by max bounty
programs = sorted(data, key=lambda p: p.get('max_bounty', {}).get('value', 0), reverse=True)
for p in programs[:20]:
    print(f\"{p['name']} | Max: \${p.get('max_bounty', {}).get('value', 0)} | Targets: {len(p.get('targets', {}).get('in_scope', []))} | {p['url']}\")
"
```

### Data Structure
- `id`, `name`, `company_handle`, `handle`, `url`, `status`
- `confidentiality_level`, `tacRequired`, `twoFactorRequired`
- `min_bounty.value`, `max_bounty.value`
- `targets.in_scope[]` — each has `type` (url/wildcard/ios/android/iprange/other), `endpoint`, `description`
- `targets.out_of_scope[]` — same structure

### Intigriti Rules (from memory)
- @intigriti.me email alias for communication
- UA: "Intigriti - <username> - <ua>"
- X-Intigriti-Username header required
- 5 req/sec max rate limit
- Login: sinaubib@gmail.com

## CDN-Fronted Target Recon Tips

When targets are behind Cloudflare/CloudFront:
1. **Port scanning is useless** — nmap will timeout against CDN IPs
2. **ffuf/nuclei timeout** — rate limiting + WAF makes automated tools impractical
3. **Manual targeted curl** is more effective — test specific paths with small batches
4. **subfinder -all** for comprehensive subdomain enum
5. **Focus on:** S3 bucket misconfigs, CSP header leaks, exposed API docs, version disclosure
6. **PD httpx** (~/go/bin/httpx) for live host probing — NOT system httpx (Python httpx CLI)

## Common Intigriti Target Patterns
- `*.pwn.<company>.rocks` — test/staging environments
- CloudFront + S3 for static assets
- Vercel/DatoCMS for marketing sites
- AWS SES for email infrastructure

## DigitalOcean Engagement Lessons (2026-05-27)

**Program:** https://www.intigriti.com/programs/digitalocean/digitalocean/detail
**Max bounty:** $10,000 | **Scope:** *.digitalocean.com, *.snapshooter.com, api, cloud, metadata (169.254.169.254), GitHub repos

**What worked:**
- S3 bucket listing on `repos-droplet.digitalocean.com` and `repos.insights.digitalocean.com` (open listing, no write)
- GenAI Agent API OpenAPI spec exposed at `agent-*.ondigitalocean.app/openapi.json`
- CSP header on `cloud.digitalocean.com` leaks extensive internal infrastructure (localdev, staging, sentry DSN)
- **Stripe webhook signature bypass on app.snapshooter.com** — highest-value finding (High, CWE-345)
- hackathon-tracker JWT verbose errors reveal library (jsonwebtoken)

**What didn't work:**
- JWT brute-force (500 secrets from SecLists) — secret is strong
- GenAI API auth bypass — properly gated (403)
- Snapshooter Laravel debug tools (telescope, ignition, log-viewer) — all 404
- Registration on Snapshooter — needs email verification, can't get authenticated session
- GlobalProtect VPN (clienteng-*.digitalocean.com) — version obfuscated, no exploitable CVE
- MCP subdomains — all redirect to docs
- Open redirect on cloud.digitalocean.com/login?next= — renders page, doesn't redirect
- DO API CORS `*` — no credentials allowed, not exploitable

**Key insight:** For heavily-Cloudflare'd targets, the highest ROI is finding subsidiary/acquired apps (Snapshooter) with weaker security posture. Main DO infrastructure is well-hardened. Authenticated testing (DO account + Snapshooter verified email) needed for deeper findings.

**Out-of-scope traps:**
- `*.ondigitalocean.app` — customer resources (OOS)
- `*.digitaloceanspaces.com` — customer resources (OOS)
- `*.db.ondigitalocean.com` — customer resources (OOS)
- `registry.digitalocean.com/*` — customer resources (OOS)
- 18 specific subdomains listed as OOS (anchor, brand, deploy, email, events, etc.)

## Intigriti XSS Challenges

Monthly challenges at `challenge-MMDD.intigriti.io`. Pattern:
- Iframe embeds `/challenge` page
- Must pop `alert()` (or `alert`1`` via tagged template)
- No self-XSS, no MiTM, max 1 click from victim
- Must work in latest Chrome
- Report on Intigriti platform with PoC URL + explanation

## Reference Files
- `references/xss-filter-bypass-techniques.md` — XSS bypass: char-restricted, signature-blocked, auto-fire vectors
