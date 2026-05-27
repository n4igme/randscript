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

## Intigriti XSS Challenges

Monthly challenges at `challenge-MMDD.intigriti.io`. Pattern:
- Iframe embeds `/challenge` page
- Must pop `alert()` (or `alert`1`` via tagged template)
- No self-XSS, no MiTM, max 1 click from victim
- Must work in latest Chrome
- Report on Intigriti platform with PoC URL + explanation

## Reference Files
- `references/xss-filter-bypass-techniques.md` — XSS bypass: char-restricted, signature-blocked, auto-fire vectors
