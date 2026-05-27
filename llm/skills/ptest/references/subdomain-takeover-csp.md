# Subdomain Takeover & CSP Bypass

## Subdomain Takeover Detection

### Recon Steps
1. Enumerate subdomains (subfinder, amass)
2. Probe with httpx — look for 404/NXDOMAIN on live CNAMEs
3. Check CNAME targets: `dig +short CNAME <subdomain>`
4. Match CNAME against known vulnerable services

### Vulnerable Services (CNAME targets)
| Service | CNAME Pattern | Fingerprint |
|---------|--------------|-------------|
| SendGrid | `sendgrid.net` | 404 nginx |
| GitHub Pages | `*.github.io` | 404 "There isn't a GitHub Pages site here" |
| Heroku | `*.herokudns.com` | "No such app" |
| AWS S3 | `*.s3.amazonaws.com` | "NoSuchBucket" |
| Shopify | `shops.myshopify.com` | "Sorry, this shop is currently unavailable" |
| Cloudfront | `*.cloudfront.net` | "Bad Request" / no distribution |
| Fastly | `*.fastly.net` | "Fastly error: unknown domain" |
| Pantheon | `*.pantheonsite.io` | 404 "unknown site" |
| Tumblr | `*.tumblr.com` | "There's nothing here" |

### SendGrid Takeover (Specific)
- CNAME → `sendgrid.net` + 404 nginx = claimable
- Claim via: Settings → Sender Auth → Link Branding → add subdomain
- Or API: `POST /v3/whitelabel/links` with domain+subdomain
- Validate: `POST /v3/whitelabel/links/{id}/validate`

### Impact Amplification
- Check cookie scope: `Domain=<parent>` means all subdomains share cookies
- Check CSP: if taken-over subdomain is in `script-src` → XSS chain
- Check CORS: if taken-over subdomain is in `Access-Control-Allow-Origin`

## CSP Bypass via Subdomain/Wildcard

### Detection
```bash
curl -sI https://target.com/ | grep -i content-security-policy | tr ';' '\n'
```

### Exploitable Patterns
| CSP Entry | Attack |
|-----------|--------|
| `script-src *.pages.dev` | Deploy on any Cloudflare Pages project |
| `script-src subdomain.target.com` (404) | Takeover → serve malicious JS |
| `script-src *.target.com` | Any subdomain takeover → XSS |
| `script-src cdn.jsdelivr.net` | Host payload via npm package |
| `script-src unpkg.com` | Same — publish npm package |

### Real Example (ENS, May 2026)
- `app.ens.domains` CSP includes `jakob.ens.domains` (404) in `script-src`
- Also includes `*.ens-app-v3.pages.dev` (wildcard Cloudflare Pages)
- Takeover either → serve JS → executes on app.ens.domains → wallet drain

### Severity Mapping (Immunefi Web3)
- Subdomain takeover + wallet interaction = Critical
- Subdomain takeover without wallet = High
- CSP bypass → XSS → wallet tx = Critical
