# Pentesting Cloudflare-Protected Targets

## Pitfalls
- Port scanning (nmap) times out — Cloudflare blocks most probes
- ffuf/gobuster extremely slow even at low rates (3-5 req/sec) — use manual curl loops instead
- nuclei scans produce zero results against CF-protected hosts
- Google/DuckDuckGo searches get CAPTCHA'd from automated browsers
- Intigriti login has reCAPTCHA + bot detection — browser automation fails

## What Works
- **Manual curl enumeration** with targeted wordlists (fastest, avoids WAF)
- **subfinder -all** for deeper subdomain discovery (passive, no CF interaction)
- **PD httpx** (~/go/bin/httpx) for live host probing — fast enough at default rate
- **CSP header analysis** — cloud.digitalocean.com CSP leaked entire internal infra
- **S3/Spaces bucket listing** — repos-*.digitalocean.com not behind CF WAF
- **API error message analysis** — JWT library disclosure, auth mechanism fingerprinting
- **Binary analysis** (strings) on downloadable agents/tools — reveals internal endpoints

## Effective Unauth Techniques for CDN Targets
1. Subdomain enum → filter OOS → httpx probe (get tech stack + status codes)
2. CSP/CORS/header analysis on main app (info leakage)
3. Targeted path fuzzing via curl loops (50-100 paths, not 10K wordlists)
4. Check for open buckets/registries on non-CDN subdomains
5. GitHub repo analysis for in-scope open source components
6. Download and reverse binaries from open package repos

## Intigriti-Specific
- Use arkadiyt/bounty-targets-data repo for offline scope enumeration
- JSON at: https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json
- Contains full in_scope/out_of_scope targets with descriptions
- Browser login blocked by bot detection — use API/data repos instead
