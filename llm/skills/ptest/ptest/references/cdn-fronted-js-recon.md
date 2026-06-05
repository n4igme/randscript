# CDN-Fronted Target Enumeration via JS Bundle Analysis

## When to Use

When a target is entirely behind CDN (Akamai, Cloudflare, Fastly, CloudFront):
- Port scanning yields only 80/443
- All IPs resolve to CDN edge nodes
- Network-layer attacks are not viable
- Traditional directory brute-force returns SPA shells

## Technique: Extract Intelligence from Page Source & JS Configs

Modern SPAs embed rich configuration in the HTML page that reveals:
- Internal API domains and endpoints
- Microservice module names and versions
- OAuth client keys and app IDs
- Region/IDC information
- CDN structure and internal hostnames

### Step 1: Fetch page source and extract embedded JSON configs

```bash
# Look for these common config patterns in page source:
curl -sk "https://target.com" | grep -oE '<script[^>]*type="application/json"[^>]*id="[^"]*"[^>]*>[^<]+</script>' | \
  sed 's/<script[^>]*>//;s/<\/script>//' | python3 -m json.tool

# Common config IDs to look for:
# gfdatav1 — Goofy Deploy (ByteDance) app config with module list
# garfishModuleInfo — Garfish micro-frontend module federation manifest
# scmconfigv1 — SCM/e-commerce config with API domains
# __NEXT_DATA__ — Next.js server-side props
# __NUXT__ — Nuxt.js state
# tiktok-environment — region, monitoring, CDN config
```

### Step 2: Extract Garfish/Module Federation manifests

```bash
# Garfish modules reveal:
# - All microservice names (attack surface map)
# - Source URLs (JS bundle locations for further analysis)
# - Internal dev domains (*.tiktokd.net patterns)
# - Version numbers (for version-specific vulns)

curl -sk "https://target.com" | python3 -c "
import sys, json, re
html = sys.stdin.read()
# Find all JSON script blocks
for match in re.finditer(r'<script[^>]*type=\"application/json\"[^>]*>([^<]+)</script>', html):
    try:
        data = json.loads(match.group(1))
        if 'garrModules' in str(data) or 'garfish' in str(data).lower():
            modules = data.get('garrModules', {}).get('data', [])
            for m in modules:
                print(f\"Module: {m.get('name')} v{m.get('version')} path:{m.get('path','/')}\")
    except: pass
"
```

### Step 3: Extract API domains and keys

```bash
# Look for exposed configuration values
curl -sk "https://target.com" | grep -ioE '(api[_-]?key|client[_-]?key|app[_-]?id|secret|token)["\s]*[:=]["\s]*[^"<,}\s]+' | sort -u

# Extract all URLs/domains from page source
curl -sk "https://target.com" | grep -oE 'https?://[a-zA-Z0-9._/-]+' | sort -u | grep -v "static\|cdn\|font\|css"
```

### Step 4: Map real API endpoints from module config

```bash
# From Garfish config, modules often have initialPathList or fetchUrl patterns
# e.g., "initialPathList": ["^/api/.*"] reveals API prefix
# e.g., "fetchUrl": "/api/v1/product/local/products/list" reveals exact endpoints

# Test discovered API paths with auth-required detection:
curl -sk "https://target.com/api/v1/endpoint" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    code = d.get('code', d.get('error_code', d.get('status_code', '')))
    print(f'API code: {code} — {d.get(\"message\", d.get(\"status_msg\", \"\"))}')
except: print('Not JSON')
"
```

## Common API Error Codes (ByteDance/TikTok)

| Code | Meaning |
|------|---------|
| 0 | Success |
| 4 | Incorrect parameters |
| 10000 | Unauthorized / auth required |
| 10001 | Invalid token |
| 10002 | Token expired |

## Key Domains to Extract

When analyzing ByteDance/TikTok targets, look for:
- `frontier*.tiktokv.us` — API gateway
- `mcs*.tiktokv.com` — telemetry/MCS
- `libraweb*.tiktok.com` — AB testing
- `starling*.tiktokv.com` — i18n service
- `mon-*.tiktokv.com` — monitoring (Slardar)
- `*.tiktokd.net` — internal dev/canary domains
- `*.byteoversea.com` — ByteDance overseas infra
- `*.byteintlapi.com` — ByteDance international API

## Pitfalls

1. **Don't confuse SPA 200s with real endpoints** — see `references/spa-false-positive-detection.md`
2. **CDN IPs are shared** — don't report "exposed IP" for Akamai/Fastly/CF addresses
3. **Google Maps API keys in page source** are usually restricted to specific referrers — test before reporting
4. **OAuth client_keys are semi-public** (needed for OAuth flows) — only a finding if they enable unauthorized actions
5. **Module version numbers** are informational unless tied to a specific CVE
