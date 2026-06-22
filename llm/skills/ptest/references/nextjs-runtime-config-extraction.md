# Next.js __NEXT_DATA__ runtimeConfig Extraction

## Trigger
- Target uses Next.js (detected via `/_next/static/` paths, `__NEXT_DATA__` script tag)
- Multiple subdomains serve different Next.js apps (webviews, pay, business, etc.)

## Technique

### 1. Extract runtimeConfig from HTML
```bash
curl -s "https://target.com" | python3 -c "
import sys, json, re
html = sys.stdin.read()
m = re.search(r'<script id=\"__NEXT_DATA__\"[^>]*>(.*?)</script>', html)
if m:
    data = json.loads(m.group(1))
    rc = data.get('runtimeConfig', data.get('props', {}).get('pageProps', {}))
    print(json.dumps(rc, indent=2))
else:
    print('No __NEXT_DATA__ found')
"
```

### 2. Extract env.js (alternative pattern)
Some Next.js apps load config from a separate env.js file:
```bash
curl -s "https://target.com/env.js"
```
Look for: `window.AppName.env = { ... }` or `window.__ENV = { ... }`

### 3. Check buildManifest for routes
```bash
# Extract buildId from __NEXT_DATA__
BUILD_ID=$(curl -s "https://target.com" | grep -oP '"buildId":"[^"]+' | cut -d'"' -f4)
curl -s "https://target.com/_next/static/${BUILD_ID}/_buildManifest.js"
```

## What to Look For

| Field | Significance |
|-------|-------------|
| apiBaseURL / apiPath | Internal API endpoints (may bypass WAF/CDN) |
| apiClientId + apiClientSecret | OAuth credentials (check if confidential vs public) |
| sentryDSN | Sentry project ID + org info |
| authEndpoint | Auth flow entry point |
| plaidEnv / plaidPublicKey | Third-party integration keys |
| environment / env | Production vs staging indicator |
| redirectUri | OAuth redirect (test for open redirect) |
| firebase* | Firebase config (test auth bypass) |
| stripeKey | Payment integration |
| algoliaAppId / algoliaApiKey | Search backend access |

## Interpreting OAuth Secrets

- `mnzpub.*` prefix (Monzo) = PUBLIC client (non-confidential, expected to be exposed)
- Short alphanumeric = likely public key
- Long base64 without prefix = check `/oauth2/clients/{id}` for `confidential: true/false`
- If `confidential: false` → client is public by design, NOT a finding
- If `confidential: true` → credential leak → High/Critical

## Batch Extraction Across Subdomains
```python
import subprocess, json, re, concurrent.futures

def extract_config(sub):
    try:
        r = subprocess.run(['curl', '-s', '--max-time', '5', f'https://{sub}'],
                          capture_output=True, text=True, timeout=8)
        # Try __NEXT_DATA__
        m = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', r.stdout)
        if m:
            data = json.loads(m.group(1))
            rc = data.get('runtimeConfig', {})
            if rc:
                return (sub, 'runtimeConfig', rc)
        # Try env.js reference
        if 'env.js' in r.stdout:
            r2 = subprocess.run(['curl', '-s', '--max-time', '5', f'https://{sub}/env.js'],
                               capture_output=True, text=True, timeout=8)
            if r2.stdout and 'window' in r2.stdout:
                return (sub, 'env.js', r2.stdout[:500])
    except:
        pass
    return None

# Run across all live hosts
with open('ptest-output/recon-active/live-hosts.txt') as f:
    subs = [l.split('|')[0] for l in f if '|https|' in l and '200' in l]

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
    results = [r for r in ex.map(extract_config, subs) if r]

for sub, source, data in results:
    print(f"\n=== {sub} ({source}) ===")
    print(json.dumps(data, indent=2) if isinstance(data, dict) else data)
```

## Source Map Check (companion technique)
When Next.js bundles are found, always check for .map files:
```bash
# Get a JS bundle URL from page source
JS_URL="https://static-assets.target.com/app/{hash}/_next/static/chunks/main-{hash}.js"
curl -sI "${JS_URL}.map" | head -1
# HTTP/2 200 → source maps exposed → white-box analysis
```

## Pitfalls
- `runtimeConfig` is ONLY in server-rendered pages (getServerSideProps/getInitialProps)
- Static pages (getStaticProps) have runtimeConfig={} — check other routes
- Some apps put config in `props.pageProps` instead of `runtimeConfig`
- The buildManifest endpoint may 404 if assets are on a different CDN (check actual src paths)
- plaidEnv="development" in production doesn't mean Plaid dev mode — it may be the client-side env name
- `mnzpub.*` secrets are PUBLIC BY DESIGN — don't waste time reporting known public OAuth clients

## Monzo-Specific Findings (June 2026)
- pay.monzo.com → runtimeConfig: apiClientId, apiClientSecret, sentryDSN, apiBaseURL=internal-api
- webviews.monzo.com → runtimeConfig: plaidPublicKey, authEndpoint, apiClientSecret
- staffonboarding.monzo.com → env.js: OAuth client, redirectUri, authEndpoint
- All secrets used `mnzpub.*` prefix (public clients, listed in program OOS)
