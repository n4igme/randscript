# Next.js Source Map + runtimeConfig Extraction

## Trigger
- Target uses Next.js (identified by `/_next/static/` paths, `__NEXT_DATA__` in HTML)
- Multiple Next.js apps on different subdomains (common in fintech/SaaS)

## Technique 1: __NEXT_DATA__ runtimeConfig Extraction

Next.js apps embed server-side config in `<script id="__NEXT_DATA__">` on every page.
This often leaks OAuth credentials, API paths, Sentry DSNs, and feature flags.

```bash
curl -s "https://target.com" | python3 -c "
import sys, json, re
html = sys.stdin.read()
m = re.search(r'<script id=\"__NEXT_DATA__\"[^>]*>(.*?)</script>', html)
if m:
    data = json.loads(m.group(1))
    rc = data.get('runtimeConfig', {})
    if rc:
        print(json.dumps(rc, indent=2))
    else:
        print(f'No runtimeConfig. Keys: {list(data.keys())}')
"
```

**Common leaks in runtimeConfig:**
- `apiPath` / `apiBaseURL` → internal API endpoints
- `clientId` + `clientSecret` → OAuth credentials (check if mnzpub/public prefix)
- `sentryDSN` → Sentry project info
- `plaidEnv` + `plaidPublicKey` → third-party integration keys
- `environment` → confirms prod/staging

## Technique 2: Source Map Discovery

Next.js serves source maps at `{bundle_url}.map`. Check ALL chunks, not just main.

```bash
# Step 1: Extract all JS URLs from page
curl -s "https://target.com" | grep -oE 'src="[^"]*\.js"' | sed 's/src="//;s/"//' > /tmp/js-urls.txt

# Step 2: Check each for source map
while read url; do
  mapurl="${url}.map"
  code=$(curl -s --max-time 3 -o /dev/null -w "%{http_code}:%{size_download}" "$mapurl")
  status=$(echo $code | cut -d: -f1)
  size=$(echo $code | cut -d: -f2)
  [ "$status" = "200" ] && [ "$size" -gt "100" ] && echo "[MAP] $mapurl ($size bytes)"
done < /tmp/js-urls.txt
```

## Technique 3: Source Map Analysis

```python
import json, re

with open('sourcemap.json') as f:
    data = json.load(f)

sources = data.get('sources', [])
contents = data.get('sourcesContent', [])

# Find auth/config/API files (skip node_modules)
for i, s in enumerate(sources):
    if 'node_modules' not in s and i < len(contents) and contents[i]:
        if any(k in s.lower() for k in ['auth', 'api', 'config', 'oauth', 'token', 'secret']):
            print(f'[{len(contents[i])}b] {s}')
```

**What to extract:**
- OAuth flow implementation (grant types, token handling)
- API endpoint paths (especially undocumented ones)
- Hardcoded secrets/keys
- Internal package names (monorepo structure)
- Error handling (what's sanitized from logging)

## Technique 4: Next.js _next/data/ Endpoint

Next.js exposes `/_next/data/{buildId}/{page}.json` for pages using getServerSideProps.
Returns server-side props as JSON without rendering HTML.

```bash
# Get buildId from __NEXT_DATA__
BUILD_ID=$(curl -s "https://target.com" | grep -oE '"buildId":"[^"]*"' | cut -d'"' -f4)

# Probe pages
for page in index download sign-up login admin settings; do
  code=$(curl -s --max-time 3 -o /dev/null -w "%{http_code}:%{size_download}" \
    "https://target.com/_next/data/${BUILD_ID}/${page}.json")
  echo "$page.json → $code"
done
```

## Pitfalls
- Source maps on S3/CDN behind CloudFront may have different access than the app itself
- `runtimeConfig` is PUBLIC by design in Next.js (publicRuntimeConfig) — not always a finding
- `mnzpub.*` / `pk_*` / `pub_*` prefixed secrets are intentionally public client keys
- Feature gates in _next/data/ are usually marketing flags, not security features
- SPA catch-all: verify source maps aren't just the catch-all HTML (check content-type + first bytes)

## Monzo Example (June 2026)
- 24 source maps on static-assets.monzo.com (~9.7MB total, 1764 source files)
- auth.monzo.com: 763 source files revealed full magic link + PKCE implementation
- pay.monzo.com: payment claiming flow (pay-anyone/read, pay-anyone/claim-fps)
- runtimeConfig leaked: OAuth clients, Plaid dev key, Sentry DSNs, staging API URLs
- All OAuth secrets had `mnzpub.*` prefix = public clients (not exploitable alone)
