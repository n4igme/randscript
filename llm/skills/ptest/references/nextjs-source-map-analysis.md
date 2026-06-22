# Next.js Source Map Analysis Technique

## Trigger
- Target uses Next.js (detected via `/_next/static/chunks/` paths, `__NEXT_DATA__` in HTML)
- Source maps (.js.map) return 200 on static-assets CDN

## Discovery

### 1. Find Build Hash
```bash
curl -s "https://target.com" | grep -oE 'src="[^"]*/_next/static/chunks/[^"]*\.js"' | head -5
# Extract build hash from path: /_next/static/{BUILD_HASH}/_buildManifest.js
```

### 2. Check Source Map Availability
```bash
# For each JS chunk, append .map
curl -sI "https://cdn.target.com/app/{hash}/_next/static/chunks/pages/_app-{chunk}.js.map" | head -3
# 200 = exposed, 403 = blocked, 404 = stripped at deploy
```

### 3. Enumerate All Source Maps
```bash
curl -s "https://target.com" | grep -oE 'src="[^"]*\.js"' | sed 's/src="//;s/"//' > /tmp/js-urls.txt
while read url; do
  code=$(curl -s --max-time 3 -o /dev/null -w "%{http_code}:%{size_download}" "${url}.map")
  status=$(echo $code | cut -d: -f1)
  size=$(echo $code | cut -d: -f2)
  [ "$status" = "200" ] && [ "$size" -gt "100" ] && echo "[MAP] ${url}.map ($size bytes)"
done < /tmp/js-urls.txt
```

## Analysis

### Priority Order for Chunks
1. `pages/_app-*.js.map` — app shell, auth providers, API clients, config
2. `pages/index-*.js.map` or `pages/[route]-*.js.map` — page-specific logic
3. Named chunks (624, 945, etc.) — shared libraries and features
4. `main-*.js.map` — Next.js runtime (less useful)
5. `framework-*.js.map` — React (skip)
6. `webpack-*.js.map` — bundler runtime (skip)

### What to Extract

```python
import json, re

with open('source-map.json') as f:
    data = json.load(f)

sources = data.get('sources', [])
contents = data.get('sourcesContent', [])

# 1. Non-node_modules source files (app code)
app_files = [(s, i) for i, s in enumerate(sources) if 'node_modules' not in s]

# 2. API endpoints
for i, c in enumerate(contents):
    if not c: continue
    paths = re.findall(r'["\'`](/(?:api|oauth|login|v[0-9]|pay|internal)[a-z0-9/_-]*)', c)

# 3. Secrets/keys
for i, c in enumerate(contents):
    if not c: continue
    secrets = re.findall(r'(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*["\']([^"\']{10,})', c)

# 4. Internal URLs
for i, c in enumerate(contents):
    if not c: continue
    urls = re.findall(r'https?://[^\s"\'<>\\]{5,100}', c)
```

### Key Files to Target (by name pattern)
- `**/auth/**`, `**/oauth/**` — auth flow, token handling
- `**/api/**`, `**Client.ts` — API client configuration
- `**/config.ts`, `**/env.ts` — environment config
- `**/*Sdk.ts`, `**/*Api.ts` — SDK/API wrappers with endpoint definitions
- `**/types/*.ts` — type definitions reveal data models
- `**/hooks/*.ts` — React hooks show API call patterns

## __NEXT_DATA__ Extraction (Complementary)

Always check `__NEXT_DATA__` script tag for runtimeConfig:
```python
import re, json
html = requests.get('https://target.com').text
m = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', html)
if m:
    data = json.loads(m.group(1))
    runtime = data.get('runtimeConfig', {})
    # Contains: apiPath, clientId, clientSecret, sentryDSN, environment
```

## Monzo-Specific Patterns (June 2026)

- Static assets served from: `static-assets.monzo.com/{app-name}/{build-hash}/`
- App names: `monzo-com`, `external-login`, `webviews`
- webviews JS on S3: `monzo-prod-s3bucketcreator-ffs-web-export.s3-eu-west-1.amazonaws.com/webviews/{hash}/`
- webviews .map files are 403 (S3 ACL), but monzo-com maps are public
- `mnzpub.` prefix in clientSecret = public OAuth2 client (non-confidential)
- client_credentials grant DISABLED for all public clients (returns "could not authenticate")

## Pitfalls

- **SPA catch-all vs real source maps:** If .map files return the same size as the SPA HTML catch-all, they're NOT real source maps. Verify content-type.
- **S3 source maps may be ACL'd differently:** webviews on S3 bucket may be 403 while CloudFront-served maps (static-assets CDN) are public.
- **Don't waste time on node_modules:** Most large chunks (2304, framework) are all dependencies. Check app_files count first.
- **runtimeConfig on EVERY subdomain:** Check __NEXT_DATA__ on every Next.js host — each may have different OAuth clients, API paths, and feature flags.
- **Build hash changes on deploy:** Source maps are point-in-time. Re-check after target deploys.
