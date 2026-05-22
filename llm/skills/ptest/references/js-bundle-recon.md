# JS Bundle Analysis — Phase 1 Recon

## Overview

Production JavaScript bundles are one of the richest Phase 1 recon sources available. Modern frontend build tools (webpack, Vite, Rollup, esbuild) inline the entire application configuration into static JS files served to every visitor. This includes:

- Internal/staging API endpoints that were never meant to be public
- Microservice names and architecture topology
- Feature flags revealing unreleased functionality
- OAuth configurations with client IDs and redirect URIs
- Environment-specific config objects (dev, staging, prod)
- WebSocket, GraphQL, and gRPC-web endpoints
- Cloud storage bucket URLs

Unlike server-side configs, these are **served directly to unauthenticated users**. Developers routinely forget that "build-time" environment variables become public the moment they're bundled.

This is distinct from Phase 3 secret scanning (finding API keys/tokens). Phase 1 bundle analysis focuses on **intelligence gathering** — mapping the target's internal architecture, discovering hidden services, and identifying attack surface before active testing begins.

---

## Finding Bundles

### View Source — Script Tags

```bash
# Fetch and extract all script sources
curl -s https://target.com | grep -oP 'src="[^"]*\.js[^"]*"' | sort -u

# Also check for dynamically loaded chunks
curl -s https://target.com | grep -oP '(?:src|href)="([^"]*\.js[^"]*)"' | sort -u
```

### Common Bundle Paths

| Framework | Typical Paths |
|-----------|--------------|
| Webpack (CRA) | `/static/js/main.*.js`, `/static/js/*.chunk.js` |
| Next.js | `/_next/static/chunks/*.js`, `/_next/static/*/pages/*.js` |
| Nuxt.js | `/_nuxt/*.js` |
| Vite | `/assets/*.js`, `/assets/index-*.js` |
| Angular | `/main.*.js`, `/runtime.*.js`, `/polyfills.*.js` |
| Vue CLI | `/js/app.*.js`, `/js/chunk-vendors.*.js` |
| Gatsby | `/component---*.js`, `/app-*.js` |
| Remix | `/build/*.js` |

```bash
# Brute-force common paths
for path in /static/js/ /assets/ /_next/static/chunks/ /_nuxt/ /build/ /js/ /dist/; do
  curl -s -o /dev/null -w "%{http_code} %{url_effective}\n" "https://target.com${path}"
done
```

### Source Maps — The Jackpot

Source maps (`.map` files) contain the **original unminified source code** including comments, variable names, and file structure.

```bash
# Check if source maps are accessible
# Method 1: Append .map to known JS files
curl -s -o /dev/null -w "%{http_code}" https://target.com/static/js/main.abc123.js.map

# Method 2: Check sourceMappingURL comment in JS files
curl -s https://target.com/static/js/main.abc123.js | tail -1
# Look for: //# sourceMappingURL=main.abc123.js.map

# Method 3: Check X-SourceMap header
curl -sI https://target.com/static/js/main.abc123.js | grep -i sourcemap
```

### Webpack Chunk Manifests

Webpack apps often have a runtime/manifest chunk that lists ALL chunk filenames:

```bash
# Look for the webpack runtime that contains chunk mappings
curl -s https://target.com/static/js/runtime-main.*.js | grep -oP '"[a-f0-9]+":\s*"[^"]*"'

# Next.js build manifest
curl -s https://target.com/_next/static/buildManifest.js
curl -s https://target.com/_next/static/*/buildManifest.js

# Next.js route manifest (reveals all pages/routes)
curl -s https://target.com/_next/routes-manifest.json
```

---

## Extraction Techniques

### Internal API URLs

The highest-value extraction. Look for base URLs, API paths, and service endpoints.

```bash
# Download all JS files first
mkdir -p js_bundles && cd js_bundles
# (use getJS, wget, or manual download)

# Extract URLs from all bundles
grep -rhoP 'https?://[a-zA-Z0-9._\-/]+' *.js | sort -u > urls.txt

# Filter for internal/interesting domains
grep -iP '(internal|staging|dev|api|admin|backend|service|micro|grpc)' urls.txt

# Extract relative API paths
grep -rhoP '"/api/v[0-9]+/[a-zA-Z0-9/_\-]+"' *.js | sort -u
grep -rhoP '"/(api|v[0-9]|graphql|ws|socket|internal|admin)/[^"]*"' *.js | sort -u

# Look for fetch/axios base URLs
grep -rhoP '(baseURL|BASE_URL|API_URL|apiUrl|apiBase|endpoint)["\s:=]+["'\''`]([^"'\''`]+)' *.js
```

**Regex patterns for API endpoint extraction:**

```bash
# REST endpoints
grep -rhoP '["'\''`]/(api|v[0-9]|rest|service)/[a-zA-Z0-9/_\-{}:]+["'\''`]' *.js

# Full URLs with subdomains
grep -rhoP 'https?://[a-z0-9\-]+\.(internal|corp|local|staging|dev|test)\.[a-z.]+' *.js

# Path patterns with parameters
grep -rhoP '["'\''`]/[a-zA-Z]+/:[a-zA-Z]+(/[a-zA-Z/:]+)*["'\''`]' *.js
```

### Environment Detection

```bash
# process.env references (webpack DefinePlugin replacements)
grep -rhoP 'process\.env\.[A-Z_]+' *.js | sort -u

# Config objects — look for environment switching logic
grep -rhoP '(production|staging|development|local)["'\'']*\s*:\s*["'\''`][^"'\''`]+' *.js

# React/Next.js public env vars (NEXT_PUBLIC_*, REACT_APP_*)
grep -rhoP '(NEXT_PUBLIC|REACT_APP|VITE|VUE_APP)_[A-Z_]+["'\'']*\s*[:=]\s*["'\''`][^"'\''`]+' *.js

# Conditional environment blocks
grep -rhoP '(NODE_ENV|APP_ENV|ENVIRONMENT)\s*[=!]==?\s*["'\''](production|staging|development)' *.js
```

### Feature Flags

Feature flags reveal unreleased functionality — potential attack surface that hasn't been hardened yet.

```bash
# Common feature flag patterns
grep -rhoP '(feature[_-]?flag|featureToggle|isEnabled|FF_|FEATURE_)[A-Za-z_]+' *.js | sort -u

# LaunchDarkly flags
grep -rhoP '(ld|launchdarkly)[^"]*["'\''`]([a-z\-]+)["'\''`]' *.js

# Split.io, Unleash, Flagsmith patterns
grep -rhoP '(treatment|toggle|flag)["\s:]+["'\''`]([a-zA-Z0-9_\-]+)["'\''`]' *.js

# Boolean feature checks
grep -rhoP '(enable|disable|show|hide|allow|beta|experiment)[A-Z][a-zA-Z]+' *.js | sort -u
```

### OAuth Client IDs

Client IDs aren't secrets, but they enable redirect_uri manipulation testing (Phase 5/6).

```bash
# OAuth client IDs
grep -rhoP '(client_id|clientId|client-id|appId|app_id)["'\'']*\s*[:=]\s*["'\''`]([^"'\''`]+)' *.js

# Google OAuth
grep -rhoP '[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com' *.js

# Auth0 domains and client IDs
grep -rhoP '[a-z0-9\-]+\.auth0\.com' *.js
grep -rhoP '(AUTH0_CLIENT_ID|auth0ClientId)["'\'']*\s*[:=]\s*["'\''`]([^"'\''`]+)' *.js

# Okta
grep -rhoP '[a-z0-9]+\.okta\.com' *.js
grep -rhoP '0o[a-z0-9]{18,}' *.js  # Okta client ID format

# OAuth redirect URIs (reveals valid callback URLs)
grep -rhoP '(redirect_uri|callback_url|redirectUri)["'\'']*\s*[:=]\s*["'\''`]([^"'\''`]+)' *.js
```

### WebSocket Endpoints

```bash
# WebSocket URLs
grep -rhoP 'wss?://[a-zA-Z0-9._\-:/]+' *.js | sort -u

# Socket.io connections
grep -rhoP '(io|socket)\s*\(\s*["'\''`]([^"'\''`]+)["'\''`]' *.js

# WebSocket path patterns
grep -rhoP '(wsEndpoint|socketUrl|WS_URL|websocket)["\s:=]+["'\''`]([^"'\''`]+)' *.js
```

### GraphQL Endpoints and Schema Hints

```bash
# GraphQL endpoint URLs
grep -rhoP '(graphql|gql)[_\-]?(endpoint|url|uri|server)["'\'']*\s*[:=]\s*["'\''`]([^"'\''`]+)' *.js
grep -rhoP 'https?://[^"'\''`\s]+/graphql' *.js

# GraphQL operation names (reveals schema)
grep -rhoP '(query|mutation|subscription)\s+([A-Z][a-zA-Z]+)' *.js | sort -u

# GraphQL field names from queries
grep -rhoP 'gql`[^`]*`' *.js  # Template literal queries

# Introspection hints
grep -rhoP '__schema|__type|introspection' *.js
```

### Service Worker URLs

Service workers often reference additional API endpoints and caching strategies.

```bash
# Service worker registration
grep -rhoP 'navigator\.serviceWorker\.register\s*\(\s*["'\''`]([^"'\''`]+)' *.js

# Workbox/SW precache manifests
curl -s https://target.com/service-worker.js | grep -oP 'https?://[^"'\''`\s,]+' | sort -u
curl -s https://target.com/sw.js | grep -oP '"url"\s*:\s*"([^"]+)"'
```

### CDN/Storage Bucket URLs

```bash
# AWS S3 buckets
grep -rhoP '(https?://)?[a-z0-9\-]+\.s3[.\-][a-z0-9\-]+\.amazonaws\.com' *.js
grep -rhoP 's3://[a-z0-9\-]+' *.js
grep -rhoP 'https?://s3[.\-][a-z0-9\-]+\.amazonaws\.com/[a-z0-9\-]+' *.js

# Google Cloud Storage
grep -rhoP 'https?://storage\.googleapis\.com/[a-z0-9\-]+' *.js
grep -rhoP 'https?://[a-z0-9\-]+\.storage\.googleapis\.com' *.js

# Azure Blob Storage
grep -rhoP 'https?://[a-z0-9]+\.blob\.core\.windows\.net/[a-z0-9\-]+' *.js

# CloudFront / CDN distributions
grep -rhoP 'https?://[a-z0-9]+\.cloudfront\.net' *.js

# Firebase
grep -rhoP 'https?://[a-z0-9\-]+\.firebaseio\.com' *.js
grep -rhoP 'https?://[a-z0-9\-]+\.web\.app' *.js
```

---

## Tools

### LinkFinder

Extracts endpoints from JS files using regex patterns.

```bash
# Install
pip3 install linkfinder

# Basic usage — single file
python3 linkfinder.py -i https://target.com/static/js/main.js -o cli

# Crawl and extract from all JS
python3 linkfinder.py -i https://target.com -d -o results.html

# Output as plain text for piping
python3 linkfinder.py -i https://target.com/static/js/main.js -o cli | sort -u
```

### getJS

Fetches all JavaScript files from a target.

```bash
# Install
go install github.com/003random/getJS@latest

# Get all JS URLs from a page
echo "https://target.com" | getJS

# With subdomains from stdin
cat subdomains.txt | getJS --complete

# Download all JS files
echo "https://target.com" | getJS | xargs -I{} wget -P js_bundles/ {}
```

### JSParser (retired but pattern is useful)

```bash
# Modern alternative: use linkfinder or manual regex
# JSParser extracted relative URLs from JS using Tornado + jsbeautifier
```

### Source Map Extraction

```bash
# sourcemapper — reconstruct source tree from .map files
go install github.com/nicholasgasior/sourcemapper@latest
sourcemapper -url https://target.com/static/js/main.abc123.js.map -output ./source_tree/

# unwebpack-sourcemap — specifically for webpack maps
pip3 install unwebpack-sourcemap
unwebpack-sourcemap --make-directory https://target.com/static/js/main.abc123.js.map ./output/

# Manual extraction with curl + jq
curl -s https://target.com/static/js/main.js.map | jq '.sources[]' | head -50
# This shows the original file tree structure

# Extract original source content
curl -s https://target.com/static/js/main.js.map | jq -r '.sourcesContent[0]'
```

### Beautification

Minified code is hard to analyze. Beautify first.

```bash
# js-beautify
pip3 install jsbeautifier
js-beautify -f main.min.js -o main.pretty.js

# prettier (if Node available)
npx prettier --write "*.js"

# Online: beautifier.io (don't use for sensitive targets)

# Quick one-liner with Python
python3 -c "import jsbeautifier; print(jsbeautifier.beautify(open('main.min.js').read()))" > main.pretty.js
```

### Automated Workflow Script

```bash
#!/bin/bash
# js-recon.sh — Automated JS bundle recon
TARGET=$1
OUTDIR="./js_recon_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$OUTDIR"/{bundles,extracted}

echo "[*] Fetching JS file URLs..."
echo "https://$TARGET" | getJS --complete | sort -u | tee "$OUTDIR/js_urls.txt"

echo "[*] Downloading bundles..."
while read url; do
  wget -q -P "$OUTDIR/bundles/" "$url" 2>/dev/null
  # Check for source maps
  wget -q -P "$OUTDIR/bundles/" "${url}.map" 2>/dev/null
done < "$OUTDIR/js_urls.txt"

echo "[*] Extracting endpoints..."
grep -rhoP 'https?://[a-zA-Z0-9._\-:/]+' "$OUTDIR/bundles/" | sort -u > "$OUTDIR/extracted/urls.txt"
grep -rhoP '"/api/[^"]*"' "$OUTDIR/bundles/" | sort -u > "$OUTDIR/extracted/api_paths.txt"
grep -rhoP 'wss?://[^\s"'\'']+' "$OUTDIR/bundles/" | sort -u > "$OUTDIR/extracted/websockets.txt"

echo "[*] Looking for environment configs..."
grep -rhoP '(NEXT_PUBLIC|REACT_APP|VITE|VUE_APP)_[A-Z_]+=?["'\''`]?[^"'\''`\s]*' "$OUTDIR/bundles/" | sort -u > "$OUTDIR/extracted/env_vars.txt"

echo "[*] Extracting potential domains..."
grep -rhoP '[a-z0-9\-]+\.(internal|corp|local|staging|dev|test|preprod)\.[a-z.]+' "$OUTDIR/bundles/" | sort -u > "$OUTDIR/extracted/internal_domains.txt"

echo "[*] Done. Results in $OUTDIR/extracted/"
wc -l "$OUTDIR/extracted/"*
```

---

## Staging Domain Discovery from Bundles

### How Dev/Staging URLs End Up in Production

This happens because of how build tools handle environment variables:

1. **Build-time substitution with fallbacks** — Webpack's `DefinePlugin` replaces `process.env.API_URL` at build time, but conditional logic may preserve all environment URLs:
   ```javascript
   // Original source
   const API = process.env.NODE_ENV === 'production' 
     ? 'https://api.target.com' 
     : 'https://api-staging.target.internal';
   
   // After webpack build — BOTH URLs are in the bundle
   const API = "production" === "production" 
     ? "https://api.target.com" 
     : "https://api-staging.target.internal";
   ```

2. **Config objects with all environments** — Common anti-pattern:
   ```javascript
   const config = {
     production: { api: "https://api.target.com" },
     staging: { api: "https://api-staging.target.internal" },
     development: { api: "http://localhost:3001" }
   };
   ```

3. **Dead code not eliminated** — Tree-shaking doesn't remove string literals in config objects.

### Environment Variable Leakage Patterns

```bash
# Find multi-environment config blocks
grep -rhoP '(staging|dev|development|test|preprod|uat|sandbox)["\s:]+["'\''`](https?://[^"'\''`]+)' *.js

# Internal domain patterns
grep -rhoP 'https?://[a-z0-9\-]+\.(internal|corp|local|intra|private)(\.[a-z]+)+' *.js

# Non-production TLDs and subdomains
grep -rhoP 'https?://(dev|staging|stg|uat|preprod|sandbox|test|qa|demo)[.\-][a-z0-9.\-]+' *.js

# Kubernetes/Docker internal service names
grep -rhoP 'https?://[a-z\-]+\.(default|kube-system|svc\.cluster\.local)' *.js
grep -rhoP 'https?://[a-z\-]+:[0-9]{4,5}' *.js  # Internal ports

# IP addresses (internal services)
grep -rhoP 'https?://(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9.]+[:/][0-9a-z/]*' *.js
```

### Build-Time vs Runtime Config

Understanding the difference helps predict what leaks:

- **Build-time** (webpack DefinePlugin, Vite `import.meta.env`, Next.js `NEXT_PUBLIC_*`): Inlined as string literals. ALL referenced values end up in the bundle regardless of current environment.
- **Runtime** (fetched from `/config.json` or injected via `window.__CONFIG__`): Only current environment values present, but the config endpoint itself is discoverable.

```bash
# Find runtime config injection points
grep -rhoP 'window\.__[A-Z_]+__' *.js | sort -u
grep -rhoP 'window\.(config|CONFIG|env|ENV|settings|SETTINGS)' *.js

# Check for config endpoints
grep -rhoP '["'\''`](/config|/env|/settings|/app-config)[^"'\''`]*["'\''`]' *.js
curl -s https://target.com/config.json
curl -s https://target.com/env.js
```

---

## Architecture Mapping from Bundles

### Identifying Microservice Names from API Paths

```bash
# Extract unique API path prefixes (likely = microservice names)
grep -rhoP '["'\''`]/(api/)?v[0-9]+/([a-z\-]+)/' *.js | \
  sed 's/.*\/\(v[0-9]*\/\)\?//' | sed 's/\/.*//' | sort | uniq -c | sort -rn

# Common patterns:
# /api/v1/users/...      → user-service
# /api/v1/payments/...   → payment-service  
# /api/v1/inventory/...  → inventory-service
# /api/v2/search/...     → search-service

# Look for service name references directly
grep -rhoP '(service|svc|microservice)[_\-]?(name|id|url)["'\'']*\s*[:=]\s*["'\''`]([^"'\''`]+)' *.js

# API gateway routing hints
grep -rhoP '(gateway|proxy|upstream|backend)[_\-]?(url|host|endpoint)["'\'']*\s*[:=]\s*["'\''`]([^"'\''`]+)' *.js
```

### Mapping Frontend Routes to Backend Services

```bash
# React Router / Vue Router route definitions
grep -rhoP '(path|route)\s*:\s*["'\''`](/[^"'\''`]+)["'\''`]' *.js | sort -u

# Next.js pages (from build manifest)
curl -s https://target.com/_next/static/*/buildManifest.js | grep -oP '"/[^"]*"' | sort -u

# Angular route modules
grep -rhoP 'loadChildren\s*:\s*.*?["'\''`]([^"'\''`]+)["'\''`]' *.js

# Map routes to their API calls (manual correlation)
# 1. Find route: /admin/users
# 2. Find corresponding chunk
# 3. Extract API calls from that chunk → /api/v1/admin/users
```

### Identifying Auth Flow

```bash
# OAuth/OIDC provider detection
grep -rhoP '(authorize_url|authorization_endpoint|token_endpoint|issuer)["'\'']*\s*[:=]\s*["'\''`]([^"'\''`]+)' *.js

# Auth library detection
grep -rhoP '(auth0|okta|cognito|firebase|keycloak|supertokens|clerk)' *.js | head -20

# Token storage mechanism
grep -rhoP '(localStorage|sessionStorage)\.(get|set)Item\s*\(\s*["'\''`]([^"'\''`]+)' *.js
# Common keys: access_token, id_token, refresh_token, auth_token

# JWT handling
grep -rhoP '(jwt|token|bearer|authorization)[_\-]?(header|key|name|prefix)' *.js

# PKCE / OAuth flow type
grep -rhoP '(code_challenge|code_verifier|response_type|grant_type)' *.js

# Session/cookie names
grep -rhoP '(cookie|session)[_\-]?(name|key|id)["'\'']*\s*[:=]\s*["'\''`]([^"'\''`]+)' *.js
```

---

## Integration with Other Phases

### Phase 1/2 — Subdomain Enumeration

Feed discovered domains back into recon:

```bash
# Extract all unique domains from bundles
grep -rhoP 'https?://([a-z0-9\-]+\.)+[a-z]{2,}' js_bundles/*.js | \
  sed 's|https\?://||' | sed 's|/.*||' | sort -u > discovered_domains.txt

# Add to subdomain wordlist
cat discovered_domains.txt >> subdomains_to_resolve.txt

# Check which are alive
cat discovered_domains.txt | httpx -silent -status-code

# Feed internal domains into DNS brute-forcing
# If you find api-staging.target.internal, try:
#   admin-staging.target.internal
#   auth-staging.target.internal
#   etc.
```

### Phase 3 — API Endpoint Enumeration

```bash
# Build API path wordlist from bundles
grep -rhoP '"/(api|v[0-9])/[^"]*"' js_bundles/*.js | \
  tr -d '"' | sort -u > api_paths_from_bundles.txt

# Feed into directory brute-forcing
ffuf -u https://api.target.com/FUZZ -w api_paths_from_bundles.txt -mc 200,201,401,403

# Test discovered endpoints for auth bypass
while read path; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://api.target.com${path}")
  echo "$code $path"
done < api_paths_from_bundles.txt | grep -v "^404"

# Extract parameter names for fuzzing
grep -rhoP '(params|query|body)\.[a-zA-Z_]+' js_bundles/*.js | \
  sed 's/.*\.//' | sort -u > param_names.txt
```

### Phase 5/6 — OAuth and Auth Testing

```bash
# Extracted OAuth client_ids enable:
# 1. Redirect URI manipulation
# 2. Token theft via open redirect
# 3. Client confusion attacks

# Build OAuth authorization URL for testing
CLIENT_ID="extracted_client_id"
# Try various redirect_uri values:
REDIRECT_URIS=(
  "https://evil.com/callback"
  "https://target.com.evil.com/callback"  
  "https://target.com/callback/../../../evil"
  "https://target.com/callback?next=https://evil.com"
)

for uri in "${REDIRECT_URIS[@]}"; do
  echo "https://auth.target.com/authorize?client_id=${CLIENT_ID}&redirect_uri=${uri}&response_type=code"
done

# Test discovered callback URLs for open redirect
grep -rhoP '(redirect_uri|callback)[^"]*["'\''`]([^"'\''`]+)["'\''`]' js_bundles/*.js | \
  sort -u > oauth_callbacks.txt
```

### Quick Reference — What to Feed Where

| Extracted Data | Feed Into | Phase |
|---|---|---|
| Internal domains | Subdomain enumeration, DNS brute | 1/2 |
| Staging URLs | Direct access testing | 2 |
| API paths | Endpoint enumeration, auth bypass | 3 |
| Feature flags | Hidden functionality testing | 3/4 |
| OAuth client_ids | Redirect URI manipulation | 5/6 |
| WebSocket URLs | WS injection testing | 4 |
| GraphQL endpoints | Introspection, query fuzzing | 3/4 |
| S3/GCS buckets | Bucket permission testing | 3 |
| JWT/token config | Token forgery, algorithm confusion | 5 |

---

## Quick One-Liner Cheatsheet

```bash
# Full pipeline: fetch → extract → deduplicate
echo "https://target.com" | getJS --complete | \
  xargs -I{} curl -s {} | grep -oP 'https?://[^\s"'\''`<>]+' | sort -u

# Find source maps for any JS URL
curl -s https://target.com/static/js/main.js | grep -oP 'sourceMappingURL=\K[^\s]+'

# One-shot internal domain extraction
curl -s https://target.com | grep -oP 'src="[^"]*\.js"' | \
  sed 's/src="//;s/"//' | \
  xargs -I{} curl -s "https://target.com{}" | \
  grep -oP '(staging|dev|internal|corp|test)\.[a-z0-9.\-]+' | sort -u

# Extract all string literals (nuclear option — noisy but thorough)
grep -rhoP '"[^"]{5,200}"' js_bundles/*.js | sort -u | less
```
