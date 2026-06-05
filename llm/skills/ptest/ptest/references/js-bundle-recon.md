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

## SPA False-Positive Detection (CRITICAL — Check FIRST)

Modern SPAs (React, Vue, Angular, Garfish micro-frontends) return HTTP 200 with the same HTML shell for ALL paths due to client-side routing. This causes massive false positives when brute-forcing directories, actuator endpoints, .git, swagger, etc.

**Detection method:** Before running any directory/endpoint enumeration, establish a baseline:

```bash
# Get baseline response size for a known-nonexistent path
BASELINE=$(curl -sk "https://target.com/nonexistent-xyz-baseline-12345" 2>/dev/null | wc -c)
echo "SPA baseline: $BASELINE bytes"

# Only flag responses that DIFFER from baseline
# Same size = SPA catch-all (false positive)
# Different size = real server-side endpoint
```

**Indicators of SPA catch-all:**
- ALL paths return 200 OK with identical response size
- Response is HTML containing `<div id="root"></div>` or similar mount point
- Response contains framework bootstrap (React, Vue, Garfish, Goofy Deploy)
- `/nonexistent-random-path` returns same size as `/actuator/health`

**Real endpoint indicators (different from baseline):**
- Different response size (even a few bytes difference matters)
- JSON response instead of HTML
- Different HTTP status code (403, 401, 301 = real server-side routing)
- Different Content-Type header
- 0 bytes (blocked but exists)

**ByteDance/TikTok Goofy Deploy pattern (discovered May 2026):**
- Server: TLB + X-Powered-By: Goofy Deploy/Node
- SPA shell contains `gfdatav1` JSON with full module architecture
- SPA shell contains `scmconfigv1` JSON with API keys, region config
- SPA shell contains `pumbaa-rule` JSON with privacy/network interception rules
- Real APIs are at `/api/v1/*` paths and return JSON (different size from shell)
- POST requests to API paths return structured JSON errors even without auth
- GET to same API paths may return 404 (nginx) while POST returns JSON

**Garfish micro-frontend detection:**
- Look for `garrModules` in page source — lists ALL micro-app names and CDN URLs
- Each module has `source_url` (CDN JS) and `gfurl` (origin fallback)
- Module names map to frontend routes AND backend API prefixes
- `garfishModuleInfo` contains VMOK federation metadata with shared dependencies

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

### Module Federation (Webpack 5 Micro-Frontends)

Modern SPAs using Module Federation load independent micro-apps at runtime via `remote-entry-*.js` files. Each micro-app is a separate webpack build with its own chunks, API endpoints, and potentially different security configurations.

```bash
# Identify Module Federation from the main bundle
curl -s https://target.com/app.*.js | grep -oP 'https?://[^"]+remote-entry[^"]+\.js' | sort -u

# Example output (real-world: Moka POS backoffice):
# https://backoffice.mokapos.com/auth-micro-apps/remote-entry-BoAuthApp.js
# https://backoffice.mokapos.com/payment-micro-apps/remote-entry-BoPaymentApp.js
# https://backoffice.mokapos.com/customer-micro-apps/remote-entry-BoCustomerApp.js

# Each remote-entry is a loader that references actual chunks:
curl -s https://target.com/auth-micro-apps/remote-entry-BoAuthApp.js | \
  grep -oP '[a-zA-Z0-9_-]+\.js' | sort -u

# The actual app logic is in dynamically-loaded chunks, not the remote-entry itself.
# To find chunks, look for chunk hash patterns in the remote-entry:
curl -s https://target.com/auth-micro-apps/remote-entry-BoAuthApp.js | \
  grep -oP '"[a-f0-9]{8,}"' | sort -u
```

**Why this matters for pentesting:**
- Each micro-app may talk to different backend services with different auth
- Micro-apps loaded from the same origin share cookies (CSRF potential)
- A compromised micro-app CDN path = supply chain attack on the entire SPA
- Different teams build different micro-apps → inconsistent security controls
- The remote-entry URL pattern reveals the internal team/domain structure

```bash
# Derive team/service names from micro-app paths:
# /auth-micro-apps/ → auth team
# /payment-micro-apps/ → payment team
# /customer-micro-apps/ → customer team
# These map to backend microservices and potential API prefixes

# Try to access chunk files directly (may contain API URLs):
# Pattern: /{app-name}-micro-apps/{hash}.js
for app in auth common payment customer online-store ingredient purchase-order table-management; do
  # Check if directory listing works
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/${app}-micro-apps/"
  echo " ${app}-micro-apps/"
done
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
grep -rhoP '["\\x27`](/config|/env|/settings|/app-config)[^"\\x27`]*["\\x27`]' *.js
curl -s https://target.com/config.json
curl -s https://target.com/env.js
```

### config.json Systematic Sweep (HIGH YIELD)

Many SPAs load runtime config from `/config.json`. This is a **first-class recon check** — run it on EVERY live web app discovered. Unlike source maps (which may be stripped), config.json is required for the app to function and is rarely protected.

```bash
# Sweep all live hosts for config.json
for host in $(cat live-200-hosts.txt | sed 's|https\?://||'); do
  resp=$(curl -s --max-time 5 "https://${host}/config.json" 2>/dev/null)
  if echo "$resp" | grep -q '"' 2>/dev/null && ! echo "$resp" | grep -q '<!DOCTYPE\|<html' 2>/dev/null; then
    echo "--- ${host}/config.json ---"
    echo "$resp" | head -c 500
    echo ""
  fi
done
```

**What config.json typically exposes:**
- Sentry DSNs (confirmed active = can inject fake errors)
- Google OAuth client IDs (enables OAuth flow testing)
- Internal IAM client IDs (Concedo, GrabID, etc.)
- Partner/service UIDs (production identifiers)
- Internal API gateways (`api-restricted.*`, `*.internal.*`)
- RUM/APM tokens (Datadog, Grafana Faro)
- Hedwig/notification template IDs
- Environment indicators (prd/stg)
- Segmentation platform URIs

**Real-world example (Grab, May 2026):**
- `omega-rtc.grab.com/config.json` → Sentry DSN, 6 production Partner UIDs, internal Hedwig API, Google OAuth client ID, Concedo IAM client ID, RUM token
- `bolt.grab.com/config.json` → Sentry DSN + Google OAuth
- `taxi.grab.com/config.json` → Sentry DSN + GrabID + VAPID key + map tiles server
- `drishti.grab.com/config.json` → IAM client ID + gateway URI

**Severity:** config.json with Sentry DSNs alone = Low. With production partner UIDs + internal service URLs = Medium. With actual API keys/secrets = High.

### Inline $_ENV in HTML Body (Module Federation Pattern)

Modern Module Federation host apps often inject the FULL environment config as a `<script>` block in the HTML body, NOT in JS bundles. This is because micro-frontends need runtime config that can change without rebuilding.

**Detection:**
```bash
# Check HTML body directly (not JS files!)
curl -sk "https://target.com/" | grep -oE '\$_ENV\s*=\s*\{[^}]*\}'

# Also check: window.__ENV__, window.__CONFIG__, window.env
curl -sk "https://target.com/" | grep -oE '(window\.__[A-Z_]+__|var \$_ENV|\$_ENV)\s*=\s*\{[^}]*\}'
```

**Extraction (parse as JSON):**
```bash
curl -sk "https://target.com/" | grep -oE '\$_ENV\s*=\s*\{[^}]*\}' | \
  python3 -c "
import json, sys, re
raw = sys.stdin.read().strip()
m = re.search(r'\{.*\}', raw)
if m:
    d = json.loads(m.group())
    for k,v in sorted(d.items()):
        print(f'{k}: {v}')
"
```

**Why this is critical:**
- Contains ALL API hosts, OAuth client IDs, feature flag keys, internal domains
- Often exposes staging/internal URLs that aren't in DNS or CT logs
- Different portals (prod, staging, internal) have DIFFERENT configs — compare them
- Docker image tags and commit IDs reveal deployment cadence

**Multi-portal comparison technique (discovered in GoBiz engagement, May 2026):**
1. Extract $_ENV from the production portal
2. Find staging/integration portals (common patterns: portal-integration.*, portal-stg.*, app.stg.*)
3. Find internal portals (internal.*, app.gobiz.com, admin.*)
4. Compare configs — differences reveal:
   - Staging API hosts (api-s.*, api.stg.*, integration-api.*)
   - Internal-only domains (internal.s.*, *.corp.*)
   - Different OAuth configs (registration enabled/disabled)
   - Different feature flags (beta features on staging)

**Real-world example (GoBiz/GoFood Merchant, May 2026):**
```
Production (portal.gofoodmerchant.co.id):
  REACT_APP_API_HOST: https://api.gobiz.co.id
  REACT_APP_ENABLE_REGISTRATION: true
  REACT_APP_COSMO_HOST: https://api.gobiz.co.id/cosmo

Staging (portal-integration.gofoodmerchant.co.id):
  REACT_APP_API_HOST: https://api-s.gobiz.co.id        ← NEW domain
  REACT_APP_ENVIRONMENT: staging
  REACT_APP_GOJEK_API_HOST: https://integration-api.gojekapi.com  ← NEW domain
  REACT_APP_ZEUS_LOGIN_HOST: https://internal.s.gobiz.com          ← NEW domain

Internal (internal.gobiz.com/micro-app/auth/login/email):
  REACT_APP_ENABLE_REGISTRATION: false                  ← Different!
  REACT_APP_COSMO_HOST: https://api-s.gobiz.co.id/cosmo ← Points to staging API
  REACT_APP_MF_HOST_*: https://app.gobiz.com/micro-app/* ← Internal host
```

**Module Federation remoteEntry.js as additional config source:**
```bash
# MF host apps reference micro-app URLs in their config
# Each micro-app has its own remoteEntry.js with potentially different config
curl -sk "https://target.com/micro-app/auth/remoteEntry.js" -o mf-auth.js
curl -sk "https://target.com/micro-app/dashboard/remoteEntry.js" -o mf-dashboard.js

# The micro-app HTML pages also have their own $_ENV:
curl -sk "https://target.com/micro-app/auth/login/email" | grep '\$_ENV'
# This may have DIFFERENT config than the host app!
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

### Source Map Exploitation — Full Source Recovery

**Chain exploitation:** See `references/source-map-token-exploitation.md` for the full pattern: source map → token extraction → verified API write access. This chain elevates severity from Medium (info disclosure) to High (authenticated write access). Also covers: multi-app sweep methodology, telemetry token exploitation, CORS+debug combined attacks, CMS route discovery, and Flutter/protobuf analysis.

When source maps are found accessible, extract the complete original source tree:

### Verification & Impact Assessment

```bash
# Check source map size (>500KB = likely full source)
curl -sk -o /dev/null -w "%{http_code}:%{size_download}" "https://target.com/static/js/main.abc123.js.map"

# Quick structure check
curl -sk "https://target.com/static/js/main.abc123.js.map" | python3 -c "
import json, sys
sm = json.load(sys.stdin)
app_sources = [s for s in sm.get('sources',[]) if 'node_modules' not in s]
print(f'Total files: {len(sm[\"sources\"])}')
print(f'App files (non-node_modules): {len(app_sources)}')
print(f'Has sourcesContent: {bool(sm.get(\"sourcesContent\"))}')
total_chars = sum(len(c) for c in sm.get('sourcesContent',[]) if c)
print(f'Total source chars: {total_chars:,} (~{total_chars//60:,} lines)')
for s in sorted(app_sources):
    print(f'  {s}')
"
```

### Extract Specific Files

```python
import json

with open('sourcemap.json') as f:
    sm = json.load(f)

sources = sm.get('sources', [])
contents = sm.get('sourcesContent', [])

# Extract files matching pattern
targets = ['environment', 'config', 'auth', 'api', 'clickstream', 'App.tsx']
for t in targets:
    for i, s in enumerate(sources):
        if t.lower() in s.lower() and i < len(contents) and contents[i]:
            print(f'=== {s} ===')
            print(contents[i][:2000])
```

### What to Look For in Recovered Source

| Target | Why |
|--------|-----|
| `helpers/environment.ts`, `config.ts` | API URLs, feature flags, env detection |
| `utils/auth.ts`, `utils/api.ts` | Auth token patterns, header construction |
| `utils/clickstream.ts`, `analytics.ts` | Telemetry tokens, event pipeline URLs |
| `router/routes.tsx` | Full route structure, lazy-loaded pages |
| Comments with URLs | Internal wiki, GitLab, Jira references |
| `package.json` (in sources) | Exact dependency versions for CVE |

### Real-World Example (GoPay, May 2026)

Production source map at `gopay-web-page.gopayapi.com/static/js/main.*.js.map`:
- 201 source files, 990KB of TypeScript/React source
- Revealed `Authorization: Basic ${token}` pattern in clickstream utility
- Exposed internal GitLab URL: `source.golabs.io/gopay/gopay-target-redirection-web-app`
- Exposed Confluence wiki: `go-jek.atlassian.net/wiki/spaces/EP/pages/...`
- Led to confirmed write access on production event pipeline (chained finding)

**Key insight:** Always check BOTH production AND staging source maps. Staging often has MORE verbose config (debug flags, internal URLs) that production strips.

### Reporting Source Map Findings

Severity depends on what's IN the source:
- Source map exists but only has node_modules → **Info** (framework code only)
- Source map with app code but no secrets → **Low-Medium** (architecture disclosure)
- Source map revealing auth patterns + internal URLs → **Medium** (aids further attacks)
- Source map containing hardcoded tokens/keys → **High** (direct credential exposure)

---

## Flutter Web Bundle Analysis

Flutter Web apps compile Dart to a single `main.dart.js` (often 3-10MB). These contain ALL app logic including API paths, deep link schemes, and business logic.

```bash
# Download Flutter main.dart.js
curl -sk "https://target.com/main.dart.js" -o main.dart.js
wc -c main.dart.js  # Expect 3-10MB

# Extract API paths (Flutter uses string literals for routes)
grep -oE '"/v[0-9]+/[a-z][a-z0-9/_.-]{3,80}"' main.dart.js | sort -u

# Extract full URLs
grep -oiE 'https?://[a-zA-Z0-9._:/-]+' main.dart.js | sort -u

# Extract deep link schemes
grep -oiE '[a-z]+://[a-z0-9/_.-]+' main.dart.js | grep -v "http" | sort -u

# Flutter service worker (lists cached assets)
curl -sk "https://target.com/flutter_service_worker.js" | grep -oiE 'https?://[^"]+' | sort -u
```

**Flutter-specific patterns:**
- API paths are plain string literals (no obfuscation in web builds)
- Deep link schemes reveal mobile app integration points
- `findaya.co.id`, `app.jago.com` type URLs reveal partner integrations
- Config JSON paths like `/mm_fe_configs/...` may be accessible on the same host

---

## OpenAPI Schema in JS Bundles (HIGH YIELD)

Modern SPAs that use code-generated API clients (openapi-typescript, orval, swagger-codegen) often bundle the **complete OpenAPI schema** as a JS module. This is distinct from source maps — it's the actual API specification compiled into the client code.

**Detection:**
```bash
# Check for openapi-named JS files in page source
curl -s https://target.com/ | grep -oE 'src="[^"]*openapi[^"]*\.js"'

# Also check for api-client, swagger, schema named chunks
curl -s https://target.com/ | grep -oiE 'src="[^"]*(openapi|swagger|api-client|api-schema)[^"]*\.js"'
```

**Extraction:**
```bash
# Download and extract all URL patterns (contains full endpoint definitions)
curl -s 'https://target.com/static/js/openapi.*.js' > /tmp/openapi_bundle.js

# Extract all API endpoints
grep -oE 'url:"[^"]+"' /tmp/openapi_bundle.js | sed 's/url:"//;s/"//' | sort -u

# Extract HTTP methods paired with URLs
grep -oE '(method:"(get|post|put|patch|delete)".*?url:"[^"]+"|url:"[^"]+".*?method:"[^"]+")' /tmp/openapi_bundle.js
```

**What this reveals (beyond source maps):**
- Complete list of ALL API endpoints (including internal/admin paths)
- Request/response schemas with field names and types
- Enum values (error codes, status values, user roles)
- Path parameters and their types
- Media types accepted per endpoint

**Real-world example (Wallet on Telegram, May 2026):**
- `https://walletbot.me/static/js/openapi.3a40364718.js` (97KB)
- Contained 494 API endpoints across 15+ microservices
- Revealed internal admin paths (`/internal/orgs`, `/internal/users/{id}/tokens`)
- Exposed transaction-scanner retool-api (admin panel)
- Revealed full P2P trading flow (escrow, appeals, merchant API keys)
- Exposed auth mechanism details (Telegram initData fields required)
- Contained enum values for error codes, order states, appeal reasons

**Severity assessment:**
- OpenAPI bundle with only public endpoints → Low (architecture disclosure)
- OpenAPI bundle revealing internal/admin endpoints → Medium
- OpenAPI bundle with hardcoded tokens or secrets in default values → High

**Key difference from config.json:** Config.json exposes runtime secrets (DSNs, API keys). OpenAPI bundles expose the complete API surface map — every endpoint, every parameter, every enum value. Combined, they give an attacker a complete blueprint.

**Pitfall:** The endpoints in the OpenAPI bundle may be served on different hosts than where the JS is loaded from. Check the SPA's network requests or CSP `connect-src` directive to identify which backend hosts serve which API paths.

---

## Quick One-Liner Cheatsheet

### Internal Logging/Telemetry Service Exploitation (NELO Pattern)

Client-side JS bundles often contain hardcoded logging service endpoints and project identifiers. Unlike analytics (Sentry, Datadog) where tokens are read-only, some internal logging services accept arbitrary WRITES from anyone who knows the project name.

**Discovery:**
```bash
# Find logging/telemetry endpoints in JS bundles
grep -rhoP '(nelo|logstash|fluentd|loki|elastic|kibana|splunk|log[_-]?server)[^"'\''`]{0,100}' *.js
grep -rhoP 'https?://[^\s"'\''<>]+(_store|/logs|/ingest|/collect|/track)' *.js

# Find project names/identifiers
grep -rhoP '(projectName|project_name|projectId|project_id|logSource)["\s:]+["'\''`]([^"'\''`]+)' *.js

# NELO-specific (Naver internal logging)
grep -rhoP '["\x27]P[0-9a-f]+_[a-z_]+["\x27]' *.js
grep -rhoP 'nelo\.navercorp\.com[^"'\''`]*' *.js
```

**Exploitation (once endpoint + project name found):**
```bash
# Test if the project accepts unauthenticated writes
curl -s -X POST "https://<nelo-endpoint>/_store" \
  -H "Content-Type: application/json" \
  -d '[{"projectName":"<project_id>","projectVersion":"1.0.0","logSource":"test","logLevel":"info","body":"auth_test"}]'

# Success: {"code":200,"message":"Success"}
# Fail: {"code":400,"message":"...Invalid project. Please register project and use valid projectKey..."}
```

**Impact escalation:**
- `info` level: log pollution, evidence tampering
- `fatal` level: trigger PagerDuty/on-call alerts (social engineering via ops)
- XSS in body: potential stored XSS in internal monitoring dashboards
- Bulk injection: log DoS, hide real attacks in noise

**Real-world (LINE WORKS, June 2026):**
- JS bundle at `cxtalk-service.line-works.com/jp1/dist/history/history.main-*.js` (2MB)
- 4 NELO project names discovered: P6349d1_cstalk_connect (WRITABLE), P84f543_cstalk_userdata, P95625c_cstalk_jserror, P275bc3_cstalk_pageload
- Endpoint: `jp-col-ext.nelo.navercorp.com/_store` (publicly accessible)
- All log levels accepted, bulk injection works, no rate limiting

**Key insight:** When you find a logging endpoint in JS, test EACH project name separately — some require auth tokens while others don't. The project-level auth is independent per project.

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
