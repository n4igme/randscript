# SPA JS Bundle Endpoint Extraction

## When to Use
- Angular/React/Vue SPA detected (chunk-based lazy loading, main-*.js)
- Third-party identity SDKs embedded (Transmit Security, Auth0, Okta, Firebase Auth)
- API routes returning consistent "missing auth" errors — JS reveals the full surface

## MANDATORY: Analyze ALL Webpack Chunks, Not Just Main (AltoCMS, June 2026)

**Problem:** Only `main.*.chunk.js` and one numbered chunk were analyzed. The main chunk contained 8 API endpoints. But the app had 40+ lazy-loaded chunks that contained 50+ additional authenticated API endpoints (user/add, card/reset-pin-tries, role/access-list, transaction/download-transaction-data, etc.).

**Root cause:** Autopilot — analyzed files already on disk without fetching ALL chunks referenced in the webpack bootstrap.

**Fix — mandatory for React/webpack SPAs:**
1. Read HTML source — find webpack runtime bootstrap (inline `<script>` mapping chunk IDs to hashes)
2. Extract ALL chunk ID→hash mappings (e.g., `{0:"a0a7007f", 1:"84c865b2", ...}`)
3. Fetch EVERY chunk: `https://target/static/js/{id}.{hash}.chunk.js`
4. Extract API paths from EACH: `grep -oE '"[a-z][a-z_-]+/[a-z_/-]+"' chunk.js`
5. Deduplicate and test ALL discovered endpoints for auth enforcement

**Key insight:** Main chunk only has auth endpoints. Business logic (card mgmt, transactions, user CRUD, downloads) lives in lazy-loaded chunks. These are publicly accessible static assets even though the routes need auth.

```bash
# Extract all chunk URLs from webpack bootstrap
grep -oE '"[0-9]+":"[a-f0-9]+"' index.html | while IFS=: read id hash; do
  id=$(echo $id | tr -d '"'); hash=$(echo $hash | tr -d '"')
  echo "https://target/static/js/${id}.${hash}.chunk.js"
done
```

## Key Lesson (bitbank.cc, June 2026)

Standard API fuzzing with ffuf/gobuster found ZERO undocumented endpoints. But JS bundle analysis revealed:
- 90+ `/user/*` endpoints (OTP, FIDO, KYC, margin trading, lending)
- Root-level auth endpoints (`/login`, `/signup`, `/reset_password`, `/fido/*`) with NO version prefix
- CIS (Customer Identity Service) under `/cis/v1/*` path prefix on the app domain
- Different error format on FIDO endpoint (Transmit Security vs app's own format)

**The JS bundles are the real API documentation for bug bounty targets.**

## Technique: Multi-Layer JS Analysis

### Layer 1: App Chunks (Angular/React main bundles)
```bash
# Download all chunks
curl -sk 'https://app.target.com/' | grep -oE 'src="[^"]+\.js"' | sed 's/src="//;s/"//'
# Download each, search for paths
grep -ohE '"/[a-zA-Z0-9/_-]+"' /tmp/chunk-*.js | sort -u
```

### Layer 2: Third-Party SDKs (CRITICAL — often missed)
Look for embedded SDK scripts that reveal separate backend services:
- `ts-platform-websdk.js` → Transmit Security CIS (`/cis/v1/auth-session/*`, `/cis/v1/webauthn/*`)
- `auth0-spa-js` → Auth0 (`/authorize`, `/oauth/token`, `/userinfo`)
- `firebase-auth.js` → Firebase Auth endpoints
- `okta-auth-js` → Okta (`/api/v1/authn`, `/oauth2/default`)

```bash
# Find SDK scripts
grep -oE 'src="[^"]*sdk[^"]*"' /tmp/index.html
# Analyze for path patterns
grep -ohE '"/(v1|api|cis|auth|oauth|iam|identity|fido|webauthn)/[a-zA-Z0-9/_-]*"' /tmp/sdk.js | sort -u
```

### Layer 3: Path Prefix Discovery
Endpoints found in JS may live on different path prefixes or even different hosts:
```bash
# JS reveals: /v1/auth-session/status
# Test on all in-scope hosts AND with path prefixes:
for host in api.target.com app.target.com target.com; do
  for prefix in "" "/cis" "/api" "/iam" "/auth"; do
    curl -sk "https://${host}${prefix}/v1/auth-session/status" -X POST -d '{}' \
      -o /dev/null -w "${host}${prefix}/v1/auth-session/status -> %{http_code} %{size_download}\n"
  done
done
```

### Layer 4: Root-Level Endpoints
Some auth endpoints exist WITHOUT any version prefix:
```bash
# These are often invisible to standard API fuzzing:
/login, /signup, /register_mail, /reset_password
/fido/login/authenticate/start
/fido/login/authenticate/complete
```
Test both `GET` and `POST` — CloudFront distributions configured for cacheable-only requests will block POST with 403 while GET returns catch-all.

## SPA Catch-All Filtering

When the target is an SPA on S3+CloudFront:
1. First determine catch-all size: `curl -sk 'https://app.target.com/random-uuid-12345' -o /dev/null -w '%{size_download}'`
2. Any response with that exact size = client-side route (not a real backend path)
3. Real backend responses will have DIFFERENT sizes, different content-types, or different status codes
4. CloudFront POST → 403 "distribution supports only cacheable requests" = real backend exists but CF blocks non-GET

## Signals That More Endpoints Exist
- Error format changes (e.g., `{"success":0,"data":{"code":X}}` vs `{"error_code":"...","message":"..."}`) = different backend service
- Different HTTP status codes for similar operations (400 vs 200 with error JSON)
- SDK files > 100KB (contain full client logic with all endpoint paths)
- `hostname)?"/prefix":""` patterns in SDK = configurable path prefix
