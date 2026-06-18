# SPA Proxy Prefix Auth Bypass Pattern

## Pattern

When a K8s/Istio microservice architecture serves:
- A backend API at `/app/service-name/` (returns 400/401 due to Istio auth routing)
- A frontend SPA at `/app/client-name/` (serves static files)

The SPA path often PROXIES backend API calls through its own serving layer, bypassing Istio auth header requirements.

## Detection

1. Backend direct path returns 400 "Bad Request" (11 bytes, text/plain, from Istio Envoy)
2. SPA path returns 200 for static assets
3. Same API endpoint via SPA prefix returns 200 with actual data

## Testing

```bash
# Direct backend (blocked by Istio)
curl -sk "https://target/app-jfs/loan-service/loans" 
# → 400 Bad Request

# Via SPA proxy (bypasses auth)
curl -sk "https://target/app-jfs/jfs-client/loans"
# → 200 with loan data
```

## Key Indicators

- Istio Envoy returning consistent 400 "Bad Request" (not 401/403)
- Response is `text/plain` with exactly 11 bytes
- `x-envoy-upstream-service-time` header present (request DID reach backend mesh)
- SPA's JS source/config shows relative API URLs (e.g., `loan/v1`, `jfs/`)
- SPA `<meta name=base_url content="">` is empty (relative paths)

## Write Method Testing

Once GET works via proxy prefix, test POST/PUT/DELETE:
- If proxy is nginx serving SPA: POST may also be proxied
- If proxy is strict static server: POST returns connection reset (only GET forwarded)

## LoanPlatform Example (June 2026)

- `/app-jfs/loan-service/*` → 400 for ALL paths (Istio blocks without auth header)
- `/app-jfs/jfs-client/*` → proxies to same backend services WITHOUT auth
- Result: 5,327 financial records, disbursement PII, repayment execution — all unauth
- POST `/jfs-client/jfs/repayments/execute` → 200 SUCCESS (Critical write action)
- POST to `/jfs-client/private/*` → connection reset (proxy blocks non-GET on some paths)

## Trigger Conditions

Look for this pattern when:
- Istio/Envoy returns 400 (not 401) on API paths
- SPA and API share the same ingress IP
- JS source maps reveal relative API URLs without base domain
- SPA meta tags show empty base_url
