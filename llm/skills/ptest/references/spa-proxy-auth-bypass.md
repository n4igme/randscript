# SPA Proxy Authentication Bypass Pattern

## Trigger
- Target serves a Single Page Application (Vue/React/Angular) at a subpath (e.g., `/app/client/`)
- Backend API services exist at parallel paths (e.g., `/app/service/`)
- Backend returns 400/connection-reset while SPA path returns different responses

## Pattern
Modern K8s/Istio deployments often configure nginx or Envoy to:
1. Serve static SPA files at `/app/client/*`
2. Proxy relative API calls from the SPA to backends WITHOUT auth validation

The SPA is expected to attach Bearer tokens (from JS session storage) to API calls. But the proxy itself doesn't enforce auth — it relies on the backend to reject unauthenticated requests. If the backend doesn't check auth on all endpoints, the proxy becomes an auth bypass.

## Discovery Steps
1. Identify SPA base path from HTML source (`<base href=/app/client/>`)
2. Identify backend service paths (from Swagger, Prometheus URI labels, JS config)
3. Test: `GET /app/client/{backend-relative-path}` without auth
4. Compare: same path via direct backend prefix may return 400 (Istio routing) while SPA prefix returns 200

## Example (LoanPlatform JFS, June 2026)
```
Direct:  GET /app-jfs/loan-service/jfs/batch-monitoring/search → 400 "Bad Request"
Via SPA: GET /app-jfs/jfs-client/jfs/batch-monitoring/search  → 200 (269 records!)

Direct:  POST /app-jfs/loan-service/jfs/repayments/execute   → 400 "Bad Request"  
Via SPA: POST /app-jfs/jfs-client/jfs/repayments/execute     → 200 SUCCESS (Critical!)
```

## What to Test Once Pattern Confirmed
1. ALL GET endpoints from JS config (data exfiltration)
2. ALL POST endpoints (write actions — repayments, uploads, key generation)
3. Sequential ID enumeration (IDOR via `/resource/{1,2,3,...}`)
4. PUT/DELETE methods (may be blocked by proxy even if GET/POST work)

## Impact Assessment
- Read-only access to financial/PII data = High
- Write access to financial operations = Critical
- Crypto key generation = High (partner impersonation)

## Key Indicators
- Backend response: `400 Bad Request` (11 bytes, text/plain, server: istio-envoy)
- SPA proxy response: `200 OK` with JSON business data
- SPA HTML has `<meta name=base_url content="">` (empty = relative paths)
- JS config shows relative API URLs (`loan/v1`, `jfs/`) not absolute

## Remediation
- Enforce auth at the proxy/ingress layer (Istio AuthorizationPolicy)
- SPA path should ONLY serve static assets, not proxy API calls
- Backend services must validate auth independently regardless of request source
