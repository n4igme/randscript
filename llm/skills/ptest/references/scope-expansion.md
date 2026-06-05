# Scope Expansion Techniques

Run during Phase 1 exit / Phase 2 entry to maximize attack surface before testing.

---

## Mandatory Expansion Checks

### 1. Mobile-Only Endpoints
Even on web-only scope, proxy the mobile app:
- Mobile APIs often expose admin/internal endpoints the web UI never touches
- Different auth middleware (weaker token validation)
- Undocumented endpoints for push notifications, device management, sync

### 2. JS Bundle Mining
```bash
# Extract all URLs from webpack/vite bundles
curl -s https://target.com | grep -oE 'src="[^"]*\.js"' | sed 's/src="//;s/"//'
# For each JS file, extract API paths:
curl -s "$JS_URL" | grep -oE '"/api/[^"]*"' | sort -u
curl -s "$JS_URL" | grep -oE 'url:"[^"]*"' | sort -u
# Look for environment configs baked in:
curl -s "$JS_URL" | grep -oE '(REACT_APP|NEXT_PUBLIC|VUE_APP)_[A-Z_]+' | sort -u
```
Hidden paths found this way: /internal/, /debug/, /admin/, staging URLs, webhook endpoints.

### 3. Version/Environment Discovery
```bash
# Staging/dev environments
for prefix in staging dev beta sandbox preprod uat; do
  host $prefix.target.com 2>/dev/null | grep "has address"
  host $prefix-api.target.com 2>/dev/null | grep "has address"
done
# Older API versions (often lack auth)
for v in v0 v1 v2 v3 beta internal legacy; do
  curl -sk -o /dev/null -w "%{http_code} /api/$v/\n" "$BASE_URL/api/$v/"
done
```

### 4. SSRF as Recon Tool
When SSRF is confirmed, USE it to expand scope:
```
Internal network scan targets:
- 172.16.0.0/12, 10.0.0.0/8 (common ranges)
- Common ports: 8080, 8443, 9090, 3000, 5000, 6379, 27017
- Cloud metadata: 169.254.169.254
- K8s API: https://kubernetes.default.svc
- Service mesh: localhost:15000 (Envoy admin)
```
Every internal service you find = new attack surface.

### 5. Subdomain Behavior Differences
Subdomains that 302 to main app often have:
- Different WAF rules (less restrictive)
- Older middleware (missing auth checks added to main)
- Debug headers still enabled
- CORS allowing that subdomain specifically

### 6. Deprecated App Versions
- APKPure / archive.org for older APKs
- Older versions may hardcode endpoints that still respond
- API keys in old versions may still be valid
- Old auth flows (pre-MFA) may still work on backend

### 7. Error-Driven Discovery
Intentional bad requests reveal hidden surface:
- 405 Method Not Allowed → confirms endpoint exists, try other methods
- 401 on /admin/something → admin panel exists, find auth bypass
- Stack traces reveal: internal paths, libraries, other service names
- Validation errors reveal: field names, expected formats, related endpoints

---

## When to Stop Expanding

- Time budget: max 25% of Phase 1 on expansion
- Diminishing returns: 3 consecutive checks find nothing new → move on
- Enough surface: 20+ endpoints mapped = sufficient for Phase 2
- Exception: if early expansion reveals critical (staging env, leaked creds) → exploit immediately
