# Spring Boot OpenAPI/Swagger Auth Filter Bypass

## Pattern (AltoCMS, June 2026)

Spring Boot 3.x with springdoc-openapi serves the OpenAPI spec at a **parent context path** that often falls OUTSIDE the API security filter chain.

### The Bypass

```
App context path: /jago/
API path (auth-gated): /jago/api/*
OpenAPI (NO AUTH):     /jago/v3/api-docs      ← 97KB, 95 endpoints, 130 schemas
Swagger UI (NO AUTH):  /jago/swagger-ui/index.html
Swagger config:        /jago/v3/api-docs/swagger-config
Health (NO AUTH):      /jago/health
Webjars (NO AUTH):     /jago/webjars/swagger-ui/*

Auth-gated:            /jago/api/v2/api-docs   ← 401
Auth-gated:            /jago/actuator/*         ← 401
```

### Why It Happens

Spring Security filter chain is typically configured for `/api/**` pattern. springdoc-openapi registers endpoints at the context root (`/v3/api-docs`, `/swagger-ui/**`) which is OUTSIDE the `/api/**` filter. Developers assume "everything under our app is protected" but the security config only covers the API prefix.

### Detection Methodology

For EVERY discovered context path prefix, test BOTH:
```bash
for base in "" "/jago" "/app" "/service" "/api" "/backend"; do
  for path in /v3/api-docs /swagger-ui/index.html /swagger-ui.html /health /info; do
    code=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code} %{size_download}" "https://target.com${base}${path}")
    echo "${base}${path} -> $code"
  done
done
```

### What Gets Exposed

1. **Full OpenAPI spec** (95 endpoints, all request/response schemas)
2. **Interactive Swagger UI** (try-it-out functionality)
3. **Sensitive schema fields** (password, token, PIN counters, role mappings)
4. **Security scheme documentation** (Bearer JWT format)
5. **Server description** (often says "Development environment" on prod)
6. **Internal hostname** (via swagger-config oauth2RedirectUrl)

### Additional Info Leaks Found

- `/jago/v3/api-docs/swagger-config` → `oauth2RedirectUrl` reveals internal hostname: `dashboard-jago.cms.local.alto.id`
- `/jago/health` → PostgreSQL database type, datasource names, disk space
- Server description in OpenAPI: "Server URL in Development environment" (on production!)

### Impact Assessment

- Full API surface disclosure enables targeted exploitation
- Schema knowledge eliminates guesswork for IDOR/auth bypass attempts  
- Business logic exposure (approval workflows, card operations, PIN reset)
- Interactive Swagger UI = ready-made testing interface for attackers
- Combined with brute-force (no rate limit): attacker has full map once creds obtained

### Severity: Medium (CVSS 5.3)
AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

### Remediation

1. Add `/v3/api-docs/**` and `/swagger-ui/**` to the security filter chain
2. Or: disable springdoc in production (`springdoc.api-docs.enabled=false`)
3. Or: require auth via `springdoc.swagger-ui.oauth.use-pkce-with-authorization-code-grant=true`
4. Restrict `/health` to authorized users or remove details (`management.endpoint.health.show-details=when_authorized`)

### Checklist Addition for Phase 3

When a Spring Boot app is detected (x-envoy-upstream-service-time, JSON errors with {timestamp,status,error,path}):
- [ ] Test `/v3/api-docs` at EVERY context path prefix
- [ ] Test `/swagger-ui/index.html` at EVERY context path prefix  
- [ ] Test `/health` at EVERY context path prefix
- [ ] If found: download full spec, count endpoints/schemas, check for sensitive fields
- [ ] Check swagger-config for internal hostnames
