# Spring Boot Springdoc/Swagger Unauthenticated Exposure

## Pattern (AltoCMS, June 2026)

Spring Boot apps using springdoc-openapi commonly misconfigure security filters,
leaving documentation and actuator paths outside the auth filter chain.

## Discovery Flow

1. Probe `/{context}/v3/api-docs` (OpenAPI 3.0 JSON spec)
2. Probe `/{context}/swagger-ui/index.html` (interactive UI)
3. Probe `/{context}/swagger-ui/swagger-initializer.js` (config — may leak internal hostnames)
4. Probe `/{context}/v3/api-docs/swagger-config` (internal hostname in oauth2RedirectUrl)
5. Probe `/{context}/health` (database type, disk space, component status)
6. Probe `/{context}/webjars/swagger-ui/*` (static assets confirm UI accessible)

## Typical Unprotected Paths

```
/{context}/v3/api-docs              → Full OpenAPI spec (endpoints + schemas)
/{context}/v3/api-docs/swagger-config → Internal hostname, oauth redirect URL
/{context}/swagger-ui/index.html    → Interactive API testing interface
/{context}/swagger-ui/*             → All Swagger UI static resources
/{context}/webjars/swagger-ui/*     → Alternative Swagger UI path
/{context}/health                   → DB type, disk space, component health
```

## Typical Protected Paths (for comparison)

```
/{context}/actuator/*               → 401 (properly gated)
/{context}/api/*                    → 401 (main API filter)
/{context}/v2/api-docs              → 401 (older version often gated)
/{context}/swagger-resources        → 401
/{context}/info                     → 401
/{context}/env                      → 401
/{context}/metrics                  → 401
```

## Why It Happens

Spring Security's `WebSecurityConfigurerAdapter` or `SecurityFilterChain` typically
configures `.antMatchers("/api/**").authenticated()` but forgets to cover:
- `/v3/api-docs/**`
- `/swagger-ui/**`
- `/webjars/**`
- `/health`

Springdoc registers these paths outside `/api/` by default.

## Impact Assessment

| What's Exposed | Severity | Why |
|---|---|---|
| Full endpoint list + schemas | Medium | Maps entire attack surface for targeted exploitation |
| Request/response field names | Medium | Eliminates guesswork for IDOR/injection |
| Swagger UI (interactive) | Medium | Ready-made testing interface for attackers |
| Internal hostname | Low | Infrastructure disclosure |
| DB type + health status | Low | Confirms tech stack for CVE targeting |
| Sensitive schema fields (password, PIN, token) | Medium | Reveals auth flow internals |

## Exploitation After Discovery

1. Download full spec: `curl -sk /{context}/v3/api-docs -o api-docs.json`
2. Extract all endpoints: `python3 -c "import json; ..."`
3. Batch test ALL endpoints for unauth access (execute_code, 50 at a time)
4. Look for endpoints that bypass auth (fire-and-forget utilities like `remove-files`)
5. Check `swagger-config` for internal hostnames → add to scope
6. Use schema field names for targeted mass-assignment testing

## Key Lesson

When ONE path outside `/api/` is unprotected (like `/v3/api-docs`), systematically
probe ALL non-API paths. The auth filter gap often covers multiple paths.
In AltoCMS: `/v3/api-docs` + `/swagger-ui/*` + `/health` + `/api/download/remove-files`
were all unprotected while `/api/*` (94 other endpoints) were properly gated.
