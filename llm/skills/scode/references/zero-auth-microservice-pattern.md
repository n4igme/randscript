---
name: ref-zero-auth-microservice
description: "Detection and reporting strategy for microservices with no authentication at all. Use when vuln-access-control finds zero auth."
---

# Zero-Auth Microservice Pattern

## Detection (Run in Recon Phase)

```bash
# Spring Boot / Kotlin / Java
grep -r "spring-boot-starter-security\|spring-security" build.gradle* pom.xml
grep -rn "@PreAuthorize\|@Secured\|@RolesAllowed\|@EnableWebSecurity\|SecurityFilterChain" --include="*.kt" --include="*.java"
grep -rn "OncePerRequestFilter\|HandlerInterceptor\|WebFilter" --include="*.kt" --include="*.java" | grep -v test

# Check Istio/K8s auth enforcement
find . -name "*.yaml" -o -name "*.yml" | xargs grep -l "AuthorizationPolicy\|PeerAuthentication\|NetworkPolicy" 2>/dev/null

# Check for API gateway auth (Helm values)
find . -name "values*.yaml" | xargs grep -i "auth\|jwt\|mtls\|bearer" 2>/dev/null
```

If ALL return empty → Zero-Auth confirmed.

## Reporting Strategy

### DO NOT create 20+ individual AC findings per endpoint.

Instead, create a tiered structure:

1. **VULN-001 (Critical)**: Systemic — No Application-Level Authentication
   - List ALL affected endpoints in a table
   - Note: `/private/` prefix is naming convention only, zero enforcement

2. **VULN-002-005 (Critical)**: Group by IMPACT TIER for the highest-risk endpoints:
   - Fund exfiltration (BIFast, interbank)
   - Bulk operations (payroll, batch)
   - Admin operations (manual adjustment, rate update)
   - Data access (transaction queries, reports)

3. Other categories (logic, data-exposure, DoS, etc.) remain independent findings.

## Common Architecture (Internal Banking Microservices)

Typical zero-auth microservice relies on:
- Kubernetes network isolation (namespace-level)
- Istio service mesh (routing only, no AuthorizationPolicy)
- Internal DNS (*.svc.cluster.local)

### Why This Is Still Critical

- Single compromised pod = full access to all financial operations
- No defense-in-depth
- No audit trail (no caller identity logged)
- Lateral movement trivial within cluster

## Validation Checklist

- [ ] No `spring-boot-starter-security` in any build file
- [ ] No custom auth filters/interceptors (only logging interceptors)
- [ ] No `@PreAuthorize`, `@Secured`, `@RolesAllowed` anywhere
- [ ] No Istio AuthorizationPolicy in repo
- [ ] No PeerAuthentication (mTLS enforcement) in repo
- [ ] `/private/` prefix has no backing enforcement mechanism
- [ ] Swagger/OpenAPI may define security schemes but NO enforcement code exists
- [ ] Headers like `x-partner-id` propagated for tracing only, never validated

## Remediation Template

```yaml
# Phase 1: Service-to-service auth
- Add spring-boot-starter-security
- Implement JWT validation for inter-service calls
- Deploy Istio AuthorizationPolicy per service

# Phase 2: Role-based access
- Define service roles (payment-service, admin-service, etc.)
- Add @PreAuthorize per endpoint group
- Restrict admin endpoints to specific caller services

# Phase 3: mTLS
- Enable PeerAuthentication STRICT mode
- Verify with istioctl analyze
```

## Real-World Example: ms-transaction-coordinator (Bank Jago, 2026-05)

- 16 controllers, 1,516 Kotlin files
- Handles: BIFast transfers, FX trading, loan disbursement, card transactions, payroll
- Zero Spring Security, zero custom auth
- Result: 75 confirmed vulnerabilities (16 Critical)
- Key attack chains:
  1. BIFast fund exfiltration (one POST, irrecoverable)
  2. FX rate manipulation → trade at fake rate
  3. Bulk payroll drain (single request, unlimited beneficiaries)
  4. Heapdump → extract all credentials
  5. Mass assignment `additionalPayload.force=true` → bypass fraud detection
