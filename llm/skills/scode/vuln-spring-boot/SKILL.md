---
name: vuln-spring-boot
description: "Scan for Spring Boot vulnerabilities (actuator exposure, missing @PreAuthorize, SpEL injection, mass assignment, unsafe deserialization). Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Spring Boot Vulnerabilities

Scan for Spring Boot-specific security issues: actuator exposure, annotation gaps, SpEL injection, Jackson deserialization, and mass assignment.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Applicability

```bash
find . -name "pom.xml" -o -name "build.gradle" -o -name "build.gradle.kts" | xargs grep -l "spring-boot" 2>/dev/null | head -1
```
If no results → report "No Spring Boot project found — scanner not applicable" and skip.

## Vulnerability Patterns

### Actuator Exposure
- `management.endpoints.web.exposure.include: *` exposes all endpoints
- Actuator excluded from security filter chain (`permitAll()`)
- Heapdump/env endpoints exposing secrets

**Grep patterns**: `management.endpoints.web.exposure`, `actuator`, `permitAll`, `@Endpoint`, `heapdump`

### Missing Security Annotations
- Controllers without `@PreAuthorize` / `@Secured` / `@RolesAllowed`
- Method-level annotations not covering all methods in a class
- `hasRole` with wrong case or missing ROLE_ prefix

**Grep patterns**: `@RestController`, `@Controller` vs `@PreAuthorize`, `@Secured`, `@RolesAllowed`

### SpEL Injection
- User input reaching `SpelExpressionParser.parseExpression()`
- Dynamic `@Value` or `@PreAuthorize` with user-controlled strings
- `@Cacheable(key = "...")` with untrusted input

**Grep patterns**: `SpelExpressionParser`, `parseExpression`, `ExpressionParser`, `#` in `@Value`

### Jackson Deserialization (Polymorphic)
- `enableDefaultTyping()` / `activateDefaultTyping()` without whitelist
- `@JsonTypeInfo(use = Id.CLASS)` on user-facing DTOs
- Missing `PolymorphicTypeValidator`

**Grep patterns**: `enableDefaultTyping`, `activateDefaultTyping`, `@JsonTypeInfo`, `ObjectInputStream`, `readObject`

### Mass Assignment
- `@RequestBody` binding to entity/domain objects directly
- `Map<String, Object>` as DTO (accepts any field)
- Missing `@JsonIgnore` on sensitive fields (role, isAdmin, balance)

**Grep patterns**: `@RequestBody`, `Map<String, Object>`, `Map<String, Any>`, `@JsonIgnore`

### CORS Misconfiguration
- `@CrossOrigin("*")` with credentials
- `allowedOrigins("*")` in CorsConfiguration
- Credential-bearing CORS without origin whitelist

**Grep patterns**: `@CrossOrigin`, `CorsConfiguration`, `addAllowedOrigin`, `allowCredentials`

### SQL via Native Queries
- `createNativeQuery()` with string concatenation
- `@Query` with `+` (concatenation) instead of `:param`
- JPQL injection via dynamic sort/filter

**Grep patterns**: `createNativeQuery`, `@Query.*+`, `nativeQuery = true`

### SSRF via RestTemplate/WebClient
- User-controlled URL passed to `RestTemplate.getForObject()` or `WebClient`
- Missing URL validation/allowlist

**Grep patterns**: `RestTemplate`, `WebClient`, `getForObject`, `exchange`, `retrieve`

## Process

1. **Check actuator config** — is it exposed? Is it behind auth?
2. **Map all controllers** — identify which have security annotations and which don't
3. **Find SpEL usage** — can user input reach expression evaluation?
4. **Check Jackson config** — is polymorphic deserialization enabled?
5. **Review DTOs** — are entities used directly as request bodies?
6. **Check CORS** — wildcard origins with credentials?
7. **Assess impact** — RCE (SpEL/deser), secret exposure (actuator), auth bypass (missing annotations)

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Spring Boot

**Date**: {date}
**Scanner**: vuln-spring-boot

## Findings

### VULN-SPRING-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Actuator / Missing Auth / SpEL / Deserialization / Mass Assignment / CORS / SQL / SSRF}
**Location**: `{file}:{line}`
**CWE**: CWE-{200|862|917|502|915|942|89|918}

**Description**:
{What the vulnerability is}

**Vulnerable Code**:
```java
{code snippet}
`` `

**Attack Scenario**:
1. {Step-by-step exploitation}

**Impact**:
{RCE, secret exposure, privilege escalation, data theft}

**Remediation**:
```java
{fixed code}
`` `

---
```

## Positive Observations

While scanning, note strong patterns. Add to `# Positive Security Observations` at end of `vulnerabilities.md`:

```markdown
- vuln-spring-boot: {what the codebase does well}
```

## Rules

- **@PreAuthorize on one method doesn't cover the class** — check EACH method independently.
- **Actuator behind internal network may be acceptable** — check if K8s NetworkPolicy restricts access.
- **Mass assignment needs a mutable sensitive field** — read-only fields aren't exploitable.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — Spring Boot` section, replace it entirely.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
