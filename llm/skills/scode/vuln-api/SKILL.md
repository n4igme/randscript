---
name: vuln-api
description: "Step 3m of bug bounty workflow. Scan for API-specific vulnerabilities (mass assignment, GraphQL, rate limiting, versioning). Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Step 3m: API-Specific Vulnerabilities

Scan for vulnerabilities specific to REST and GraphQL APIs — mass assignment, excessive data exposure, broken function-level authorization, and GraphQL-specific attacks.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Vulnerability Patterns

### Mass Assignment / Parameter Pollution
- Request body directly passed to ORM create/update without allowlist
- `req.body` spread into database models
- Missing field-level filtering on input (user can set `role`, `isAdmin`, `price`)
- HTTP Parameter Pollution (duplicate params with different values)

**Grep patterns**: `Object.assign(`, `...req.body`, `req.body)`, `.create(req.body`, `.update(req.body`, `fillable`, `guarded`, `$request->all()`, `permit(`, `strong_params`

### Excessive Data Exposure
- API responses returning full database objects without field filtering
- Internal fields leaked (password hashes, internal IDs, tokens)
- Different verbosity between list and detail endpoints
- Error responses exposing stack traces or internal state

**Grep patterns**: `res.json(`, `res.send(`, `JSON.stringify(`, `serialize`, `toJSON`, `select(`, `exclude(`, `.lean()`, `response_model`

### GraphQL-Specific
- Introspection enabled in production
- No query depth/complexity limits (DoS via nested queries)
- Batching attacks (multiple operations in single request)
- Field-level authorization missing (all fields accessible to all roles)
- Alias-based rate limit bypass

**Grep patterns**: `graphql`, `apollo`, `schema`, `resolver`, `typeDefs`, `introspection`, `depthLimit`, `costAnalysis`, `complexity`, `maxDepth`, `Query`, `Mutation`

### Broken Function-Level Authorization
- Admin endpoints accessible without role check
- API versioning exposing deprecated unprotected endpoints
- Missing authorization on state-changing operations
- Horizontal privilege escalation via API (accessing other users' resources by ID)

**Grep patterns**: `router.`, `app.get`, `app.post`, `app.put`, `app.delete`, `@route`, `@api_view`, `middleware`, `authorize`, `isAdmin`, `role`, `permission`

### Improper Rate Limiting
- No rate limiting on expensive operations
- Rate limit by IP only (bypassable via headers like `X-Forwarded-For`)
- Missing rate limit on authentication endpoints
- Batch endpoints allowing unlimited items per request

**Grep patterns**: `rateLimit`, `rate_limit`, `throttle`, `X-RateLimit`, `express-rate-limit`, `slowDown`, `limiter`, `burst`

### API Versioning & Documentation Exposure
- Old API versions still active without security patches
- Swagger/OpenAPI docs exposed in production
- Debug endpoints left active (`/api/debug`, `/graphql/playground`)

**Grep patterns**: `/v1/`, `/v2/`, `/api-docs`, `/swagger`, `playground`, `graphiql`, `debug`, `openapi.json`, `swagger.json`

## Process

For each priority target from threat-model.md:

1. **Map API surface** — identify all endpoints, methods, and input schemas
2. **Check input filtering** — are request bodies allowlisted before reaching the data layer?
3. **Check output filtering** — are responses stripped of sensitive/internal fields?
4. **Audit GraphQL** — if present, check introspection, depth limits, and field-level auth
5. **Verify rate limits** — are expensive/sensitive endpoints rate-limited?
6. **Assess impact** — privilege escalation, data theft, DoS

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — API-Specific

**Date**: {date}
**Scanner**: vuln-api

## Findings

### VULN-API-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Mass Assignment / Data Exposure / GraphQL / Broken Function Auth / Rate Limiting / Versioning}
**Location**: `{file}:{line}`
**CWE**: CWE-{915|200|306|770|1059}

**Description**:
{What the vulnerability is}

**Vulnerable Code**:
```{lang}
{code snippet}
`` `

**Attack Scenario**:
1. {Step-by-step exploitation}

**Proof of Concept**:
```http
{HTTP request showing the exploit}
`` `

**Impact**:
{Privilege escalation, data theft, DoS}

**Remediation**:
```{lang}
{fixed code}
`` `

---
```

## Rules

- **Only report confirmed API flaws** — verify the unfiltered field is actually writable/readable.
- **For mass assignment, identify the dangerous field** — show which field (role, admin, price) can be set.
- **For GraphQL, test actual query depth** — don't just flag missing limits without showing exploitability.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — API-Specific` section, replace it entirely. See `sc3-vuln-scan` idempotency rule.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
