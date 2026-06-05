# CDN-Aware Phase 5 Workarounds

## Problem
When targets are behind Fastly/Cloudflare/Akamai, automated scanners timeout or get rate-limited:
- `testssl.sh` → timeout (120s+) against CDN-terminated TLS
- `nuclei` → 0 findings (CDN absorbs/blocks probes)
- `nikto` → timeout (same as testssl)

## Workarounds

### TLS Assessment (replaces testssl.sh)
```bash
# Quick cert check on all hosts (5s each vs 120s+ testssl)
echo | openssl s_client -connect HOST:443 -servername HOST 2>/dev/null | openssl x509 -noout -text | grep -E "Protocol|Cipher|Subject:|Not After|Signature"

# TLS 1.0/1.1 rejection verification
echo | openssl s_client -connect HOST:443 -servername HOST -tls1 2>&1 | grep "alert"

# Cert CN mismatch detection (shared CDN IPs serve wrong certs)
echo | openssl s_client -connect HOST:443 -servername HOST 2>/dev/null | grep "subject="
```

### Nuclei (run anyway but expect 0 from CDN)
```bash
# Rate-limit to avoid CDN blocks
nuclei -l live-urls.txt -rate-limit 10 -bulk-size 2 -concurrency 2 -timeout 10 -retries 1
# Document "CDN blocked" as gap, not as "target is clean"
```

### Manual CDN-Bypass Checks (replace automated scanning)
Focus on what CDN doesn't inspect:
1. **Response header analysis** — Vary, X-Cache, s-maxage (cache poisoning indicators)
2. **CORS testing** — CDN passes Origin header through
3. **HTTP method override** — X-HTTP-Method-Override bypasses CDN method filtering
4. **Path encoding confusion** — Envoy/nginx behind CDN handle encoded paths differently
5. **Token format oracle** — application-layer logic, CDN transparent

### Cache Poisoning Detection
```bash
# Check if CDN caches with s-maxage
curl -sI https://target/ | grep -i "s-maxage\|cache-control\|age"
# s-maxage=15 → 15s cache window
# Test unkeyed headers (X-Forwarded-Host, X-Original-URL)
# Check Vary header to know what's keyed
```

## WinTicket Lesson (June 2026)
- testssl.sh timed out at 120s against Fastly-fronted targets
- nuclei ran 8min → 0 findings (all probes absorbed by CDN)
- openssl quick-check completed in <2s per host
- Manual testing found: Sentry DSN write, no rate limit, TLS cert mismatch, missing CSP
- Conclusion: manual targeted checks > automated scanners against modern CDN
