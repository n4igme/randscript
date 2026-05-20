# Partner Gateway Probing

When a shared IP hosts multiple partner subdomains (e.g., `bfi.jago.com`, `tokopedia.jago.com` all on 34.50.79.16), this is typically a partner API gateway. Here's the systematic approach:

## Identification

- Multiple subdomains tagged `partner` in DNS zone comments
- All resolve to the same IP
- All return identical response (same status code, same byte size)

## Probe Sequence

### 1. Confirm the blocking mechanism

| Blocker | Indicators |
|---------|-----------|
| Cloudflare WAF IP allowlist | 403 with CF challenge JS (`/cdn-cgi/challenge-platform/`), `cache-control: private`, `x-frame-options: SAMEORIGIN` |
| mTLS | TLS handshake fails or returns `CertificateRequest` in handshake |
| Application-level auth | 401/403 with JSON body, different per path |
| IP allowlist (non-CF) | Connection refused or TCP RST |

### 2. Path enumeration

Test common API paths — if ALL return the same status, the block is pre-routing (WAF/IP level):
```
/ /api /api/v1 /health /healthz /status /swagger /swagger-ui.html
/docs /api-docs /callback /webhook /v1 /v2 /actuator /actuator/health
/login /oauth /token /.well-known/openid-configuration
```

### 3. HTTP method variation

```bash
for method in GET POST PUT DELETE OPTIONS HEAD PATCH; do
  curl -sk -X "$method" -o /dev/null -w "%{http_code}" "https://target/"
done
```

If all methods return the same code = pre-routing block.

### 4. Header fuzzing

```bash
for header in "X-API-Key: test" "X-Partner-ID: test" "Authorization: Bearer test" \
  "X-Forwarded-For: 10.0.0.1" "X-Real-IP: 10.0.0.1" "CF-Connecting-IP: 10.0.0.1"; do
  curl -sk -H "$header" -o /dev/null -w "%{http_code}" "https://target/"
done
```

If no header changes the response = WAF-level block, not application-level.

### 5. Compare production vs staging

Staging equivalents often have weaker controls:
- Same CF WAF rules? (403 = yes)
- Different response? (404 "Not Found" = request reaches backend, no WAF block)
- A 404 from backend means the WAF allowlist is missing for that subdomain — the service exists but has no routes

### 6. Response size comparison across partners

```bash
for sub in partner bfi bibit tokopedia; do
  size=$(curl -sk -o /dev/null -w "%{size_download}" "https://${sub}.domain.com/")
  echo "${sub}: ${size} bytes"
done
```

Identical byte sizes = same WAF block page. Different sizes = different backend behavior (investigate further).

### 7. TLS inspection

```bash
curl -svk "https://target/" 2>&1 | grep -i "certificate\|handshake\|alert"
```

If handshake completes without `CertificateRequest` = NOT mTLS. The block is at HTTP layer.

## Decision Tree

```
All partners same 403 + CF challenge JS?
  YES → Cloudflare IP allowlist. Cannot bypass externally.
        Check staging equivalents for gaps.
  NO  → Check if mTLS (TLS handshake inspection)
        Check if application auth (different responses per path/method)
```

## When to Stop

If production returns identical CF challenge 403 on all paths/methods/headers, and TLS handshake shows no mTLS requirement, the gateway is properly hardened via Cloudflare IP allowlist. Document as "properly configured" and move on. Maximum 15 minutes on this target class.

## Staging Anomalies

When staging returns 404 instead of 403:
- The request bypasses CF WAF (no IP allowlist on this subdomain)
- Backend is reachable but has no routes configured
- Could be: decommissioned service, not-yet-deployed, or misconfigured CF rule
- Document as "configuration drift" (informational) — staging WAF rules inconsistent with production
- Monitor: if routes are added later, they'll be accessible without IP restriction

## Real-World Example (Bank Jago)

- Production: 17 partner subdomains on 34.50.79.16, all 403 (CF WAF)
- Staging: 17 equivalents on 34.101.154.105
  - 15 return 403 (same CF WAF)
  - 2 return 404 (stagingpartner, stagingtokopedia) — backend reachable, no routes
- Conclusion: CF IP allowlist properly enforced on prod. Staging has minor config drift (2 hosts missing WAF rule). No exploitable path.
