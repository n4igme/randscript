# Cloudflare API Shield / API Gateway Assessment

## Overview

Cloudflare API Shield is distinct from Cloudflare Access (Zero Trust). It protects API endpoints with token-based authentication at the Cloudflare edge — requests never reach the origin without a valid token.

## Identification

When hitting a CF API Shield-protected endpoint without credentials:
```json
{"message":"Rejected by Cloudflare! {\"error\":{\"message\":\"MISSING_API_TOKEN\",\"code\":\"Unauthorized\"}}."}
```

Key differences from Cloudflare Access:
| Feature | CF Access | CF API Shield |
|---------|-----------|---------------|
| Error message | "Please log in" / redirect to IdP | "MISSING_API_TOKEN" |
| Auth method | Browser-based SSO, service tokens | API tokens, mTLS, JWT |
| Headers | CF-Access-Client-Id/Secret | Varies (often custom header) |
| Bypass via headers | Sometimes (CF-Access-Client-*) | No — token validated at edge |

## Bypass Attempts (from Bank Jago engagement)

### What DOESN'T work:
```bash
# Standard auth headers — all return same MISSING_API_TOKEN error
curl -H "Authorization: Bearer test" "https://api.target.com/"
curl -H "CF-Access-Client-Id: test" -H "CF-Access-Client-Secret: test" "https://api.target.com/"
curl -H "X-API-Token: test" "https://api.target.com/"
curl -H "X-API-Key: test" "https://api.target.com/"
```

### What MIGHT work:
1. **Direct-to-origin IP**: If you can find the origin IP (not behind CF), bypass entirely
   - Check DNS history (SecurityTrails, ViewDNS)
   - Check other subdomains on same infra that resolve to origin
   - Send `Host: api.target.com` to discovered GCP/AWS IPs
   
2. **Subdomain with weaker protection**: Dev/staging APIs may use different CF config
   - `dev-api.target.com` — same protection? Different token?
   - `internal-api.target.com` — may not be behind CF at all

3. **Token discovery**:
   - JS bundles on other subdomains
   - Mobile app decompilation (API tokens often hardcoded)
   - GitHub/GitLab search for the domain
   - Heapdumps/actuator on other services

4. **mTLS client certificate**: If API Shield uses mTLS, you need the client cert
   - Check if any service exposes its client cert (heapdump, config files)

## Reconnaissance Value

Even without bypass, the error message confirms:
- Backend exists and is live (CF is proxying to something)
- Auth mechanism is token-based (not session/cookie)
- The specific error format can reveal if it's CF API Gateway vs custom worker

### Actuator behind CF Shield
If `/actuator` returns 401 (not 404), the backend has Spring Boot actuator endpoints. With a valid token, these would be accessible. This is worth noting in the report — the actuator exists, it's just gated by CF.

## Report Guidance

Document as:
- **Finding**: API endpoints accessible but protected by Cloudflare API Shield (informational)
- **Note**: If CF Shield token is compromised (leaked in mobile app, JS, CI/CD), actuator endpoints would be exposed
- **Recommendation**: Ensure API tokens are rotated regularly, not hardcoded in client apps, and scoped to minimum required permissions

## Integration with Other Findings

If you find credentials elsewhere (heapdump, .env, JS), check if they're CF API tokens:
- CF API tokens often start with specific prefixes
- They may be in environment variables named `CF_API_TOKEN`, `CLOUDFLARE_TOKEN`, `API_TOKEN`
- Mobile apps often embed them in build configs
