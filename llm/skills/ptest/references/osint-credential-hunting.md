# OSINT Credential Hunting via GitHub & Public Sources

## When to Use
During bug bounty or pentest engagements when you need authenticated access but don't have credentials. Search for leaked tokens, API keys, session IDs, and JWTs in public repositories.

## GitHub Code Search (gh CLI)

```bash
# Search for specific auth headers/tokens
gh search code 'X-Mts-Ssid' --limit 20
gh search code '<target> authorization bearer' --limit 20
gh search code '<target> api_key' --limit 20
gh search code '<target> secret' --limit 20

# Search for SDK wrappers that might have hardcoded tokens
gh search repos '<target> api' --language python --limit 10

# Search for disclosed HackerOne reports (learn attack patterns)
gh search code '<target> hackerone' --limit 10
```

## What to Look For

### High-Value Targets
- **JWT tokens** — decode with base64, check `exp` claim (some expire in 2038+)
- **API keys** — especially those with `AKIA` (AWS), `gho_` (GitHub), `sk-` (OpenAI/Stripe)
- **Session tokens** — `x-mts-ssid`, `Authorization: Bearer`, cookies
- **OAuth client secrets** — `client_secret`, `app_secret`
- **Sentry DSNs** — format: `https://<key>@sentry.io/<project_id>`
- **Firebase configs** — `apiKey`, `authDomain`, `databaseURL`

### Common Leak Sources
- Third-party SDK wrappers (developers hardcode tokens in examples)
- Omnichannel/integration tools (connect multiple services)
- Disclosed bug bounty reports (reveal endpoint patterns + auth flow)
- CI/CD configs (.github/workflows, .gitlab-ci.yml)
- Docker images (inspect layers with `docker history --no-trunc`)
- Terraform state files
- Jupyter notebooks

## JWT Token Validation

```python
import json, base64, datetime

token = "<leaked_jwt>"
# Decode payload (no verification needed to read claims)
payload_b64 = token.split('.')[1]
payload_b64 += '=' * (4 - len(payload_b64) % 4)
payload = json.loads(base64.urlsafe_b64decode(payload_b64))

# Check expiry
exp = datetime.datetime.fromtimestamp(payload['exp'])
print(f"Expires: {exp}")
print(f"Still valid: {datetime.datetime.now() < exp}")
print(f"Audience: {payload.get('aud')}")
print(f"Subject: {payload.get('sub')}")
```

## Testing Leaked Tokens

```bash
# Test against target API with leaked token
curl -s -w '\nHTTP:%{http_code}' '<api_endpoint>' \
  -H 'Authorization: Bearer <token>' \
  -H 'User-Agent: <app_user_agent>'

# If 502: likely geo-blocked (try VPN to target region)
# If 401/403: token expired or revoked
# If 200: valid — document and report as finding
```

## OAuth Refresh Token Hunting (Dropbox, Google, etc.)

A high-value variant: search for leaked OAuth refresh tokens + app secrets. Unlike short-lived access tokens, refresh tokens often **never expire** and can generate fresh access tokens indefinitely.

```bash
# Search for OAuth refresh tokens by provider
gh search code "DROPBOX_REFRESH_TOKEN" "DROPBOX_APP_SECRET" --filename .env
gh search code "GOOGLE_REFRESH_TOKEN" "GOOGLE_CLIENT_SECRET" --filename .env
gh search code "refresh_token" "client_secret" --filename .env --limit 30

# Also check process.env files, docker-compose, and config files
gh search code "DROPBOX_REFRESH_TOKEN" --filename docker-compose.yml
gh search code "refresh_token" "dropbox" --filename config
```

### Validation Flow
```python
import urllib.request, urllib.parse, json

# Exchange refresh_token for fresh access_token
data = urllib.parse.urlencode({
    "grant_type": "refresh_token",
    "refresh_token": "<leaked_refresh_token>",
    "client_id": "<leaked_app_key>",
    "client_secret": "<leaked_app_secret>",
}).encode()
req = urllib.request.Request("https://api.dropboxapi.com/oauth2/token", data=data)
resp = json.loads(urllib.request.urlopen(req).read())
# If HTTP 200 → token is valid, get access_token from resp["access_token"]
```

### Provider Secret Scanning Comparison
| Provider | Auto-revokes leaked tokens? | Partner program? |
|----------|----------------------------|-----------------|
| GitHub   | ✅ Yes (since 2018)        | Secret Scanning |
| Google   | ✅ Yes                     | GCP key revocation |
| AWS      | ✅ Yes + notifies owner    | Compromised key policy |
| Dropbox  | ❌ No                      | Not a partner |
| Slack    | ✅ Yes                     | Secret Scanning partner |

When a provider does NOT auto-revoke, the finding is reportable as a **platform security gap** (CWE-522). Frame it as "lack of secret scanning integration" rather than blaming the developer who leaked.

### Report Framing for No-Revocation Findings
- **Title:** "Leaked OAuth Refresh Tokens on GitHub — No Automated Detection/Revocation"
- **Impact:** Persistent unauthorized account access (refresh tokens never expire)
- **Remediation:** Join GitHub Secret Scanning partner program, auto-revoke on detection
- **Severity:** Medium (CVSS ~6.5) — requires attacker to find the leak, but impact is full account access

## Pitfalls
- **Geo-blocking**: Many APIs (especially SEA companies like Grab, Gojek) return 502 from outside their region. Need VPN to SG/ID/MY to test.
- **Token audience**: A MEXUSERS token won't work on passenger endpoints. Match the `aud` claim to the right API.
- **Truncated hashes in breach data**: Some apps store truncated hashes (e.g., 31 chars instead of 32 for MD5). Standard cracking tools won't match. Always check hash length first — if it's 31 chars, compare `hashlib.md5(pwd).hexdigest()[:31]` against stored value. BFI 2026-05: credentials.csv had 31-char MD5 hashes; 15/42 users had password "123" (`202cb962ac59075b964b07152d234b7` = first 31 of MD5("123")).
- **Breach creds vs Keycloak**: Leaked passwords from internal apps often don't work on SSO/Keycloak — different credential stores. Test both `user@domain.com` and `user` formats, but don't waste time if first 5 fail.
- **Ethical boundary**: Only use leaked tokens to prove the vulnerability exists (e.g., confirm it's not expired). Don't access other users' data.
- **GitHub rate limits**: Unauthenticated API search returns 0 results. Use `gh` CLI (authenticated) for code search.
- **False positives**: Many repos contain redacted tokens or test fixtures. Always decode and verify before testing.

## Reporting
If a valid leaked credential is found in a public repo:
- **Title**: "Leaked [token type] in public GitHub repository allows [impact]"
- **Severity**: High if token grants data access, Critical if it allows account takeover
- **PoC**: Show the repo URL, decoded token claims, and proof it's still valid (HTTP 200 response)
- **Remediation**: Rotate the credential, add secret scanning to CI/CD
