# Identity SDK Endpoint Extraction

## When to Use
- Target SPA loads a third-party identity/auth SDK (Transmit Security, Auth0, Okta, Firebase Auth, Descope, Stytch)
- Standard API fuzzing finds nothing because auth endpoints live on a different path prefix
- JS bundle analysis reveals auth-related paths not reachable on the main API domain

## Identifying Identity SDKs

Look for these script names in the SPA HTML:
| SDK Name | Script Pattern | Path Prefix |
|----------|---------------|-------------|
| Transmit Security | `ts-platform-websdk.js`, `platform-websdk-*` | `/cis/v1/`, `/cis/api/v1/` |
| Auth0 | `auth0-spa-js`, `@auth0/auth0-react` | `/authorize`, `/.well-known/openid-configuration` |
| Okta | `@okta/okta-auth-js` | `/oauth2/`, `/api/v1/authn` |
| Firebase Auth | `firebase-auth.js`, `firebaseui` | `identitytoolkit.googleapis.com` |
| Descope | `@descope/web-js` | `/v1/auth/`, `/v2/auth/` |
| Stytch | `@stytch/vanilla-js` | `/v1/passwords/`, `/v1/magic_links/` |

## Extraction Technique

### 1. Download and Search the SDK JS
```bash
# Find the SDK script URL from page source
curl -sk 'https://app.target.com/' | grep -oE 'src="[^"]+sdk[^"]*"'

# Download
curl -sk 'https://app.target.com/assets/platform-websdk-1.3.3/ts-platform-websdk.js' -o /tmp/sdk.js

# Extract all API paths
grep -ohE '"/[a-zA-Z0-9/_-]+"' /tmp/sdk.js | sort -u | grep -E '/(v1|v2|api|auth|session|identity|verification|webauthn|fido|device)'
```

### 2. Determine the Correct Host/Prefix
The SDK paths may be mounted on:
- The same domain with a prefix (e.g., `app.target.com/cis/v1/auth-session/status`)
- A separate subdomain (e.g., `auth.target.com/v1/...`)
- A third-party hosted service (e.g., `company.transmitsecurity.io/...`)

**Discovery technique:**
```python
import httpx
client = httpx.Client(verify=False, timeout=8)

# Try each candidate host+prefix with POST (auth endpoints are usually POST)
prefixes = ['/cis', '/auth', '/identity', '/iam', '']
hosts = ['app.target.com', 'api.target.com', 'auth.target.com', 'id.target.com']
test_path = '/v1/auth-session/status'

for host in hosts:
    for prefix in prefixes:
        url = f'https://{host}{prefix}{test_path}'
        resp = client.post(url, json={}, headers={'Content-Type': 'application/json'})
        if len(resp.content) != CATCH_ALL_SIZE:
            print(f"FOUND: {url} -> [{resp.status_code}] {resp.text[:80]}")
```

### 3. Common Transmit Security CIS Endpoints
```
/v1/auth-session/status
/v1/auth-session/attach-device
/v1/auth-session/detach-device
/v1/auth-session/start-restricted
/v1/webauthn/authenticate/start
/v1/webauthn/authenticate/complete
/v1/webauthn/authenticate/passkey/start
/v1/webauthn/authenticate/passkey/complete
/v1/webauthn/register/start
/v1/webauthn/register/complete
/api/v1/verification/start
```

### 4. Error Format Differentiation
Identity SDKs often return errors in their OWN format (not the app's standard format):
```json
// App standard format:
{"success":0,"data":{"code":20003}}

// Transmit Security CIS format:
{"error_code":"auth_session_id_not_provided","message":"Requested action can't be performed for the given session"}
```

This format difference confirms the endpoint hits a different backend — useful for mapping architecture.

### 5. CloudFront Behavior Policy Gotcha
If the CIS endpoints are behind CloudFront with a "cacheable only" behavior policy:
- GET requests → return SPA catch-all (200, large HTML)
- POST requests → 403 "distribution supports only cachable requests"

The 403 on POST **confirms the endpoint exists** (different from 404). The CIS backend is there but CloudFront won't proxy non-cacheable methods. This may be exploitable if:
- The behavior policy has exceptions for specific paths
- A CDN bypass exists (direct origin IP)
- The target has a different environment (staging) without this restriction

## Real-World Example (bitbank.cc, June 2026)
- `ts-platform-websdk.js` (241KB) loaded by app.bitbank.cc
- SDK paths mounted at `app.bitbank.cc/cis/*`
- CloudFront blocks POST on /cis/* (cacheable-only policy)
- GET returns SPA catch-all, POST returns CF 403
- Also discovered root-level auth endpoints from SDK context: `/login`, `/signup`, `/reset_password`, `/fido/login/authenticate/*`
- SDK search revealed the exact login request body format: `{mail, password, g-recaptcha-response, otp_token?, mail_otp_token?}`
