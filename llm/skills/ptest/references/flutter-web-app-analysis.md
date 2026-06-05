# Flutter Web App Analysis

## When to Use
- Target serves `main.dart.js` + `flutter.js` (check page source)
- `AssetManifest.json` and `FontManifest.json` accessible
- Typically 4-10MB compiled Dart → JS bundle

## Discovery Indicators
```
<script src="main.dart.js" type="application/javascript"></script>
<script src="flutter.js"></script>
```

Or paths: `/partner-webview/`, `/app/`, `/web/` serving Flutter content.

## Asset Enumeration

```bash
# Confirm Flutter web app
curl -sk https://target.com/flutter.js -o /dev/null -w "%{http_code}"
curl -sk https://target.com/version.json  # {"app_name":"...","version":"...","build_number":"..."}

# Get full asset manifest
curl -sk https://target.com/assets/AssetManifest.json | python3 -m json.tool

# Check for source maps (rare but high-value)
curl -sk https://target.com/main.dart.js.map -o /dev/null -w "%{http_code}"
```

## main.dart.js Analysis

The compiled Dart bundle is large (4-10MB) but contains extractable intelligence:

### JWT Tokens (hardcoded dev/test tokens)
```python
import re, base64, json

# Find JWTs (header.payload.signature)
jwts = re.findall(r'(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?)', js)

for jwt in jwts:
    parts = jwt.split('.')
    for i, part in enumerate(parts[:2]):
        padded = part + '=' * (4 - len(part) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(padded))
        label = "Header" if i == 0 else "Payload"
        print(f"  {label}: {json.dumps(decoded, indent=2)}")
```

**What to look for in JWT payloads:**
- `iss` — issuer URL reveals internal auth infrastructure (ForgeRock AM, Keycloak, Auth0)
- `sub` — subject reveals user/service account naming
- `aud` — audience reveals OAuth client names
- `scope` — reveals available API permissions
- `customerId`, `partnerId` — business identifiers
- `exp` — if expired, token is info-disclosure only; if valid, test it

### Auth Header Patterns
```python
# Look for header key names used in API calls
# Pattern: .h(0,"header-name") or headers["header-name"]
headers = re.findall(r'["\']([a-z][-a-z0-9]*(?:token|key|auth|id|secret)[a-z0-9-]*)["\']', js, re.IGNORECASE)
```

Common findings: `access-token`, `auth-id`, `partner-id`, `customer-id`, `x-api-key`, `x-device-id`

### Internal URLs and Domains
```python
# Full URLs with internal domains
urls = re.findall(r'https?://[^\s"\'<>]+', js)
internal = [u for u in set(urls) if any(x in u for x in ['internal', 'dev', 'staging', 'local', '.io:'])]

# Internal domain patterns (often .io or .internal)
domains = re.findall(r'https?://([a-z0-9.-]+\.[a-z]{2,})', js)
non_public = [d for d in set(domains) if d not in known_public_domains]
```

### Partner/Integration IDs
```python
# Partner identifiers
partners = re.findall(r'partner[_-]?id["\s:=]+([^\s"\'<>,;]+)', js, re.IGNORECASE)
# OAuth client names
clients = re.findall(r'oauth_client_([a-z0-9_-]+)', js)
```

### hCaptcha/reCAPTCHA Site Keys
```python
# Check HTML assets for captcha config
# assets/html/recaptcha.html often contains data-sitekey
sitekeys = re.findall(r'data-sitekey="([^"]+)"', html_content)
```

## Version Comparison Across Environments

Always check the same Flutter app on all environment variants:
```python
for host in ['api.example.com', 'dev-api.example.com', 'stg-api.example.com']:
    r = httpx.get(f'https://{host}/partner-webview/version.json')
    # Different versions may have debug features or source maps
    r2 = httpx.get(f'https://{host}/partner-webview/main.dart.js.map')
    if r2.status_code == 200:
        print(f"SOURCE MAP on {host}!")
```

## Impact Assessment

| Finding | Severity | Condition |
|---------|----------|-----------|
| Valid (unexpired) JWT with prod scope | High | Token actually works against API |
| Expired dev JWT with internal URLs | Medium | Info disclosure of architecture |
| Internal domain names (NXDOMAIN externally) | Low-Medium | Aids targeted attacks |
| Partner IDs / service account names | Low | Aids social engineering |
| hCaptcha/reCAPTCHA sitekey | Info | Public by design, but confirms integration |
| Source map available | High | Full original Dart source code exposed |

## Pitfalls
- **Dart-compiled JS is obfuscated** — standard regex for `/api/v1/path` patterns often fail. Look for string literals near route definitions instead.
- **Large file handling** — 4-10MB JS files. Download once, analyze locally. Don't re-download per regex.
- **Expired tokens** — most hardcoded tokens are from dev/test and expired years ago. Still valuable for architecture disclosure but don't report as "valid credential exposure."
- **Same app, multiple hosts** — Flutter web apps are often deployed identically across environments. Check version.json first; if same version, skip re-analysis but still check for source maps on each.
