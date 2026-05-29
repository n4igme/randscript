# Flutter Web App Analysis (Phase 3 / Phase 6)

## When to Use
- Target serves a Flutter web application (detected by `main.dart.js`, `flutter.js`, or `flutter_service_worker.js` in page source)
- Common on partner portals, internal tools, mobile-first apps with web fallback

## Discovery Signals
```html
<!-- In page source -->
<script src="main.dart.js" type="application/javascript"></script>
<script src="flutter.js"></script>
```

## Asset Enumeration

### Step 1: Confirm Flutter and get asset manifest
```bash
# Check for Flutter-specific files
for path in /main.dart.js /flutter.js /assets/AssetManifest.json /assets/FontManifest.json /version.json; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET${path}")
  [ "$code" = "200" ] && echo "✅ ${path}"
done
```

### Step 2: Parse AssetManifest.json
```python
import httpx, json
r = httpx.get('https://TARGET/assets/AssetManifest.json', verify=False)
assets = json.loads(r.text)
# Look for non-media assets (HTML, JSON, JS, config files)
interesting = [k for k in assets.keys() 
               if not any(x in k for x in ['.png', '.svg', '.flr', '.ttf', '.woff', '.otf', '.gif', '.jpg', '.webp'])]
```

### Step 3: Check version.json
```json
{"app_name":"app_partner_web","version":"1.0.0","build_number":"1","package_name":"app_partner_web"}
```
Reveals: app name, version, package name — useful for mobile app correlation.

## main.dart.js Analysis (4-10MB typical)

### Extract API Endpoints
```python
import re, httpx

r = httpx.get('https://TARGET/main.dart.js', verify=False, timeout=30)
js = r.text

# Full URLs
urls = re.findall(r'https?://[^\s"\'<>]+', js)

# API path patterns
api_paths = re.findall(r'["\'](/(?:api|v[0-9]|partner|internal)[/\w.-]+)["\']', js)

# Route definitions (Flutter named routes)
routes = re.findall(r'["\'](/(?:account|transfer|payment|card|loan|deposit|saving)[/\w-]*)["\']', js)
```

### Extract Auth Patterns
```python
# Header names used in HTTP calls
headers = re.findall(r'["\']((?:auth|token|api[_-]?key|x-)[a-z0-9-]+)["\']', js, re.IGNORECASE)

# JWT tokens (may be hardcoded test/dev tokens)
jwts = re.findall(r'(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?)', js)

# Partner/client IDs
partners = re.findall(r'partner[_-]?id["\s:=]+([^\s"\'<>,;]+)', js, re.IGNORECASE)
```

### Extract Secrets & Config
```python
# API keys, tokens, secrets
secrets = re.findall(r'(?:api[_-]?key|token|secret|password|auth|bearer)["\s]*[:=]["\s]*([^\s"\']{8,})', js, re.IGNORECASE)

# hCaptcha/reCAPTCHA sitekeys (from embedded HTML assets)
captcha_keys = re.findall(r'data-sitekey="([^"]+)"', js)

# Internal domain names
internal_domains = re.findall(r'https?://[^\s"\']*(?:internal|dev|staging|corp)[^\s"\']*', js)
```

### Decode Hardcoded JWTs
```python
import base64, json

for jwt in jwts:
    parts = jwt.split('.')
    for i, part in enumerate(parts[:2]):
        padded = part + '=' * (4 - len(part) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(padded))
        # Check: iss (issuer URL), sub (subject), exp (expiry), scopes, customerId
```

**What to look for in decoded JWTs:**
- `iss` — reveals internal auth infrastructure (ForgeRock AM, Keycloak, Auth0, etc.)
- `sub` — service account names, customer IDs
- `aud` — OAuth client names
- `scope` — available permissions
- `exp` — if not expired, token may still be valid!
- Custom claims — `customerId`, `partnerId`, `cif`, `DeviceId`

## Findings Classification

| Finding | Severity | Condition |
|---------|----------|-----------|
| Valid (unexpired) JWT with sensitive scopes | High | Token works against API |
| Expired JWT revealing internal infra | Medium | Exposes auth architecture, internal domains |
| Internal domain names / dev URLs | Low-Medium | Aids further reconnaissance |
| hCaptcha/reCAPTCHA sitekey | Info | Enables captcha bypass research |
| Partner IDs / service account names | Low | Aids social engineering, targeted attacks |
| API endpoint map from routes | Info (enables further testing) | Input for Phase 5-6 |

## Pitfalls
- `main.dart.js` is minified/obfuscated — regex extraction works but variable names are mangled
- Dart compilation produces different patterns than typical JS frameworks — string literals are preserved but function names are single-letter
- Large files (4-10MB) — download once, analyze locally. Don't re-fetch per regex
- SPA catch-all: Flutter apps return 200 for ALL paths (the app handles routing client-side). Use `--exclude-length` with gobuster to filter the SPA shell size
- Source maps (`main.dart.js.map`) are rarely deployed in production but always worth checking
- AssetManifest lists ALL bundled assets including HTML templates that may contain config (check `assets/html/*.html`)
