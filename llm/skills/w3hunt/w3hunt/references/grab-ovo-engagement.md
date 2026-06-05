# Grab/OVO Engagement — HackerOne (2026-05-26)

## Target
- Program: Grab (HackerOne)
- Scope: 34 assets, wildcards *.grab.com, *.grabpay.com, *.ovofinansial.com, *.ovo.id, etc.
- Working dir: ~/PenTest/Hunting/Hackerone/Grab/

## Findings (In Progress)

### Finding 1: Config Leak Chain (Two Subdomains)

**dev-website.ovofinansial.com/assets/config.js** (staging):
```javascript
window.APP_CONFIG = {
  "ENVIRONMENT": "staging",
  "BASE_URL": "https://apigw-dev.taralite.com/dashboard-service",
  "DD_CLIENT_TOKEN": "pub0261e2b3f88063d556ff0ff2be468e00",
  "DD_APP_ID": "6a9ef189-2c9a-47bf-b84b-858f73beb7df",
  "RECAPTCHA_KEY": "6LdT950eAAAAAOU_OK5beSXuyTxPOQO5VnlK3xkY",
  "CORVUS_BASE_URL": "https://griffin-stg.taralite.com/apis/cepanel",
  "FUNDING_SERVICE_BASE_URL": "https://griffin-stg.taralite.com/apis/fds",
  "LEANPLUM_APP_ID": "app_BLL6fQTOwkQpBu5l4TGEw14iBVJ4qHwDC8JW5suk9TU",
  "LEANPLUM_CLIENT_KEY": "dev_8Ftt1h1AESx3eZHfgjL5Bux3AXKANEKVWgT7L0yTY0Q",
  "LD_CLIENT_ID": "62287236056ff4151bd3e3ce",
  "GRIFFIN_CLIENT_ID": "8v3a5DZm40fCi3zF2dsbVfjT4anuZA1ez1NOig6l",
  "GRIFFIN_REDIRECT_URI": "https://ofin-meks-taralite-com.pvt.k8s.stg.aws.ovofinansial.com/accounts/oauth-callback",
  "GRIFFIN_LENDING_API_BASE_URL": "https://ofin-meks-griffinlendingapi.pvt.k8s.stg.aws.ovofinansial.com"
}
```

**funding.ovofinansial.com/config.js** (production):
```javascript
window.APP_CONFIG = {
  "LENDER_API": "https://griffin.ovofinansial.com/apis/lender-dashboard",
  "DD_APP_ID": "6e9d2811-8319-468b-8dce-3381f4ac0732",
  "DD_CLIENT_TOKEN": "pubef00a7f898d76747d602f266a8e2c4f1",
  "VERSION": "1.1.4",
  "LD_CLIENT_ID": "62287236056ff4151bd3e3cf",
  "GRIFFIN_HOST": "https://auth.ovofinansial.com/",
  "GRIFFIN_BASE_API_URL": "https://griffin.ovofinansial.com",
  "GRIFFIN_CLIENT_ID": "kH8u12wO8vZ1sLMA5q1PKTR3YOqlc8X9fQty7fZS",
  "GRIFFIN_REDIRECT_URI": "https://funding.ovofinansial.com/authenticated"
}
```

### Finding 2: LaunchDarkly Feature Flag Exposure (via leaked LD_CLIENT_ID)

**Endpoint:** `https://clientsdk.launchdarkly.com/sdk/evalx/62287236056ff4151bd3e3ce/contexts/eyJraW5kIjoibXVsdGkiLCJ1c2VyIjp7ImtleSI6InRlc3QifX0=`

35 flags exposed including:
- `pillar-api-keys`: `{'env': 'staging', 'tinymce': 'di5fop9q5hfpm9l6kcnauo534vlwtt8kbmpy47t8orbmw7yx'}`
- `pillar-migration-features`: Full admin panel module map (accounts, merchants, campaigns, OVO Invest, settlements, vouchers, loans, KYC, bulk operations)
- `pillar-migration-hide-modules`: Hidden/deprecated admin modules list
- `pillar-show-watermark`: `{'env': 'stg', 'enabled': True}`

### Finding 3: Exposed Services

| Service | URL | Status |
|---------|-----|--------|
| OVO Rampart File Service | doc-stg.ovofinansial.com | 200, OTP auth, CSRF protected |
| Settlement Portal | settlement.ovo.id | ASP.NET 4.0.30319, VisionRecon |
| CellBlock UI | cellblockui.ovo.id | 200, OVO app |
| CB | cb.ovo.id | 200, OVO app |
| Funding Dashboard | funding.ovofinansial.com | 200, React SPA |
| Auth (staging) | auth-stg.ovofinansial.com | Django OAuth Toolkit |
| Auth (production) | auth.ovofinansial.com | Django OAuth Toolkit |
| Griffin API (staging) | griffin-stg.taralite.com | 401 on /apis/cepanel, /apis/fds |
| Griffin API (production) | griffin.ovofinansial.com | 401 on /apis/lender-dashboard |
| GrabID Staging | api.stg-myteksi.com | OIDC config exposed, JWKS public |

## What Didn't Work

- **OAuth redirect_uri manipulation**: Django OAuth Toolkit redirects to login BEFORE validating redirect_uri — can't test without valid session
- **Griffin API fuzzing**: Everything behind auth (401), only /status returns 200 (empty)
- **GrabID staging**: Client IDs from OVO config not registered on GrabID ("specified client is not found")
- **Token endpoint grants**: Only authorization_code supported (client_credentials, password all return "unsupported_grant_type")
- **Password reset enumeration**: Django returns same response for valid/invalid emails (secure default)
- **DataDog/Leanplum tokens**: Client tokens are public-facing by design, no data access
- **Jira/Wiki (jira.grab.com, wiki.grab.com)**: Behind CloudFront 403
- **Most Grab subdomains**: Behind CloudFront 403 or connection refused

## Recon Techniques That Worked

1. **config.js pattern** — check `/assets/config.js` and `/config.js` on all subdomains (React/Vue apps expose these)
2. **LaunchDarkly SDK endpoint** — once you have LD_CLIENT_ID, query `clientsdk.launchdarkly.com/sdk/evalx/{id}/contexts/{base64}` for full flag dump
3. **crt.sh subdomain discovery** — found 18 ovofinansial.com + 75 ovo.id subdomains
4. **Batch HTTP probing** — ThreadPoolExecutor with 5 workers, categorize by status code
5. **JS bundle analysis** — check for `/config.js`, `/static/js/main.*.js` patterns on SPAs

## LaunchDarkly Exploitation Pattern (Reusable)

When you find a LaunchDarkly client-side SDK ID:
```python
import requests, base64, json

LD_CLIENT_ID = "62287236056ff4151bd3e3ce"
# Create a minimal context (user with key "test")
context = base64.b64encode(json.dumps({"kind":"multi","user":{"key":"test"}}).encode()).decode()
resp = requests.get(f"https://clientsdk.launchdarkly.com/sdk/evalx/{LD_CLIENT_ID}/contexts/{context}")
flags = resp.json()
print(f"Flags: {len(flags)}")
for name, data in sorted(flags.items()):
    print(f"  {name}: {data.get('value')}")
```

**Impact assessment:**
- Feature flags revealing internal module structure = Medium (info disclosure)
- API keys in flags (TinyMCE, etc.) = check if they grant write access
- Environment confirmation (staging vs prod) = useful for further attacks
- Hidden modules list = roadmap for admin panel exploitation

## Infrastructure Notes

- **OVO Finansial stack:** Django + Envoy + AWS (K8s) + GCS + DataDog + Leanplum + LaunchDarkly
- **Grab stack:** Next.js + Mantine + Cloudflare + AWS
- **Internal tools:** GitLab, Spinnaker, Vault, Consul, Kibana, Waypoint (HashiCorp)
- **Legacy brand:** Taralite (now OVO Finansial)
- **K8s namespaces:** ofin-meks-*.pvt.k8s.stg.aws.ovofinansial.com
- **GrabID staging JWKS:** RSA (RS256) + EC (ES256, kid: ES256_1779478390)

## Next Steps
1. Write up config leak + LaunchDarkly chain as HackerOne report (Medium)
2. Try to bypass doc-stg CSRF for file upload
3. Probe settlement.ovo.id for ASP.NET-specific vulns (ViewState deserialization?)
4. Check if production LD_CLIENT_ID (62287236056ff4151bd3e3cf) also leaks flags
5. Enumerate more OVO API endpoints using admin module names from LD flags
