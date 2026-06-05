# SPA Recon Techniques

## Pitfall: SPA Catch-All Detection

When probing web hosts, SPAs (React/Vue/Angular) serve the same index.html for ALL paths via frontend routing. This means:

- `/api`, `/admin`, `/swagger`, `/actuator`, `/graphql` ALL return HTTP 200
- Response size is IDENTICAL (e.g., 35661b for every path)
- This is NOT a real endpoint — it's frontend catch-all routing

**Detection:** If 5+ different paths return same status + same size → SPA catch-all. Skip those paths for that host.

**Real backend indicators:**
- Different response sizes for different paths
- JSON/XML error responses (not HTML)
- Different HTTP status codes (401, 403, 405, 500)
- Headers like `Set-Cookie: JSESSIONID` or API-specific headers

**Example (Antom 2026-06-03):**
- `dashboard.antom.com/*` → ALL return 200, 35661b (SPA)
- `navigator.antom.com/*` → ALL return 405, 2657b (catch-all error page)
- `open-sectest-sg.antom.com/gateway.do` → 200, 108b (REAL — different size)
- `mgs-region-gcash.alipayplus.com/` → JSON response (REAL API)

## Technique: Alibaba Tern/Marmot Site Config Extraction

Alibaba's SPA deployment platform (Tern/Marmot/Yuyan) embeds FULL application configuration in the HTML source as a `<script type="tern-site-config">` JSON block.

**What it leaks:**
- All micro-app names and yuyan IDs
- All frontend routes (including IDOR-prone patterns like `/invoiceDetail/:invoiceId`)
- Internal environment URLs (DEV, TEST, PRE, SIM, PROD)
- Backend proxy targets (e.g., `dashboard-apiv2.antom.com` → `global.alipay.com`)
- Feature flags (reveals unreleased features and gray-scale rollouts)
- Auth configuration (login URLs, identity cloud endpoints)
- Third-party integrations (Apple Pay PSP IDs, Google Pay config)

**Extraction:**
```bash
curl -sk "https://TARGET/" | grep -oE '<script type="tern-site-config">[^<]+' | sed 's/<script type="tern-site-config">//' | python3 -m json.tool
```

Or in the HTML source, look for `window.marmotInjectInfo` and `window.injectInfo` for environment details.

**Indicators target uses Tern/Marmot:**
- JS from `render-intl.alipayobjects.com/p/yuyan/`
- `x-marmot-unio-trace-id` cookie
- `window.marmotInjectInfo` in page source
- `acw_tc` cookie (Alibaba Cloud WAF)

**Proven on:** Antom dashboard.antom.com (2026-06-03) — extracted 12 micro-apps, 70+ routes, internal DEV/TEST/PRE URLs, feature flags, KYC verification endpoints.

## Technique: Referer-Gated API Bypass

Some Alibaba APIs check Referer header but return config data without session auth:

```bash
# Fails:
curl -sk "https://connect-api.alipayplus.com/ighome/api/account/user.json"
# → {"stat":"fail","msg":"RefererCheckFailed"}

# Works:
curl -sk "https://connect-api.alipayplus.com/ighome/api/home/getConfig.json?bizScene=APLUS_IGHOME" \
  -H "Referer: https://connect.alipayplus.com/"
# → Full config with auth URLs, gateway lists, region endpoints
```

Try Referer values from the same domain family (connect.*, partner.*, docs.*).

## Technique: Alipay Open Payment Gateway (iopengw)

Identified by:
- Title: `iopengw`
- `/gateway.do` returns XML: `<alipay><error>SYSTEM_ERROR</error><is_success>F</is_success></alipay>`
- CSS from `sprint_react-demo2_*.assets.alipay.net`

These are Alipay payment gateway instances. They process requests but need valid `sign` parameters. Found on security testing (`open-sectest-sg`) and 3DS (`threeds-visa`) subdomains.
