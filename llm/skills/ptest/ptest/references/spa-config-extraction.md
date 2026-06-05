# SPA Site-Config Extraction Technique

## Overview
Modern SPAs (React/Vue/Angular) embed configuration in inline `<script>` tags at page load.
This config often reveals internal architecture that would normally require auth to discover.

## What to Extract

### 1. Inline Config Objects
```bash
curl -sk "https://target.com/" | grep -oE 'window\.[a-zA-Z]+=[^;]+'
```
Look for:
- `window.injectInfo` — env (PROD/PRE/TEST/SIM/DEV), app metadata
- `window.__TERN__` — SSR config, user object, network type, tenant
- `window.marmotInjectInfo` — deployment iteration ID, application UUID
- `window.publicPath` — CDN paths (reveals deployment platform)

### 2. Site Config in `<script type="tern-site-config">`
Contains full micro-frontend orchestration:
- **proxy** — backend API targets per environment (DEV/PRE/PROD/SIM)
- **routes** — all frontend routes with microApp mapping
- **envInfo** — internal service URLs (dev/test/pre/prod)
- **grayScales** — feature flags (reveals unreleased features)
- **switches** — A/B test flags
- **apps** — all micro-apps with yuyanId and entry URLs

### 3. Extracting API Routes from Config
```bash
# Extract proxy targets (reveals real backend)
curl -sk "https://target.com/" | grep -oE '"proxy":\{[^}]+\}'

# Extract all route paths
curl -sk "https://target.com/" | grep -oE '"path":"[^"]+"' | sort -u
```

## Proven Pattern (Ant Group / Antom 2026-06)

`dashboard.antom.com` exposed via robots.txt (SPA catch-all):
- 12 micro-apps (payment, risk, dispute, onboard, trade, insight, etc.)
- 70+ frontend routes with IDOR-prone patterns (`:invoiceId`, `:type`)
- Backend proxy: `dashboard-apiv2.antom.com` → `global.alipay.com`
- Internal URLs: DEV/TEST/PRE/SIM environments
- Feature flags: 60+ grayscale flags revealing upcoming features
- NEW HOST discovered: `dashboard-apiv2-pre.antom.com` from PRE config

## JS Bundle Analysis (Phase 3)

After finding publicPath/entry URLs, download JS bundles and grep:
```bash
# API route extraction from JS
curl -sk "$JS_BUNDLE_URL" | grep -oE '"/(api|merchant|open|user|auth)[^"]{2,80}"' | sort -u

# Internal service URLs
curl -sk "$JS_BUNDLE_URL" | grep -oE '"https?://[^"]*\.(alipay|antom|internal)[^"]*"' | sort -u
```

From `index.fe30f678.js` on Antom, extracted 291 API endpoints including:
- `/merchant/proxyapi/member/getPubKey.json` (RSA key without auth!)
- `/merchant/account/api/account/syncAndRegister.json`
- `/merchant/proxyapi/funds/withdraw/apply.json`

## Key Insight
SPA config extraction is technically Phase 1 (passive) but yields Phase 3-level endpoint maps.
Do it EARLY — before directory fuzzing. The config gives you the real routes that ffuf/gobuster will miss (SPAs return same HTML for all paths = catch-all).

## Anti-Pattern: Don't Waste Time on SPA Fuzzing
If `curl target.com/nonexistent` returns same size as `curl target.com/`:
- It's SPA catch-all routing
- ffuf/gobuster will only find false positives
- Extract routes from JS/config instead
- Target the BACKEND (API host from proxy config) for real fuzzing
