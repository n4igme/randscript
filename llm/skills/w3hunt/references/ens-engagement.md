# ENS Engagement Notes (2026-05-27)

## Target
- **Program:** ENS (Ethereum Name Service) on Immunefi
- **Max Bounty:** $250,000 (SC), $25,000 flat (Web Critical)
- **Key Rules:** PoC required, Primacy of Impact enabled (April 2026), Vault program ($132K USDC)
- **Working Dir:** ~/PenTest/Hunting/Immunefi/ENS/
- **Last Updated:** 19 May 2026

## Full Scope (verified 2026-05-27)

### Smart Contracts (Critical $10K-$250K, High $25K-$100K)
- `github.com/ensdomains/ens-contracts` — tagged releases (vx.x.x, vx.x.x-RCX, vx.x.x-testnet)
- `github.com/ensdomains/contracts-v2` — newer contracts repo (releases)
- Contract deployments: https://github.com/ensdomains/ens-contracts/wiki/ENS-Contract-Deployments
- V1 contracts remain in scope during migration period

### Websites & Applications (Critical $25K, High $5K-$20K)
- `app.ens.domains` ✅ tested
- `metadata.ens.domains` ✅ tested (queryNFT DoS found)
- `docs.ens.domains` ❌ NOT TESTED
- `ens.domains` (landing page) — partially tested

### Source Code (Web)
- `github.com/ensdomains/ens-app-v3` ✅ cloned/reviewed
- `github.com/ensdomains/ens-metadata-service` ✅ cloned/reviewed
- `github.com/ensdomains/ensdomains-landing` ❌ NOT TESTED

### Out of Scope
- `ens.dev`

### Scope-Specific Severity Rules
- XSS on app.ens.domains triggering malicious tx = Critical
- XSS on other subdomains with wallet connection: stored=High, reflected=Medium
- XSS on static sites (metadata.ens.domains, docs.ens.domains) = Low unless impacts app.ens.domains
- "Taking down the application/website" = Critical

## Web/App Reward Structure
- Critical: $25,000 flat
- High: $5,000–$20,000
- Medium: $2,500 flat
- Low: $1,000 flat

## XSS Severity Rules (ENS-specific)
- XSS on app.ens.domains triggering malicious tx = **Critical**
- Stored XSS on other ENS subdomains with wallet connection = **High**
- Reflected XSS on other subdomains with wallet = **Medium**
- XSS on static sites (metadata.ens.domains) = **Low** unless impacts app.ens.domains

## Key Findings

### 1. CSP Entry for jakob.ens.domains (DOWNGRADED — NOT exploitable)
- `jakob.ens.domains` in CSP `script-src` — returns 404 on root
- Source code comment: `// allow PostHog`
- .env: `NEXT_PUBLIC_POSTHOG_HOST=https://jakob.ens.domains`
- **VALIDATED:** Domain is ACTIVE PostHog proxy:
  - `/decide/?v=3` responds (says "invalid API key" with fake token)
  - `/array/.../config` returns 200
  - `/static/array.js` serves full PostHog SDK (180KB+ JS)
- **NOT a takeover candidate** — it's a working Cloudflare Worker proxying PostHog
- **Lesson:** 404 on root ≠ abandoned. Always probe service-specific paths.

### 2. CSP Disabled for Firefox/Safari (~30% users) (Critical)
- `functions/_middleware.ts:60-70` strips CSP for Firefox/Safari
- Only `frame-ancestors` remains — zero script-src protection
- Any XSS vector trivially exploitable for these users

### 3. CSP Wildcard *.ens-app-v3.pages.dev (High)
- Cloudflare Pages preview deployments trusted by CSP
- If external PRs get preview deploys → CSP bypass

### 4. SendGrid Subdomain Takeover (High)
- `58923185.ens.domains` CNAME → `sendgrid.net` → 404 nginx
- Cookies scoped to `Domain=ens.domains` (shared all subdomains)
- Takeover guide saved at: ~/PenTest/Hunting/Immunefi/ENS/sendgrid-takeover-guide.md

### 5. Incomplete CSP (no default-src, img-src, connect-src) (Low)
- Only script-src and worker-src defined
- Enables data exfiltration if HTML injection achieved

## Technique: CSP Source Code Audit (High-Value First Pass)

**Pattern discovered:** For NextJS/React web3 apps, auditing the CSP creation source code is the highest-ROI first step. Steps:
1. Find CSP file: `grep -r "script-src\|content-security" --include="*.ts" --include="*.js" src/`
2. Extract all whitelisted domains from script-src
3. Probe each domain: `curl -sI https://{domain}/ | head -5`
4. Check for: 404s (abandoned), dangling CNAMEs, wildcard patterns
5. Cross-reference with DNS: `dig +short CNAME {domain}`
6. Check if CSP is conditionally disabled (browser UA checks)

**Why this works on web3 apps:**
- Web3 frontends often add analytics/tracking domains then abandon them
- CSP is complex with wallet injectors (MetaMask, etc.) — devs add exceptions then forget
- Browser-specific CSP exceptions (Firefox/Safari) are common due to wallet extension conflicts
- Wildcard Pages/Vercel preview domains are frequently whitelisted for CI/CD

## Recon Summary
- 65 subdomains found (subfinder)
- 32 live HTTP services
- Tech: NextJS 13.5.8, Cloudflare Pages, Express/Node.js (metadata)
- Metadata API on GCP (not behind Cloudflare WAF)
- Repos cloned: ens-app-v3, ens-metadata-service

## Validation Results (2026-05-27)

| Finding | Validation | Status |
|---------|-----------|--------|
| jakob.ens.domains CSP bypass | Active PostHog proxy (serves JS on /static/array.js) | **DOWNGRADED — not exploitable** |
| CSP disabled Firefox/Safari | Confirmed: only `frame-ancestors` sent | **CONFIRMED Critical (needs XSS chain)** |
| *.ens-app-v3.pages.dev wildcard | main + deploy-preview-1 return 404 | Valid but unproven |
| SendGrid subdomain takeover | Still 404 nginx, CNAME to sendgrid.net | **Pending manual PoC** |
| CVE-2025-29927 middleware bypass | x-middleware-subrequest header — CSP still present | **NOT exploitable (CF Workers)** |
| HTMLRewriter XSS via normalize() | All HTML special chars rejected by normalize() | **NOT exploitable** |
| __NEXT_DATA__ reflection | query params not reflected in HTML (client-side app) | **NOT exploitable** |

## Exploitation Attempts (Failed)
- Unicode quotation marks (U+201D, U+FF02) → normalize() rejects
- Path-based injection (`<script>.eth`) → "Invalid Name"
- `/tld/` path with query param injection → not reflected in HTML
- `sec-fetch-dest: document` on metadata → works but name comes from subgraph (on-chain), not URL

### 6. queryNFT DoS — 502 Bad Gateway (Medium/High)
- Any ERC-721 contract with tokenURI causes metadata service to crash with 502
- Reproducible on `metadata.ens.domains` via eip155 URI format
- PoC saved: `~/PenTest/Hunting/Immunefi/ENS/poc/poc_querynft_dos.py`
- Report saved: `~/PenTest/Hunting/Immunefi/ENS/poc/immunefi-report-querynft-dos.md`
- Severity: "Taking down the application/website" = Critical per scope, but likely downgraded to Medium ($2.5K) since only one endpoint affected

## Untested Attack Surface (remaining work)
1. **`docs.ens.domains`** — not tested at all (web vulns, XSS, info disclosure)
2. **`ensdomains-landing`** repo — ens.domains main site source, not reviewed
3. **`ens-contracts`** — Solidity smart contract audit (Critical $10K-$250K)
4. **`contracts-v2`** — newer contracts, not reviewed (highest payout potential)
5. **metadata rasterize endpoint** — uses canvas/puppeteer, potential SSRF
6. **metadata header image endpoints** — untested
7. **SSRF via malicious ENS avatar** — needs ETH to register name with malicious avatar record

## Status
- Phase: Exploitation partially complete
- queryNFT DoS: report drafted, ready to submit
- SendGrid takeover: pending manual PoC (user needs to claim on SendGrid platform)
- CSP disabled Firefox/Safari: confirmed Critical but needs XSS chain
- Smart contracts: NOT STARTED (highest bounty potential $250K)
- Next: submit queryNFT DoS, test docs.ens.domains, consider SC audit

## OOS Notes
- "Taking over broken links from sources that are no longer considered active" — but this refers to archival content links, NOT infrastructure subdomains
- "Products funded or maintained by the DAO that are not on the published asset list are excluded" — Primacy of Impact overrides this for valid impacts
