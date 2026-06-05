# Phase 2: Recon (1 hr)

### Gate: subdomains mapped, GitHub/SDK repos cloned, API endpoints discovered, frontend framework identified

**Scope:** Discover what exists (endpoints, repos, subdomains). No exploitation attempts.

**Priority order (if time-constrained, cut from bottom):**
1. **2a. GitHub & SDK** (20 min) — highest ROI, reveals backend URLs + contract addresses
2. **2c. Frontend Analysis** (15 min) — API endpoints from JS bundles, security headers
3. **2d. Backend API Enum** (15 min) — probe discovered endpoints
4. **2b. Subdomain Enum** (10 min) — passive only, lowest priority

**Time-constrained cut:** If only 30 min available, do 2a + 2c only. Subdomains can wait.

**Minimum viable recon (all must be checked before advancing):**
- ✅ At least 1 SDK/frontend repo cloned (or confirmed none exist)
- ✅ crt.sh + HackerTarget results merged into subdomains.txt
- ✅ At least 3 API endpoints discovered (or confirmed none exist: GitHub repos have no backend code, JS bundles have no fetch calls, common paths all 404)
- ✅ Frontend framework identified
- ✅ CSP/CORS headers captured for all web targets

Run in parallel (delegate_task with 3 sub-agents):

### 2a. GitHub & SDK Enumeration (DO THIS FIRST — highest ROI)
- Find org repos via GitHub API: `https://api.github.com/orgs/{org}/repos?per_page=100&sort=updated`
- Clone SDK/trading-sdk repos immediately (shallow: `git clone --depth 1`)
- Extract from SDK: contract addresses, ABIs, backend URLs, trade construction logic
- Identify: frontend repo, API/backend repo, smart contracts repo, subgraph repos
- **SDK repos reveal more attack surface than subdomain scanning**

### 2b. Subdomain Enumeration (Passive)
- HackerTarget: `curl -s "https://api.hackertarget.com/hostsearch/?q={domain}"`
- crt.sh: `curl -s "https://crt.sh/?q=%25.{domain}&output=json"`
- DNS lookups on all discovered subdomains (A, CNAME records)
- Flag: beta/staging, legacy, internal APIs, RPC proxies, payment/onramp

### 2c. Frontend Analysis
- Framework detection (React/Vue/Next.js, build tool)
- API endpoint discovery from JS bundles
- Security headers audit (CSP, CORS, HSTS)
- Source map exposure check
- Transaction construction flow mapping

### 2d. Backend API Enumeration
```bash
# Common DeFi backend patterns (found in SDK constants.ts):
for path in /health /trading-variables /open-trades /config /admin /graphql /ws /metrics /debug; do
  curl -s -w "\n%{http_code}" "${URL}${path}" | tail -1
done
```

**Script:** `scripts/phase2_recon.py` — batches the full pipeline (GitHub + crt.sh + HackerTarget + headers + API probe + gate check).
