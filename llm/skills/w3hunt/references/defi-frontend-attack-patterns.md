# DeFi Frontend Attack Patterns

Patterns discovered during Beefy Finance engagement (2026-05-25). Applicable to any DeFi protocol with web+contract scope on Immunefi.

## Architecture Patterns (Common DeFi Frontend Stack)

Typical DeFi frontend:
- React SPA (Vite/Next.js), hosted on Cloudflare Pages or Vercel
- No server-side auth (wallet-based, stateless)
- Redux/Zustand state persisted to localStorage
- API backend on Heroku/Railway behind Cloudflare proxy
- Multiple API subdomains (main, data, balance, investor, CLM)
- Direct RPC calls to 20+ chains from browser
- Contract addresses bundled at build time from static JSON config

## Attack Surface Map

### What Usually Works (DeFi-specific)

1. **Source map exposure on secondary apps** — main app often blocks .map files, but analytics/dashboard/vote subdomains may not. Check ALL subdomains.

2. **Debug/internal endpoints on APIs** — DeFi APIs often have `/debug`, `/swaps/debug` endpoints that leak internal pricing logic, thresholds, and error reasons.

3. **Verbose error messages** — Fastify/Express validation errors reveal full API schema (parameter names, types, allowed values). GraphQL errors leak subgraph IDs and query structure.

4. **Missing CSP on frontend** — extremely common in DeFi because wallet providers inject scripts. No CSP = any XSS is fully exploitable for wallet drain.

5. **CORS * on all APIs** — standard in DeFi (public blockchain data). Not a vuln alone, but combined with write endpoints = critical.

### What Usually Doesn't Work (Save Time)

1. **XSS via dangerouslySetInnerHTML** — modern DeFi frontends (React) rarely use it. Check but don't spend hours.

2. **Contract address poisoning via API** — most protocols bundle addresses at build time from static JSON, not fetched at runtime. Verify before investing time.

3. **SSRF via RPC proxy** — chain validation is usually strict (whitelist of known chain names/IDs). Path traversal in chainId blocked by validation.

4. **Host header injection** — Cloudflare blocks with 403.

5. **Subdomain takeover** — most DeFi uses Cloudflare A records (not CNAME). Only Vercel/Netlify CNAMEs are candidates, and they're usually claimed.

6. **beta/legacy subdomains** — often just 301 redirects to main app, not separate deployments.

## Proxy Endpoint Analysis (Zap/Swap Proxies)

DeFi protocols often proxy to aggregators (1inch, Kyber, Paraswap). Check:

1. **Chain validation** — is chainId validated against whitelist? (Usually yes)
2. **API key leakage** — do error messages expose the key? (Usually redacted)
3. **Request forwarding** — can you inject extra params that reach the upstream API?
4. **POST body forwarding** — Kyber/LiquidSwap POST endpoints forward body to upstream

Typical security model:
- baseURL hardcoded per chain (not user-controllable)
- API key sent as Bearer token or header (not in URL)
- `redactSecrets()` strips known env vars from error messages
- Rate limiting via PQueue (server-side, not bypassable)

## API Endpoint Discovery Techniques

1. **Clone frontend repo** → grep for API URLs in source
2. **Clone API repo** → read router file for all endpoints
3. **Source maps on secondary apps** → extract URLs from sourcesContent
4. **Validation errors** → send requests with missing params, errors reveal schema
5. **Status/health endpoints** → often leak infrastructure details (subgraph names, chain configs)

## Reporting Tips (Immunefi-Specific)

- Source map exposure = Medium ($4K) — clear, reproducible, always accepted
- Debug endpoint exposure = Low ($2K) — borderline, may be rejected as informational
- Missing security headers alone = usually rejected unless combined with exploit
- Verbose errors leaking infra = Low ($2K) — accepted if it reveals actionable info
- API schema disclosure via validation errors = usually informational (not paid)
