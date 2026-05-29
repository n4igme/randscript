# Phase 3: Web Assessment (30 min - 2 hr)

## Gate

Quick-kill checklist completed, web vectors identified or ruled out, at least one finding OR documented "web layer hardened".

## Scope

Test what was discovered for vulnerabilities. Active exploitation attempts.

This phase is NOT conditional — ALWAYS run it. Web is your competitive edge.

## Workflow

**First: run proven patterns (15 min) — see `references/proven-patterns.md`**
These are confirmed-working chains from past engagements. Run the 5 quick-checks before the generic checklist below. If any hits → fast-track to Phase 5.

**Time decision point:**
- Run quick-kill items 1-4 first (15 min).
- If ALL negative (no CORS reflection, no GraphQL, CSP present, no source maps) → cap at 30 min total, finish items 5-8 quickly, then move to Phase 4.
- If ANY shows promise → extend to 2 hr on that vector.

**Web-is-dead fast-exit (30 min cap):**
- All 8 quick-kill items negative
- Frontend is static/CDN-only (no API calls, no dynamic content)
- All endpoints return proper auth challenges (401/403 with no bypass)
→ Document "web layer hardened" and move to Phase 4.

---

## Quick Kill Checklist (in order)

1. **CORS on ALL API subdomains** — if origin reflected + credentials=true → VALIDATE IMPACT (public data = no impact, wallet-sig auth = no impact)
2. **GraphQL introspection** — if mutations exist, test WITHOUT auth. Unauth write = High.
3. **CSP headers** — no CSP = XSS potential
4. **Source maps** — check `*.js.map` exposure
5. **API discovery** — grep JS bundles for `/api/`, `fetch(`, backend URLs
6. **Subdomain takeover** — check CNAME records for dangling entries
7. **Wallet interaction flow** — how does frontend construct transactions? API-sourced addresses?
8. **RPC proxy** — test for SSRF with internal IPs

---

## DeFi Web Critical ($25K) Patterns

- XSS on app domain → inject malicious `eth_sendTransaction` → drain connected wallet
- API endpoint serving contract addresses → poison it → users interact with attacker contract
- Subdomain takeover on wallet-connected domain → phishing with legitimate origin
- SSRF via RPC proxy → access internal services / cloud metadata

---

## Attack Vector Prioritization (DeFi-Specific)

| Priority | Vector | Impact | Typical Payout |
|----------|--------|--------|----------------|
| P1 | XSS → Wallet Drain | Inject malicious tx signing | Critical $25K |
| P1 | SSRF via RPC Proxy | Internal service access | Critical $25K |
| P1 | API Data Poisoning → Tx Manipulation | Substitute contract addresses | Critical $25K |
| P2 | Unauthenticated API Writes | Poison vault/price data | Critical/High |
| P2 | Subdomain Takeover | Phishing w/ wallet interaction | Critical/High |
| P3 | IDOR on User APIs | Balance/position disclosure | High $10K |
| P3 | Payment Flow Manipulation | Onramp parameter tampering | High $10K |

---

## DeFi Frontend-Specific Checks

1. **No CSP = XSS goldmine** — DeFi frontends often skip CSP for wallet injection compat
2. **Transaction construction** — frontend builds calldata client-side, can params be manipulated?
3. **Contract address sourcing** — hardcoded, from API, or from on-chain registry?
4. **Slippage/deadline injection** — can frontend be tricked into setting 100% slippage?
5. **RPC proxy abuse** — if protocol runs its own RPC, test for SSRF
6. **Wallet connection flow** — WalletConnect, injected provider, deep link manipulation
