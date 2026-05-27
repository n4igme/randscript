# Bug Bounty Platform Selection Guide

## Platform Assessment (as of May 2026)

### Immunefi (Web3)
- **Best for:** DeFi protocols with web frontends
- **Payouts:** $1K–$100K+ (highest ceiling)
- **Limit:** 1 report/day
- **Geo-restriction:** None
- **Edge:** Most hunters only look at Solidity — web-layer bugs (CORS, SSRF, API auth) on DeFi frontends are underexplored

### YesWeHack
- **Best for:** APAC programs, French/EU companies
- **Payouts:** €500–€15K for Critical
- **Geo-restriction:** None (some programs EU-only)
- **Programs:** Gojek, GoTo Financial, CoinDCX, Dojo CTF challenges
- **Note:** Dojo challenges are reputation-only (no payout), but build profile for private invites

### HackerOne
- **Best for:** Volume + private invite pipeline
- **Payouts:** $500–$100K+
- **Geo-restriction:** Varies by program
- **Strategy:** Find 3-5 valid bugs on public programs → get invited to $10K-$50K private programs
- **Largest program pool globally

### Bugcrowd
- **Best for:** Fintech, identity, crypto programs
- **Payouts:** $50–$75K (Okta highest)
- **Geo-restriction:** Varies — some US-only (Chime)
- **Notable programs:**
  - Okta ($100–$75K) — auth/identity, needs Bugcrowd credentials
  - Zendesk ($100–$50K) — SaaS
  - Chime ($50–$20K) — US-only, geo-blocked from non-US IPs
  - eToro ($100–$15K) — global, trading/fintech
  - Fireblocks ($20–$12K) — web3 infra
  - Blockchain.com ($100–$10K) — crypto exchange
  - Rapyd ($100–$7.5K) — payment APIs

### Intigriti
- **Best for:** EU fintech/banking
- **Payouts:** €25–€20K
- **Geo-restriction:** Many programs EU/UK-only (Spring Heist explicitly excludes non-EU)
- **Assessment:** Small public program pool, mostly VDP (no bounty). Skip unless EU-based.
- **Paid programs found:** Randstad (€25–€5K), Coveo, MindGeek group (Pornhub/Brazzers)

### HackenProof
- **Best for:** Web3/blockchain
- **Payouts:** Varies
- **Blocker:** Requires $5 credit to submit reports (unknown top-up mechanism)

## Geo-Blocking Pitfalls (from Indonesia/APAC)

Programs that geo-block non-US traffic at CDN level:
- **Chime** — ALL endpoints return Cloudflare 403 from non-US IPs (including QA env)
- **Any US-only fintech** requiring KYC with SSN

**Detection:** If curl returns `403` with `content-length: 16` and `server: cloudflare` from a SIN/SGP PoP, it's geo-blocked. Check `cf-ray` header for PoP location.

**Before committing to a target:** Always probe the main domain from your actual IP first. A 403 with 16-byte body from Cloudflare = geo-block = don't waste time on recon.

## Target Selection Criteria (for non-US researcher)

1. **No geo-restriction** — verify with curl before starting recon
2. **API-heavy** — more attack surface accessible without full account
3. **Web + crypto hybrid** — leverages both web pentest and web3 knowledge
4. **High P1 ceiling** — $10K+ for Critical
5. **Low competition** — newer programs or niche targets
6. **Account creation accessible** — no US SSN/phone requirement

## Recommended Priority (for n4igme's skillset)

1. Immunefi — web3 + web hybrid (active, reports ready)
2. YesWeHack — APAC programs (active, reports ready)
3. Bugcrowd — Okta, eToro, Fireblocks, Rapyd (global access)
4. HackerOne — build rep for private invites
5. Skip: Intigriti (EU-focused), HackenProof (blocked)
