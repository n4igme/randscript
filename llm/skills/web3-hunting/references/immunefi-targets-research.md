# Immunefi Target Research & Selection

Last updated: 2026-05-25

## Selection Criteria

- BOTH web/app scope AND smart contract scope (hybrid programs)
- Mid-tier payout: $10K-$100K for Critical
- Multi-chain deployments preferred (larger surface, inconsistency bugs)
- Active programs on EVM chains
- Protocols with complex web layers (APIs, aggregators, dashboards)

## Shortlist (ranked by web pentest edge)

### HIGH Priority (most web-heavy)

1. **Nexo** — CeFi/DeFi hybrid lending, traditional web app, KYC, fiat flows. $50K max.
2. **Immunefi** — their own platform, pure web + vault contracts. $50K max.
3. **Beefy Finance** — 20+ chain yield aggregator, complex API layer. $75K max.
   - Status: TESTED (2026-05-25). Web layer well-hardened. Source map on analytics subdomain (Medium). Chainlink oracle bug in contracts (High).

### MEDIUM (hybrid web+contract)

4. **Gains Network (gTrade)** — perpetuals trading UI. $75K max.
5. **Alpaca Finance** — leveraged yield farming. $100K max.
6. **Mean Finance** — DCA scheduling frontend. $60K max.

### LOWER (more contract-focused, but high bounty)

7. **Angle Protocol** — stablecoin, multi-chain. $500K max (highest bounty).
8. **Olympus DAO** — governance/treasury. $100K max.
9. **QiDAO / MAI Finance** — multi-chain stablecoin. $100K max.
10. **Exactly Protocol** — fixed-rate lending on Optimism. $50K max.

## Beefy Finance — Engagement Notes

Program URL: https://immunefi.com/bug-bounty/beefyfinance/
Scope verified: 2026-05-25

**Web scope:** https://app.beefy.finance/ (single target)
**Contract scope:** Polygon Zap contracts, vaults, strategies

**Payouts:**
- Smart Contract Critical: $75K | High: $15K | Medium: $2K
- Web Critical: $25K | High: $10K | Medium: $4K | Low: $2K

**Key findings:**
- Web: Source map exposed on analytics.beefy.finance (Medium, $4K)
- Contract: BeefyOracleChainlink negative price + no staleness (High, $15K)
- Contract: BaseAllToNativeStrat wantHarvested miscalculation (Medium, $2K)
- Contract: StrategyERC4626 addWantAsReward bypass (Medium, $2K)

**Architecture learned:**
- Frontend: React SPA (Vite), Cloudflare Pages, no auth (wallet-based)
- APIs: Koa (beefy-api) + Fastify (balance-api, investor-api, clm-api) on Heroku
- Contracts: BeefyVaultV7 + strategies + BeefyOracle + BeefySwapper
- All behind Cloudflare, CORS *, no CSP on frontend
- Contract addresses bundled at build time (not from API)
- Vault configs from static JSON in frontend repo

**What didn't work:**
- SSRF via rpc.beefy.finance (decommissioned, 404)
- SSRF via zap proxy (chain validation strict, baseURL hardcoded)
- XSS (no sinks: no dangerouslySetInnerHTML, no eval)
- beta/legacy subdomains (301 redirects)
- Contract address poisoning (static config, not API-sourced)
- Subdomain takeover (all Cloudflare except vote-archive which is active on Vercel)

## Platform Notes

- Cloudflare bot detection blocks automated Immunefi browsing after ~5 page loads
- Scope tab has a combobox dropdown to switch between "Smart Contract" and "Web & App" views
- Programs with "Primacy of Rules" may reject findings on assets not explicitly listed
- All web/app bugs require PoC AND fix suggestion
- Payouts in stablecoin/BTC/ETH at team's discretion
