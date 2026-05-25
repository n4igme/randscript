# Immunefi Target Shortlist v3 (2026-05-25)

## Targets Explored & Eliminated

| Protocol | Max Bounty | Result | Reason |
|----------|-----------|--------|--------|
| Beefy Finance | $75K | DEAD | 60 in-scope contracts all 2022-era, empty/paused, old unirouter arch. SC-1 unsalvageable. |
| Origin Protocol | $1M | NO FINDING | Well-hardened. Oracle router has unsafe cast but no active call path. Harvesters don't swap. Single-asset vaults. |
| Ethena | $3M | KNOWN ISSUE | unstake() blacklist bypass already in C4 2023 (#707/#734), classified QA. Trust-based arch, tiny on-chain surface. |
| Enzyme Finance | $200K | NEEDS DEEP REVIEW | No C4/Sherlock contests. Beefy pattern doesn't apply (owner-only trades, user-supplied slippage). GatedRedemptionQueue (1168 lines, Apr 2026) is best target for deep review. |
| Gains Network | $200K | NO FINDING | 400-function Diamond, proper accounting, oracle restricted to keepers. |
| Olympus DAO | $100K | NO FINDING | Proper Chainlink validation, role-based access on all state-changing functions. |

## Key Architecture Lessons

**Oracle→harvest→sandwich pattern requires ALL THREE:**
1. Permissionless trigger (harvest/compound/rebase)
2. On-chain oracle-dependent swap (not transfer to strategist)
3. Slippage calculated from oracle price (not user-supplied)

**Protocols that deliberately avoid this pattern:**
- Origin: harvesters just transfer() to strategist, swap happens off-chain
- Ethena: no on-chain oracle at all, trust-based mint/burn
- Enzyme: trades are owner-only, slippage is user-supplied

## Next Targets (Prioritized)

### Tier 1: Deep Review Candidates (commit 10-20h or skip)

**Enzyme Finance ($200K)** — GatedRedemptionQueueSharesWrapperLib
- 1168 lines, newest in-scope (April 2026)
- No prior audit contest = less external scrutiny
- Attack surface: redemption queue logic, share accounting, window timing
- Multi-chain (ETH, Polygon, Base, Arbitrum)
- Repo: github.com/enzymefinance/protocol (515 .sol files)
- Dir: ~/PenTest/Hunting/Immunefi/enzyme-finance/

### Tier 2: Fresh Targets (need initial recon)

**Lombard Finance ($250K)** — Bitcoin liquid staking (LBTC)
- Newer protocol, likely less battle-tested
- Slug: lombard-finance
- Check: permissionless mint/redeem? Oracle for BTC pricing?

**DeXe Protocol ($500K)** — DAO investment pools with automated strategies
- Slug: dexeprotocol
- Automated strategies = potential for permissionless triggers
- Check: how are strategies executed? Oracle dependency?

**SSV Network ($250K)** — Ethereum staking infrastructure
- Slug: ssvnetwork
- Operator/validator management
- Check: slashing conditions, reward distribution

### Tier 3: High Bounty but Likely Hardened

**GMX ($5M)** — Perp DEX, explored via Gains (similar arch)
- Custom oracle, likely well-audited
- Only worth it with a specific hypothesis

## Pre-Recon Checklist (apply to ALL new targets)

1. `curl -sL -o /dev/null -w "%{http_code}" "https://immunefi.com/bug-bounty/${slug}/information/"` — verify live
2. Search C4/Sherlock: `github.com/code-423n4/*${protocol}*` and `github.com/sherlock-audit/*${protocol}*`
3. Check scope freshness (last updated date) — stale scopes = dead contracts
4. Verify 3 prerequisites before committing to source review
5. Check on-chain: are in-scope contracts active? (`paused()`, `balanceOf()`, `totalSupply()`)
