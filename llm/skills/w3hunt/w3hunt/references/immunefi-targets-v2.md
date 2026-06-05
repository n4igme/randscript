# Immunefi Target Shortlist v2 (2026-05-25)

## Strategy Shift

After Beefy SC-1 (oracle + permissionless harvest), focus on protocols with the SAME architectural pattern rather than grinding mature perp DEXes or treasury protocols.

**Proven exploit pattern:** Oracle returns bad price → harvest/swap has no slippage protection → sandwich attack steals yield. Requirements:
1. Permissionless trigger function (harvest, compound, rebase)
2. Oracle-dependent swap (Chainlink, TWAP, custom)
3. Slippage calculated from oracle price (not user-supplied)

## Confirmed Active Programs (2026-05-25)

| Protocol | Slug | Max Bounty | Why |
|----------|------|-----------|-----|
| Origin Protocol | originprotocol | $1M | OUSD/OETH auto-compounding, harvest+oracle swaps, EXACT Beefy pattern |
| Ethena | ethena | $3M | USDe synthetic dollar, funding rate oracle, yield distribution |
| Enzyme Blue | enzymefinance | $200K | On-chain vaults with strategies, NAV price feeds |
| GMX | gmx | $5M | Perp DEX, GLP/GM vaults, custom oracle (likely hardened) |
| Lombard Finance | lombard-finance | $250K | Bitcoin liquid staking (LBTC), newer protocol |
| DeXe Protocol | dexeprotocol | $500K | DAO investment pools with automated strategies |
| Gains Network | gainsnetwork | $200K | Perp DEX (explored — well-audited, no finding) |
| Olympus DAO | olympus | $100K | Treasury/staking (explored — proper Chainlink validation) |
| Yearn Finance | yearnfinance | $200K+ | Yield aggregator (original pattern, likely well-audited) |
| SSV Network | ssvnetwork | $250K | Ethereum staking infrastructure |

## Top Pick: Origin Protocol

**Why #1:**
- OUSD (Origin Dollar) and OETH (Origin Ether) are yield-bearing tokens
- They auto-compound by harvesting from strategies (Aave, Compound, Curve, Convex, Morpho)
- Architecture: Vault → Strategy → Harvest → Swap rewards → Rebase
- This is EXACTLY the Beefy pattern at 20x the payout ($1M vs $50K)
- Open source: github.com/OriginProtocol
- Multi-strategy = multiple oracle dependencies = multiple potential bugs

**Recon starting points:**
- GitHub: https://github.com/OriginProtocol
- Key repos: origin-dollar (OUSD), origin-ether (OETH)
- Look for: harvest functions, oracle usage, swap slippage calculation
- Check: Chainlink validation, permissionless triggers, strategy migration

## Protocols That Disappeared (were on v1 shortlist, now 404)

- Angle Protocol (angleprotocol) — GONE
- Nexo — GONE
- Alpaca Finance — GONE
- QiDAO / MAI Finance — GONE
- Exactly Protocol — GONE
- Mean Finance — GONE

**Lesson:** Immunefi programs churn fast. Always verify before starting recon.

## Protocols Explored But No Finding

- **Gains Network** — 400-function Diamond, proper accounting (realized PnL tracking), oracle restricted to whitelisted keepers, delegation properly access-controlled. Web layer ($40K Critical) is React SPA behind Cloudflare with read-only Express.js APIs.
- **Olympus DAO** — Kernel-Module-Policy architecture, proper Chainlink validation (price > 0, staleness, round completeness), role-based access on all state-changing functions. Heart.beat() is permissionless but only triggers role-gated downstream functions.
- **Origin Protocol** — Well-hardened. Vaults are single-asset (no oracle for mint/redeem). Harvesters don't swap on-chain (just transfer to strategist). All rebalance functions access-controlled. Oracle routers have code bugs (unsafe cast) but no active call path = no impact.
- **Ethena** — Trust-based architecture. No on-chain oracle/AMM/algorithmic pricing. Contracts are just mint/burn/stake wrappers around off-chain delta-neutral strategy. EthenaMinting relies on MINTER_ROLE + benefactor EIP-712 signature (no price validation on-chain). StakedUSDeV2 blacklist bypass via unstake() is a KNOWN ISSUE (Code4rena 2023-10-ethena #707, downgraded to QA). 8-hour vesting mitigates reward front-running. $3M bounty is for catastrophic minting/signature bugs only.

## Pattern Transferability Assessment (updated 2026-05-25)

The Beefy oracle→harvest→sandwich pattern requires ALL THREE:
1. Permissionless trigger (harvest/compound/rebase)
2. On-chain swap during that trigger
3. Oracle-dependent slippage calculation

Protocols that AVOID this (pattern does NOT transfer):
- Single-asset vaults (no oracle needed for mint/redeem)
- Harvesters that just transfer() to strategist EOA (no on-chain swap)
- Access-controlled rebalance/harvest (not permissionless)
- Trust-based systems with off-chain pricing (Ethena)

Best remaining targets for this pattern:
- **Enzyme Finance** ($200K) — on-chain vaults with NAV price feeds, closest to Beefy
- **Lombard Finance** ($250K) — newer Bitcoin liquid staking, less audited
- **DeXe Protocol** ($500K) — DAO pools with automated strategies

## Pre-Submission Research Gate (added 2026-05-25)

Before writing a report, ALWAYS check if the finding was already reported:
1. Search `code-423n4/{protocol}-findings` on GitHub (if contest existed)
2. Search Sherlock audit contests for the same protocol
3. Check the protocol's `security/` or `audit/` repo for known issues
4. If found in prior audit → DO NOT SUBMIT to Immunefi (will be rejected as "known issue")
