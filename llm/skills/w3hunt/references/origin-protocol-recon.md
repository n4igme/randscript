# Origin Protocol Recon Notes (2026-05-25)

## Program Details
- Platform: Immunefi
- Slug: originprotocol
- Max Bounty: $1,000,000
- Last Updated: 13 May 2026
- PoC Required: YES
- Vault Program: YES, Arbitration enabled
- Chains: Ethereum, Base, Sonic

## In-Scope Assets (30 contracts)

### High-Priority (strategies with yield/oracle logic)
- [ETH] 0xB1d624fc40824683e2bFBEfd19eB208DbBE00866 — OUSD Morpho V2 CrossChain Master Strategy (Feb 2026)
- [BASE] same address — OUSD Morpho V2 CrossChain Remote Strategy (Feb 2026)
- [ETH] 0x26a02ec47ACC2A3442b757F45E0A82B8e993Ce11 — Curve USDC AMO Strategy (Dec 2025)
- [ETH] 0xba0e352AB5c13861C26e4E773e7a833C3A223FE6 — Curve OETH+WETH AMO Strategy (Dec 2025)
- [ETH] 0x3643cafA6eF3dd7Fcc2ADaD1cabf708075AFFf6e — Morpho OUSD v2 Strategy (Dec 2025)
- [ETH] 0xaF04828Ed923216c77dC22a2fc8E077FDaDAA87d — CompoundingStakingSSVStrategyProxy (Nov 2025)
- [BASE] 0xF611cC500eEE7E4e4763A05FE623E2363c86d2Af — AerodromeAMOStrategyProxy (Nov 2024)
- [ETH] 0x85b78aca6deae198fbf201c82daf6ca21942acc6 — ARM stETH/WETH (Nov 2024)
- [ETH] 0x596B0401479f6DfE1cAF8c12838311FeE742B95c — Sonic Staking Strategy (Mar 2025)

### Core Vaults & Tokens
- [ETH] 0x39254033945AA2E4809Cc2977E7087BEE48bd7Ab — OETH Vault (single-asset: WETH)
- [ETH] 0xe75d77b1865ae93c7eaa3040b038d7aa7bc02f70 — OUSD Vault (single-asset: USDC)
- [BASE] 0x98a0cbef61bd2d21435f433be4cd42b56b38cc93 — SuperOETHb Vault
- [ETH] 0xa3c0eCA00D2B76b4d1F170b0AB3FdeA16C180186 — Origin Sonic Vault
- [SONIC] 0xb1e25689D55734FD3ffFc939c4C3Eb52DFf8A794 — Origin Sonic

### Governance & Utility
- Timelocks, OGN staking, xOGN, Migrator, BeaconProofs, wOETH, etc.

## Architecture (Key Security Properties)

### Why Beefy oracle pattern does NOT apply:
1. **Vaults are single-asset** — OETH=WETH only, OUSD=USDC only. No oracle needed for mint/redeem.
2. **Harvesters don't swap** — OETHHarvesterSimple/SuperOETHHarvester/OSonicHarvester just call collectRewardTokens() then transfer raw tokens to strategist. Off-chain swap.
3. **All rebalance functions are access-controlled** — onlyGovernorOrStrategist, not permissionless.
4. **Strategies use Curve virtual_price** for slippage, not Chainlink oracles.

### OETH Vault Strategies (on-chain verified):
- 0xba0e... — Curve OETH+WETH AMO
- 0x1827... — (unknown, not in scope list)
- 0x4685... — (unknown, not in scope list)
- 0xaF04... — CompoundingStakingSSVStrategy

### Oracle Routers (code exists but largely unused):
- OETHOracleRouter — ETH-denominated feeds (frxETH, stETH, rETH, CRV, CVX, cbETH, BAL)
- OracleRouter — USD-denominated (DAI, USDC, USDT, COMP, AAVE, CRV, CVX)
- OETHBaseOracleRouter — Base chain
- OSonicOracleRouter — Sonic chain (extends OETHFixedOracle)

## Findings (all Low/Informational — no exploitable impact)

### F1: OETHOracleRouter unsafe cast (Low/Info)
- Line 44: `uint256(_iprice)` instead of `_iprice.toUint256()`
- Negative Chainlink price wraps to max uint256
- No range check (comment: "This implementation does not (!) do range checks")
- NOT exploitable: oracle not called in any active fund-flow path

### F2: Zero-price propagation for non-pegged assets (Low/Info)
- AbstractOracleRouter: non-pegged assets have no MIN_DRIFT check
- Same issue: no active caller

### F3: SonicHarvester no slippage when priceProvider=address(0)
- arm-oeth/src/contracts/SonicHarvester.sol line 141-142
- Early return skips slippage check AND transfer to rewardRecipient
- Requires: operator role + priceProvider unset
- Trusted role dependency

### F4: ARM permissionless allocate() — griefing only, no fund extraction

## GitHub Repos
- origin-dollar (OUSD + OETH contracts) — main target
- arm-oeth (ARM stETH/WETH, LidoARM, EtherFiARM, EthenaARM, OriginARM)
- ousd-governance (OGN staking, xOGN)
- morpho-utils (Morpho strategy utilities)
- security (audit reports)

## Verdict
Codebase is well-audited and architecturally hardened. No Critical/High finding apparent from source review. The oracle bug is valid code but has no impact path. Not worth submitting as Low ($500) given effort-to-reward ratio. Better to pivot to softer targets.

## Remaining Attack Surface (if returning later)
1. CrossChain CCTP message handling — race conditions, replay, out-of-order delivery
2. Aerodrome AMO pool manipulation during rebalance (MEV on strategist txs)
3. Sonic chain contracts (newest, March 2025, less audit coverage)
4. ARM lending market integration (Morpho/Silo market wrappers)
