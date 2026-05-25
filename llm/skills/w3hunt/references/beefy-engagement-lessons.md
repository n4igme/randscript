# Beefy Finance Engagement — Lessons Learned (2026-05-25)

## Summary
Target: Beefy Finance (multi-chain yield optimizer, $50K max bounty)
Duration: Single session (recon → PoC → report)
Result: SC-1 REJECTED (out-of-scope asset), 1 dropped (SC-5 onlyOwner), 1 skipped (SC-4 Low), 1 dropped (Web-1 source maps)

## SC-1 Rejection Post-Mortem (2026-05-25)

**Rejection reason:** "claimed asset by the whitehat is not in scope for the bug bounty program"

The vulnerability was valid (zero-price oracle → harvest sandwich), the PoC worked, the impact was correctly classified. But BeefyOracleChainlink and BeefySwapper are NOT in Beefy's Immunefi asset list (which only contains ~180 Polygon contracts from 2022: Zap contracts, specific vaults, specific strategies).

**What Immunefi did:** Closed the report without forwarding to Beefy for evaluation. Under "Primacy of Rules," triagers enforce asset scope mechanically — they don't assess validity or check if the project would care.

**What we should have done:**
1. Cross-checked the vulnerable contract addresses against the scope list BEFORE writing the report
2. Found an in-scope strategy contract that calls BeefySwapper during harvest (the call chain: in-scope Strategy → harvest() → _swapRewardsToNative() → BeefySwapper.swap() → BeefyOracleChainlink.getPrice())
3. Submitted with the in-scope Strategy as the primary "Impacted Asset" and explained the call chain

**Salvage options (ALL EXHAUSTED 2026-05-25):**
- ~~Re-submit targeting a specific in-scope Polygon strategy that routes through BeefySwapper+BeefyOracleChainlink~~
  VERIFIED DEAD: All 60 in-scope contracts are May 2022 era. All 27 strategies use old `unirouter()` pattern (direct DEX router: QuickSwap 0xa5E0..., SushiSwap 0x1b02..., Cometh 0x93bc...). NONE have swapper() or beefySwapper(). BeefySwapper is 2023+ infrastructure that will never appear in this frozen scope.
  Additionally: QuickSwap strategies are ALL empty (balance=0). Cometh and SushiSwap strategies are ALL paused with only dust remaining. No active harvest possible.
- Contact Beefy directly — low probability, they have no obligation
- ~~Move on to Origin Protocol ($1M bounty)~~ — ATTEMPTED: Origin's architecture doesn't use oracle-dependent on-chain swaps during harvest. Harvesters just transfer raw tokens. Pattern does NOT transfer.
- **FINAL VERDICT: SC-1 is unsalvageable. Move to next target class.**

**Scope verification results (2026-05-25):**
- Total in-scope contracts: 60 (all Polygon, all added 10 May 2022)
- Breakdown: 6 Zaps, 12 Cometh pairs, 24 QuickSwap pairs, 12 SushiSwap pairs, 6 extra QuickSwap pairs
- Router addresses confirmed on-chain:
  - QuickSwap Router: 0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff
  - SushiSwap Router: 0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506
  - Cometh Router: 0x93bcDc45f7e62f89a8e901DC4A0E2c6C427D9F25
- Full asset list saved: ~/PenTest/Hunting/Immunefi/beefy-finance/scope-assets.txt
- CONCLUSION: SC-1 is dead. No call chain from any in-scope contract to BeefySwapper/BeefyOracleChainlink exists.

## What Worked

### Oracle attack pattern (SC-1: BeefyOracleChainlink zero price)
- **Discovery path:** scode audit → BeefyOracleChainlink.sol → `latestAnswer()` without zero/negative validation → traced downstream to BeefySwapper slippage calculation → slippage becomes 0 when price is 0 → harvest sandwich enabled
- **On-chain verification:** Used `cast call` to confirm deployment on Polygon + Arbitrum, read `staleness()` (returned 0 = no cache), confirmed `harvest()` is permissionless
- **PoC:** Foundry fork test on Arbitrum mainnet, 6/6 tests pass. Mocked Chainlink feed returning 0, demonstrated full attack chain (harvest → swap with 0 slippage → sandwich profit)
- **Key insight:** Negative price is "accidentally safe" in Solidity 0.8 (int256 → uint256 cast overflows and reverts). Only ZERO price is exploitable. This took 2 iterations to discover.

### Recon efficiency
- Delegated 3 parallel sub-agents (GitHub enum, subdomain enum, frontend analysis)
- Found 20 subdomains, 5 repos, full API map in one pass
- env-prefix mutation found e-pmo2 pattern (useful for discovering hidden subdomains)

### Web layer assessment (fast negative)
- React SPA, no dangerouslySetInnerHTML, vault addresses bundled at build time
- APIs parameterized, SSRF locked down (1inch proxy validates chain IDs)
- Source maps found on analytics.beefy.finance but Immunefi v2.2 excludes open source code
- Decision: pivot to smart contracts after ~30 min of web testing

## What Didn't Work / Pitfalls

1. **SC-5 (addWantAsReward)** — looked promising but `onlyOwner`. Always check access control FIRST before building exploit chain.
2. **Web-1 (source maps)** — wasted time documenting before checking Immunefi severity table. Source maps without secrets = None severity = not reportable.
3. **Impacted asset not in scope list** — BeefyOracleChainlink (0xD07F...) is NOT in Immunefi's 180-contract Polygon scope list. Had to use manual asset submission. Risk of "out of scope" rejection.
4. **"Requires external conditions" risk** — SC-1 requires Chainlink to return 0. Attacker can't cause this. Framed as "theft of yield WHEN condition occurs" but this is the #1 rejection reason for oracle bugs.
5. **Negative price red herring** — spent time building PoC for negative price before discovering Solidity 0.8 overflow makes it revert. Test BOTH zero AND negative separately.

## Severity Assessment Lessons

- "Theft of unclaimed yield" = High per Immunefi v2.2 (NOT Critical)
- External precondition (Chainlink returning 0) may cause downgrade
- permissionless harvest() upgrades severity (attacker controls timing)
- onlyOwner = dead finding, always (centralization risk = out of scope)

## Tempo Decision

After finding SC-1 (High, $15K potential):
- SC-4 (Low, $500 potential) — skipped, not worth hours of validation
- Web layer exhausted — no more attack surface
- Decision: submit SC-1, move to next target (Angle Protocol, $500K max)
- Rationale: 10x payout potential on Angle, oracle pattern transfers directly

## Reusable Patterns for Next Target

1. Check if protocol uses Chainlink oracles → same zero-price pattern may apply
2. Check if harvest/liquidate/claim is permissionless → MEV sandwich vector
3. Multi-chain deployments → check if oracle config differs per chain
4. staleness=0 means no cache → oracle bugs are more impactful
5. Factory vs non-factory versions → non-factory may have known-but-unfixed bugs
