# Olympus DAO (OHM) Architecture Notes

## Architecture: Kernel-Module-Policy (Default Framework)

- **Kernel**: Central registry, manages modules and policies, role-based access
- **Modules**: State storage (PRICE, RANGE, TRSRY, MINTR, ROLES, BLREG, CHREG, DEPOS, DLGTE, INSTR, VOTES, RGSTY)
- **Policies**: Business logic (Operator, Heart, EmissionManager, MonoCooler, Clearinghouse, etc.)

Chains: Ethereum (primary), Arbitrum

GitHub: OlympusDAO (fully open source)
- `olympus-v3`: active codebase (Default Framework)
- `olympus-contracts`: legacy v1/v2 (Staking, BondDepository, Treasury)
- `olympus-external`: zaps (BondHelper, OlympusZap)

## Key Contracts & Access Control

| Contract | Lines | Permissionless Functions | Notes |
|----------|-------|--------------------------|-------|
| Heart.sol | 253 | `beat()` | Triggers price update, rebase, periodic tasks. Mints OHM reward to caller. Rate-limited by frequency. |
| Operator.sol | 927 | `swap(tokenIn, amountIn, minAmountOut)` | Buy/sell OHM at wall prices. Uses stored price (last observation), NOT live Chainlink. |
| MonoCooler.sol | 1066 | `batchLiquidate(accounts[])` | Liquidate unhealthy positions. Custom LTV oracle (admin-set, not Chainlink). |
| EmissionManager.sol | 818 | None | `execute()` is role-gated to Heart. `callback()` is teller-only. |
| LoanConsolidator.sol | 905 | None | Requires Cooler ownership. Uses flash loans. |
| LimitOrders.sol | 776 | None | `cancelOrder` requires order ownership. |

## Security Posture (Well-Hardened)

**Chainlink validation (OlympusPrice.sol):**
```solidity
if (
    ohmEthPriceInt <= 0 ||                                    // rejects zero/negative
    updatedAt < block.timestamp - uint256(ohmEthUpdateThreshold) ||  // staleness
    answeredInRound != roundId                                 // round completeness
) revert Price_BadFeed(address(ohmEthPriceFeed));
```
This is the CORRECT pattern. Our Beefy-style oracle attack does NOT work here.

**Price lag (by design, not a bug):**
- `PRICE.getLastPrice()` returns last stored observation (updated on `beat()`)
- `Operator.swap()` uses this stored price for wall calculations
- Between heartbeats, wall price is "stale" relative to market — this is intentional (RBS design)
- The `_onlyWhileActive()` check reverts if price is >3x observation frequency stale

**Other controls:**
- `nonReentrant` on all user-facing state-changing functions
- No delegatecall in user paths (only governance)
- No tx.origin for auth
- Role-based access via Kernel (not simple Ownable)
- MonoCooler uses custom LTV oracle (not market-dependent, admin-controlled rate of change)

## Remaining Attack Surface (if revisiting)

1. **ConvertibleDepositAuctioneer** — auction tick mechanics, unchecked blocks
2. **Cross-chain bridge (CCIP)** — message validation, rate limiting
3. **GovernorBravo** — proposal execution edge cases, timelock bypass
4. **Heart beat timing** — can beat() timing be gamed to affect EmissionManager auction tracking?
5. **MonoCooler delegation** — `setAuthorization` + `setAuthorizationWithSig` (EIP-712) — replay across chains?
6. **DepositManager / DepositRedemptionVault** — newer code, less battle-tested

## Verdict

Olympus is a mature, well-audited protocol with proper security controls. The code quality is high (proper Chainlink validation, role-based access, reentrancy guards). Finding a Critical here requires either:
- A subtle logic bug in the emission/auction math
- A cross-chain replay or bridge vulnerability
- A governance manipulation vector
- Something in the newer deposit system (ConvertibleDepositAuctioneer)

Expected time investment for a finding: 20+ hours of focused review. Not recommended unless you have a specific hypothesis to test.
