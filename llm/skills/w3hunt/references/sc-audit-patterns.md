# Smart Contract Audit Patterns (DeFi-Specific)

## Parallel Audit Strategy (delegate 3 sub-agents)

Batch contracts by risk tier for parallel review:

| Batch | Contracts | Focus |
|-------|-----------|-------|
| 1 | Vault (ERC-4626, share math) | Inflation attack, donation, rounding, reentrancy |
| 2 | Oracle + Swapper | Staleness, negative price, TWAP manipulation, slippage bypass |
| 3 | Strategy base + fee manager | Harvest manipulation, fee bypass, migration safety |

## High-Value Contract Bug Patterns

### Oracle bugs (often Critical/High)
- Chainlink `latestAnswer()` without staleness check or negative price validation
- Unsafe `int256` → `uint256` cast (negative becomes astronomical)
- UniswapV2 TWAP first observation using manipulable spot price
- No minimum TWAP period enforcement (1-second TWAP ≈ spot price)
- Missing fallback when oracle reverts (blocks all swaps = DoS)

### Vault/share bugs (often Critical)
- First depositor inflation (no virtual shares, no minimum deposit)
- Share price manipulation via direct token donation to vault/strategy
- `balance()` using live `balanceOf()` instead of internal accounting
- Missing `nonReentrant` on withdraw (deposit has it, withdraw doesn't)
- `earn()` public with no access control (anyone can force-deposit to strategy)
- No flash loan protection (deposit + withdraw in same tx)

### Strategy/harvest bugs (often High/Medium)
- `wantHarvested = balanceOfWant()` instead of delta (inflates totalLocked)
- Infinite approvals to routers that persist after swap
- `addWantAsReward()` bypassing `require(_token != want)` safety check
- Harvest/deposit race condition (MEV sandwich around harvest)
- Uninitialized proxy front-running (factory creates clone, attacker front-runs initialize)

## On-Chain Verification

After finding bugs in source, verify deployment:
```bash
# Check contract is deployed and has code
cast code <address> --rpc-url <rpc>

# Verify function selectors match source
cast sig 'functionName(argTypes)'

# Read state to confirm configuration
cast call <address> 'owner()(address)' --rpc-url <rpc>
cast call <address> 'staleness()(uint256)' --rpc-url <rpc>
```

**Free Polygon RPCs that work (2026):**
- `https://polygon-bor-rpc.publicnode.com` (reliable)
- Avoid: polygon-rpc.com (401), ankr (requires key), blastapi (deprecated)

## Foundry PoC

See `references/foundry-oracle-exploit-poc.md` for fork test patterns, vm.mockCall, and working RPCs.
