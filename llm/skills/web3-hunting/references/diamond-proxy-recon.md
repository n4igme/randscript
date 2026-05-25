# Diamond Proxy (EIP-2535) Recon & Attack Patterns

## Enumeration Steps

### 1. Get Facet Addresses
```bash
cast call <diamond> "facetAddresses()(address[])" --rpc-url <rpc>
```

### 2. Get Full ABI
Look for ABI in protocol's SDK repo first (e.g., `sdk/abi/ContractName.json`).
Format is usually `{"_format":"hh-sol-artifact-1","sourceName":...,"abi":[...],"bytecode":...}`.

Parse functions:
```python
import json
with open('Diamond.json') as f:
    data = json.load(f)
abi = data['abi']
funcs = [x for x in abi if isinstance(x, dict) and x.get('type') == 'function']
print(f"Total functions: {len(funcs)}")
for f in sorted(funcs, key=lambda x: x.get('name','')):
    inputs = ', '.join([i['type'] + ' ' + i.get('name','') for i in f.get('inputs',[])])
    print(f"{f['name']}({inputs})")
```

### 3. Identify Permissionless Functions
Key functions to check access control on:
- `triggerOrder` / `triggerOrderWithSignatures` — order execution (usually oracle-restricted)
- `cancelOrderAfterTimeout` — anyone can cancel expired orders (griefing)
- `multicall` — batch arbitrary encoded calls (reentrancy vector)
- `delegatedTradingAction` — execute on behalf of user (delegation abuse)
- `liquidate` / `closeTrade` — position closure
- `sellGnsForCollateral` / OTC functions — token swaps
- `withdrawPositivePnl` — partial PnL withdrawal while trade open

### 4. Probe On-Chain State
```bash
# Trading state (0=active, 1=close-only, 2=paused)
cast call <diamond> "getTradingActivated()(uint8)" --rpc-url <rpc>

# Oracle addresses (who can trigger orders)
cast call <diamond> "getOracles()(address[])" --rpc-url <rpc>

# Reentrancy lock state
cast call <diamond> "getReentrancyLock()(uint256)" --rpc-url <rpc>

# Collateral info
cast call <diamond> "getCollaterals()" --rpc-url <rpc>

# Price feeds
cast call <diamond> "getCollateralUsdPriceFeed(uint8)(address)" <index> --rpc-url <rpc>

# Liquidation params
cast call <diamond> "getGroupLiquidationParams(uint256)((uint40,uint40,uint40,uint24,uint24))" <group> --rpc-url <rpc>
```

## Attack Vectors (Diamond-Specific)

### 1. Storage Collision Between Facets
Diamond pattern uses `bytes32` storage slots. If two facets accidentally use the same slot, writes from one corrupt the other. Check:
- Do facets use AppStorage pattern (single struct) or DiamondStorage (namespaced)?
- Are there any facets added after initial deployment that might conflict?

### 2. Cross-Facet Reentrancy via multicall
`multicall(bytes[] data)` executes multiple encoded function calls in sequence. If:
- Reentrancy guard is checked per-call but not across the batch
- State is partially updated between calls
Then an attacker can exploit intermediate states.

### 3. Facet Selector Collision
`bytes4` function selectors can collide. If `diamondCut` adds a facet with a colliding selector, it overwrites the original function routing. Check:
- Are there any selector collisions in the current facet set?
- Can governance add a facet that shadows a critical function?

### 4. delegatedTradingAction Abuse
If a user sets a delegate, the delegate can execute ANY trading action. Check:
- Can delegate set their own delegate (chain delegation)?
- Is there a time-lock on delegation changes?
- Can delegate withdraw funds or only trade?
- What happens if delegate opens max-leverage position then removes delegation?

### 5. Callback Manipulation
Diamond perps use callbacks (e.g., `openTradeMarketCallback`, `closeTrade`). These are called by oracles after price is fetched. Check:
- Can the callback be called directly by anyone?
- Is there validation that the callback corresponds to a real pending order?
- What happens if the oracle returns during a multicall?

## Precision Patterns (gTrade-specific, applies to similar protocols)

| Parameter | Precision | Example |
|-----------|-----------|---------|
| Price | 1e10 | BTC $100,000 = 1000000000000000 |
| Leverage | 1e3 | 150x = 150000 |
| Slippage | 1e3 | 1% = 1000 |
| Fee % | 1e10 | 0.08% = 8000000 |
| Collateral | token decimals | DAI=1e18, USDC=1e6 |

SDK uses `Math.floor()` for all conversions — truncation always favors the user (rounds down fees, rounds down prices for longs). Check if cumulative truncation across many operations can be exploited.

## Source Code Retrieval (Verified Contracts)

Priority order for getting verified Solidity source:
1. **Protocol's GitHub** — check org repos for contracts/ directory (often private for perp DEXes)
2. **SDK ABI** — `sdk/abi/ContractName.json` has full ABI (enough for attack surface mapping)
3. **Blockscout API** — BEST for full source when GitHub is private:
   ```bash
   curl -s "https://arbitrum.blockscout.com/api/v2/smart-contracts/{address}" | python3 -c "
   import json, sys, os
   d = json.load(sys.stdin)
   print(f'Name: {d.get(\"name\")}')
   src = d.get('source_code', '')
   # Save main source
   with open(f'{d.get(\"name\",\"contract\")}.sol', 'w') as f: f.write(src)
   # Save all imports (additional_sources)
   for a in d.get('additional_sources', []):
       path = a.get('file_path','')
       if path:
           os.makedirs(os.path.dirname(f'src/{path}'), exist_ok=True)
           with open(f'src/{path}', 'w') as f: f.write(a.get('source_code',''))
   print(f'Saved {len(d.get(\"additional_sources\",[]))} source files')
   "
   ```
4. **Sourcify** — `https://repo.sourcify.dev/contracts/full_match/{chainId}/{address}/` (often empty for newer contracts)
5. **Etherscan/Arbiscan V2** — requires API key: `https://api.etherscan.io/v2/api?chainid={chainId}&module=contract&action=getsourcecode&address={addr}&apikey={key}`

**Note:** Arbiscan V1 API is deprecated (returns "switch to V2" error). Blockscout is the most reliable free option for Arbitrum contracts as of 2026.

## Backend Discovery Pattern (Multi-Service DeFi)

Mature DeFi protocols often have multiple backend services beyond chain-specific APIs:
```
backend-{chain}.gains.trade     — per-chain trading state (Express.js)
backend-global.gains.trade      — cross-chain: contests, leaderboard, dapp config, trading history
backend-pricing.eu.gains.trade  — price charts, 24h-ago prices (regional)
news-forex.gains.trade          — market news feed
wrkr.gains.trade                — analytics/event worker
```

Discovery method: intercept frontend network requests via browser console:
```javascript
performance.getEntriesByType('resource')
  .filter(r => r.name.includes('backend') || r.name.includes('api') || r.name.includes('price'))
  .map(r => ({url: r.name, type: r.initiatorType}))
```

Key endpoints to probe on `backend-global`:
- `/health` — service info (DB type, uptime)
- `/api/dapp/latest/evm` — IPFS CID of current frontend deployment
- `/api/contests` — active trading contests (prize pools, leaderboards)
- `/api/leaderboard?chainId=42161` — trader rankings with addresses + PnL
- `/api/trading-history/24h?chainId=42161` — recent trades (addresses, pairs, actions)

## Gains Network Architecture (for reference)

- Diamond: 14 facets, 400 functions
- Chains: Arbitrum (primary), Polygon, Base, Apechain
- Collaterals: DAI, ETH, USDC, GNS
- Oracle: Chainlink DON (5 registered oracles, min 3 answers, 1h TWAP)
- Backend APIs: `backend-{chain}.gains.trade` (Express.js, read-only)
- RPC proxy: `rpc.gains.trade` (Arbitrum, standard methods only)
- Trading SDK: `@gainsnetwork/sdk`, `trading-sdk` (TypeScript)
- Key addresses (Arbitrum):
  - Diamond: 0xFF162c694eAA571f685030649814282eA457f169
  - gToken DAI: 0xd85E038593d7A098614721EaE955EC2022B9B91B
  - gToken USDC: 0xd3443ee1e91aF28e5FB858Fbd0D72A63bA8046E0
  - Chainlink LINK: 0xf97f4df75117a78c1A5a0DBb814Af92458539FB4
