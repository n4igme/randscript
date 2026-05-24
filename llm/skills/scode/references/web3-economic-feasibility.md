# Web3 Economic Feasibility Analysis

How to determine if a vulnerability is profitably exploitable. Immunefi requires demonstrating actual fund loss — this guide helps you calculate whether an attack is economically viable before spending hours on a PoC.

---

## 1. Flash Loan Provider Comparison

| Provider | Fee | Max Amount | Chains | Best For |
|----------|-----|-----------|--------|----------|
| Balancer | 0% | Pool liquidity | ETH, Arb, Poly, Base | Always try first (free) |
| Aave V3 | 0.05% | Pool liquidity | ETH, Arb, Opt, Poly, Base, Avax | Large USDC/WETH amounts |
| Aave V2 | 0.09% | Pool liquidity | ETH, Poly, Avax | Legacy pools |
| Uniswap V3 | Pool fee tier (0.01-1%) | Pool liquidity | ETH, Arb, Opt, Poly, Base, BSC | Token pairs not on Aave/Balancer |
| dYdX | 0% | Pool liquidity | ETH (L1 only) | WETH/USDC/DAI on mainnet |
| Maker (DAI) | 0% | Debt ceiling | ETH | Large DAI amounts |

### Checking Available Liquidity

```bash
# Aave V3 — check available liquidity for USDC
cast call 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2   "getReserveData(address)(uint256,uint128,uint128,uint128,uint128,uint128,uint40,uint16,address,address,address,address,uint128,uint128,uint128)"   0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 --rpc-url $RPC

# Balancer — check pool token balance
cast call 0xBA12222222228d8Ba445958a75a0704d566BF2C8   "getPoolTokenInfo(bytes32,address)(uint256,uint256,uint256,address)"   $POOL_ID $TOKEN --rpc-url $RPC

# Quick check: just read token balance of the lending pool
cast call $TOKEN "balanceOf(address)(uint256)" $POOL_ADDRESS --rpc-url $RPC
```

### Flash Loan Fee Calculation

```
Profit must exceed:
  flash_loan_fee + gas_cost + slippage_cost

Example (Aave V3, 1M USDC):
  Fee: 1,000,000 * 0.0005 = $500
  Gas: ~500K gas * 30 gwei * $3000/ETH = ~$45
  Slippage: depends on swap size vs pool depth

  Minimum profit needed: ~$550 (to be worth reporting as viable)
  
Example (Balancer, 1M USDC):
  Fee: $0
  Gas: ~500K gas * 30 gwei * $3000/ETH = ~$45
  
  Minimum profit needed: ~$50
```

---

## 2. AMM Price Manipulation Math

### Uniswap V2 (Constant Product: x * y = k)

```
To move price by factor F:
  Capital needed = sqrt(F) * reserve_of_input_token - reserve_of_input_token

Example: Move ETH/USDC price 2x (double ETH price)
  Pool: 1000 ETH + 3,000,000 USDC (k = 3,000,000,000)
  Need to buy ETH with USDC:
  New USDC reserve = 3,000,000 * sqrt(2) = 4,242,640 USDC
  Capital needed: 4,242,640 - 3,000,000 = $1,242,640 USDC
  
  You receive: 1000 - 1000/sqrt(2) = 293 ETH
  Slippage cost: 1,242,640 - (293 * 3000) = ~$363,640 in slippage
```

### Uniswap V3 (Concentrated Liquidity)

Harder to calculate — liquidity is concentrated in tick ranges.

```
# Check current liquidity at active tick
cast call $POOL "liquidity()(uint128)" --rpc-url $RPC

# Check tick spacing and current tick
cast call $POOL "slot0()(uint160,int24,uint16,uint16,uint16,uint8,bool)" --rpc-url $RPC

# Rough estimate: if liquidity L at current tick, to move price by 1 tick:
# amount0 = L * (1/sqrt(price_lower) - 1/sqrt(price_upper))
# amount1 = L * (sqrt(price_upper) - sqrt(price_lower))
```

**Rule of thumb for V3:** Check the pool's TVL on Uniswap info. If TVL < 10x your required price movement capital, manipulation is feasible.

### Curve (StableSwap)

Curve pools resist price manipulation much better than Uniswap for stablecoins (amplification factor A).

```
Manipulation cost ≈ A * imbalance_amount

Example: Curve 3pool (A=2000, TVL=$500M)
  To move DAI/USDC price by 1%: need ~$5M-10M capital
  To move by 5%: need ~$50M+ capital
  
  Generally NOT feasible for large Curve pools via flash loan alone.
  Exception: small Curve pools (TVL < $5M) or pools with low A factor.
```

### Quick Feasibility Check

```
Is oracle manipulation profitable?

1. Check oracle source:
   - Uniswap V2 spot price → likely manipulable
   - Uniswap V3 TWAP (30 min) → NOT manipulable in single tx
   - Chainlink → NOT manipulable (off-chain)
   - Curve get_virtual_price() → manipulable during callback only (read-only reentrancy)

2. Check pool depth:
   cast call $POOL "getReserves()(uint112,uint112,uint32)" --rpc-url $RPC
   
3. Calculate capital needed (see formulas above)

4. Compare to available flash loan liquidity:
   If capital_needed < balancer_liquidity → feasible (free flash loan)
   If capital_needed < aave_liquidity → feasible (0.05% fee)
   If capital_needed > all_flash_loan_sources → NOT feasible in single tx
```

---

## 3. Profitability Framework

### Attack Profit Formula

```
Net Profit = Extracted Value - (Flash Loan Fee + Gas Cost + Slippage Loss)

Where:
  Extracted Value = what you drain from the vulnerable protocol
  Flash Loan Fee = borrowed_amount * fee_rate
  Gas Cost = gas_used * gas_price * ETH_price
  Slippage Loss = value lost to AMM price impact during swaps
```

### Gas Cost Estimation by Chain

| Chain | Typical Gas Price | Cost for 500K gas | Cost for 2M gas |
|-------|------------------|-------------------|-----------------|
| Ethereum | 20-50 gwei | $30-75 | $120-300 |
| Arbitrum | 0.1-0.5 gwei | $0.15-0.75 | $0.60-3.00 |
| Optimism | 0.01-0.05 gwei + L1 fee | $0.50-2.00 | $2.00-8.00 |
| Base | 0.01-0.05 gwei + L1 fee | $0.30-1.50 | $1.20-6.00 |
| Polygon | 30-100 gwei | $0.02-0.05 | $0.06-0.20 |
| BSC | 3-5 gwei | $0.50-0.80 | $2.00-3.20 |

```bash
# Check current gas price
cast gas-price --rpc-url $RPC

# Estimate gas for your exploit
forge test --match-test testExploit --gas-report --fork-url $RPC
```

### Minimum Viable Exploit Thresholds

```
For Immunefi reporting (you don't need to actually execute):
  - Demonstrate profit > gas cost (even $1 profit counts as Critical if it drains funds)
  - Show it's repeatable if single-instance profit is small
  - Flash loan availability proves capital isn't a barrier

For actual execution (if you were a black hat):
  - Ethereum: profit > $500 (gas is expensive)
  - L2s: profit > $10 (gas is cheap)
  - Must account for MEV competition (others may front-run your exploit tx)
```

---

## 4. Common Economic Attack Patterns

### Pattern 1: Flash Loan → Oracle Manipulation → Overborrow

```
Profit = Overborrowed Amount - Collateral Deposited - Flash Loan Fee

Steps:
1. Flash loan X tokens (cost: X * fee_rate)
2. Swap X to crash oracle price (slippage: S)
3. Deposit collateral at inflated value
4. Borrow more than collateral is worth
5. Swap back to restore price (slippage: S)
6. Repay flash loan

Profit = Borrowed - Collateral - 2*S - Fee
Feasible when: pool_depth is low relative to protocol TVL
```

### Pattern 2: Vault Inflation (First Depositor)

```
Profit = Victim's Deposit - Attacker's Initial Cost

Steps:
1. Deposit 1 wei (get 1 share) — cost: negligible
2. Donate D tokens directly to vault — cost: D
3. Victim deposits V tokens, gets 0 shares (rounded down)
4. Attacker redeems 1 share for (1 + D + V) tokens

Profit = V - D (attacker spends D to steal V)
Feasible when: V > D (victim deposits more than attacker donates)
Constraint: D must be large enough that V/(D+1) rounds to 0

Minimum donation: D > V (to ensure V/(D+1) < 1)
So profit = V - D is actually NEGATIVE for single victim.

Real attack: attacker front-runs MANY victims:
  Total profit = sum(all_victim_deposits) - D
  Feasible when: expected_deposits > D within the front-running window
```

### Pattern 3: Sandwich / Price Manipulation

```
Profit = Price Impact on Victim * Attacker's Position Size

Steps:
1. Buy token (push price up) — cost: slippage_1
2. Victim buys at inflated price — victim overpays
3. Sell token (push price down) — receive: original + victim's overpay - slippage_2

Profit = victim_overpay - slippage_1 - slippage_2 - gas
Feasible when: victim's trade is large relative to pool liquidity
```

### Pattern 4: Governance Flash Loan

```
Profit = Treasury Value (if proposal passes)

Steps:
1. Flash loan governance tokens (cost: fee or 0 on Balancer)
2. Create + vote on malicious proposal in same tx
3. If no timelock: execute immediately
4. If timelock: this attack fails (need to hold tokens across blocks)

Feasible when:
  - Governance token is flash-loanable (on Aave/Balancer/Uniswap)
  - No snapshot delay (voting power checked at proposal time, not prior block)
  - No timelock on execution (or timelock < flash loan duration — impossible)
  
Usually feasible only for: propose + vote in same tx with immediate execution
```

### Pattern 5: Read-Only Reentrancy (LP Token Mispricing)

```
Profit = Overborrowed Amount (using inflated LP token value as collateral)

Steps:
1. Enter Balancer/Curve pool callback (during join/exit)
2. During callback, LP token's getRate() returns stale/manipulated value
3. Use LP token as collateral in lending protocol that calls getRate()
4. Borrow more than LP token is actually worth
5. Callback completes, LP token price normalizes
6. Attacker keeps overborrowed amount

Feasible when:
  - Lending protocol uses getRate()/get_virtual_price() without reentrancy check
  - Attacker can trigger a callback from Balancer/Curve (join/exit with ETH or ERC-777)
  - Borrowed amount > gas + any fees
```

---

## 5. Feasibility Decision Tree

```
Found a potential vulnerability?
│
├─ Does it require capital? (flash loan, large swap)
│  ├─ YES → Is capital available via flash loan?
│  │  ├─ YES (Balancer/Aave has enough) → FEASIBLE, continue
│  │  └─ NO (need more than all flash loan sources) → LIKELY NOT FEASIBLE
│  │     └─ Exception: multi-block attack (MEV builder, not single-tx)
│  └─ NO (just a function call) → FEASIBLE, continue
│
├─ Does it require price manipulation?
│  ├─ YES → What's the oracle?
│  │  ├─ Uniswap V2 spot → Check pool depth vs needed movement
│  │  ├─ Uniswap V3 TWAP → How many blocks? (>1 block = NOT feasible in single tx)
│  │  ├─ Chainlink → NOT manipulable (report as "stale price" only if heartbeat issue)
│  │  ├─ Curve spot → Check pool size and A factor
│  │  └─ Custom/in-house → Analyze the specific mechanism
│  └─ NO → FEASIBLE, continue
│
├─ Is profit > costs?
│  ├─ Calculate: extracted_value - flash_fee - gas - slippage
│  ├─ Profit > 0 → VIABLE for Immunefi report
│  ├─ Profit < 0 but repeatable → Calculate cumulative profit over N iterations
│  └─ Profit < 0 and not repeatable → NOT VIABLE (downgrade severity)
│
└─ Can it be front-run / MEV-protected?
   ├─ Protocol uses private mempool / Flashbots Protect → harder to execute
   ├─ Protocol has no MEV protection → fully exploitable
   └─ Note: for Immunefi, MEV protection doesn't reduce severity
     (the bug exists regardless of execution difficulty)
```

---

## 6. Useful Cast Commands for Feasibility

```bash
# Check token balance of a pool/vault (how much can be drained)
cast call $TOKEN "balanceOf(address)(uint256)" $TARGET --rpc-url $RPC | cast from-wei

# Check total supply of shares (for inflation attacks)
cast call $VAULT "totalSupply()(uint256)" --rpc-url $RPC

# Check oracle price
cast call $ORACLE "latestRoundData()(uint80,int256,uint256,uint256,uint80)" --rpc-url $RPC

# Check Uniswap V2 reserves
cast call $PAIR "getReserves()(uint112,uint112,uint32)" --rpc-url $RPC

# Check if address is a proxy (look for implementation slot)
cast storage $CONTRACT 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url $RPC

# Get current block number (for fork pinning)
cast block-number --rpc-url $RPC

# Decode transaction calldata (understand what a tx does)
cast 4byte-decode $CALLDATA

# Check contract code size (0 = EOA or not deployed)
cast codesize $ADDRESS --rpc-url $RPC
```

---

## 7. "Is This Worth My Time?" Quick Assessment

Before spending hours on a PoC, answer these:

| Question | If YES | If NO |
|----------|--------|-------|
| Is the protocol's TVL > $1M? | Worth investigating | Skip (payout will be tiny) |
| Is the bounty max > $10K? | Worth investigating | Skip unless trivial to prove |
| Can I get a flash loan for the required capital? | Attack is feasible | Need multi-block or whale — harder |
| Does the oracle use spot price? | Manipulation likely feasible | Need different attack vector |
| Is the vulnerable function externally callable? | Direct exploit | Need to find a path to trigger it |
| Has the protocol been audited recently? | Bug may be subtle/novel | Low-hanging fruit may exist |
| Is the code < 6 months old? | Higher chance of bugs | More eyes have reviewed it |

### Time Budget per Target

```
Recon (scope, contracts, TVL):     30 min
Initial code review:                2-4 hours
Deep dive on promising lead:        4-8 hours
PoC development:                    2-6 hours
Report writing:                     1-2 hours

Total per target: 1-2 days
If no promising leads after 4 hours of review: MOVE ON
```
