# Bug Bounty — Step 3n: Front-Running/MEV & Flash Loan/Oracle Manipulation

Scan for transaction ordering exploits and economic manipulation via flash loans and oracle attacks.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Vulnerability Patterns

### Front-Running (Transaction Ordering)
- Commit-reveal not used for sensitive operations (auctions, liquidations)
- Predictable outcomes visible in mempool before execution
- First-come-first-served logic exploitable by gas bidding
- NFT mint/claim without commit-reveal or VRF

**Grep patterns**: `commit`, `reveal`, `hash`, `secret`, `deadline`, `block.timestamp`, `block.number`

### Sandwich Attacks
- Swap operations without minimum output enforcement
- Missing or user-bypassable slippage protection
- No deadline parameter on DEX interactions
- Large state-changing operations observable in mempool

**Grep patterns**: `amountOutMin`, `slippage`, `deadline`, `block.timestamp + `, `swap(`, `swapExact`, `getAmountsOut`

### Back-Running / Liquidation MEV
- Liquidation functions callable by anyone (MEV bots front-run)
- Arbitrage opportunities created by protocol state changes
- Reward claiming without protection against back-running

**Grep patterns**: `liquidate(`, `liquidatePosition`, `harvest(`, `claim(`, `getReward(`, `arbitrage`

### Flash Loan Attacks
- State-changing functions exploitable within a single transaction
- Price/balance checks that can be manipulated atomically
- Governance voting without snapshot delay (flash loan → vote → repay)
- Collateral deposit + borrow in same transaction without cooldown

**Grep patterns**: `flashLoan`, `flash(`, `onFlashLoan`, `executeOperation`, `IERC3156`, `balanceOf(address(this))`, `totalSupply()`

### Oracle Manipulation
- Spot price from single DEX pool (manipulable via large swap)
- `balanceOf(address(pool))` as price source
- Missing TWAP (time-weighted average price)
- Stale oracle data accepted (no freshness check)
- Single oracle source without fallback

**Grep patterns**: `getReserves`, `latestRoundData`, `latestAnswer`, `updatedAt`, `staleness`, `twap`, `TWAP`, `oracle`, `priceFeed`, `Chainlink`, `answeredInRound`

### Oracle Stale Data
- Chainlink `latestRoundData` without checking `updatedAt` timestamp
- Missing `answeredInRound >= roundId` validation
- No fallback when oracle returns zero or reverts
- Heartbeat interval not enforced

**Grep patterns**: `latestRoundData()`, `(,int256 price,,,)`, `updatedAt`, `heartbeat`, `sequencerUptimeFeed`, `require(price > 0`

### Multi-Block MEV
- State that can be manipulated across multiple blocks
- Time-delayed operations where attacker controls intermediate state
- Validator/proposer extractable value in PoS

**Grep patterns**: `block.number`, `block.timestamp`, `lastUpdate`, `cooldown`, `delay`, `timelock`

## Process

1. **Identify MEV-sensitive operations** — swaps, liquidations, auctions, mints, governance votes
2. **Check slippage/deadline** — are user-facing swap operations protected?
3. **Audit oracle usage** — is price from TWAP or spot? Is freshness validated?
4. **Test flash loan vectors** — can any state be manipulated and exploited atomically?
5. **Check commit-reveal** — are outcomes predictable from mempool observation?
6. **Check permissionless triggers (FORCE MULTIPLIER)** — can the attacker call the vulnerable function themselves?
   - `harvest()`, `liquidate()`, `claim()` without access modifiers = attacker controls timing
   - This upgrades severity: a sandwich attack on a keeper-only function is Medium (requires timing luck), but on a permissionless function is High (attacker triggers at will)
   - Grep: look for `external` or `public` functions with NO `onlyOwner`, `onlyKeeper`, `onlyManager`, `onlyRole` modifier
7. **Assess profitability** — is the MEV extraction profitable after gas + flash loan fees?

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — MEV & Oracle Manipulation

**Date**: {date}
**Scanner**: vuln-web3-mev

## Findings

### VULN-MEV-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Front-Running / Sandwich / Flash Loan / Oracle Manipulation / Stale Oracle / Multi-Block}
**Location**: `{file}:{line}`
**CWE**: CWE-{362|841|682}

**Description**:
{What the vulnerability is}

**Vulnerable Code**:
```solidity
{code snippet}
`` `

**Attack Sequence**:
1. {Flash loan borrow / mempool observation}
2. {Manipulation step}
3. {Exploit step}
4. {Repay / profit extraction}

**Proof of Concept**:
```solidity
{Exploit contract showing atomic attack}
`` `

**Profit Calculation**:
{Estimated profit = extracted value - gas - flash loan fee}

**Impact**:
{User fund loss, protocol drain, unfair extraction}

**Remediation**:
```solidity
{Fixed code — TWAP, commit-reveal, slippage enforcement, cooldown}
`` `

---
```

## Rules

- **Show the full economic attack sequence** — especially for flash loan attacks.
- **Verify oracle manipulation is feasible** — how much capital is needed to move the price?
- **Check for existing MEV protections** — private mempools, Flashbots, commit-reveal, TWAP.
- **Distinguish user-configurable slippage from missing slippage** — user setting 100% slippage is their choice.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — MEV & Oracle Manipulation` section, replace it entirely. See `sc3-vuln-scan` idempotency rule.
- **Save to `./assessment/vulnerabilities.md`** and confirm.