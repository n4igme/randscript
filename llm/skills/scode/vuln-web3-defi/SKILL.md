---
name: vuln-web3-defi
description: "Step 3q of bug bounty workflow. Scan for DeFi protocol vulnerabilities (AMM, lending, bridges, governance). Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Step 3q: DeFi Protocol Vulnerabilities

Scan for vulnerabilities specific to DeFi protocols — AMMs, lending, bridges, yield farming, and governance.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Applicability

This scanner applies when the codebase contains DeFi protocol logic:
- AMM / DEX contracts (swap, liquidity provision)
- Lending / borrowing protocols
- Yield aggregators / vaults
- Cross-chain bridges
- Governance / DAO contracts
- Staking / reward distribution

If none present, report "No DeFi protocol logic found — scanner not applicable" and skip.

## Vulnerability Patterns

### AMM / DEX Exploits
- Constant product invariant violations after fee/tax token interactions
- Virtual reserve manipulation via donation attacks
- LP token inflation (first depositor attack — minting shares for dust)
- Imbalanced pool draining via calculated swap sequences
- Missing slippage protection on liquidity add/remove
- Sandwich-able operations without deadline or minimum output

**Grep patterns**: `getReserves`, `swap(`, `addLiquidity`, `removeLiquidity`, `mint(`, `burn(`, `k =`, `reserve0`, `reserve1`, `totalSupply`, `balanceOf(address(this))`, `sync(`, `skim(`

### Lending Protocol Flaws
- Bad debt accumulation (underwater positions not liquidatable)
- Liquidation threshold manipulation via oracle lag
- Interest rate model exploits (utilization rate manipulation)
- Collateral factor misconfiguration allowing undercollateralized borrows
- Flash loan → deposit → borrow → withdraw in single tx
- Share/exchange rate manipulation in vault-style lending (ERC-4626)

**Grep patterns**: `borrow(`, `repay(`, `liquidate(`, `collateral`, `healthFactor`, `exchangeRate`, `utilizationRate`, `accrueInterest`, `totalBorrows`, `totalReserves`, `supplyRate`, `borrowRate`

### Cross-Chain Bridge Attacks
- Message replay across chains (missing source chain ID in hash)
- Validator/relayer collusion (insufficient threshold)
- Deposit credited before finality confirmation
- Withdrawal proof forgery (weak Merkle verification)
- Token mapping mismatch (bridging to wrong token on destination)
- Stuck funds from failed cross-chain messages without recovery

**Grep patterns**: `bridge`, `relay`, `messenger`, `crossChain`, `sourceChain`, `destChain`, `nonce`, `merkleProof`, `verifyProof`, `finality`, `confirmations`, `lock(`, `unlock(`, `mint(`, `burn(`

### Governance Exploits
- Flash loan → acquire voting power → vote → repay in single block
- Proposal injection (creating malicious proposals with low quorum)
- Voting power snapshot manipulation (acquire before snapshot, dump after)
- Timelock bypass or insufficient delay
- Delegated voting abuse (delegate → vote → undelegate)
- Quorum manipulation via token supply changes

**Grep patterns**: `propose(`, `vote(`, `execute(`, `queue(`, `timelock`, `quorum`, `votingPower`, `delegate(`, `getPriorVotes`, `snapshot`, `proposalThreshold`, `GovernorBravo`, `GovernorAlpha`

### Yield Farming / Reward Exploits
- Reward calculation rounding errors (dust accumulation or loss)
- Reward rate manipulation via deposit/withdraw timing
- Compounding exploits (claim → deposit → claim in same block)
- Reward token drain via inflated share calculation
- Missing reward checkpoint on transfer (rewards lost or double-claimed)

**Grep patterns**: `rewardPerToken`, `earned(`, `stake(`, `withdraw(`, `getReward`, `notifyRewardAmount`, `rewardRate`, `periodFinish`, `accRewardPerShare`, `pendingReward`, `harvest(`

### Staking / Slashing
- Slashing conditions that can be triggered by attacker
- Unstaking without proper cooldown enforcement
- Validator set manipulation via stake/unstake timing
- Reward dilution attacks (stake large → claim → unstake)

**Grep patterns**: `stake(`, `unstake(`, `slash(`, `cooldown`, `unbonding`, `validator`, `delegation`, `epoch`, `checkpoint`

## Process

1. **Identify protocol type** — AMM, lending, bridge, governance, yield, or hybrid
2. **Map economic flows** — deposits, withdrawals, swaps, borrows, liquidations, rewards
3. **Check invariants** — are protocol invariants maintained across all operations?
4. **Analyze oracle dependencies** — what happens if oracle returns stale/manipulated data?
5. **Test economic attacks** — flash loan sequences, sandwich, first-depositor
6. **Check governance safety** — timelocks, quorum, snapshot timing
7. **Assess impact** — protocol insolvency, fund theft, governance takeover

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — DeFi Protocol

**Date**: {date}
**Scanner**: vuln-web3-defi

## Findings

### VULN-DEFI-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {AMM / Lending / Bridge / Governance / Yield / Staking}
**Location**: `{file}:{line}`
**CWE**: CWE-{841|682|362|284}

**Description**:
{What the vulnerability is}

**Vulnerable Code**:
```solidity
{code snippet}
`` `

**Economic Attack Sequence**:
1. {Step-by-step: flash loan → manipulate → exploit → profit}

**Proof of Concept**:
```solidity
{Exploit contract}
`` `

**Profit Calculation**:
{Estimated attacker profit vs cost (gas + flash loan fees)}

**Impact**:
{Protocol insolvency, LP fund theft, governance takeover}

**Remediation**:
```solidity
{fixed code}
`` `

---
```

## Rules

- **Show the full economic attack** — borrow → manipulate → exploit → repay with profit calculation.
- **Check for existing DeFi protections** — timelocks, minimum deposit amounts, oracle TWAP, pause mechanisms.
- **Consider multi-block attacks** — not everything happens in one transaction.
- **Verify economic feasibility** — is the attack profitable after gas + flash loan fees?
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — DeFi Protocol` section, replace it entirely. See `sc3-vuln-scan` idempotency rule.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
