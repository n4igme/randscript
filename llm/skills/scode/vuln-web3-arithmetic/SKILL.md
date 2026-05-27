# Bug Bounty — Step 3n: Integer Overflow/Underflow & Precision Loss

Scan for numeric safety issues — overflow, underflow, truncation, and precision loss in arithmetic operations.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Vulnerability Patterns

### Integer Overflow (Solidity < 0.8)
- Arithmetic without SafeMath wrapping
- Addition/multiplication exceeding `type(uint256).max`
- Token balance manipulation via overflow

**Grep patterns**: `SafeMath`, `pragma solidity 0.7`, `pragma solidity 0.6`, `pragma solidity 0.5`, `pragma solidity 0.4`, `.add(`, `.sub(`, `.mul(`, `.div(`

### Unchecked Arithmetic (Solidity >= 0.8)
- `unchecked { }` blocks with user-influenced values
- Gas optimization unchecked blocks that skip safety checks on external input
- Loop counters in unchecked blocks with user-controlled bounds

**Grep patterns**: `unchecked {`, `unchecked{`

### Type Casting Truncation
- Downcasting `uint256` → `uint128`/`uint96`/`uint64`/`uint32`/`uint8` without range check
- Signed to unsigned conversion (negative becomes large positive)
- `SafeCast` not used on user-influenced values
- Implicit narrowing in struct packing

**Grep patterns**: `uint8(`, `uint16(`, `uint32(`, `uint64(`, `uint96(`, `uint128(`, `int256(`, `int128(`, `SafeCast`, `toUint128`, `toUint96`

### Precision Loss (Rounding Errors)
- Division before multiplication (truncates intermediate result)
- Integer division rounding exploited over many transactions (dust accumulation)
- Fee/reward calculations losing precision on small amounts
- Share price manipulation via rounding direction (ERC-4626)
- Missing `mulDiv` for safe full-precision multiplication

**Grep patterns**: `/ `, `* `, `1e18`, `1e27`, `WAD`, `RAY`, `mulDiv`, `FullMath`, `PRBMath`, `fixedPoint`, `roundUp`, `roundDown`

### Multiplication Overflow Before Division
- `a * b / c` where `a * b` overflows before the division
- Missing intermediate overflow protection
- Should use `mulDiv(a, b, c)` pattern

**Grep patterns**: `* `, `/ `, `mulDiv`, `FullMath.mulDiv`

### ERC-4626 Vault Inflation Attack (First Depositor)
- First depositor mints 1 share, then donates large amount to inflate share price
- Second depositor's deposit rounds down to 0 shares (funds stolen by first depositor)
- Missing minimum deposit or dead shares (virtual offset) protection
- `convertToShares` returning 0 for non-trivial deposit amounts
- Vault with no `_decimalsOffset()` override (OpenZeppelin 4.9+ mitigation)
- Share price manipulation via direct token transfer (donation) to vault

**Grep patterns**: `ERC4626`, `convertToShares`, `convertToAssets`, `totalAssets`, `_decimalsOffset`, `deposit(`, `mint(`, `previewDeposit`, `previewMint`, `virtualAssets`, `virtualShares`, `10 ** _decimalsOffset`

**Checklist:**
1. Is there a minimum first deposit enforced?
2. Does the vault use virtual assets/shares (dead shares pattern)?
3. Can `convertToShares(deposit_amount)` return 0 for reasonable amounts?
4. Is direct token transfer to vault address handled (sync vs donation)?
5. Does `totalAssets()` use internal accounting or `balanceOf(address(this))`?

### Accumulator/Index Overflow
- Reward-per-token accumulators that can overflow over time
- Cumulative price indices (Uniswap-style) without overflow handling
- Block number or timestamp multiplied by rate without bounds

**Grep patterns**: `rewardPerToken`, `cumulativePrice`, `accRewardPerShare`, `index`, `accumulator`, `+= `, `block.timestamp *`

## Process

1. **Check Solidity version** — is it < 0.8 (needs SafeMath) or >= 0.8 (check unchecked blocks)?
2. **Find all arithmetic** — addition, subtraction, multiplication, division on user-influenced values
3. **Check casting** — are downcasts protected by range validation or SafeCast?
4. **Check operation order** — is multiplication done before division?
5. **Analyze rounding** — which direction does rounding favor? Can it be exploited repeatedly?
6. **Assess impact** — fund theft via overflow, slow drain via rounding, broken accounting

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Integer Overflow & Precision Loss

**Date**: {date}
**Scanner**: vuln-web3-arithmetic

## Findings

### VULN-ARITH-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Overflow / Underflow / Truncation / Precision Loss / Rounding}
**Location**: `{file}:{line}`
**CWE**: CWE-{190|191|681|682}

**Description**:
{What the vulnerability is}

**Vulnerable Code**:
```solidity
{code snippet}
`` `

**Attack Scenario**:
1. {Step-by-step: input values that trigger overflow/precision loss}

**Proof of Concept**:
{Specific values that demonstrate the issue}

**Impact**:
{Fund theft, broken accounting, reward drain}

**Remediation**:
```solidity
{Fixed code with SafeCast, mulDiv, or reordered operations}
`` `

---
```

## Rules

- **Check Solidity version first** — overflow in >= 0.8 only matters inside `unchecked` blocks.
- **For precision loss, quantify the impact** — how much is lost per transaction? Is it exploitable at scale?
- **Rounding direction matters** — rounding should favor the protocol, not the user.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — Integer Overflow & Precision Loss` section, replace it entirely. See `sc3-vuln-scan` idempotency rule.
- **Save to `./assessment/vulnerabilities.md`** and confirm.