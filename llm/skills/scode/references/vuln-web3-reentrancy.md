# Bug Bounty — Step 3n: Reentrancy & Unchecked External Calls

Scan for unsafe external call patterns — reentrancy attacks and unchecked call return values.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Vulnerability Patterns

### Classic Reentrancy
- External calls before state updates (checks-effects-interactions violation)
- ETH transfer via `.call{value:}` before balance deduction
- Token transfer before internal accounting update

**Grep patterns**: `.call{value:`, `.call{`, `withdraw`, `balances[`, `msg.sender.call`, `payable(msg.sender)`

### Cross-Function Reentrancy
- Shared state modified by multiple functions, one callable during callback
- Function A calls external contract, function B reads stale state during callback
- Mutex not applied across all functions sharing state

**Grep patterns**: `nonReentrant`, `ReentrancyGuard`, `_status`, `locked`, `modifier`

### Cross-Contract Reentrancy
- Contract A calls Contract B, which calls back into Contract A via Contract C
- Shared state across multiple contracts not protected by single mutex
- Composability exploits in multi-contract protocols

**Grep patterns**: `interface`, `external`, `IPool`, `IVault`, `callback`, `hook`, `onFlashLoan`, `uniswapV3SwapCallback`

### Read-Only Reentrancy
- View functions returning stale state during external call execution
- Price/share calculations based on mid-transaction balances
- Other protocols reading manipulated state during callback

**Grep patterns**: `view`, `getPrice`, `getRate`, `exchangeRate`, `totalAssets`, `convertToShares`, `convertToAssets`, `balanceOf(address(this))`

### Unchecked External Calls
- Low-level `.call()` without checking `bool success` return
- `.send()` return value ignored (fails silently on 2300 gas)
- Token `transfer()`/`transferFrom()` on non-reverting ERC-20s (returns false)
- Missing `safeTransfer`/`safeTransferFrom` wrapper

**Grep patterns**: `.call(`, `.send(`, `(bool success`, `require(success`, `safeTransfer`, `SafeERC20`, `IERC20(`, `.transfer(`

### Delegatecall Injection
- `delegatecall` to user-controlled address
- Implementation contract with unprotected `delegatecall`
- `delegatecall` in loop to untrusted targets

**Grep patterns**: `.delegatecall(`, `delegatecall`, `implementation`, `_delegate(`, `fallback()`

## Process

1. **Find all external calls** — `.call`, `.send`, `.transfer`, `delegatecall`, token transfers
2. **Check CEI pattern** — are state changes made BEFORE the external call?
3. **Check return values** — is every call's success/failure handled?
4. **Check reentrancy guards** — is `nonReentrant` applied to all state-changing functions with external calls?
5. **Trace cross-contract flows** — can a callback reach stale state in this or another contract?
6. **Assess impact** — fund drainage, double-spend, state corruption

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Reentrancy & Unchecked Calls

**Date**: {date}
**Scanner**: vuln-web3-reentrancy

## Findings

### VULN-REENT-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Classic Reentrancy / Cross-Function / Cross-Contract / Read-Only / Unchecked Call / Delegatecall}
**Location**: `{file}:{line}`
**CWE**: CWE-{841|252}

**Description**:
{What the vulnerability is}

**Vulnerable Code**:
```solidity
{code snippet showing CEI violation or unchecked call}
`` `

**Attack Scenario**:
1. {Step-by-step: attacker contract calls → callback → re-enters → drains}

**Proof of Concept**:
```solidity
{Attacker contract}
`` `

**Impact**:
{Fund drainage amount, state corruption}

**Remediation**:
```solidity
{Fixed code with CEI pattern or ReentrancyGuard}
`` `

---
```

## Rules

- **Verify the reentrancy is exploitable** — a callback must exist AND state must be stale at that point.
- **Check for ReentrancyGuard** — if applied correctly, the issue is mitigated.
- **For unchecked calls, confirm the token is non-reverting** — standard OZ ERC-20 reverts on failure.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — Reentrancy & Unchecked Calls` section, replace it entirely. See `sc3-vuln-scan` idempotency rule.
- **Save to `./assessment/vulnerabilities.md`** and confirm.