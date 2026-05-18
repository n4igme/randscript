---
name: vuln-web3-token
description: "Step 3n-v of bug bounty workflow. Scan for token and signature vulnerabilities in smart contracts. Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Step 3n: Token & Signature Vulnerabilities

Scan for ERC-20/721/1155 token implementation flaws and cryptographic signature misuse.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Vulnerability Patterns

### ERC-20 Approval Race Condition
- `approve()` without `increaseAllowance`/`decreaseAllowance`
- Front-runnable approval change (old allowance spent before new one set)
- Missing zero-approval-first pattern

**Grep patterns**: `approve(`, `allowance(`, `increaseAllowance`, `decreaseAllowance`, `_approve(`

### Non-Standard Token Behavior
- Fee-on-transfer tokens (received amount < sent amount)
- Rebasing tokens (balance changes without transfer)
- Tokens with blacklist/pause (transfer can revert unexpectedly)
- Tokens returning `false` instead of reverting on failure
- Tokens with >18 or <18 decimals breaking assumptions

**Grep patterns**: `balanceOf(`, `transfer(`, `transferFrom(`, `decimals()`, `fee`, `tax`, `rebase`, `blacklist`, `pause`

### Infinite Mint
- Unprotected `mint()` function
- Mint amount not validated against cap
- Overflow in mint calculation allowing excessive minting
- Bridge/wrapper mint without proper burn verification

**Grep patterns**: `mint(`, `_mint(`, `totalSupply`, `maxSupply`, `cap(`, `MAX_SUPPLY`

### Token Accounting Errors
- Balance tracking diverging from actual token balance
- Missing balance update on direct token transfer (donation attack)
- `balanceOf(address(this))` used instead of internal accounting
- Transfer hooks (`_beforeTokenTransfer`) modifying expected behavior

**Grep patterns**: `balanceOf(address(this))`, `_balances[`, `_beforeTokenTransfer`, `_afterTokenTransfer`, `ERC777`, `tokensReceived`

### Signature Replay
- Missing nonce in signed messages (same signature valid multiple times)
- Missing `chainId` in EIP-712 domain separator (cross-chain replay)
- Nonce not incremented on successful use
- Signature valid across multiple contracts (missing `address(this)` in hash)

**Grep patterns**: `ecrecover`, `ECDSA.recover`, `nonce`, `nonces[`, `_useNonce`, `DOMAIN_SEPARATOR`, `domainSeparator`, `EIP712`

### Signature Malleability
- `ecrecover` without checking `s` value is in lower half
- Both `(v, r, s)` and `(v', r, s')` accepted for same message
- Missing `v` value validation (only 27 or 28)
- Using raw `ecrecover` instead of OpenZeppelin ECDSA library

**Grep patterns**: `ecrecover(`, `ECDSA`, `v`, `r`, `s`, `0x7FFFFFFF`, `bytes32 s`

### ecrecover Zero Address
- `ecrecover` returns `address(0)` on invalid signature
- Missing `require(recovered != address(0))` check
- Zero address has special meaning in some protocols (burn address with balance)

**Grep patterns**: `ecrecover(`, `require(signer != address(0)`, `address(0)`, `recover(`

### Permit (EIP-2612) Flaws
- Permit deadline not enforced
- Permit nonce not properly tracked per-user
- Permit signature usable after token transfer (follows token, not user)
- Missing permit support detection (griefing on `permit()` revert)

**Grep patterns**: `permit(`, `PERMIT_TYPEHASH`, `nonces`, `deadline`, `EIP2612`, `IERC20Permit`

### ERC-777 / Hooks Abuse
- `tokensReceived` hook enabling reentrancy
- `tokensToSend` hook blocking transfers (DoS)
- ERC-777 backward compatibility issues with ERC-20 assumptions
- Missing ERC-1820 registry check

**Grep patterns**: `ERC777`, `tokensReceived`, `tokensToSend`, `IERC777Recipient`, `IERC777Sender`, `ERC1820`, `_callTokensReceived`

## Process

1. **Identify token standards** — ERC-20, ERC-721, ERC-1155, ERC-777, ERC-4626
2. **Check approval patterns** — is approve race condition mitigated?
3. **Test with non-standard tokens** — does the protocol handle fee-on-transfer, rebasing, or non-reverting tokens?
4. **Audit mint/burn** — are they properly access-controlled and bounded?
5. **Check all signature usage** — nonce, chainId, contract address, malleability, zero-address
6. **Verify permit implementation** — deadline, nonce tracking, domain separator
7. **Assess impact** — token theft, infinite mint, signature replay for unauthorized actions

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Token & Signature

**Date**: {date}
**Scanner**: vuln-web3-token

## Findings

### VULN-TOKEN-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Category**: {Approval Race / Non-Standard Token / Infinite Mint / Accounting / Signature Replay / Malleability / Permit / ERC-777}
**Location**: `{file}:{line}`
**CWE**: CWE-{362|345|347|284}

**Description**:
{What the vulnerability is}

**Vulnerable Code**:
```solidity
{code snippet}
`` `

**Attack Scenario**:
1. {Step-by-step exploitation}

**Proof of Concept**:
```solidity
{Exploit showing token theft or signature replay}
`` `

**Impact**:
{Token theft, unauthorized approval, infinite mint, replay attack}

**Remediation**:
```solidity
{Fixed code}
`` `

---
```

## Rules

- **For non-standard tokens, identify which specific token causes the issue** — not all tokens are fee-on-transfer.
- **For signatures, show the exact replay scenario** — same chain, cross-chain, or cross-contract.
- **Check OpenZeppelin usage** — OZ ECDSA library handles malleability and zero-address checks.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
