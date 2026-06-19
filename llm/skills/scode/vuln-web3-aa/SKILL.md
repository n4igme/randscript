---
name: vuln-web3-aa
description: "Scan for Account Abstraction (ERC-4337) vulnerabilities (paymasters, bundlers, smart accounts). Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Step 3w-j: Account Abstraction (ERC-4337) Vulnerabilities

Scan for vulnerabilities in ERC-4337 implementations — UserOperation replay, paymaster drain, smart account flaws.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Applicability

This scanner applies when the codebase contains:
- ERC-4337 bundlers or EntryPoint interactions
- Paymaster contracts
- Smart contract wallets / accounts
- Session keys, modules, or recovery mechanisms

If none present, report "No Account Abstraction logic found — scanner not applicable" and skip.

## Vulnerability Patterns

### UserOperation Replay
- Missing chain ID in UserOp hash
- Nonce not properly incremented on failure
- Cross-account replay (same UserOp valid for multiple accounts)
- Replay after account upgrade (validation logic changes)

**Grep patterns**: `userOp`, `UserOperation`, `userOpHash`, `nonce`, `getNonce`, `validateUserOp`, `_validateSignature`, `chainid`, `block.chainid`

### Validation Phase Exploits
- `validateUserOp` accessing forbidden opcodes (TIMESTAMP, BLOCKHASH, etc.)
- Validation passing but execution reverting (bundler griefing)
- Signature validation bypass (ecrecover returns zero address)
- Aggregated signature manipulation (BLS aggregator flaws)

**Grep patterns**: `validateUserOp`, `_validateSignature`, `SIG_VALIDATION_FAILED`, `validAfter`, `validUntil`, `aggregator`, `validateSignatures`, `IAccount`

### Paymaster Drain
- Paymaster sponsoring unlimited gas without rate limiting
- Paymaster `postOp` revert causing gas payment to fall back to user (who has no ETH)
- Paymaster validation accepting any UserOp (missing whitelist)
- Token paymaster exchange rate manipulation
- Paymaster deposit drain via crafted UserOps

**Grep patterns**: `validatePaymasterUserOp`, `postOp`, `IPaymaster`, `paymaster`, `paymasterAndData`, `deposit`, `withdrawTo`, `getDeposit`, `addStake`, `unlockStake`

### EntryPoint Exploits
- Reentrancy in EntryPoint during execution phase
- Bundler manipulation (reordering UserOps for MEV)
- handleOps gas estimation manipulation
- Beneficiary address manipulation (fee theft)

**Grep patterns**: `handleOps`, `handleAggregatedOps`, `EntryPoint`, `IEntryPoint`, `beneficiary`, `innerHandleOp`, `_executeUserOp`, `delegateAndRevert`

### Smart Account Flaws
- Module installation without proper auth (malicious module)
- Fallback handler hijacking
- Session key over-permission (time/value bounds not enforced)
- Recovery mechanism bypass (social recovery, guardian manipulation)
- Execution mode confusion (single vs batch vs delegatecall)

**Grep patterns**: `installModule`, `execute(`, `executeBatch`, `executeFromExecutor`, `fallback`, `sessionKey`, `guardian`, `recovery`, `addOwner`, `removeOwner`, `threshold`, `ModeCode`

## Process

1. **Identify AA components** — bundler, paymaster, smart account, modules
2. **Check UserOp validation** — is replay prevented across chains and upgrades?
3. **Audit paymaster** — can it be drained? Are gas limits enforced?
4. **Test smart account auth** — can modules be installed without proper authorization?
5. **Check session keys** — are time/value/target bounds properly enforced?
6. **Assess impact** — account takeover, paymaster drain, bundler griefing

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Account Abstraction

**Date**: {date}
**Scanner**: vuln-web3-aa

## Findings

### VULN-AA-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {UserOp Replay / Validation / Paymaster / EntryPoint / Smart Account}
**Location**: `{file}:{line}`
**CWE**: CWE-{284|345|362|682}

**Description**:
{What the vulnerability is}

**Vulnerable Code**:
```solidity
{code snippet}
`` `

**Attack Sequence**:
1. {Step-by-step exploitation}

**Foundry PoC**:
```solidity
{Working exploit test}
`` `

**Impact**:
{Account takeover, paymaster drain, griefing}

**Remediation**:
```solidity
{Fixed code}
`` `

---
```

## Positive Observations

While scanning, note any strong security patterns relevant to this scanner's domain. Add them to the `# Positive Security Observations` section at the end of `vulnerabilities.md`:

```markdown
- {scanner-name}: {what the codebase does well in this area}
```

## Rules

- **Always write a Foundry PoC** — Immunefi requires working PoC for Critical/High.
- **Check ERC-4337 spec compliance** — forbidden opcodes in validation, storage access rules.
- **Verify paymaster has deposit limits** — unbounded sponsorship = drain vector.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — Account Abstraction` section, replace it entirely.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
