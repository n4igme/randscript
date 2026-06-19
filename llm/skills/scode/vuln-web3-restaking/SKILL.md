---
name: vuln-web3-restaking
description: "Scan for restaking/AVS vulnerabilities (EigenLayer, Symbiotic, slashing, operator delegation). Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Step 3w-i: Restaking & AVS Vulnerabilities

Scan for vulnerabilities in restaking protocols — slashing conditions, operator delegation, AVS security, and withdrawal queues.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Applicability

This scanner applies when the codebase contains:
- Restaking / liquid staking / AVS logic (EigenLayer, Symbiotic, Karak)
- Operator registration and delegation
- Slashing conditions and dispute resolution
- Withdrawal queues with delay mechanisms

If none present, report "No restaking/AVS logic found — scanner not applicable" and skip.

## Vulnerability Patterns

### Slashing Condition Exploits
- Attacker-triggerable slashing (force an operator into a slashable state)
- Slashing amount exceeds operator's stake (bad debt)
- Slashing oracle manipulation (false evidence submission)
- Double-slashing (same offense slashed multiple times)
- Slashing during withdrawal queue (race condition)

**Grep patterns**: `slash(`, `slashOperator`, `slashAmount`, `slashingCondition`, `evidence`, `fraudProof`, `dispute`, `challenge`, `freezeOperator`, `veto`

### Operator Delegation Flaws
- Delegating to malicious operator without cooldown
- Undelegation not properly queuing withdrawals
- Operator can prevent undelegation (griefing)
- Share calculation manipulation during delegation
- Missing minimum delegation amount (dust attacks)

**Grep patterns**: `delegate(`, `undelegate(`, `delegateTo`, `operator`, `delegation`, `shares`, `strategyManager`, `queueWithdrawal`, `completeWithdrawal`, `withdrawalDelay`

### AVS (Actively Validated Service) Security
- AVS registration without stake verification
- Quorum manipulation (register many operators with minimum stake)
- Task response forgery (invalid computation accepted)
- Reward distribution manipulation
- AVS can drain operator stake via malicious slashing

**Grep patterns**: `registerOperator`, `AVS`, `avs`, `quorum`, `taskResponse`, `respondToTask`, `createTask`, `taskNumber`, `middleware`, `serviceManager`, `registryCoordinator`

### Withdrawal Queue Attacks
- Withdrawal delay bypass via share transfer
- Front-running withdrawal completion with slashing
- Withdrawal amount calculation using stale exchange rate
- Queue ordering manipulation

**Grep patterns**: `withdrawalQueue`, `queuedWithdrawal`, `completeQueuedWithdrawal`, `withdrawalDelay`, `withdrawalRoot`, `nonce`, `startBlock`

## Process

1. **Map restaking architecture** — identify operator, delegator, AVS, and slasher roles
2. **Check slashing conditions** — can an attacker force an operator into a slashable state?
3. **Audit delegation flows** — are share calculations manipulation-resistant?
4. **Test withdrawal timing** — can delays be bypassed or exploited?
5. **Verify AVS registration** — is stake verification enforced?
6. **Assess impact** — operator stake theft, bad debt, griefing

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Restaking & AVS

**Date**: {date}
**Scanner**: vuln-web3-restaking

## Findings

### VULN-RESTAKE-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Slashing / Delegation / AVS / Withdrawal Queue}
**Location**: `{file}:{line}`
**CWE**: CWE-{284|362|682|841}

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
{Operator stake theft, bad debt, griefing, protocol insolvency}

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
- **Check existing mitigations** — timelocks, veto periods, minimum stake amounts.
- **Verify slashing is bounded** — slashing should never exceed operator's actual stake.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — Restaking & AVS` section, replace it entirely.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
