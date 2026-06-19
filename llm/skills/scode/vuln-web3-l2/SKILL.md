---
name: vuln-web3-l2
description: "Scan for L2/Rollup vulnerabilities (bridges, sequencer, cross-domain messaging). Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Step 3w-k: L2/Rollup Vulnerabilities

Scan for vulnerabilities in L2/Rollup infrastructure — sequencer manipulation, bridge attacks, cross-domain message replay.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Applicability

This scanner applies when the codebase contains:
- L2/Rollup bridge contracts (Optimism, Arbitrum, Base, zkSync, Scroll)
- Sequencer or batch submission logic
- Cross-domain messaging (L1↔L2)
- Dispute/fraud proof systems

If none present, report "No L2/Rollup logic found — scanner not applicable" and skip.

## Vulnerability Patterns

### Sequencer Manipulation
- Sequencer censorship enabling time-sensitive exploits (liquidation prevention)
- Sequencer downtime not handled (stale L2 state accepted by L1)
- Forced inclusion bypass (L1 → L2 message not processed)
- Sequencer fee manipulation (overcharging users)
- Priority ordering exploitation by sequencer operator

**Grep patterns**: `sequencer`, `Sequencer`, `forceInclusion`, `delayedInbox`, `sequencerInbox`, `l2GasPrice`, `enqueue`, `appendSequencerBatch`, `sequencerUptimeFeed`

### L1 ↔ L2 Message Replay
- Cross-domain message replay (same message executed twice)
- Message hash collision (different messages, same hash)
- Source chain ID not verified in message
- Relayer can withhold messages (censorship)
- Message expiry not enforced (stale messages executed)

**Grep patterns**: `sendMessage`, `relayMessage`, `xDomainMessage`, `CrossDomainMessenger`, `L1CrossDomainMessenger`, `L2CrossDomainMessenger`, `messageNonce`, `failedMessages`, `successfulMessages`, `versionedHash`

### Bridge Finality Assumptions
- Optimistic bridge accepting withdrawals before challenge period
- ZK bridge accepting invalid proofs (verifier bug)
- Bridge not checking L1 reorg (finalized block reverted)
- Withdrawal proof using outdated state root
- Bridge token minting without proper L1 deposit verification

**Grep patterns**: `proveWithdrawal`, `finalizeWithdrawal`, `challengePeriod`, `FINALIZATION_PERIOD`, `stateRoot`, `outputRoot`, `l2OutputOracle`, `disputeGame`, `portal`, `OptimismPortal`, `L1StandardBridge`

### Rollup-Specific State Issues
- Storage proof manipulation (invalid MPT proof accepted)
- Batch submission with invalid state transition
- Data availability failure (blob not posted, state unverifiable)
- Escape hatch not functional (users can't force-exit)

**Grep patterns**: `stateCommitment`, `batchSubmit`, `proveFraud`, `dataAvailability`, `blob`, `blobhash`, `POINT_EVALUATION_PRECOMPILE`, `escapeHatch`, `forceWithdraw`

## Process

1. **Identify L2 type** — optimistic rollup, ZK rollup, validium, or hybrid
2. **Map trust assumptions** — who is the sequencer? What happens if it goes down?
3. **Check message replay protection** — nonces, chain IDs, hash uniqueness
4. **Audit bridge finality** — are challenge periods enforced? Can proofs be forged?
5. **Test forced inclusion** — can users bypass a censoring sequencer?
6. **Assess impact** — bridged asset theft, censorship, state corruption

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — L2/Rollup

**Date**: {date}
**Scanner**: vuln-web3-l2

## Findings

### VULN-L2-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Sequencer / Message Replay / Bridge Finality / State / Data Availability}
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
{Bridged asset theft, censorship, state corruption}

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
- **Fork mainnet for realistic testing** — use actual deployed bridge state.
- **Check challenge periods** — are they long enough? Can they be bypassed?
- **Consider sequencer liveness** — what happens during downtime?
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — L2/Rollup` section, replace it entirely.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
