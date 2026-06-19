---
name: vuln-web3-intents
description: "Scan for intent/solver protocol vulnerabilities (UniswapX, Dutch auctions, cross-chain intents). Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Step 3w-l: Intent-Based Protocol Vulnerabilities

Scan for vulnerabilities in intent/solver protocols — solver manipulation, intent replay, Dutch auction exploits, cross-chain intents.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Applicability

This scanner applies when the codebase contains:
- Intent/solver-based protocols (UniswapX, CoW Protocol, 1inch Fusion)
- Dutch auction order reactors
- Cross-chain intent settlement
- Solver/filler registration and competition

If none present, report "No intent-based protocol logic found — scanner not applicable" and skip.

## Vulnerability Patterns

### Solver Manipulation
- Solver providing suboptimal execution (worse price than available)
- Solver front-running their own fills
- Solver collusion (all solvers agree on bad price)
- Solver griefing (taking exclusive rights then not filling)
- Missing solver bond/slashing for bad fills

**Grep patterns**: `solver`, `filler`, `resolver`, `executor`, `fill(`, `fillOrder`, `settle(`, `resolve(`, `exclusiveFiller`, `exclusivityDeadline`, `dutch`, `decay`

### Intent Replay
- Signed intent replayable after partial fill
- Intent valid across multiple chains (missing chain scope)
- Nonce not invalidated on cancellation
- Expired intent still fillable (timestamp not checked on-chain)

**Grep patterns**: `order`, `Order`, `orderHash`, `nonce`, `deadline`, `expiry`, `cancel(`, `invalidateNonce`, `permit2`, `witness`, `SignedOrder`

### Dutch Auction Exploits (UniswapX pattern)
- Decay function manipulation (block.timestamp gaming)
- Exclusive filler period too long (user gets worse price)
- Output amount underflow at auction end
- Reactor contract not validating fill amounts properly

**Grep patterns**: `dutchDecay`, `decayStartTime`, `decayEndTime`, `startAmount`, `endAmount`, `DutchOutput`, `ExclusiveDutchOrderReactor`, `resolve(`, `ResolvedOrder`

### Cross-Chain Intent Attacks
- Fill on destination chain without proof of source chain lock
- Optimistic fill with insufficient challenge period
- Relayer withholding fill proof (user funds stuck)
- Intent hash collision across chains

**Grep patterns**: `originSettler`, `destinationSettler`, `fill(`, `prove(`, `claim(`, `GaslessCrossChainOrder`, `OnchainCrossChainOrder`, `ResolvedCrossChainOrder`, `originChainId`, `destinationChainId`

## Process

1. **Identify intent architecture** — single-chain vs cross-chain, auction type
2. **Map solver incentives** — what prevents solvers from providing bad execution?
3. **Check intent lifecycle** — creation, filling, cancellation, expiry
4. **Test replay vectors** — can intents be replayed after partial fill or cancellation?
5. **Audit Dutch auction math** — can decay functions underflow or be gamed?
6. **Assess impact** — user fund loss via bad execution, stuck funds, MEV extraction

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Intent-Based Protocols

**Date**: {date}
**Scanner**: vuln-web3-intents

## Findings

### VULN-INTENT-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Solver Manipulation / Intent Replay / Dutch Auction / Cross-Chain}
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
{User fund loss, stuck funds, MEV extraction}

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
- **Calculate solver profitability** — is the manipulation profitable after gas?
- **Check Permit2 integration** — intent protocols often use Permit2 for approvals.
- **Verify cancellation works** — can users always cancel unfilled intents?
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — Intent-Based Protocols` section, replace it entirely.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
