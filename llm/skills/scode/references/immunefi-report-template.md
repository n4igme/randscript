# Immunefi Report Template & Guidelines

How to write reports that pass Immunefi triage and maximize payout.

---

## Immunefi Severity Scale

Immunefi uses its own classification (NOT CVSS). Payout tiers are per-program.

### Critical (typically $50K-$1M+)
- Direct theft of user funds (any amount)
- Permanent freezing of funds (>$1M or >10% of protocol TVL)
- Protocol insolvency / bad debt that cannot be socialized
- Governance takeover leading to fund extraction
- Minting unlimited tokens that can be sold for profit
- Draining the protocol's treasury or reserves

### High (typically $10K-$50K)
- Theft of unclaimed yield/rewards (not principal)
- Temporary freezing of funds (recoverable by admin/governance)
- Manipulation causing loss to specific users (not protocol-wide)
- Griefing attacks that cost the protocol significant gas/resources
- Theft requiring specific preconditions (low liquidity, specific timing)
- Oracle manipulation with limited profit window

### Medium (typically $1K-$10K)
- Griefing without direct profit (DoS, gas waste)
- Theft requiring unrealistic preconditions
- Information disclosure of sensitive on-chain data
- Contract fails to deliver promised returns (not theft, just malfunction)
- Minor accounting errors that accumulate slowly

### Low (typically $100-$1K)
- Best practice violations without direct exploit path
- Gas optimization issues
- Minor view function errors
- Events not emitted correctly

### What Gets Rejected (Informational / Out of Scope)
- Centralization risks ("admin can rug") — unless explicitly in scope
- Front-running on public mempool (MEV, not a bug)
- Issues requiring compromised private keys
- Theoretical issues without PoC
- Issues on deprecated/paused contracts
- Gas griefing below economic threshold
- Known issues listed in audit reports

---

## Report Structure

```markdown
# [Vulnerability Title — Clear, Specific]

## Summary
[2-3 sentences: what's broken, what's the impact, who's affected]

## Vulnerability Detail
[Technical explanation of the root cause. Include:]
- Which contract/function is vulnerable
- What the intended behavior is
- What actually happens
- Why existing protections don't prevent it

## Impact
[Concrete impact statement:]
- How much can be stolen/frozen (in USD terms if possible)
- Who is affected (all users, specific LPs, governance, etc.)
- Is it repeatable? One-time or continuous drain?
- Capital requirements for the attack

## Proof of Concept

### Environment
- Chain: Ethereum Mainnet (fork block: 19,500,000)
- Foundry version: [version]
- Date: [date]

### Setup
```bash
forge init poc && cd poc
forge install OpenZeppelin/openzeppelin-contracts
# Add fork URL to foundry.toml
```

### Exploit Code
```solidity
// Full working test — copy-paste ready
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract ExploitTest is Test {
    function setUp() public {
        vm.createSelectFork("mainnet", 19_500_000);
    }

    function testExploit() public {
        // Step 1: ...
        // Step 2: ...
        // Step 3: ...
        // Log profit
    }
}
```

### Execution Output
```
[PASS] testExploit() (gas: XXXXX)
Logs:
  Attacker balance before: 0
  Attacker balance after: 1,000,000 USDC
  PROFIT: 1,000,000 USDC
```

### Step-by-Step Explanation
1. Attacker flash loans X from Balancer (0 fee)
2. Attacker calls `vulnerable_function()` which...
3. Due to [root cause], the contract...
4. Attacker extracts Y tokens worth $Z
5. Attacker repays flash loan, net profit: $Z

## Recommended Fix
```solidity
// Before (vulnerable)
function withdraw(uint256 amount) external {
    token.transfer(msg.sender, amount);  // external call first
    balances[msg.sender] -= amount;       // state update after
}

// After (fixed)
function withdraw(uint256 amount) external nonReentrant {
    balances[msg.sender] -= amount;       // state update first
    token.transfer(msg.sender, amount);  // external call last
}
```

## References
- [Similar past exploit if applicable]
- [Relevant EIP or standard]
- [Audit report mentioning related issue]
```

---

## Common Rejection Reasons & How to Avoid

### 1. "No PoC provided"
- **Rule:** Critical and High MUST have working Foundry/Hardhat PoC
- **Fix:** Always include runnable code, not just description

### 2. "Theoretical / requires unrealistic preconditions"
- **Examples:** "attacker needs 51% of governance tokens" (without flash loan path), "requires compromised admin key"
- **Fix:** Prove the preconditions are achievable. Flash loan? Existing whale? Specific market condition that has occurred before?

### 3. "Known issue / acknowledged risk"
- **Rule:** Check the protocol's audit reports and known issues list BEFORE submitting
- **Fix:** Search their GitHub issues, audit PDFs, and Discord announcements. If it's known, don't submit

### 4. "Out of scope"
- **Rule:** Read the program's scope CAREFULLY — specific contracts, specific chains, specific versions
- **Fix:** Verify the exact contract addresses in scope. Proxy implementations change — confirm current impl

### 5. "Centralization risk, not a bug"
- **Rule:** "Admin can do X" is NOT a vulnerability unless the program explicitly includes governance/admin risks
- **Fix:** Only report admin issues if: (a) admin action is unintended, (b) non-admin can trigger admin-like behavior, (c) timelock can be bypassed

### 6. "Impact below minimum threshold"
- **Rule:** Many programs have minimum impact thresholds ($1K, $10K, etc.)
- **Fix:** Calculate exact profit. If borderline, show it's repeatable (profit × N iterations)

### 7. "Duplicate"
- **Rule:** First valid report wins. If you suspect others found it, submit FAST with minimal PoC, then enhance
- **Fix:** Submit within hours of finding. A working PoC beats a detailed writeup submitted days later

### 8. "MEV / front-running is not a bug"
- **Rule:** Sandwich attacks, JIT liquidity, and general MEV are NOT bugs — they're features of public mempools
- **Fix:** Only report if the protocol SHOULD have MEV protection but doesn't (e.g., missing slippage check in protocol-owned swap)

---

## Immunefi Process & Timeline

1. **Submit** — report goes to triage team (24-72h initial response)
2. **Triage** — Immunefi reviews for validity, may ask for clarification
3. **Escalation** — valid reports sent to protocol team
4. **Protocol Review** — team confirms/denies (7-14 days typical)
5. **Negotiation** — severity/payout discussion (can take weeks)
6. **Fix & Payout** — protocol deploys fix, bounty paid (30-90 days total)

### Tips for Faster Resolution
- Respond to triage questions within 24h
- If asked to "prove impact in USD terms" — add a price feed to your PoC
- If severity is disputed, provide comparable past incidents with payouts
- Be professional — adversarial tone delays resolution

---

## Severity Negotiation Tactics

### Upgrading from High to Critical
- Show the attack is **repeatable** (not one-time)
- Show it affects **all users** (not just edge cases)
- Show **no admin intervention** can prevent it in time
- Show the **profit scales** with TVL (not fixed amount)
- Compare to past Critical payouts on same program

### Defending Against Downgrade
- "Requires flash loan" is NOT a downgrade reason — flash loans are free and available
- "Low probability" — show the precondition has occurred before (link to block explorer)
- "Limited impact" — show it's repeatable or scales with deposits
- "Admin can pause" — show the attack completes in 1 transaction (faster than any admin response)

---

## Pre-Submission Checklist

- [ ] Verified contract is IN SCOPE (correct address, correct chain)
- [ ] Checked current implementation (not outdated proxy impl)
- [ ] Searched for existing audit findings on same issue
- [ ] PoC runs successfully on mainnet fork with pinned block
- [ ] PoC demonstrates actual profit/loss (not just revert or state change)
- [ ] Calculated profit after gas and flash loan fees
- [ ] Explained each step clearly in comments
- [ ] Included recommended fix
- [ ] Severity matches Immunefi's scale (not CVSS)
- [ ] No sensitive info (your real identity, other unreported bugs)

---

## Program Selection Strategy

### High-Value Targets for Web Pentesters
1. **Bridges** — web dashboards + relayer APIs + smart contracts. Web vulns here = Critical (key exposure)
2. **DEX aggregators** — complex routing logic, API endpoints, solver networks
3. **Lending protocols** — oracle dependencies, liquidation bots, admin dashboards
4. **Yield aggregators** — strategy contracts + web vaults + keeper infrastructure
5. **L2/Rollup infra** — sequencer APIs, bridge UIs, explorer backends

### Red Flags (Avoid These Programs)
- Bounty < $10K max (not worth the effort)
- No response history (check Immunefi leaderboard for program activity)
- "Paused" or "Reviewing" status
- Scope limited to 1-2 simple contracts (low attack surface)
- Program has been live 2+ years with no payouts (either very secure or doesn't pay)

### Green Flags (Prioritize These)
- Recently launched (< 6 months, less audited)
- High max bounty ($500K+) with active TVL
- Broad scope (web + contracts + infrastructure)
- Recent code changes (new features = new bugs)
- Multiple chains deployed (cross-chain logic = complexity = bugs)
