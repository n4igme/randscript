# Bug Bounty — Step 3r: Modern DeFi Patterns (2025-2026)

Scan for vulnerabilities in restaking, account abstraction, L2/rollup, and intent-based protocols.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Applicability

This scanner applies when the codebase contains:
- Restaking / liquid staking / AVS logic (EigenLayer, Symbiotic, Karak)
- Account Abstraction (ERC-4337 bundlers, paymasters, smart accounts)
- L2/Rollup bridge or sequencer logic (Optimism, Arbitrum, Base, zkSync)
- Intent/solver-based protocols (UniswapX, CoW Protocol, 1inch Fusion)

If none present, report "No modern DeFi patterns found — scanner not applicable" and skip.

## Vulnerability Patterns

### 1. Restaking / EigenLayer Patterns

**Context:** Restaking protocols allow ETH stakers to "re-stake" their ETH to secure additional services (AVSs). Slashing conditions, operator delegation, and withdrawal queues are the primary attack surface.

#### Slashing Condition Exploits
- Attacker-triggerable slashing (force an operator into a slashable state)
- Slashing amount exceeds operator's stake (bad debt)
- Slashing oracle manipulation (false evidence submission)
- Double-slashing (same offense slashed multiple times)
- Slashing during withdrawal queue (race condition)

**Grep patterns**: `slash(`, `slashOperator`, `slashAmount`, `slashingCondition`, `evidence`, `fraudProof`, `dispute`, `challenge`, `freezeOperator`, `veto`

#### Operator Delegation Flaws
- Delegating to malicious operator without cooldown
- Undelegation not properly queuing withdrawals
- Operator can prevent undelegation (griefing)
- Share calculation manipulation during delegation
- Missing minimum delegation amount (dust attacks)

**Grep patterns**: `delegate(`, `undelegate(`, `delegateTo`, `operator`, `delegation`, `shares`, `strategyManager`, `queueWithdrawal`, `completeWithdrawal`, `withdrawalDelay`

#### AVS (Actively Validated Service) Security
- AVS registration without stake verification
- Quorum manipulation (register many operators with minimum stake)
- Task response forgery (invalid computation accepted)
- Reward distribution manipulation
- AVS can drain operator stake via malicious slashing

**Grep patterns**: `registerOperator`, `AVS`, `avs`, `quorum`, `taskResponse`, `respondToTask`, `createTask`, `taskNumber`, `middleware`, `serviceManager`, `registryCoordinator`

#### Withdrawal Queue Attacks
- Withdrawal delay bypass via share transfer
- Front-running withdrawal completion with slashing
- Withdrawal amount calculation using stale exchange rate
- Queue ordering manipulation

**Grep patterns**: `withdrawalQueue`, `queuedWithdrawal`, `completeQueuedWithdrawal`, `withdrawalDelay`, `withdrawalRoot`, `nonce`, `startBlock`

---

### 2. Account Abstraction (ERC-4337)

**Context:** ERC-4337 introduces UserOperations, bundlers, paymasters, and smart contract wallets. The validation/execution separation creates unique attack vectors.

#### UserOperation Replay
- Missing chain ID in UserOp hash
- Nonce not properly incremented on failure
- Cross-account replay (same UserOp valid for multiple accounts)
- Replay after account upgrade (validation logic changes)

**Grep patterns**: `userOp`, `UserOperation`, `userOpHash`, `nonce`, `getNonce`, `validateUserOp`, `_validateSignature`, `chainid`, `block.chainid`

#### Validation Phase Exploits
- `validateUserOp` accessing forbidden opcodes (TIMESTAMP, BLOCKHASH, etc.)
- Validation passing but execution reverting (bundler griefing)
- Signature validation bypass (ecrecover returns zero address)
- Aggregated signature manipulation (BLS aggregator flaws)

**Grep patterns**: `validateUserOp`, `_validateSignature`, `SIG_VALIDATION_FAILED`, `validAfter`, `validUntil`, `aggregator`, `validateSignatures`, `IAccount`

#### Paymaster Drain
- Paymaster sponsoring unlimited gas without rate limiting
- Paymaster `postOp` revert causing gas payment to fall back to user (who has no ETH)
- Paymaster validation accepting any UserOp (missing whitelist)
- Token paymaster exchange rate manipulation
- Paymaster deposit drain via crafted UserOps

**Grep patterns**: `validatePaymasterUserOp`, `postOp`, `IPaymaster`, `paymaster`, `paymasterAndData`, `deposit`, `withdrawTo`, `getDeposit`, `addStake`, `unlockStake`

#### EntryPoint Exploits
- Reentrancy in EntryPoint during execution phase
- Bundler manipulation (reordering UserOps for MEV)
- handleOps gas estimation manipulation
- Beneficiary address manipulation (fee theft)

**Grep patterns**: `handleOps`, `handleAggregatedOps`, `EntryPoint`, `IEntryPoint`, `beneficiary`, `innerHandleOp`, `_executeUserOp`, `delegateAndRevert`

#### Smart Account Flaws
- Module installation without proper auth (malicious module)
- Fallback handler hijacking
- Session key over-permission (time/value bounds not enforced)
- Recovery mechanism bypass (social recovery, guardian manipulation)
- Execution mode confusion (single vs batch vs delegatecall)

**Grep patterns**: `installModule`, `execute(`, `executeBatch`, `executeFromExecutor`, `fallback`, `sessionKey`, `guardian`, `recovery`, `addOwner`, `removeOwner`, `threshold`, `ModeCode`

---

### 3. L2/Rollup-Specific Patterns

**Context:** L2s have unique trust assumptions around sequencers, bridges, and message passing. Bugs here can affect billions in bridged assets.

#### Sequencer Manipulation
- Sequencer censorship enabling time-sensitive exploits (liquidation prevention)
- Sequencer downtime not handled (stale L2 state accepted by L1)
- Forced inclusion bypass (L1 → L2 message not processed)
- Sequencer fee manipulation (overcharging users)
- Priority ordering exploitation by sequencer operator

**Grep patterns**: `sequencer`, `Sequencer`, `forceInclusion`, `delayedInbox`, `sequencerInbox`, `l2GasPrice`, `enqueue`, `appendSequencerBatch`, `sequencerUptimeFeed`

#### L1 ↔ L2 Message Replay
- Cross-domain message replay (same message executed twice)
- Message hash collision (different messages, same hash)
- Source chain ID not verified in message
- Relayer can withhold messages (censorship)
- Message expiry not enforced (stale messages executed)

**Grep patterns**: `sendMessage`, `relayMessage`, `xDomainMessage`, `CrossDomainMessenger`, `L1CrossDomainMessenger`, `L2CrossDomainMessenger`, `messageNonce`, `failedMessages`, `successfulMessages`, `versionedHash`

#### Bridge Finality Assumptions
- Optimistic bridge accepting withdrawals before challenge period
- ZK bridge accepting invalid proofs (verifier bug)
- Bridge not checking L1 reorg (finalized block reverted)
- Withdrawal proof using outdated state root
- Bridge token minting without proper L1 deposit verification

**Grep patterns**: `proveWithdrawal`, `finalizeWithdrawal`, `challengePeriod`, `FINALIZATION_PERIOD`, `stateRoot`, `outputRoot`, `l2OutputOracle`, `disputeGame`, `portal`, `OptimismPortal`, `L1StandardBridge`

#### Rollup-Specific State Issues
- Storage proof manipulation (invalid MPT proof accepted)
- Batch submission with invalid state transition
- Data availability failure (blob not posted, state unverifiable)
- Escape hatch not functional (users can't force-exit)

**Grep patterns**: `stateCommitment`, `batchSubmit`, `proveFraud`, `dataAvailability`, `blob`, `blobhash`, `POINT_EVALUATION_PRECOMPILE`, `escapeHatch`, `forceWithdraw`

---

### 4. Intent-Based Protocols

**Context:** Intent protocols separate "what" (user intent) from "how" (solver execution). Solvers compete to fill orders, creating new MEV and manipulation vectors.

#### Solver Manipulation
- Solver providing suboptimal execution (worse price than available)
- Solver front-running their own fills
- Solver collusion (all solvers agree on bad price)
- Solver griefing (taking exclusive rights then not filling)
- Missing solver bond/slashing for bad fills

**Grep patterns**: `solver`, `filler`, `resolver`, `executor`, `fill(`, `fillOrder`, `settle(`, `resolve(`, `exclusiveFiller`, `exclusivityDeadline`, `dutch`, `decay`

#### Intent Replay
- Signed intent replayable after partial fill
- Intent valid across multiple chains (missing chain scope)
- Nonce not invalidated on cancellation
- Expired intent still fillable (timestamp not checked on-chain)

**Grep patterns**: `order`, `Order`, `orderHash`, `nonce`, `deadline`, `expiry`, `cancel(`, `invalidateNonce`, `permit2`, `witness`, `SignedOrder`

#### Dutch Auction Exploits (UniswapX pattern)
- Decay function manipulation (block.timestamp gaming)
- Exclusive filler period too long (user gets worse price)
- Output amount underflow at auction end
- Reactor contract not validating fill amounts properly

**Grep patterns**: `dutchDecay`, `decayStartTime`, `decayEndTime`, `startAmount`, `endAmount`, `DutchOutput`, `ExclusiveDutchOrderReactor`, `resolve(`, `ResolvedOrder`

#### Cross-Chain Intent Attacks
- Fill on destination chain without proof of source chain lock
- Optimistic fill with insufficient challenge period
- Relayer withholding fill proof (user funds stuck)
- Intent hash collision across chains

**Grep patterns**: `originSettler`, `destinationSettler`, `fill(`, `prove(`, `claim(`, `GaslessCrossChainOrder`, `OnchainCrossChainOrder`, `ResolvedCrossChainOrder`, `originChainId`, `destinationChainId`

---

### 5. Foundry PoC Templates

#### Basic Exploit Test

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/VulnerableContract.sol";

contract ExploitTest is Test {
    VulnerableContract target;
    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");

    function setUp() public {
        // Deploy target contract
        target = new VulnerableContract();
        
        // Setup initial state
        deal(address(target), 100 ether);
        deal(victim, 10 ether);
    }

    function testExploit() public {
        uint256 attackerBalanceBefore = attacker.balance;
        
        vm.startPrank(attacker);
        // ... exploit steps ...
        vm.stopPrank();
        
        uint256 attackerBalanceAfter = attacker.balance;
        assertGt(attackerBalanceAfter, attackerBalanceBefore, "Exploit should profit");
    }
}
```

#### Flash Loan Exploit Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Target.sol";

interface IFlashLoanProvider {
    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external;
}

contract FlashLoanExploit is Test {
    Target target;
    IERC20 token;
    IFlashLoanProvider lender;
    
    function setUp() public {
        // Fork mainnet at specific block
        vm.createSelectFork("mainnet", BLOCK_NUMBER);
        target = Target(TARGET_ADDRESS);
        token = IERC20(TOKEN_ADDRESS);
        lender = IFlashLoanProvider(LENDER_ADDRESS);
    }

    function testFlashLoanAttack() public {
        uint256 balanceBefore = token.balanceOf(address(this));
        
        // Step 1: Flash loan
        lender.flashLoan(
            address(this),
            address(token),
            LOAN_AMOUNT,
            abi.encode(/* attack params */)
        );
        
        uint256 profit = token.balanceOf(address(this)) - balanceBefore;
        console.log("Profit:", profit);
        assertGt(profit, 0, "Attack should be profitable");
    }
    
    // Flash loan callback
    function onFlashLoan(
        address initiator,
        address tokenAddr,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32) {
        // Step 2: Manipulate state
        // Step 3: Exploit vulnerability
        // Step 4: Repay loan + fee
        IERC20(tokenAddr).approve(msg.sender, amount + fee);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
```

#### Oracle Manipulation Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IUniswapV2Router {
    function swapExactTokensForTokens(uint, uint, address[] calldata, address, uint) external returns (uint[] memory);
}

contract OracleManipulationTest is Test {
    function setUp() public {
        vm.createSelectFork("mainnet", BLOCK_NUMBER);
    }

    function testOracleManipulation() public {
        // Step 1: Large swap to move spot price
        deal(address(manipToken), address(this), LARGE_AMOUNT);
        manipToken.approve(address(router), type(uint256).max);
        
        address[] memory path = new address[](2);
        path[0] = address(manipToken);
        path[1] = address(targetToken);
        router.swapExactTokensForTokens(LARGE_AMOUNT, 0, path, address(this), block.timestamp);
        
        // Step 2: Exploit manipulated price
        // (borrow at inflated collateral value, liquidate at deflated price, etc.)
        
        // Step 3: Swap back (restore price, keep profit)
    }
}
```

#### Reentrancy Exploit Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract ReentrancyExploit is Test {
    Target target;
    AttackContract attacker;

    function setUp() public {
        target = new Target();
        deal(address(target), 10 ether);
        attacker = new AttackContract(address(target));
        deal(address(attacker), 1 ether);
    }

    function testReentrancy() public {
        uint256 targetBalanceBefore = address(target).balance;
        
        attacker.attack{value: 1 ether}();
        
        assertEq(address(target).balance, 0, "Target should be drained");
        assertGt(address(attacker).balance, targetBalanceBefore, "Attacker should have funds");
    }
}

contract AttackContract {
    Target immutable target;
    uint256 constant REENTER_COUNT = 10;
    uint256 count;

    constructor(address _target) {
        target = Target(_target);
    }

    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }

    receive() external payable {
        if (count < REENTER_COUNT && address(target).balance > 0) {
            count++;
            target.withdraw(msg.value);
        }
    }
}
```

#### Mainnet Fork Test Setup

```solidity
// foundry.toml
// [profile.default]
// eth_rpc_url = "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
// [rpc_endpoints]
// mainnet = "${ETH_RPC_URL}"
// arbitrum = "https://arb-mainnet.g.alchemy.com/v2/YOUR_KEY"
// optimism = "https://opt-mainnet.g.alchemy.com/v2/YOUR_KEY"
// base = "https://base-mainnet.g.alchemy.com/v2/YOUR_KEY"

// Run: forge test --fork-url mainnet --fork-block-number 19000000 -vvv
```

---

## Process

1. **Identify protocol category** — restaking, AA, L2 bridge, intent, or hybrid
2. **Map trust assumptions** — who is trusted (sequencer, solver, operator, bundler)?
3. **Check state transitions** — can any trusted party be forced into a bad state?
4. **Test economic attacks** — is manipulation profitable after costs?
5. **Verify timing assumptions** — challenge periods, delays, deadlines
6. **Check cross-domain interactions** — L1↔L2, cross-chain, cross-account
7. **Write Foundry PoC** — prove exploitability with a fork test

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Modern DeFi Patterns

**Date**: {date}
**Scanner**: vuln-web3-modern

## Findings

### VULN-MODERN-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Restaking / Account Abstraction / L2-Rollup / Intent-Based}
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
{Fund theft, protocol insolvency, griefing, censorship}

**Remediation**:
```solidity
{Fixed code}
`` `

---
```

## Rules

- **Always write a Foundry PoC** — Immunefi requires working PoC for Critical/High.
- **Fork mainnet for realistic testing** — use actual deployed contract state.
- **Calculate profitability** — include gas costs, flash loan fees, slippage.
- **Check existing mitigations** — timelocks, challenge periods, rate limits, pausing.
- **Consider multi-tx attacks** — not everything is atomic, especially on L2.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — Modern DeFi Patterns` section, replace it entirely.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
