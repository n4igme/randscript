# Phase 4: Smart Contract Targeted Audit (2-3 hr, conditional)

## Gate

At least one bug class tested with working PoC, OR documented "prerequisites fail / no SC scope".

## Skip Criteria

No SC in scope, OR all 3 oracle prerequisites fail AND web assessment yielded findings worth submitting.

## SC-Dead Fast-Exit (abandon at 90 min)

- All 3 batches checked with no leads after 90 min → abandon SC, submit web findings if any
- Contracts are heavily audited (3+ prior audits, active bug bounty for 1+ year) → reduce to 1 hr cap
- All state-changing functions have proper access control + reentrancy guards → document "hardened"

---

## Audit Checklist (3 batches, parallel if possible)

### Batch 1: Vault/Share Math (45 min cap)

- [ ] First depositor inflation (no virtual shares, no minimum deposit)
- [ ] Donation attack (direct transfer inflates share price)
- [ ] `balance()` using `balanceOf()` instead of internal accounting
- [ ] Missing `nonReentrant` on withdraw
- [ ] `earn()` / `deposit()` public without access control
- [ ] Flash loan: deposit + withdraw in same tx

### Batch 2: Oracle + Swapper (45 min cap)

- [ ] `latestAnswer()` without staleness check
- [ ] Negative price → unsafe `int256` to `uint256` cast
- [ ] TWAP with manipulable first observation
- [ ] No minimum TWAP period (1-second ≈ spot)
- [ ] Oracle revert blocks all swaps (DoS)
- [ ] Slippage hardcoded or derived from manipulable source

### Batch 3: Strategy/Harvest (30 min cap)

- [ ] `harvest()` permissionless (MEV sandwich)
- [ ] `wantHarvested = balanceOfWant()` instead of delta
- [ ] Infinite approvals persisting after swap
- [ ] Uninitialized proxy front-running
- [ ] Harvest/deposit race condition

---

## scode Handoff Protocol

When delegating to `scode` for deeper analysis:

1. Run `scode start` on the cloned contract repo
2. Use web3 scanners only: `vuln-web3-arithmetic`, `vuln-web3-reentrancy`, `vuln-web3-access`, `vuln-web3-token`, `vuln-web3-mev`, `vuln-web3-defi`
3. Time cap: 2 hours for full scode pipeline
4. Findings flow back: any High+ from scode → create finding in w3hunt `findings/` directory
5. If scode finds nothing after 90 min → abandon SC phase

---

## On-Chain Verification

After finding bugs in source, verify deployment:

```bash
cast code <address> --rpc-url <rpc>
cast call <address> 'owner()(address)' --rpc-url <rpc>
cast call <address> 'paused()(bool)' --rpc-url <rpc>
```

> Full patterns, working RPCs, and Foundry PoC templates: `references/sc-audit-patterns.md`

---

## Protocol-Type Checklists

The 3 default batches above target yield vaults. For other protocol types, use the appropriate checklist below instead of (or in addition to) the default batches.

### DEX / AMM (Uniswap-style, Curve-style, order books)

- [ ] Price manipulation via low-liquidity pool (sandwich on add/remove liquidity)
- [ ] Fee-on-transfer token handling (actual received ≠ amount parameter)
- [ ] Reentrancy via callback tokens (ERC-777, hooks on transfer)
- [ ] LP token inflation on first mint (same as vault first-depositor)
- [ ] Rounding direction favoring attacker on swap math
- [ ] Imbalanced pool creation → immediate arbitrage drain
- [ ] `sync()` / `skim()` abuse after direct token transfer
- [ ] Concentrated liquidity: tick crossing accounting errors
- [ ] Permit/permit2 replay across chains (same nonce, different chain)

### Lending / Borrowing (Aave-style, Compound-style)

- [ ] Oracle manipulation → borrow against inflated collateral → default
- [ ] Liquidation threshold bypass via flash loan (borrow + repay same block)
- [ ] Interest rate model: edge case at 100% utilization (division by zero, overflow)
- [ ] Collateral factor manipulation (governance attack or misconfigured asset)
- [ ] Bad debt socialization: liquidation doesn't cover full position
- [ ] cToken/aToken exchange rate manipulation (donation attack)
- [ ] Borrow against non-transferable or rebasing collateral
- [ ] Frozen market bypass (can still liquidate/repay but not withdraw)
- [ ] Cross-market reentrancy (enter market A, callback manipulates market B)

### Bridge / Cross-Chain Messaging

- [ ] Message replay across chains (no chain ID in signed payload)
- [ ] Relayer front-running: extract message, submit with own address as recipient
- [ ] Incomplete finality: message processed before source chain confirms
- [ ] Token mapping mismatch (bridge mints wrong token on destination)
- [ ] Rate limit bypass via multiple small transfers
- [ ] Paused bridge: funds stuck with no recovery path (griefing)
- [ ] Validator set rotation: old validators can still sign during transition
- [ ] Nonce gap: skip nonce N, submit N+1, then submit N to double-process

### Governance / DAO (Governor, Timelock, Multisig)

- [ ] Flash loan governance: borrow tokens → propose/vote → return (same block)
- [ ] Proposal front-running: see pending proposal, vote before snapshot
- [ ] Timelock bypass: execute before delay expires (off-by-one in timestamp check)
- [ ] Quorum manipulation: delegate to self, vote, undelegate (double-count)
- [ ] Role persistence after token transfer (ENS-style: delegated roles not revoked)
- [ ] Guardian/admin key rotation: old key still valid during transition period
- [ ] Proposal collision: two proposals with same action hash cancel each other
- [ ] Emergency function without proper access control (anyone can pause/unpause)

### NFT / Token (ERC-721, ERC-1155, custom tokens)

- [ ] Reentrancy via `onERC721Received` / `onERC1155Received` callbacks
- [ ] Unlimited mint: public mint function without cap or access control
- [ ] Royalty bypass: direct transfer vs marketplace sale
- [ ] Metadata manipulation: tokenURI points to mutable off-chain source
- [ ] Approval persistence after transfer (approved operator carries over)
- [ ] Batch mint overflow: `balanceOf` incremented but `totalSupply` not (or vice versa)
- [ ] Signature replay on lazy-mint / permit patterns (no nonce or expiry)

---

### Choosing the Right Checklist

```
Protocol type unknown?
│
├── Has deposit/withdraw + shares/receipt token → Vault batches (default)
├── Has swap/addLiquidity/removeLiquidity → DEX/AMM
├── Has borrow/repay/liquidate → Lending
├── Has sendMessage/relayMessage/bridge → Bridge
├── Has propose/vote/execute/timelock → Governance
├── Has mint/transfer + tokenId → NFT/Token
└── Multiple of the above → run all applicable checklists
```
