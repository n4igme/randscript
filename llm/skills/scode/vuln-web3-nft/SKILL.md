---
name: vuln-web3-nft
description: "Scan for NFT-specific vulnerabilities (metadata, randomness, royalty bypass). Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Step 3r: NFT-Specific Vulnerabilities

Scan for vulnerabilities specific to NFT contracts — metadata manipulation, randomness prediction, royalty bypass, and minting exploits.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Applicability

This scanner applies when the codebase contains NFT logic:
- ERC-721 / ERC-1155 implementations
- NFT marketplaces
- Minting contracts (public mint, allowlist, lazy mint)
- Reveal/randomness mechanisms
- Royalty implementations (EIP-2981)

If none present, report "No NFT logic found — scanner not applicable" and skip.

## Vulnerability Patterns

### Metadata Manipulation
- Mutable `tokenURI` / `baseURI` allowing post-mint rug
- No event emission on metadata change (silent swap)
- Centralized IPFS gateway (single point of failure/censorship)
- Off-chain metadata without content hash verification
- `setBaseURI` callable by owner after reveal with no timelock

**Grep patterns**: `tokenURI`, `baseURI`, `setBaseURI`, `setTokenURI`, `_baseURI`, `metadata`, `ipfs`, `arweave`, `json`, `reveal`

### Randomness Prediction
- `block.timestamp` / `blockhash` / `block.number` as randomness source
- Predictable token ID assignment (sequential without shuffle)
- Reveal randomness derivable before reveal transaction
- Chainlink VRF request/fulfill in same block (front-runnable fulfillment)
- Miner-manipulable randomness in mint outcome

**Grep patterns**: `block.timestamp`, `blockhash`, `block.difficulty`, `block.prevrandao`, `keccak256(abi.encodePacked(block`, `random`, `VRFConsumer`, `requestRandomness`, `fulfillRandomWords`, `seed`

### Royalty Bypass
- EIP-2981 not enforced on-chain (marketplace-dependent)
- Direct `transferFrom` bypassing marketplace royalty logic
- Wrapper contracts that transfer NFT without triggering royalty
- `setApprovalForAll` to intermediary that sells without royalty
- Missing royalty on `safeTransferFrom` hooks

**Grep patterns**: `royaltyInfo`, `EIP2981`, `_setDefaultRoyalty`, `_setTokenRoyalty`, `supportsInterface`, `0x2a55205a`, `transferFrom(`, `safeTransferFrom(`

### Minting Exploits
- Allowlist bypass (Merkle proof with wrong leaf structure)
- Mint quantity manipulation (no per-tx or per-wallet cap)
- Free mint via reentrancy on mint callback (`onERC721Received`)
- Price manipulation (msg.value check with multiplication overflow)
- Contract minting when only EOA intended (missing `tx.origin == msg.sender` or `isContract` check)

**Grep patterns**: `mint(`, `safeMint(`, `maxMint`, `maxPerWallet`, `maxPerTx`, `MerkleProof`, `verify(`, `leaf`, `msg.value`, `price`, `isContract`, `tx.origin`, `onERC721Received`

### Enumeration / Sniping
- Predictable token IDs allowing rarity sniping
- Metadata accessible before reveal (IPFS directory enumerable)
- Sequential mint without randomized assignment
- `totalSupply()` as next token ID (predictable)

**Grep patterns**: `totalSupply`, `_tokenIdCounter`, `tokenByIndex`, `tokenOfOwnerByIndex`, `ERC721Enumerable`, `nextTokenId`

### Lazy Minting Flaws
- Voucher/signature replay (missing nonce or expiry)
- Price mismatch between voucher and actual payment
- Creator signature not validated against token parameters
- Voucher usable after collection parameters change

**Grep patterns**: `voucher`, `lazymint`, `redeem(`, `verify`, `signature`, `signer`, `recover`, `expiry`, `deadline`

## Process

1. **Identify NFT type** — ERC-721, ERC-1155, marketplace, minting contract
2. **Check metadata immutability** — can owner change tokenURI after mint/reveal?
3. **Audit randomness** — is reveal/mint randomness truly unpredictable?
4. **Test mint logic** — can caps be bypassed, price manipulated, or reentrancy exploited?
5. **Check royalty enforcement** — is royalty on-chain enforceable or marketplace-dependent?
6. **Assess impact** — rug pull, rarity manipulation, free minting, royalty theft

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — NFT

**Date**: {date}
**Scanner**: vuln-web3-nft

## Findings

### VULN-NFT-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Metadata / Randomness / Royalty Bypass / Minting / Enumeration / Lazy Mint}
**Location**: `{file}:{line}`
**CWE**: CWE-{330|284|841|682}

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
{Exploit contract or sequence}
`` `

**Impact**:
{Rug pull, rarity sniping, free mint, royalty loss}

**Remediation**:
```solidity
{fixed code}
`` `

---
```


## Positive Observations

While scanning, note any strong security patterns relevant to this scanner's domain. Add them to the `# Positive Security Observations` section at the end of `vulnerabilities.md`:

```markdown
- {scanner-name}: {what the codebase does well in this area}
```
## Rules

- **Only report exploitable NFT flaws** — mutable metadata is only a vuln if owner can rug without timelock/governance.
- **For randomness, prove predictability** — show how the attacker derives the outcome before committing.
- **For royalty bypass, consider the marketplace context** — some are inherently unenforceable.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — NFT` section, replace it entirely. See `sc3-vuln-scan` idempotency rule.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
