---
name: vuln-web3-access
description: "Step 3n-iii of bug bounty workflow. Scan for access control and proxy/upgradeability vulnerabilities in smart contracts. Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Step 3n: Access Control & Proxy/Upgradeability

Scan for permission flaws and unsafe upgrade patterns in smart contracts.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Vulnerability Patterns

### Missing Access Modifiers
- Sensitive functions without `onlyOwner`, `onlyRole`, or custom modifier
- State-changing functions with default `public` visibility that should be restricted
- Admin functions (pause, mint, setFee, withdraw) callable by anyone
- Missing zero-address check on ownership/role transfer

**Grep patterns**: `function `, `public`, `external`, `onlyOwner`, `onlyRole`, `modifier`, `require(msg.sender`, `_checkRole`, `hasRole`

### tx.origin Authentication
- `require(tx.origin == owner)` instead of `msg.sender`
- Phishing attack via malicious contract that forwards `tx.origin`
- Mixed `tx.origin` and `msg.sender` checks creating confusion

**Grep patterns**: `tx.origin`, `require(tx.origin`

### Unprotected Initializers
- `initialize()` callable by anyone (front-running deployment)
- Missing `initializer` modifier from OpenZeppelin
- Multiple initialization possible (no `initialized` flag)
- Implementation contract left uninitialized (takeover via direct call)

**Grep patterns**: `initialize(`, `initializer`, `initialized`, `_disableInitializers`, `constructor`, `Initializable`

### Proxy Storage Collision
- Implementation and proxy using same storage slots for different variables
- Missing storage gap (`__gap`) in upgradeable base contracts
- New variables inserted before existing ones in upgrade
- Struct layout change between versions

**Grep patterns**: `_gap`, `uint256[50]`, `uint256[49]`, `ERC1967`, `StorageSlot`, `bytes32 private constant`, `keccak256("eip1967`

### Upgrade Authorization
- `upgradeTo` / `upgradeToAndCall` without proper access control
- UUPS missing `_authorizeUpgrade` override
- TransparentProxy admin functions callable by non-admin
- No timelock on upgrades (instant rug vector)
- Missing upgrade event emission

**Grep patterns**: `upgradeTo(`, `upgradeToAndCall(`, `_authorizeUpgrade`, `UUPS`, `TransparentUpgradeableProxy`, `ProxyAdmin`, `ERC1967Upgrade`

### Function Selector Clashing
- Proxy admin functions with same selector as implementation functions
- `transparent` pattern not properly isolating admin calls
- Custom proxy with selector collision between admin and user functions

**Grep patterns**: `selector`, `bytes4(keccak256(`, `fallback()`, `_fallback(`, `_delegate(`

### Role Management Flaws
- Single admin key controlling critical functions (no multisig)
- `renounceOwnership` leaving contract permanently ownerless
- Role granted without event (silent privilege escalation)
- Missing role revocation mechanism
- DEFAULT_ADMIN_ROLE not properly secured

**Grep patterns**: `grantRole`, `revokeRole`, `renounceRole`, `renounceOwnership`, `DEFAULT_ADMIN_ROLE`, `AccessControl`, `Ownable`, `multisig`, `Gnosis`

## Process

1. **List all state-changing functions** — check each has appropriate access control
2. **Check initializers** — are they protected and single-use?
3. **Map proxy architecture** — identify proxy type (Transparent, UUPS, Beacon, Diamond)
4. **Verify storage layout** — compare slots between proxy and implementation versions
5. **Audit upgrade path** — who can upgrade? Is there a timelock? Can it be bricked?
6. **Check role hierarchy** — is admin power properly distributed and revocable?
7. **Assess impact** — unauthorized fund withdrawal, contract takeover, permanent bricking

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Access Control & Proxy

**Date**: {date}
**Scanner**: vuln-web3-access

## Findings

### VULN-ACCESS-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Missing Modifier / tx.origin / Unprotected Init / Storage Collision / Upgrade Auth / Selector Clash / Role Mgmt}
**Location**: `{file}:{line}`
**CWE**: CWE-{284|285|269}

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
{Exploit showing unauthorized access}
`` `

**Impact**:
{Contract takeover, fund theft, permanent DoS}

**Remediation**:
```solidity
{Fixed code with proper access control}
`` `

---
```

## Rules

- **Check all public/external functions** — every state-changing function needs explicit access control or a reason to be permissionless.
- **For proxies, verify storage layout compatibility** between versions.
- **For initializers, check both proxy AND implementation** — implementation must also be initialized or disabled.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — Access Control & Proxy` section, replace it entirely. See `sc3-vuln-scan` idempotency rule.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
