# Bug Bounty — Step 3s: Low-Level EVM & Assembly Vulnerabilities

Scan for vulnerabilities in inline assembly, raw storage manipulation, and EVM-specific edge cases.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Applicability

This scanner applies when the codebase contains:
- Inline assembly (`assembly { }`) blocks
- Raw `sstore` / `sload` operations
- Low-level `call` / `delegatecall` / `staticcall` with manual ABI encoding
- Yul or Huff contracts
- Custom proxy implementations with manual storage slots

If no assembly or low-level EVM code is present, report "No low-level EVM code found — scanner not applicable" and skip.

## Vulnerability Patterns

### Storage Slot Manipulation
- Direct `sstore`/`sload` to arbitrary slots without validation
- Storage slot collision between contracts sharing storage layout
- Unstructured storage (EIP-1967 style) with incorrect slot calculation
- Overwriting adjacent storage variables via packed slot writes
- Missing storage gap in upgradeable base contracts

**Grep patterns**: `assembly`, `sstore`, `sload`, `slot`, `keccak256(`, `storage`, `_gap`, `bytes32 private constant`, `EIP1967`

### Returnbomb Attack
- Unbounded `returndatacopy` consuming caller's gas
- External call return data forwarded without size limit
- `abi.decode` on untrusted return data of arbitrary length
- Missing gas cap on calls to untrusted contracts

**Grep patterns**: `returndatasize`, `returndatacopy`, `call(gas()`, `.call{gas:`, `abi.decode(`, `returndata`, `externalCall`

### Dirty Higher-Order Bits
- Values not cleaned after `calldataload` (dirty upper bits in < 32-byte types)
- `address` type not masked to 20 bytes from calldata
- `bool` not validated as 0 or 1
- Comparison of dirty values leading to unexpected equality/inequality

**Grep patterns**: `calldataload`, `mload`, `and(`, `mask`, `0xff`, `0xffffffffffffffffffffffffffffffffffffffff`, `shr(`, `shl(`, `byte(`

### Phantom Function Calls
- Calling functions on contracts that don't implement them (hits fallback)
- Missing interface check (`supportsInterface`) before call
- Fallback function accepting any call silently (no revert)
- `address(0)` calls succeeding silently

**Grep patterns**: `fallback()`, `receive()`, `supportsInterface`, `ERC165`, `.call(abi.encodeWithSelector`, `.call(abi.encodeWithSignature`, `interfaceId`

### Memory Safety in Assembly
- Writing beyond allocated memory (`mstore` past free memory pointer)
- Free memory pointer (`0x40`) not updated after manual allocation
- Memory overlap between variables in assembly
- Stack too deep workarounds creating memory corruption

**Grep patterns**: `mstore(0x40`, `mload(0x40)`, `mstore(`, `mload(`, `add(ptr`, `calldatacopy`, `codecopy`, `extcodecopy`

### Transient Storage (EIP-1153, Cancun+)
- `TSTORE`/`TLOAD` used for reentrancy guards that reset at end of transaction
- Transient storage not persisting across transactions (developer assumes persistence)
- Reentrancy guard via transient storage bypassed in cross-transaction attack
- `TSTORE` slot collision between different contracts in same transaction (delegatecall)
- Transient storage used for access control that resets (lock valid only within tx)
- Missing `TLOAD` check before `TSTORE` (overwriting mid-transaction state)
- Callback-based attacks where transient guard is set but attacker re-enters via different path not checking same slot

**Grep patterns**: `tstore`, `tload`, `TSTORE`, `TLOAD`, `transient`, `assembly.*tstore`, `assembly.*tload`, `EIP1153`, `ReentrancyGuardTransient`

### EVM Version Incompatibilities
- `PUSH0` opcode used on chains not supporting it (pre-Shanghai)
- `SELFDESTRUCT` reliance on chains deprecating it (post-Dencun)
- `PREVRANDAO` vs `DIFFICULTY` confusion across forks
- `basefee` opcode on L2s where it behaves differently

**Grep patterns**: `pragma solidity`, `evmVersion`, `shanghai`, `cancun`, `selfdestruct`, `prevrandao`, `difficulty`, `basefee`, `push0`

### ABI Encoding/Decoding Exploits
- `abi.encodePacked` hash collision (dynamic types concatenated without length prefix)
- Incorrect offset in manual ABI encoding
- Struct encoding mismatch between contracts
- Tuple decoding with wrong parameter count (silent truncation)

**Grep patterns**: `abi.encodePacked(`, `abi.encode(`, `abi.decode(`, `encodeWithSelector`, `encodeWithSignature`, `encodeCall`

### Gas Griefing
- `1/64th` gas rule exploitation (insufficient gas forwarded to subcall)
- `gasleft()` checks that can be manipulated by caller
- Intentional out-of-gas in subcall to trigger partial execution
- `SSTORE` gas refund manipulation

**Grep patterns**: `gasleft()`, `gas()`, `63/64`, `stipend`, `2300`, `call{gas:`, `SSTORE_RESET`

## Process

1. **Find all assembly blocks** — locate every `assembly { }` and Yul/Huff file
2. **Map storage layout** — verify slot assignments match between proxy and implementation
3. **Check memory management** — is free memory pointer correctly maintained?
4. **Audit external call handling** — are return data sizes bounded? Gas forwarded safely?
5. **Verify type cleaning** — are calldata values properly masked for their type?
6. **Check ABI encoding** — any `encodePacked` with multiple dynamic types?
7. **Assess impact** — storage corruption, gas theft, silent failures, fund loss

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Low-Level EVM

**Date**: {date}
**Scanner**: vuln-web3-evm

## Findings

### VULN-EVM-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Storage Slot / Returnbomb / Dirty Bits / Phantom Function / Memory Safety / EVM Compat / ABI Encoding / Gas Griefing}
**Location**: `{file}:{line}`
**CWE**: CWE-{787|119|682|670}

**Description**:
{What the vulnerability is}

**Vulnerable Code**:
```solidity
{code snippet with assembly}
`` `

**Attack Scenario**:
1. {Step-by-step exploitation}

**Proof of Concept**:
```solidity
{Exploit demonstrating the issue}
`` `

**Impact**:
{Storage corruption, fund theft, gas griefing, silent failure}

**Remediation**:
```solidity
{fixed code}
`` `

---
```

## Rules

- **Only report if the assembly/low-level code is reachable from external input.**
- **Check Solidity version** — many issues are version-specific (e.g., dirty bits fixed in newer compilers).
- **For storage collisions, show the exact slot overlap** with calculation.
- **For returnbomb, calculate the gas cost** to the victim.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — Low-Level EVM` section, replace it entirely. See `sc3-vuln-scan` idempotency rule.
- **Save to `./assessment/vulnerabilities.md`** and confirm.