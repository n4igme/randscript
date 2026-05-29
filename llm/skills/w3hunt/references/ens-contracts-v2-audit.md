# ENS contracts-v2 Audit Notes (2026-05-28)

## Target
- **Repo:** github.com/ensdomains/contracts-v2
- **Tag:** v0.0.1-namechain (only release, pre-mainnet)
- **Scope:** All Solidity under `contracts/src/` (61 files, 4410 LoC)
- **Bounty:** Critical $10K-$250K (10% of funds), High $25K-$100K
- **Working Dir:** ~/PenTest/Hunting/Immunefi/ENS/contracts-v2/

## Confirmed Finding: Delegated Roles Persist After Transfer (High)

**Root cause:** `PermissionedRegistry._update()` transfers roles from `from` to `to` via `_transferRoles()` but does NOT increment `eacVersionId`. Third-party delegated roles remain active on the unchanged resource.

**Impact:** After a name is sold/transferred, any previously-delegated party can still call `setResolver()` or `setSubregistry()` — redirecting resolution to phishing addresses.

**PoC:** `contracts/test/unit/registry/RolePersistenceAfterTransfer.t.sol`
- Both tests pass: `forge test --match-contract RolePersistenceAfterTransferTest -vvv`
- Gas: 186708 (resolver change), 168657 (subregistry change)

**Report:** `~/PenTest/Hunting/Immunefi/ENS/poc/immunefi-report-role-persistence.md`

**Analogous to:** CVE-2020-5232 (Critical in ENSv1) — explicitly called out in AUDIT_README §5.3

## Architecture Notes

### Key Contracts
- `PermissionedRegistry.sol` — ERC1155 name ownership + EAC roles + expiry
- `ETHRegistrar.sol` — commit-reveal registration, ERC20 payments
- `EnhancedAccessControl.sol` — bitmap-packed roles (nybble per role, 64 max)
- `ERC1155Singleton.sol` — one-owner-per-token ERC1155
- `PermissionedResolver.sol` — aliasing, multicall, fine-grained permissions
- `StandardRentPriceOracle.sol` — pricing with discounts/premiums
- `LockedWrapperReceiver.sol` / `UnlockedMigrationController.sol` — v1→v2 migration

### Version System
- `eacVersionId` — incremented on unregister/re-register only. Defines EAC resource.
- `tokenVersionId` — incremented on unregister AND on _regenerate (role grant/revoke). Defines ERC1155 token ID.
- `LibLabel.withVersion(anyId, versionId)` — XORs lower 32 bits with version

### Role Bitmap Layout
- Lower 128 bits: regular roles (nybble-packed)
- Upper 128 bits: admin roles (same layout, shifted)
- REGISTRATION_ROLE_BITMAP: SET_SUBREGISTRY + SET_SUBREGISTRY_ADMIN + SET_RESOLVER + SET_RESOLVER_ADMIN + CAN_TRANSFER_ADMIN

### Transfer Flow
1. `super._update()` — ownership moves
2. Check `ROLE_CAN_TRANSFER_ADMIN` on `from`
3. `_transferRoles(resource, from, to, false)` — moves FROM's roles only, no callbacks

### _regenerate Flow (triggered by grantRoles/revokeRoles with callbacks=true)
1. `_burn(owner, oldTokenId, 1)` — no callback (to=address(0))
2. `++entry.tokenVersionId`
3. `_mint(owner, newTokenId, 1, "")` — ERC1155 callback to owner
4. Potential reentrancy but state is consistent at callback time

## Investigated But Not Exploitable

| Vector | Why Not |
|--------|---------|
| Premium bypass via latestOwner | Intentional ("prior owners are exempt") |
| Reentrancy via _regenerate mint callback | State is consistent at callback time, no value extraction |
| Operator griefing via transfer | _transferRoles uses executeCallbacks=false |
| Role escalation token→root | grantRoles rejects ROOT_RESOURCE, grantRootRoles needs root admin |
| uint64 overflow in renew | Solidity 0.8 reverts on overflow |
| integratedDiscount division by zero | _setDiscountPoints reverts if t==0 |
| ResolverProfileRewriterLib OOB | Two fixes already merged (#283, #312), bounds checks now present |
| Commit-reveal front-running | Commitment binds all params, can't extract from hash |
| LibLabel collision | 224-bit collision required — infeasible |
| resolve() recursive DoS | View function, gas-limited, no state change |
| Alias cycle DoS | Documented known issue, requires admin (ROLE_SET_ALIAS) |

## Foundry Setup

```bash
cd ~/PenTest/Hunting/Immunefi/ENS/contracts-v2
git submodule update --init --recursive
# If verifiable-factory is empty:
cd contracts/lib/verifiable-factory && git restore --staged . && git checkout -- . && cd ../../..
cd contracts
~/.foundry/bin/forge build --skip test  # verify compilation (warnings OK)
~/.foundry/bin/forge test --match-contract <Name> -vvv  # run specific test
```

## Status
- Finding confirmed with passing PoC
- Report written, ready to submit on Immunefi
- Impacted asset: https://github.com/ensdomains/contracts-v2
