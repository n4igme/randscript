# ENS contracts-v2 Engagement (2026-05-27/28)

## Target
- Program: ENS on Immunefi
- Asset: https://github.com/ensdomains/contracts-v2 (Smart Contract scope)
- Payout: SC Critical $10k-$250k, High $25k-$100k
- Tag: v0.0.1-namechain (pre-mainnet, testnet release)
- Dir: ~/PenTest/Hunting/Immunefi/ENS/

## Confirmed Vulnerability: Delegated Roles Persist After Transfer

**Severity:** High (unauthorized state-modifying actions on names owned by others)

**Root cause:** `PermissionedRegistry._update()` transfers roles from `from` to `to` via `_transferRoles()` but does NOT increment `eacVersionId`. Third-party delegated roles remain active on the unchanged EAC resource after token transfer.

**Attack flow:**
1. Alice registers name → gets token + admin roles
2. Alice grants ROLE_SET_RESOLVER to Mallory
3. Alice sells/transfers name to Bob
4. Mallory still has ROLE_SET_RESOLVER → changes resolver to phishing address
5. Bob's name resolves to attacker-controlled addresses → fund theft

**Key code locations:**
- `contracts/src/registry/PermissionedRegistry.sol` lines 175-196 (`_update` override)
- `eacVersionId` only increments on `unregister()` (line 189) and re-registration (line 392)
- `_transferRoles` called with `executeCallbacks=false` — no `_regenerate`, no version bump

**PoC:** `contracts/test/unit/registry/RolePersistenceAfterTransfer.t.sol`
- Run: `cd contracts && forge test --match-contract RolePersistenceAfterTransferTest -vvv`
- Both tests pass: resolver change + subregistry redirect after transfer

**Report:** `~/PenTest/Hunting/Immunefi/ENS/poc/immunefi-report-role-persistence.md`

**Analogous to:** CVE-2020-5232 (Critical in ENSv1) — previous owners retained access after transfer. ENS team explicitly calls this out in AUDIT_README §5.3 as a concern area.

## Approach That Worked

1. Read AUDIT_README.md first — reveals team's own concerns and known issues
2. Focused on "Name transfer safety" (§5.3) — explicitly flagged concern
3. Traced `_update()` → `_transferRoles()` → noticed `eacVersionId` NOT incremented
4. Verified by checking all places `eacVersionId` increments (only 2: unregister + re-register)
5. Wrote Foundry test using their existing test framework patterns
6. Ran `forge test` — both tests pass, confirming exploitation

## Build Setup Notes

- Submodules needed: `git submodule update --init` from repo root (not contracts/)
- `verifiable-factory` submodule was empty — needed `git restore --staged . && git checkout -- .` inside it
- Forge at `~/.foundry/bin/forge` (not in PATH)
- Build: `forge build --skip test` (skip tests to avoid compilation of all fixtures)
- Run specific test: `forge test --match-contract <Name> -vvv`

## Other Findings (Lower Priority)

- queryNFT DoS: metadata.ens.domains/queryNFT?uri=eip155:1/erc721:... → 502 (reproducible, Medium)
- SendGrid subdomain takeover: 58923185.ens.domains CNAME → sendgrid.net (needs manual claim)
- CSP disabled for Firefox/Safari on app.ens.domains (no XSS chain found)
- docs.ens.domains: static Vocs site, no vulns
- ens.domains landing: Next.js, hardened, no vulns
