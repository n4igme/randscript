---
name: sc3-vuln-scan
description: "Step 3 of bug bounty workflow. Orchestrator that runs all vulnerability sub-scanners. Outputs vulnerabilities.md."
allowed-tools: Read Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Step 3: Vulnerability Scanning (Orchestrator)

This step is split into focused sub-scanners. Run them in order (or pick specific ones based on your threat model priorities):

## Sub-Skills

| Step | Skill | Focus |
|------|-------|-------|
| 3a | `vuln-injection` | SQL, command, SSTI, XSS, NoSQL injection |
| 3b | `vuln-access-control` | IDOR, missing authz, privilege escalation |
| 3c | `vuln-data-exposure` | Secrets, verbose errors, PII in logs, missing encryption |
| 3d | `vuln-ssrf` | User-controlled URLs, internal service access |
| 3e | `vuln-deserialization` | Unsafe deserialize, XXE |
| 3f | `vuln-misconfig` | CORS, CSP, debug mode, default creds |
| 3g | `vuln-logic` | Race conditions, rate limiting, workflow bypass |
| 3h | `vuln-authn-session` | Broken auth, JWT flaws, session fixation, OAuth/OIDC |
| 3i | `vuln-crypto` | Weak algorithms, key management, TLS issues |
| 3j | `vuln-file-path` | Unrestricted upload, path traversal, LFI |
| 3k | `vuln-client-side` | Open redirect, clickjacking, prototype pollution |
| 3l | `vuln-dependency` | Known CVEs, dependency confusion, supply chain |
| 3m | `vuln-api` | Mass assignment, GraphQL, rate limiting, data exposure |
| 3n-i | `vuln-web3-reentrancy` | Reentrancy, unchecked external calls, delegatecall injection |
| 3n-ii | `vuln-web3-arithmetic` | Integer overflow/underflow, precision loss, type truncation |
| 3n-iii | `vuln-web3-access` | Access control, proxy/upgradeability, role management |
| 3n-iv | `vuln-web3-mev` | Front-running/MEV, flash loan, oracle manipulation |
| 3n-v | `vuln-web3-token` | Token standard flaws, signature replay/malleability |
| 3o | `vuln-dos` | ReDoS, algorithmic complexity, resource exhaustion, zip/XML bombs |
| 3p | `vuln-memory` | Buffer overflow, use-after-free, format strings (C/C++/Rust/native) |
| 3q | `vuln-web3-defi` | AMM exploits, lending flaws, bridge attacks, governance |
| 3r | `vuln-web3-nft` | Metadata manipulation, randomness, royalty bypass, minting |
| 3s | `vuln-web3-evm` | Storage slots, returnbomb, dirty bits, phantom functions, gas griefing |

## Usage

Run all sub-scanners sequentially:
```
/skill vuln-injection
/skill vuln-access-control
/skill vuln-data-exposure
/skill vuln-ssrf
/skill vuln-deserialization
/skill vuln-misconfig
/skill vuln-logic
/skill vuln-authn-session
/skill vuln-crypto
/skill vuln-file-path
/skill vuln-client-side
/skill vuln-dependency
/skill vuln-api
/skill vuln-web3-reentrancy
/skill vuln-web3-arithmetic
/skill vuln-web3-access
/skill vuln-web3-mev
/skill vuln-web3-token
/skill vuln-dos
/skill vuln-memory
/skill vuln-web3-defi
/skill vuln-web3-nft
/skill vuln-web3-evm
```

Or run only the ones relevant to your threat model's priority targets.

## Scanner Selection by Tech Stack

Before running all 23 scanners, check `./assessment/recon.md` and skip scanners that don't apply:

| Tech Stack | Skip These Scanners |
|------------|-------------------|
| No Solidity/Vyper/smart contracts | All `vuln-web3-*` (7 scanners) |
| No C/C++/Rust/native code | `vuln-memory` |
| No file upload endpoints | `vuln-file-path` (still check path traversal) |
| No XML/SOAP processing | `vuln-deserialization` (still check JSON deserialization) |
| Pure API (no HTML rendering) | `vuln-client-side` (still check open redirect) |
| No third-party dependencies | `vuln-dependency` |

### Web3 Skip-Fast Check

Before invoking any `vuln-web3-*` scanner, run this single check:

```bash
find . -name "*.sol" -o -name "*.vy" | head -1
```

If no results → mark ALL Web3 scanners as `SKIPPED (no smart contract code)` in `scan-progress.md` and skip them entirely. This saves invoking 7 scanners individually just to have each one say "not applicable."

Each sub-skill appends its findings to `./assessment/vulnerabilities.md`.

## Cross-Scanner Deduplication

Before writing findings, each scanner should check if `vulnerabilities.md` already contains a finding for the same vulnerable code location (file:line). If a prior scanner already reported the same sink/location:
- If the new finding adds a different angle (e.g., vuln-dos reports ReDoS on the same regex that vuln-injection reported as XSS), note the overlap but still report it — sc4-validate will merge them.
- If the new finding is essentially identical (same location, same attack, same impact), skip it and add a note: "Already reported by {prior scanner} as VULN-{ID}."

This reduces duplicate work in sc4-validate while preserving findings that offer genuinely different exploitation angles on the same code.

## Idempotency Rule

Each sub-scanner's output section is identified by its header (e.g., `# Vulnerability Findings — Injection`). When writing output:
- If `vulnerabilities.md` does not exist → create it and write the section.
- If `vulnerabilities.md` exists but has no section for this scanner → append the section.
- If `vulnerabilities.md` already contains a section for this scanner → **replace** that section entirely (delete from the scanner's `# Vulnerability Findings — {Category}` header to the next `# Vulnerability Findings —` header or end of file, then write the new content).

This allows re-running a scanner without producing duplicates.

## Severity Rubric

All sub-scanners must use this shared rubric for consistent severity ratings:

| Severity | Criteria | Examples |
|----------|----------|----------|
| **Critical** | RCE, full fund drain, complete auth bypass, protocol insolvency | Command injection, unprotected `selfdestruct`, admin key takeover |
| **High** | Significant data breach, privilege escalation, partial fund theft, account takeover | SQLi with data exfil, IDOR on sensitive resources, flash loan drain |
| **Medium** | Limited data exposure, restricted privilege escalation, DoS, conditional exploits | Stored XSS, CSRF on state-changing actions, oracle staleness |
| **Low** | Information disclosure, minor misconfig, requires unlikely preconditions | Missing security headers, verbose errors, weak RNG for non-critical use |

**Modifiers:**
- Upgrade severity if: unauthenticated, no user interaction required, affects all users, or automatable
- Downgrade severity if: requires privileged access, needs unlikely preconditions, limited blast radius, or compensating controls exist

## Confidence Scoring

Every finding must include a **Confidence** field indicating how certain the scanner is that this is a real, exploitable issue:

| Confidence | Meaning | Validation Priority |
|------------|---------|-------------------|
| **High** | Full data flow traced from source to sink, no sanitization found | Verify last (likely real) |
| **Medium** | Sink identified with probable user input, but full trace not confirmed | Verify next |
| **Low** | Pattern match only — dangerous function found but input source unclear | Verify first (likely false positive) |

`sc4-validate` should process Low-confidence findings first (most likely to be eliminated) and High-confidence last (most likely to be confirmed).

## Prerequisites

- `./assessment/recon.md` must exist (run `sc1-recon` first)
- `./assessment/threat-model.md` must exist (run `sc2-threat-model` first)

## Next Step

After scanning, run `sc4-validate` to confirm findings before generating the final report.

## Progress Tracking

Before running scanners, create `./assessment/scan-progress.md` (or update if it exists):

```markdown
# Scan Progress

| # | Scanner | Status | Findings | Notes |
|---|---------|--------|----------|-------|
| 3a | vuln-injection | PENDING | — | |
| 3b | vuln-access-control | PENDING | — | |
| 3c | vuln-data-exposure | PENDING | — | |
| 3d | vuln-ssrf | PENDING | — | |
| 3e | vuln-deserialization | PENDING | — | |
| 3f | vuln-misconfig | PENDING | — | |
| 3g | vuln-logic | PENDING | — | |
| 3h | vuln-authn-session | PENDING | — | |
| 3i | vuln-crypto | PENDING | — | |
| 3j | vuln-file-path | PENDING | — | |
| 3k | vuln-client-side | PENDING | — | |
| 3l | vuln-dependency | PENDING | — | |
| 3m | vuln-api | PENDING | — | |
| 3n-i | vuln-web3-reentrancy | PENDING | — | |
| 3n-ii | vuln-web3-arithmetic | PENDING | — | |
| 3n-iii | vuln-web3-access | PENDING | — | |
| 3n-iv | vuln-web3-mev | PENDING | — | |
| 3n-v | vuln-web3-token | PENDING | — | |
| 3o | vuln-dos | PENDING | — | |
| 3p | vuln-memory | PENDING | — | |
| 3q | vuln-web3-defi | PENDING | — | |
| 3r | vuln-web3-nft | PENDING | — | |
| 3s | vuln-web3-evm | PENDING | — | |
```

After each scanner completes, update its row:
- `DONE (N findings)` — scanner ran, found N issues
- `SKIPPED (reason)` — not applicable to this codebase
- `FAILED (reason)` — scanner encountered an error
