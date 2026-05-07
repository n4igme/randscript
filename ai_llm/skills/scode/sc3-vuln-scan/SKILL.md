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

Each sub-skill appends its findings to `./assessment/vulnerabilities.md`.

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

## Prerequisites

- `./assessment/recon.md` must exist (run `sc1-recon` first)
- `./assessment/threat-model.md` must exist (run `sc2-threat-model` first)

## Next Step

After scanning, run `sc4-validate` to confirm findings before generating the final report.
