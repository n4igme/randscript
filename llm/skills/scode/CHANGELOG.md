# Changelog

All notable changes to the bug bounty skills are documented here.

## [2025-05-28] — Structural Improvements

### Added
- **README.md** — Top-level documentation explaining workflow, scanner categories, and usage
- **CHANGELOG.md** — This file
- **vuln-web3-restaking** — Dedicated scanner for EigenLayer/Symbiotic restaking, AVS, slashing
- **vuln-web3-aa** — Dedicated scanner for ERC-4337 Account Abstraction, paymasters, smart accounts
- **vuln-web3-l2** — Dedicated scanner for L2/Rollup bridges, sequencer, cross-domain messaging
- **vuln-web3-intents** — Dedicated scanner for intent/solver protocols, Dutch auctions
- **Parallelism guidance** in sc3-vuln-scan — 5 parallel groups for concurrent execution
- **Time/effort budgets** in sc3-vuln-scan — per-scanner and total budgets by codebase size
- **Platform severity mapping** in sc5-report — Immunefi, HackerOne, Bugcrowd, Code4rena mapping
- **Positive observations section** added to all 25 vuln-* sub-scanners
- **Graceful tool checks** in sc1-recon — pre-scan tools checked with `command -v` before running

### Changed
- **sc3-vuln-scan numbering** — Web3 scanners renumbered to `3w-a`–`3w-l`, systems to `3x-a`–`3x-c`
- **vuln-web3-modern** — Reduced to shared Foundry PoC templates only (scanning logic moved to focused scanners)
- Scanner count increased from 25 to 28 (split of vuln-web3-modern into 4 focused skills)

### Fixed
- Inconsistent numbering scheme (was: 3n-i, 3o, 3p, 3q, 3r, 3s, 3s-ii, 3t)

---

## [2025-05-21] — Infrastructure & Validation

### Added
- **vuln-infra** — IaC scanner covering Terraform, Dockerfile, K8s, CI/CD, Helm
- Multi-hop taint tracking procedure in sc4-validate
- Scope definition guidance in sc1-recon for large codebases

---

## [2025-05-20] — Business Logic & False Positive Reduction

### Changed
- **vuln-logic** — Added workflow bypass precondition verification
- **vuln-access-control** — Added data lifecycle tracing before reporting missing checks
- **vuln-injection** — Added framework-aware false positive prevention (React, Vue, Supabase)

---

## [2025-05-07] — Initial Release

### Added
- 5-step workflow: sc1-recon → sc2-threat-model → sc3-vuln-scan → sc4-validate → sc5-report
- 13 traditional web/API scanners (3a–3m)
- 8 Web3/smart contract scanners
- 2 systems scanners (vuln-dos, vuln-memory)
- Severity rubric, confidence scoring, idempotency rules, cross-scanner deduplication
- Progress tracking via scan-progress.md
