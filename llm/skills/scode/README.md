# Bug Bounty Skills

A structured 5-step workflow for AI-assisted security assessments of codebases, covering traditional web/API, Web3/smart contracts, and infrastructure.

## Workflow

```
sc1-recon → sc2-threat-model → sc3-vuln-scan → sc4-validate → sc5-report
```

| Step | Skill | What it does | Output |
|------|-------|-------------|--------|
| 1 | `sc1-recon` | Map codebase structure, entry points, data flows | `assessment/recon.md` |
| 2 | `sc2-threat-model` | STRIDE analysis, attack trees, priority targets | `assessment/threat-model.md` |
| 3 | `sc3-vuln-scan` | Orchestrate 28 focused vulnerability scanners | `assessment/vulnerabilities.md` |
| 4 | `sc4-validate` | Re-read code, trace data flows, eliminate false positives | `assessment/validated-vulnerabilities.md` |
| 5 | `sc5-report` | Professional report with CVSS, remediation, roadmap | `assessment/bug-bounty-report.md` |

## Quick Start

```bash
# Full assessment (run in target repo directory)
/skill sc1-recon
/skill sc2-threat-model
/skill sc3-vuln-scan    # orchestrates all relevant sub-scanners
/skill sc4-validate
/skill sc5-report

# Or target a specific scanner
/skill vuln-injection
/skill vuln-web3-reentrancy
```

## Scanner Categories

### Traditional Web/API (3a–3m)

| Skill | Focus |
|-------|-------|
| `vuln-injection` | SQL, command, SSTI, XSS, NoSQL |
| `vuln-access-control` | IDOR, missing authz, privilege escalation |
| `vuln-data-exposure` | Secrets, verbose errors, PII leaks |
| `vuln-ssrf` | User-controlled URLs, internal access |
| `vuln-deserialization` | Unsafe deserialize, XXE |
| `vuln-misconfig` | CORS, CSP, debug mode, default creds |
| `vuln-logic` | Race conditions, workflow bypass |
| `vuln-authn-session` | Broken auth, JWT, session fixation |
| `vuln-crypto` | Weak algorithms, key management |
| `vuln-file-path` | Upload, path traversal, LFI |
| `vuln-client-side` | Open redirect, clickjacking, prototype pollution |
| `vuln-dependency` | CVEs, dependency confusion |
| `vuln-api` | Mass assignment, GraphQL, rate limiting |

### Web3 / Smart Contracts (3w-a–3w-l)

| Skill | Focus |
|-------|-------|
| `vuln-web3-reentrancy` | Reentrancy, unchecked calls, delegatecall |
| `vuln-web3-arithmetic` | Overflow, precision loss, truncation |
| `vuln-web3-access` | Access control, proxy, upgradeability |
| `vuln-web3-mev` | Front-running, flash loan, oracle manipulation |
| `vuln-web3-token` | Token flaws, signature replay |
| `vuln-web3-defi` | AMM, lending, bridges, governance |
| `vuln-web3-nft` | Metadata, randomness, royalty bypass |
| `vuln-web3-evm` | Storage slots, returnbomb, gas griefing |
| `vuln-web3-restaking` | EigenLayer, AVS, slashing, delegation |
| `vuln-web3-aa` | ERC-4337, paymasters, smart accounts |
| `vuln-web3-l2` | L2 bridges, sequencer, cross-domain |
| `vuln-web3-intents` | Solver protocols, Dutch auctions |

Shared Foundry PoC templates: `vuln-web3-modern`

### Systems & Infrastructure (3x-a–3x-c)

| Skill | Focus |
|-------|-------|
| `vuln-dos` | ReDoS, algorithmic complexity, resource exhaustion |
| `vuln-memory` | Buffer overflow, use-after-free (C/C++/Rust) |
| `vuln-infra` | Terraform, Docker, K8s, CI/CD, Helm |

## Key Features

- **Auto-skip**: Scanners detect when they're not applicable and skip gracefully
- **Idempotent**: Re-running a scanner replaces its section (no duplicates)
- **Deduplication**: Cross-scanner overlap is detected and noted
- **Positive observations**: Each scanner notes what the codebase does well
- **Platform-aware**: sc5-report maps severity to Immunefi/HackerOne/Bugcrowd/Code4rena
- **Parallelizable**: Independent scanners can run simultaneously (see sc3 parallelism guide)

## Output Structure

All outputs go to `./assessment/` in the target repository:

```
assessment/
├── recon.md                      # Step 1 output
├── threat-model.md               # Step 2 output
├── vulnerabilities.md            # Step 3 output (all scanners append here)
├── scan-progress.md              # Step 3 progress tracker
├── validated-vulnerabilities.md  # Step 4 output
├── bug-bounty-report.md          # Step 5 final report
├── gitleaks.json                 # Pre-scan tool outputs (optional)
├── semgrep.json
└── ...
```
