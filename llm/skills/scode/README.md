# scode — Source Code Security Review

Structured 5-step pipeline for source code security assessment with 23 focused vulnerability sub-scanners.

## Install

```bash
cp -r llm/skills/scode ~/.kiro/skills/scode
```

## Usage

```
> start              # Initialize review — define scope, create output dir
> recon              # Step 1: Map codebase, entry points, data flows
> threat-model       # Step 2: STRIDE analysis, attack trees
> scan               # Step 3: Run all 23 vulnerability scanners
> scan <category>    # Run specific scanner (e.g., scan injection)
> validate           # Step 4: Trace data flows, eliminate false positives
> report             # Step 5: Generate final report
> status             # Show progress
> resume             # Resume interrupted review
```

## Pipeline

```
sc1-recon → sc2-threat-model → sc3-vuln-scan (23 scanners) → sc4-validate → sc5-report
```

## Vulnerability Scanners

| Category | Scanner | Focus |
|----------|---------|-------|
| Web | injection | SQLi, command injection, SSTI, XSS, NoSQL |
| Web | access-control | IDOR, missing authz, privilege escalation |
| Web | data-exposure | Secrets, verbose errors, PII logging |
| Web | ssrf | User-controlled URLs, internal service access |
| Web | deserialization | Insecure deserialization, XXE |
| Web | misconfig | CORS, CSP, debug mode, default creds |
| Web | logic | Race conditions, rate limiting, workflow bypass |
| Web | authn-session | Broken auth, JWT flaws, session fixation |
| Web | crypto | Weak algorithms, key management, TLS |
| Web | file-path | Unrestricted upload, directory traversal |
| Web | client-side | Open redirect, clickjacking, prototype pollution |
| Web | dependency | Known CVEs, dependency confusion |
| Web | api | Mass assignment, GraphQL, rate limiting |
| Web | dos | ReDoS, algorithmic complexity, resource exhaustion |
| Web | memory | Buffer overflow, use-after-free, format strings |
| Infra | infra | Terraform, Dockerfile, K8s, CI/CD, Helm |
| Web3 | web3-reentrancy | Reentrancy, unchecked external calls |
| Web3 | web3-arithmetic | Integer overflow/underflow, precision loss |
| Web3 | web3-access | Access control, proxy/upgradeability |
| Web3 | web3-mev | Front-running, flash loan/oracle manipulation |
| Web3 | web3-token | Token and signature vulnerabilities |
| Web3 | web3-defi | AMM, lending, bridges, governance |
| Web3 | web3-nft | Metadata, randomness, royalty bypass |
| Web3 | web3-evm | Storage slots, returnbomb, dirty bits |

## Output

```
./assessment/
├── state.yaml
├── recon.md
├── threat-model.md
├── vulnerabilities.md
├── validated-vulnerabilities.md
├── security-review-report.md
└── poc/
```

## Related Skills

- **ptest** — validate findings against live targets
- **parse-finding** — format findings for Jira
