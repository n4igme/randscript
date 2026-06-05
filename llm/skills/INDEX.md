# Security Skills — Routing Index

Quick decision guide for selecting the right skill based on engagement type.

## Engagement Type → Skill

| Engagement | Primary Skill | Secondary | Notes |
|------------|---------------|-----------|-------|
| Web pentest (external) | ptest | atest (if API-heavy) | Full 8-phase framework |
| Web pentest (internal) | ptest | ctest (if cloud) | Add AD refs if Windows domain |
| API-only scope | atest | ptest (for web context) | 4-phase, skip infra recon |
| Mobile app (Android/iOS) | mtest | atest (for APIs found) | 10-phase, feature-driven |
| Cloud/container pentest | ctest | ptest (for web apps found) | 5-phase, IAM-first |
| Source code review | scode | ptest/atest (dynamic validation) | 23 sub-scanners |
| Bug bounty (web) | ptest | scode (if source available) | Fast-track on first High |
| Bug bounty (DeFi/Web3) | w3hunt | scode (contracts), ptest (frontend) | Web-first strategy |
| Bug bounty (mobile) | mtest | atest (APIs) | Bug bounty fast-path mode |
| Exploit development | xdev | retools (RE tooling) | From crash to reliable exploit |
| Reverse engineering | retools | xdev (if exploiting), mtest (if mobile) | Tooling utility skill |
| OSINT / person recon | osint | opsec (defensive flip) | Progressive discovery |
| OPSEC self-assessment | opsec | osint (validate exposure) | Quarterly audit cycle |

## Decision Tree

```
What's the target?
│
├── Web application / website
│   ├── Has API docs / API-heavy → atest (primary) + ptest (web context)
│   ├── Standard webapp → ptest
│   ├── DeFi / Web3 frontend → w3hunt
│   └── SPA with mobile backend → ptest + mtest (for mobile APIs)
│
├── Mobile application
│   ├── Android / iOS native → mtest
│   ├── TWA / WebView wrapper → mtest Phase 2 (config extract) → ptest (web testing)
│   └── Flutter / React Native → mtest (with bypass references)
│
├── Cloud infrastructure
│   ├── AWS / GCP / Azure → ctest
│   ├── Kubernetes / containers → ctest Phase 4
│   └── Serverless (Lambda/Functions) → ctest Phase 3
│
├── Source code available
│   ├── Web app source → scode → ptest/atest (dynamic)
│   ├── Smart contracts → scode (web3 scope) + w3hunt
│   └── Binary / native → retools → xdev (if exploiting)
│
├── Internal network
│   ├── AD environment → ptest (network scope) + references/internal-ad-attacks.md
│   ├── Cloud-connected → ptest + ctest
│   └── Flat network → ptest (network scope)
│
├── Person / organization
│   ├── Offensive recon → osint
│   └── Self-assessment → opsec
│
└── Vulnerability → working exploit
    └── Any platform → xdev + retools
```

## Cross-Skill Chain Patterns

**Mobile app pentest (full):**
mtest (Phase 1-4) → discovers API → atest (auth/injection) → finds cloud storage → ctest

**Bug bounty (hybrid web+SC):**
w3hunt (triage) → ptest (web frontend) → scode (contract review) → w3hunt (submit)

**Internal pentest (bank):**
ptest (recon) → mtest (mobile app for API discovery) → atest (API testing) → ctest (cloud)

**Source-assisted pentest:**
scode (find vulns in code) → ptest/atest (validate dynamically) → xdev (if exploit needed)

## Shared Conventions

- Finding IDs: `{SKILL}-{NNN}` (PTEST-001, MTEST-001, ATEST-001, etc.)
- State tracking: `state.yaml` in `{skill}-output/` directory
- Gate enforcement: `scripts/gate_check.py` (run before phase advancement)
- Findings log: `findings.jsonl` for cross-skill chaining
- Pitfall: Burp MCP output is 100-200KB — always parse via execute_code, never raw in context
- Pitfall: Max 300 lines per write_file/patch operation
