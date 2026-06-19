---
name: ref-web3-immunefi-strategy
description: "Target selection and hunting strategy for Immunefi Web3 bug bounties. Use before starting a Web3 engagement."
---

# Web3 Bug Bounty Hunting — Immunefi Target Selection & Strategy

## When to Use

Before starting a web3 bug bounty engagement on Immunefi. Guides target selection for hunters with strong web pentest background transitioning into smart contract auditing.

## Target Selection Criteria

### Ideal Targets (Web Pentester Edge)
1. **Hybrid scope** — programs with BOTH "Websites and Applications" AND "Smart Contract" categories
2. **Mid-tier payouts** — $10K-$100K for Critical (avoid over-audited top-tier like Aave/Uniswap)
3. **Complex web layer** — DeFi frontends, admin panels, APIs, off-chain components
4. **Multi-chain deployments** — more surface area, deployment inconsistencies
5. **Active programs** — not paused, responsive team

### Target Categories by Web Pentest Edge

**HIGH edge (most web-heavy):**
- CeFi/DeFi hybrids (traditional web app + contracts)
- Bug bounty platforms themselves
- Multi-chain yield aggregators (complex API layer)

**MEDIUM edge (hybrid web+contract):**
- Perpetuals/trading DEXs (complex trading UI)
- Leveraged yield farming (position management frontend)
- DCA/scheduling protocols (time-based frontend logic)

**LOWER edge (more contract-focused, still viable):**
- Stablecoin protocols (novel mechanisms = less audited)
- Reserve/treasury protocols (governance UI)
- Fixed-rate lending (novel math = edge cases)

## Attack Approach by Target Type

### Web-Heavy Targets
- Standard web pentest: auth bypass, IDOR, SSRF, API abuse
- Session management, JWT/token handling
- Admin panel discovery, debug endpoints
- API rate limiting, business logic flaws
- Cross-chain data aggregation bugs

### Hybrid Targets (Web + Contract)
- Frontend parameter manipulation before contract calls
- Price feed display vs actual contract price (discrepancy exploitation)
- Transaction construction bugs (wrong calldata from frontend)
- Approval/allowance management in UI
- Slippage/deadline parameter injection from frontend

### Contract-Focused with Web
- Smart contract audit using sc1–sc5 pipeline (sc1-sc5 pipeline)
- Flash loan attack vectors
- Cross-chain deployment inconsistencies
- Governance manipulation
- Oracle/price feed attacks

## Workflow

1. Browse https://immunefi.com/bug-bounty/ — filter for programs with web scope
2. Check each program's "Scope" tab for "Websites and Applications" category
3. Verify program is active (not paused)
4. Read program rules and out-of-scope items
5. Set up working directory: `~/PenTest/Hunting/Immunefi/<target>/`
6. Run recon: `ptest` for web layer, `sc1–sc5` for contracts
7. For web findings: standard ptest reporting
8. For contract findings: Foundry PoC required (Immunefi mandates working PoC for Critical/High)

## Tooling

- Foundry (forge, cast, anvil, chisel) — contract interaction + PoC
- ptest framework — web layer testing
- sc1–sc5 pipeline — source code audit (9 web3 scanners)
- MetaMask/TrustWallet — on-chain interaction
- Browser DevTools — frontend parameter inspection

## Immunefi-Specific Rules

- **PoC required** for Critical/High smart contract findings (Foundry fork test)
- **Separate findings** per vulnerability (don't bundle)
- **Check KYC requirements** — some programs require identity verification before payout
- **Responsible disclosure** — never host PoCs on public URLs before vendor acknowledgment
- **Report format**: Description, Root Cause, Impact, PoC (code), Remediation suggestion

## Pitfalls

- Cloudflare blocks automated browsing of immunefi.com — verify scope manually
- Programs change scope frequently — always re-check before starting
- Most Immunefi programs are smart-contract-only — hybrid programs are minority
- Top-tier protocols ($1M+ bounty) have extreme competition from professional audit firms
- Web findings on DeFi frontends often get classified lower severity unless they lead to fund loss
- Some programs exclude "self-XSS" or "issues requiring physical access to device"
