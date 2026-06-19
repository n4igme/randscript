---
name: sc1-recon
description: "Step 1 of bug bounty workflow. Map the codebase structure, identify entry points, frameworks, and data flows. Outputs recon.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to code repository to scan>
---

# Bug Bounty — Step 1: Reconnaissance

Map the target codebase to understand its structure, technology stack, entry points, and data flows. This output feeds into threat modelling (Step 2).

## Input

$ARGUMENTS

- If a path is provided, scan that directory
- If no argument, scan the current working directory
- Skip: node_modules, vendor, dist, build, .git, __pycache__, .next, generated files

## Scope Definition

For large codebases (500K+ LOC), define scope before scanning:

1. **Ask the user** which directories/components are in scope (if not obvious)
2. **Record scope** at the top of `./assessment/recon.md`:
   ```markdown
   ## Scope
   - **In scope**: src/api/, src/auth/, src/services/, contracts/
   - **Out of scope**: src/ui/ (frontend only, no server logic), docs/, scripts/
   - **Skip patterns**: node_modules, vendor, dist, build, .git, __pycache__, .next
   ```
3. **Focus effort** — only map entry points and data flows within scoped directories
4. **Note boundary crossings** — if scoped code calls out-of-scope code, note the interface but don't deep-dive the out-of-scope side

If no scope is defined (small codebase), scan everything. The scope definition prevents wasting hours on irrelevant code in enterprise repos.

## Process

### 0. Automated Pre-Scan (run before manual review)

```bash
mkdir -p assessment
```

Run any available security tools and save results to `assessment/`. Skip unavailable tools without commentary:

| Tool | Command | Output |
|------|---------|--------|
| Secret scan | `gitleaks detect --source . --report-path assessment/gitleaks.json` (or trufflehog) | assessment/gitleaks.json |
| Dependency audit | `npm audit --json` / `pip-audit --format json` / `cargo audit --json` | assessment/*-audit.json |
| Pattern matching | `semgrep --config auto --json -o assessment/semgrep.json .` | assessment/semgrep.json |
| IaC scan | `checkov -d . --quiet --compact --output json` | assessment/checkov.json |

Summarize results in ≤3 lines per tool. If no tools are available, proceed with manual analysis.

Feed results into the recon report:
- Secrets found → "Sensitive Assets" section
- Dependency CVEs → "Technology Stack" with affected packages
- Semgrep hits → starting points for entry point mapping
- IaC issues → "Attack Surface Notes"

These tools are **supplementary** — they don't replace manual code reading.

### 1. Technology Stack

Identify:
- Languages (by file extensions and config files)
- Frameworks (Express, Django, Spring, Rails, Next.js, etc.)
- Package managers and dependency files
- Database technologies (from connection strings, ORMs, migrations)
- Cloud services (AWS SDK usage, GCP, Azure references)

### 2. Entry Points

Map all external-facing interfaces:
- HTTP routes/endpoints (method + path + handler file)
- GraphQL schemas and resolvers
- WebSocket handlers
- CLI commands
- Message queue consumers (SQS, Kafka, RabbitMQ)
- Cron jobs / scheduled tasks
- Serverless function handlers (Lambda, Cloud Functions)

### 3. Authentication & Authorization

Identify:
- Auth mechanism (JWT, session, OAuth, API key, etc.)
- Where auth middleware is applied (and where it's missing)
- Role/permission models
- Token validation logic location

### 4. Data Flow Mapping

For each entry point, trace:
- Where user input enters (params, body, headers, query)
- How input is validated/sanitized
- Where input reaches sensitive operations (DB, file system, external APIs, OS commands)
- What data is returned to the user

### 5. Business Features

Group related endpoints into logical business features:
- Identify distinct user-facing workflows (registration, login, checkout, messaging, etc.)
- Map which endpoints belong to each feature
- Note the feature's data lifecycle (create → read → update → delete)
- Identify cross-feature dependencies (e.g., "checkout" depends on "cart" and "payment")
- Flag features with financial, safety, or compliance implications

### 6. Sensitive Assets

Identify:
- Database models / schemas (what sensitive data is stored)
- File upload/download handlers
- Payment/financial logic
- PII handling
- Admin/privileged functionality
- Configuration and secrets management approach

### 7. Web3 / Smart Contract Architecture (if applicable)

If the codebase contains Solidity, Vyper, or other smart contract code:
- **Contract inventory** — list all contracts, their inheritance hierarchy, and deployment chain
- **Proxy pattern** — identify proxy type (Transparent, UUPS, Beacon, Diamond) and storage layout
- **Token standards** — ERC-20, ERC-721, ERC-1155, ERC-4626 implementations
- **External dependencies** — OpenZeppelin version, other imported libraries, oracle integrations (Chainlink, Uniswap TWAP)
- **Protocol type** — AMM, lending, bridge, governance, NFT, staking, or hybrid
- **Access control model** — Ownable, AccessControl, multisig, timelock
- **Upgrade mechanism** — who can upgrade, is there a timelock, initializer pattern
- **Oracle dependencies** — what price feeds or external data sources are used
- **Cross-contract interactions** — which external protocols are called (routers, pools, bridges)

If no smart contract code is present, skip this section.

## Output

Save the reconnaissance report to `./assessment/recon.md` (create the `assessment/` directory if it doesn't exist) with this structure:

```markdown
# Reconnaissance Report

**Target**: {repo path}
**Date**: {date}

## Technology Stack

| Category | Details |
|----------|---------|
| Languages | ... |
| Frameworks | ... |
| Database | ... |
| Cloud/Infra | ... |

## Entry Points

| Method | Path | Handler | Auth Required |
|--------|------|---------|---------------|
| GET | /api/users/:id | src/controllers/user.js:45 | Yes |
| POST | /api/login | src/auth/login.js:12 | No |
...

## Authentication & Authorization

{Description of auth mechanism, middleware locations, gaps}

## Data Flow Summary

{Key data flows from input to sensitive operations}

## Business Features

| Feature | Endpoints | Data Lifecycle | Dependencies | Sensitivity |
|---------|-----------|---------------|--------------|-------------|
| User Registration | POST /api/register, GET /api/verify-email | Create → Verify | Email service | PII |
| Order Management | POST /api/orders, GET /api/orders/:id, PUT /api/orders/:id/cancel | Create → Read → Cancel | Payment, Inventory | Financial |
...

## Database Access Control

| Table | RLS Enabled | SELECT Policy | Write Policies | Issues |
|-------|-------------|---------------|----------------|--------|
| users/profiles | Yes | USING(true) ⚠️ | Own row only | Overly permissive SELECT |
| orders | Yes | Own orders only | Own orders only | — |
...

{For each table with RLS: read and document the actual policy expressions. Note any USING(true), OR true, or missing policies. This section is critical — RLS misconfigurations are a top source of High-severity findings.}

## Sensitive Assets

{List of sensitive data stores, privileged operations, file handling}

## Web3 Architecture (if applicable)

| Contract | Type | Proxy | Token Standard | External Deps |
|----------|------|-------|---------------|---------------|
| Vault.sol | ERC-4626 Vault | UUPS | ERC-20 | Chainlink, Uniswap V3 |
| Governor.sol | Governance | None | — | Timelock.sol |
...

**Upgrade Authority**: {who can upgrade, timelock duration}
**Oracle Setup**: {price feeds, TWAP config, freshness checks}
**Access Roles**: {owner, admin, operator, pauser — who holds each}

## Attack Surface Notes

{Initial observations about potential weak points — NOT findings, just areas to investigate}
```

## Rules

- **Be thorough** — miss nothing. Every route, every handler, every data flow.
- **Be factual** — report what exists, don't speculate about vulnerabilities yet.
- **Include file paths and line numbers** for every entry point and handler.
- **Save output to `./assessment/recon.md`** and confirm the file location.
- **Do NOT print the full report to terminal** — just confirm it's saved.
