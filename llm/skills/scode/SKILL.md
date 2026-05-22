---
name: scode
version: 1.0.0
description: "Source code security review framework with 5 gated steps: recon, threat model, vulnerability scanning (23 sub-scanners), validation, and reporting."
tags: [code-review, bug-bounty, security, static-analysis, vulnerability]
trigger: "code review, source code audit, bug bounty, security review, vuln scan"
argument-hint: "<command: start|recon|threat-model|scan|validate|report|status|resume>"
metadata:
  hermes:
    tags: [code-review, bug-bounty, security, static-analysis, vulnerability]
    related_skills: [ptest, mtest]
---

# Source Code Security Review Framework

Structured 5-step pipeline for source code security assessment. Covers reconnaissance through reporting with 23 focused vulnerability sub-scanners.

## Architecture

```
sc1-recon → sc2-threat-model → sc3-scan (23 sub-scanners) → sc4-validate → sc5-report
```

## Commands

| Command | Action |
|---------|--------|
| `start` | Initialize new review — define scope, create output directory |
| `recon` | Step 1: Map codebase structure, entry points, data flows |
| `threat-model` | Step 2: STRIDE analysis, attack trees, priority targets |
| `scan` | Step 3: Run vulnerability sub-scanners (all or selected) |
| `scan <category>` | Run specific scanner (e.g., `scan injection`, `scan logic`) |
| `validate` | Step 4: Re-read code, trace data flows, eliminate false positives |
| `report` | Step 5: Generate final bug bounty / security review report |
| `status` | Show current step, progress, findings count |
| `resume` | Resume interrupted review from last checkpoint |

## Output Structure

```
./assessment/
├── state.yaml                  # Review state tracker
├── scope.md                    # Target scope definition
├── recon.md                    # Step 1 output
├── threat-model.md             # Step 2 output
├── scan-progress.md            # Step 3 progress tracker
├── vulnerabilities.md          # Step 3 output (all scanners append here)
├── validated-vulnerabilities.md # Step 4 output
└── bug-bounty-report.md        # Step 5 output
```

## State Tracking

On `start`, create `state.yaml`:

```yaml
review:
  name: ""
  target: ""
  started: ""
  scope_type: ""  # web, api, web3, mixed

steps:
  1_recon: OPEN
  2_threat_model: LOCKED
  3_vulnerability_scan: LOCKED
  4_validation: LOCKED
  5_reporting: LOCKED

current_step: 1
findings_count: 0
confirmed_count: 0
false_positive_count: 0

scan_progress:
  injection: PENDING
  access-control: PENDING
  data-exposure: PENDING
  ssrf: PENDING
  deserialization: PENDING
  misconfig: PENDING
  logic: PENDING
  authn-session: PENDING
  crypto: PENDING
  file-path: PENDING
  client-side: PENDING
  dependency: PENDING
  api: PENDING
  dos: PENDING
  memory: PENDING
  web3-reentrancy: PENDING
  web3-arithmetic: PENDING
  web3-access: PENDING
  web3-mev: PENDING
  web3-token: PENDING
  web3-defi: PENDING
  web3-nft: PENDING
  web3-evm: PENDING
  infra: PENDING
  spring-boot: PENDING

time_tracking:
  step_1_start: ""
  step_1_end: ""
  step_2_start: ""
  step_2_end: ""
  step_3_start: ""
  step_3_end: ""
  step_4_start: ""
  step_4_end: ""
  step_5_start: ""
  step_5_end: ""

config:
  scope_dirs: []      # directories to scan (empty = all)
  skip_dirs: [node_modules, vendor, dist, build, .git, __pycache__, .next]
  tech_stack: []      # detected languages/frameworks
  has_web3: false     # skip web3 scanners if false
  has_native: false   # skip memory scanner if false
```

### Resume (`resume`)

1. Read `./assessment/state.yaml`
2. Check which step is active
3. For step 3: read `scan-progress.md` to find next pending scanner
4. Report status and continue from last checkpoint

### Step Transition

1. Verify output file exists for current step
2. Ask user confirmation
3. Update state.yaml: mark step PASSED, unlock next, record timestamps

---

## Step 1: Reconnaissance (`recon`)

Map the target codebase to understand structure, tech stack, entry points, and data flows.

**Gate:** recon.md exists with entry points mapped

**Process:**

1. **Pre-scan with automated tools** (run before manual review):
   ```bash
   # Secrets in git history
   gitleaks detect --source . --report-path assessment/gitleaks.json 2>/dev/null
   # Or: trufflehog filesystem .

   # Dependency vulnerabilities
   npm audit --json > assessment/npm-audit.json 2>/dev/null
   pip-audit --format json > assessment/pip-audit.json 2>/dev/null
   cargo audit --json > assessment/cargo-audit.json 2>/dev/null

   # Semgrep quick scan (if available)
   semgrep --config auto --json -o assessment/semgrep.json . 2>/dev/null
   ```

2. **Technology Stack** — languages, frameworks, databases, cloud services
3. **Entry Points** — HTTP routes, GraphQL, WebSocket, CLI, queues, cron, serverless
4. **Authentication & Authorization** — mechanism, middleware, gaps
5. **Data Flow Mapping** — input → validation → processing → sink
6. **Business Features** — group endpoints into logical workflows
7. **Sensitive Assets** — DB models, file handlers, payment logic, PII, admin functions
8. **Web3 Architecture** (if applicable) — contracts, proxies, tokens, oracles

**Reference:** `references/recon.md`

**Output:** `./assessment/recon.md`

---

## Step 2: Threat Modelling (`threat-model`)

Analyze recon output to identify threats, attack vectors, and prioritize scanning.

**Gate:** threat-model.md exists with priority targets defined

**Process:**

1. **Threat Actors** — unauthenticated, authenticated, privileged, insider
2. **STRIDE Analysis** — per entry point
3. **Feature-Level Threat Analysis** — abuse cases, assets at risk, trust assumptions
4. **Attack Tree Construction** — goals, paths, preconditions
5. **Prioritize Attack Surface** — exposure × impact × complexity × sensitivity

**Reference:** `references/threat-model.md`

**Output:** `./assessment/threat-model.md`

---

## Step 3: Vulnerability Scanning (`scan`)

Run focused sub-scanners against priority targets from threat model.

**Gate:** All applicable scanners completed (DONE or SKIPPED)

### Scanner Selection by Tech Stack

Before running all 23 scanners, check recon.md and skip what doesn't apply:

| Tech Stack | Skip These |
|------------|-----------|
| No Solidity/Vyper | All web3-* (7 scanners) |
| No C/C++/Rust/native | memory |
| No IaC files (no *.tf, Dockerfile, K8s manifests, CI configs) | infra |
| No file upload endpoints | file-path (keep path traversal checks) |
| No XML/SOAP | deserialization (keep JSON deser checks) |
| Pure API (no HTML) | client-side (keep open redirect) |

### Web3 Skip-Fast Check

```bash
find . -name "*.sol" -o -name "*.vy" | head -1
```
If no results → mark ALL web3-* as SKIPPED.

### Sub-Scanners

| ID | Scanner | Reference | Focus |
|----|---------|-----------|-------|
| 3a | injection | `references/vuln-injection.md` | SQL, command, SSTI, XSS, NoSQL |
| 3b | access-control | `references/vuln-access-control.md` | IDOR, missing authz, privilege escalation |
| 3c | data-exposure | `references/vuln-data-exposure.md` | Secrets, verbose errors, PII in logs |
| 3d | ssrf | `references/vuln-ssrf.md` | User-controlled URLs, internal access |
| 3e | deserialization | `references/vuln-deserialization.md` | Unsafe deserialize, XXE |
| 3f | misconfig | `references/vuln-misconfig.md` | CORS, CSP, debug mode, default creds |
| 3g | logic | `references/vuln-logic.md` | Race conditions, rate limiting, workflow bypass |
| 3h | authn-session | `references/vuln-authn-session.md` | Broken auth, JWT, session fixation, OAuth |
| 3i | crypto | `references/vuln-crypto.md` | Weak algorithms, key management, TLS |
| 3j | file-path | `references/vuln-file-path.md` | Unrestricted upload, path traversal, LFI |
| 3k | client-side | `references/vuln-client-side.md` | Open redirect, clickjacking, prototype pollution |
| 3l | dependency | `references/vuln-dependency.md` | Known CVEs, dependency confusion, supply chain |
| 3m | api | `references/vuln-api.md` | Mass assignment, GraphQL, rate limiting |
| 3o | dos | `references/vuln-dos.md` | ReDoS, algorithmic complexity, resource exhaustion |
| 3p | memory | `references/vuln-memory.md` | Buffer overflow, use-after-free, format strings |
| 3n-i | web3-reentrancy | `references/vuln-web3-reentrancy.md` | Reentrancy, unchecked calls, delegatecall |
| 3n-ii | web3-arithmetic | `references/vuln-web3-arithmetic.md` | Integer overflow, precision loss |
| 3n-iii | web3-access | `references/vuln-web3-access.md` | Access control, proxy, upgradeability |
| 3n-iv | web3-mev | `references/vuln-web3-mev.md` | Front-running, flash loan, oracle manipulation |
| 3n-v | web3-token | `references/vuln-web3-token.md` | Token flaws, signature replay |
| 3q | web3-defi | `references/vuln-web3-defi.md` | AMM, lending, bridge, governance |
| 3r | web3-nft | `references/vuln-web3-nft.md` | Metadata, randomness, royalty bypass |
| 3s | web3-evm | `references/vuln-web3-evm.md` | Storage slots, returnbomb, gas griefing |
| 3t | infra | `references/vuln-infra.md` | Terraform, Dockerfile, K8s, CI/CD, Helm |
| 3u | spring-boot | `references/vuln-spring-boot.md` | Actuator, security annotations, SpEL, mass assignment, Keycloak |

### Parallel Execution via Delegation

For large codebases, batch scanners into parallel delegate_task calls (3 per batch):
- **Batch 1**: injection + access-control + data-exposure
- **Batch 2**: ssrf + file-path + logic
- **Batch 3**: dos + client-side + authn-session
- **Batch 4**: dependency + api + crypto + misconfig
- **Batch 5** (if Web3): web3-reentrancy + web3-arithmetic + web3-access
- **Batch 6** (if Web3): web3-mev + web3-token + web3-defi + web3-nft + web3-evm

### Cross-Scanner Deduplication

Before writing findings, check if `vulnerabilities.md` already has a finding for the same file:line. If identical → skip. If different angle on same location → note overlap, still report.

### Idempotency Rule

Each scanner's section is identified by its header (`# Vulnerability Findings — {Category}`). On re-run: replace that section entirely.

### Severity Rubric (shared across all scanners)

| Severity | Criteria |
|----------|----------|
| Critical | RCE, full fund drain, complete auth bypass, protocol insolvency |
| High | Significant data breach, privilege escalation, partial fund theft, account takeover |
| Medium | Limited data exposure, restricted escalation, DoS, conditional exploits |
| Low | Information disclosure, minor misconfig, unlikely preconditions |

**Modifiers:**
- Upgrade if: unauthenticated, no user interaction, affects all users, automatable
- Downgrade if: requires privileged access, unlikely preconditions, limited blast radius, compensating controls

### Confidence Scoring

| Confidence | Meaning | Validation Priority |
|------------|---------|-------------------|
| High | Full data flow traced source→sink, no sanitization | Verify last |
| Medium | Sink identified, probable user input, trace not confirmed | Verify next |
| Low | Pattern match only, input source unclear | Verify first |

**Output:** Each scanner appends to `./assessment/vulnerabilities.md`

---

## Step 4: Validation (`validate`)

Re-examine each finding by going back to source code. Confirm exploitability, eliminate false positives.

**Gate:** validated-vulnerabilities.md exists with all findings classified

**Process:**

1. **Re-read code** — ±50 lines around each finding, check middleware/framework protections
2. **Trace full data flow** — source → propagation → sanitization → sink
3. **Verify exploitability** — auth required? exact payload? runtime controls?
4. **Re-assess severity** — apply rubric consistently
5. **Deduplicate** — merge findings on same root cause
6. **Classify** — Confirmed / Downgraded / False Positive / Needs Dynamic Testing
7. **Renumber** — global sequence VULN-001, VULN-002... ordered by severity

**Key validation checks:**
- Is the vulnerable code actually reachable from an external request?
- Are there middleware/interceptors applying sanitization before the code is hit?
- Does the framework auto-protect? (React JSX escapes, ORM parameterizes, etc.)
- Can the prerequisite state actually exist? (workflow bypass needs reachable state)
- Does `dangerouslySetInnerHTML`/`v-html`/`[innerHTML]` actually receive user input?

**Reference:** `references/validation.md`

**Decision Trees:** See `references/validation-decision-trees.md` for framework-specific false-positive elimination (Spring Boot, React, Next.js).

**ptest Integration:** See `references/ptest-integration.md` for using external pentest findings to guide validation.

---

## Step 5: Reporting (`report`)

Compile validated findings into a professional deliverable.

**Gate:** bug-bounty-report.md exists with all sections complete

**Process:**

1. **Executive Summary** — severity breakdown, top risks, key recommendations
2. **Detailed Findings** — each with CVSS vector, CWE, PoC, remediation code
3. **Remediation Roadmap** — prioritized by severity and effort
4. **Positive Security Observations** — what the app does well (5-8 items)
5. **Scope & Limitations** — what was/wasn't tested, items needing dynamic testing
6. **Methodology** — 5-step process description

**Reference:** `references/reporting.md`

**Output:** `./assessment/bug-bounty-report.md`

---

## Finding Template

All scanners use this format:

```markdown
### VULN-{CAT}-{NUM}: {Title}

**Severity**: Critical|High|Medium|Low
**Confidence**: High|Medium|Low
**Category**: {vulnerability class}
**Location**: `{file}:{line}`
**CWE**: CWE-{number}

**Description**:
{What the vulnerability is}

**Vulnerable Code**:
```{lang}
{snippet}
`` `

**Data Flow**:
1. Input enters at: {source}
2. Passes through: {processing}
3. Reaches sink at: {dangerous call}

**Proof of Concept**:
{Exploit payload/request}

**Impact**:
{What attacker gains}

**Remediation**:
```{lang}
{fixed code}
`` `
```

---

## Scope Definition (`start`)

On initialization, collect:

1. **Target** — repository path or URL
2. **Scope type** — web, api, web3, mixed
3. **Scope directories** — specific dirs to focus on (empty = all)
4. **Skip directories** — beyond defaults (node_modules, vendor, dist, build, .git)
5. **Tech stack** — auto-detect from config files
6. **Web3 check** — `find . -name "*.sol" -o -name "*.vy" | head -1`
7. **Native check** — `find . -name "*.c" -o -name "*.cpp" -o -name "*.rs" | head -1`

Create `./assessment/` directory and `state.yaml`.

---

## Guardrails

- **Strict sequence** — don't scan without recon and threat model
- **Actually read the code** — don't just grep patterns, trace data flows
- **Framework-aware** — check auto-escaping, ORM parameterization, built-in protections before reporting
- **No noise** — false positives damage credibility. When in doubt, classify as "Needs Dynamic Testing"
- **File:line references** — every finding must point to exact code location
- **Idempotent output** — re-running a scanner replaces its section, doesn't duplicate
- **Save to files** — don't print full reports to terminal, just confirm saved
