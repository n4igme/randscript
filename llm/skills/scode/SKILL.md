---
name: scode
version: 2.1.0
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
├── state.yaml                    # Review state tracker
├── recon.md                      # Step 1 output
├── threat-model.md               # Step 2 output
├── vulnerabilities.md            # Step 3 output (all findings, written in batches)
├── validated-vulnerabilities.md  # Step 4 output
├── security-review-report.md    # Step 5 output
└── poc/                          # PoC scripts for Critical/High findings
    ├── poc_*.sh                  # curl-based API exploits
    └── cve_*.py                  # Python mock servers for CVE validation
```

### Large Assessment Output Strategy (DEFAULT for 40+ findings)

Write each scanner's findings IMMEDIATELY after delegation returns — never accumulate:
- Use `terminal` with `cat >> file << 'ENDOFFILE'` in batches (one category per append)
- Verify with `wc -l` after each append
- If heredoc fails (content has `&` or special chars), use `write_file` tool instead
- For 80+ findings, consider split files: `vulnerabilities-ac.md`, `vulnerabilities-sb.md`, etc. with an index in `vulnerabilities.md`

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
  nodejs: PENDING
  custom-crypto: PENDING
  mobile-code: PENDING

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

Before running all scanners, check recon.md and skip what doesn't apply:

| Tech Stack | Skip These |
|------------|-----------|
| No Solidity/Vyper | All web3-* (7 scanners) |
| No C/C++/Rust/native | memory |
| No IaC files (no *.tf, Dockerfile, K8s manifests, CI configs) | infra |
| No Helm/K8s deployment configs in repo | deployment-security |
| No file upload endpoints | file-path (keep path traversal checks) |
| No XML/SOAP | deserialization (keep JSON deser checks) |
| Pure API (no HTML) | client-side (keep open redirect) |
| No package.json / Node.js code | nodejs |
| No mobile code (no AndroidManifest, Info.plist, .dart, RN bundle) | mobile-code |

### Deployment Security Scanner (3v)

When Helm charts, K8s manifests, or Istio config exist in the repo, check:
- `AuthorizationPolicy` — which services can call which endpoints
- `PeerAuthentication` — mTLS mode (STRICT vs PERMISSIVE)
- `NetworkPolicy` — pod-to-pod communication restrictions
- `Ingress`/`VirtualService` — external exposure, path-based routing
- Service mesh sidecar injection — is it enforced?
- Secrets management — are secrets in Helm values or referenced from Vault/sealed-secrets?

If NO deployment configs exist in the repo, note this as a scope limitation (security may be enforced at cluster level but not visible here).

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
| 3t | web3-modern | `references/vuln-web3-modern.md` | Restaking, Account Abstraction (ERC-4337), L2/Rollup, Intent-based protocols, Foundry PoC templates |
| 3t | infra | `references/vuln-infra.md` | Terraform, Dockerfile, K8s, CI/CD, Helm |
| 3u | spring-boot | `references/vuln-spring-boot.md` | Actuator, security annotations, SpEL, mass assignment, Keycloak |
| 3v | deployment-security | (inline) | Helm values, Istio AuthorizationPolicy, NetworkPolicy, mTLS, PeerAuthentication |
| 3w | nodejs | `references/vuln-nodejs.md` | path.join traversal, require() RCE, Zip Slip, prototype pollution, vm escape, ReDoS |
| 3x | custom-crypto | `references/vuln-custom-crypto.md` | Proprietary validation, LCG, custom HMAC, Math.random(), homegrown tokens |
| 3y | mobile-code | `references/vuln-mobile-code.md` | Android/iOS decompiled code, React Native, Flutter, cert pinning, hardcoded secrets |
| — | (supplement) | `references/spring-boot-mass-assignment-patterns.md` | Map<String,Any> in DTOs, force-flag injection, validation checklist |
| — | (pattern) | `references/zero-auth-microservice-pattern.md` | Detection, reporting strategy, validation checklist for zero-auth services |
| — | (supplement) | `references/deployment-security-checks.md` | Helm values, Istio AuthorizationPolicy, NetworkPolicy, mTLS |

### Spring Boot Zero-Auth Detection (Fast Check)

For Spring Boot apps, run this early in recon to determine if auth exists at all:
```bash
# Check for Spring Security dependency
grep -r "spring-boot-starter-security\|spring-security" build.gradle* pom.xml
# Check for security annotations
grep -rn "@PreAuthorize\|@Secured\|@RolesAllowed\|@EnableWebSecurity\|SecurityFilterChain" --include="*.kt" --include="*.java"
# Check for custom auth filters
grep -rn "OncePerRequestFilter\|HandlerInterceptor\|WebFilter" --include="*.kt" --include="*.java" | grep -v test
```
If ALL return empty → mark as "Zero Auth" and apply the Zero-Auth Fast Path below.

### Zero-Auth Fast Path

When a service has ZERO authentication (no Spring Security, no custom filters, no Istio AuthorizationPolicy):

1. **Create ONE systemic finding** (Critical, CWE-306) with a table listing all controllers and their endpoints — NOT 20+ individual findings
2. **Create individual IDOR findings** ONLY for endpoints where object-level authorization matters even with service-to-service auth (e.g., transaction lookup by arbitrary ID, capture by blockingId)
3. **Create individual Critical findings** for highest-impact endpoints that warrant separate attention in remediation (BIFast transfers, bulk payroll, loan disbursement, FX rate updates)
4. **Skip creating separate findings** for each "no auth" endpoint — the systemic finding covers them
5. **Still scan other categories normally** (logic, data-exposure, etc. are independent of auth)
6. **In the report**, lead with the systemic auth gap as VULN-001, then list other findings separately
7. **During validation**, confirm zero-auth once (check all build files, interceptors, Helm/Istio config) — don't re-validate per endpoint

This reduces 21 findings to ~8-10 focused ones without losing signal.

Exception: If some endpoints have DIFFERENT risk levels (e.g., BIFast transfer vs health check), create 2-3 grouped findings by impact tier rather than one flat list.

### Special Patterns

| Pattern | Reference | When to Use |
|---------|-----------|-------------|
| Zero-auth microservice | `references/zero-auth-microservice-pattern.md` | Internal service with no Spring Security at all |

### Parallel Execution via Delegation

For large codebases, batch scanners into parallel delegate_task calls (3 per batch):
- **Batch 1**: access-control + spring-boot + data-exposure (P1 — run first, highest ROI)
- **Batch 2**: deserialization + logic + misconfig (P1 — run second)
- **Batch 3**: injection + ssrf + authn-session (P2)
- **Batch 4**: dependency + api + crypto + file-path + dos (P3)
- **Batch 5** (if Web3): web3-reentrancy + web3-arithmetic + web3-access
- **Batch 6** (if Web3): web3-mev + web3-token + web3-defi + web3-nft + web3-evm

**Pitfall:** Large reference file creation via delegate_task can timeout (600s limit). If a subagent times out, write the content directly in the main context instead of re-delegating.

**Pitfall:** Writing large vulnerability files via heredoc (`cat << 'EOF'`) fails when content contains `&` characters (shell interprets as backgrounding). Use `write_file` tool for report content, or split heredocs into smaller chunks avoiding `&`. For very large files (1000+ lines), write in multiple append operations.

**Pitfall:** The `execute_code` tool requires explicit `code` parameter — calling it without content causes repeated failures. When you need to run Python for data processing (e.g., parsing scanner results, making HTTP requests with regex extraction), always provide the code inline. For simple file operations, prefer `write_file` or `terminal` with heredoc.

**Pitfall:** macOS `grep` does not support `-P` (Perl regex). Use `grep -oE` with extended regex, or use Python/sed for complex pattern extraction. This matters when parsing SQLi output or scanner results on macOS.

**Pitfall:** When writing vulnerabilities.md with 50+ findings, the file content often exceeds what write_file can handle in a single call (context/token limits cause empty writes). Use `cat >> file << 'ENDOFFILE'` via terminal in batches (one scanner category per append). Verify with `wc -l` after each append.

**Practical batch sizing:** 3 scanners per batch is optimal. Each scanner subagent needs ~50-200 file reads. More than 3 per batch risks timeout.

**Pitfall:** Writing vulnerabilities.md after multiple scanners return can exceed single write_file limits. Strategy: write each scanner's findings as a SEPARATE file (`vulnerabilities-ac.md`, `vulnerabilities-sb.md`, etc.) immediately after each delegation returns, then create a short `vulnerabilities.md` index that references them. Alternatively, write in chunks using append mode or terminal `cat >> file`. Never defer writing — if a scanner returns findings, persist them immediately before running the next scanner.

**Pitfall:** For internal microservices with ZERO Spring Security (no `spring-boot-starter-security` dependency at all), the access-control scanner will produce 15-25+ findings because EVERY endpoint is unauthenticated. Group these by root cause ("No Spring Security dependency") in the report rather than listing each endpoint individually. The real finding is the systemic gap, not 20 instances of it.

### Output Strategy for Large Assessments

When running 4+ scanners that produce 40+ findings total, use this strategy:

1. **Write immediately after each scanner returns** — don't accumulate findings in memory
2. **Use terminal `cat >> file << 'ENDOFFILE'`** for appending scanner results (one category per append)
3. **Verify with `wc -l`** after each append to confirm write succeeded
4. **If heredoc fails** (due to `&` or special chars in content), use `write_file` tool instead
5. **For very large single writes** (500+ lines), split into multiple appends by section

Preferred file structure for 50+ findings:
```
./assessment/
├── vulnerabilities.md             # Single file, written in append chunks per scanner
├── validated-vulnerabilities.md   # Validation summary (compact)
└── security-review-report.md     # Final report (references vulnerabilities.md)
```

The single-file approach works if you append per scanner. The split-file approach (`vulnerabilities-ac.md`, `vulnerabilities-sb.md`, etc.) is fallback if single-file writes keep failing.

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

### Process

### Validation Batching Strategy

For large assessments (40+ findings), batch validation by risk tier:
1. **Critical findings** — validate individually, full data flow trace
2. **High findings** — batch by category (all AC together, all LG together), delegate 3 categories per batch
3. **Medium/Low findings** — spot-check 2-3 per category to confirm pattern, then accept rest if pattern holds

Typical delegation structure for validation:
- Batch 1: Access Control (confirm zero-auth premise, check for hidden filters/gateway)
- Batch 2: Business Logic (check MongoDB indexes, findAndModify atomicity, state guards)
- Batch 3: Spring Boot + Data Exposure + DoS (confirm configs, spot-check logging, verify no @Size)
- Batch 4: Injection + SSRF + Crypto + Dependency (version checks, config verification)

### Validation Steps

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
- **MongoDB unique indexes**: Check `@CompoundIndex(unique=true)` on models — these prevent double-spend/duplicate findings at DB level even without application-level checks. Search Mongock migrations too.
- **Mass assignment validation**: Check if `Map<String, Any>` fields are actually persisted AND used in business logic downstream (e.g., `additionalPayload?.get("force") as Boolean`). If just stored, downgrade. If controls logic, upgrade.
- **Race condition validation**: Check for `findAndModify` with preconditions vs simple `updateFirst`. The former is atomic; the latter has TOCTOU gaps.

**Reference:** `references/validation.md`

**Decision Trees:** See `references/validation-decision-trees.md` for framework-specific false-positive elimination (Spring Boot, React, Next.js).

**ptest Integration:** See `references/ptest-integration.md` for using external pentest findings to guide validation.

---

## Step 5: Reporting (`report`)

Compile validated findings into a professional deliverable.

**Gate:** security-review-report.md exists with all sections complete

**Process:**

1. **Executive Summary** — severity breakdown, top risks, key recommendations
2. **Attack Chains** — combine related findings into end-to-end exploit scenarios (e.g., "FX rate manipulation → buy/sell at fake rate"). Show 3-5 realistic attack paths with finding IDs chained.
3. **Detailed Findings** — each with CVSS vector, CWE, PoC, remediation code
4. **Remediation Roadmap** — prioritized by severity and effort (Phase 1: Immediate, Phase 2: High Priority, Phase 3: Hardening)
5. **Positive Security Observations** — what the app does well (5-8 items)
6. **Scope & Limitations** — what was/wasn't tested, items needing dynamic testing
7. **Methodology** — 5-step process description

### PoC Generation

Generate PoCs for all Critical and High findings where feasible:
- **API services (no auth)**: curl/bash scripts demonstrating the exploit
- **Race conditions**: concurrent curl with background jobs or Python `asyncio`/`threading`
- **Dependency CVEs**: Python mock servers simulating malicious responses
- **Data extraction**: Scripts that parse heapdump/responses for secrets
- **SQLi**: Python scripts using `subprocess` + `curl` + `re` for error-based extraction (avoids macOS grep -P issues)

Save to `./assessment/poc/` directory. Make shell scripts executable.

### PoC for SQLi (Error-Based Extraction Pattern)

When SQLi is confirmed via error-based technique (EXTRACTVALUE/UPDATEXML), use Python for reliable extraction:
```python
import subprocess, re
for i in range(50):
    cmd = ['curl', '-s', '-m', '10', URL, '-X', 'POST', '-d',
           f"param=' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT col FROM table LIMIT {i},1),0x7e))-- -&other=x"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    match = re.search(r"XPATH syntax error: '~([^']+)", result.stdout)
    if match:
        print(match.group(1).rstrip("'~"))
    else:
        break
```
This avoids shell quoting issues and macOS grep incompatibilities.

**Reference:** `references/reporting.md`

**Output:** `./assessment/security-review-report.md` + `./assessment/poc/`
**Output:** `./assessment/bug-bounty-report.md`

### Bug Bounty Platform Report Formats

When the target is a bug bounty program, generate a platform-specific report in addition to the standard security review report.

**Immunefi format** (`./assessment/immunefi-report.md`):
```markdown
## Brief/Intro
{One paragraph: what the bug is and what happens if exploited in production}

## Vulnerability Details
{Detailed explanation with code snippets. Make it obvious the vulnerability exists.
Include: vulnerable code, attack chain steps, why existing protections don't help.}

## Impact Details
{Detailed breakdown of losses. Map to program's in-scope impacts.
Quantify: how much can be stolen, how many users affected, which contracts.}

## References
{Links to: vulnerable contract on block explorer, source code on GitHub,
relevant documentation, Chainlink/protocol incident history}
```

**YesWeHack format** (`./assessment/ywh-report.md`):
```markdown
## Description
{What the vulnerability is and where it exists}

## Exploitation
{Step-by-step attack flow}

## PoC
{Working proof of concept — curl commands, Foundry test, or script}

## Risk
{Impact + likelihood assessment}

## Remediation
{Specific code fix with before/after}
```

**Key rules for bounty reports:**
- Map your impact to the program's EXACT severity classification wording
- Include the deployed contract address (block explorer link) as impacted asset
- PoC must be RUNNABLE — not pseudocode, not "theoretically possible"
- For web3: Foundry fork test that passes on mainnet fork
- One finding per submission (don't bundle multiple bugs)

---

## Step 5b: PoC Generation (Optional but Recommended for Internal Pentests)

After the report, generate PoCs for Critical and High findings that demonstrate real-world exploitability.

**When to generate PoCs:**
- Internal pentest engagements (developer buy-in requires proof)
- Findings that are "just a curl" (zero-auth services)
- Race conditions (need concurrent request scripts)
- Attack chains (multi-step sequences)

**PoC types by finding category:**
- **Zero-auth endpoints**: Shell scripts with curl commands
- **Race conditions**: Bash with background jobs (`&` + `wait`) or Python with threading
- **Dependency CVEs**: Python servers simulating malicious upstream responses
- **Mass assignment**: Curl with injected fields showing business logic bypass
- **Attack chains**: Numbered shell scripts showing step-by-step exploitation

**Output:** `./assessment/poc/` directory with executable scripts.

**Naming convention:** `poc_{finding_id}_{short_description}.sh` or `.py`

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
