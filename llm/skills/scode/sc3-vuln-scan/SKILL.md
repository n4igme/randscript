---
name: sc3-vuln-scan
description: "Step 3 of bug bounty workflow. Orchestrator that runs all vulnerability sub-scanners. Outputs vulnerabilities.md."
allowed-tools: Read Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Step 3: Vulnerability Scanning (Orchestrator)

This step is split into focused sub-scanners. Run them in order (or pick specific ones based on your threat model priorities):

## Sub-Skills

### Traditional Web/API Scanners (3a–3m)

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

### Web3 / Smart Contract Scanners (3w-a–3w-j)

| Step | Skill | Focus |
|------|-------|-------|
| 3w-a | `vuln-web3-reentrancy` | Reentrancy, unchecked external calls, delegatecall injection |
| 3w-b | `vuln-web3-arithmetic` | Integer overflow/underflow, precision loss, type truncation |
| 3w-c | `vuln-web3-access` | Access control, proxy/upgradeability, role management |
| 3w-d | `vuln-web3-mev` | Front-running/MEV, flash loan, oracle manipulation |
| 3w-e | `vuln-web3-token` | Token standard flaws, signature replay/malleability |
| 3w-f | `vuln-web3-defi` | AMM exploits, lending flaws, bridge attacks, governance |
| 3w-g | `vuln-web3-nft` | Metadata manipulation, randomness, royalty bypass, minting |
| 3w-h | `vuln-web3-evm` | Storage slots, returnbomb, dirty bits, phantom functions, gas griefing |
| 3w-i | `vuln-web3-restaking` | EigenLayer/Symbiotic restaking, AVS, slashing, operator delegation |
| 3w-j | `vuln-web3-aa` | Account Abstraction (ERC-4337), paymasters, smart accounts |
| 3w-k | `vuln-web3-l2` | L2/Rollup bridges, sequencer, cross-domain messaging |
| 3w-l | `vuln-web3-intents` | Intent/solver protocols, Dutch auctions, cross-chain intents |

### Systems & Infrastructure Scanners (3x-a–3x-c)

| Step | Skill | Focus |
|------|-------|-------|
| 3x-a | `vuln-dos` | ReDoS, algorithmic complexity, resource exhaustion, zip/XML bombs |
| 3x-b | `vuln-memory` | Buffer overflow, use-after-free, format strings (C/C++/Rust/native) |
| 3x-c | `vuln-infra` | Terraform, Dockerfile, K8s manifests, CI/CD pipelines, Helm charts |

### Platform-Specific Scanners (3p-a–3p-e)

| Step | Skill | Focus |
|------|-------|-------|
| 3p-a | `vuln-nodejs` | path.join traversal, Zip Slip, dynamic require, prototype pollution, vm escape |
| 3p-b | `vuln-spring-boot` | Actuator exposure, missing @PreAuthorize, SpEL injection, mass assignment |
| 3p-c | `vuln-custom-crypto` | Insecure PRNG, homegrown hashing, hardcoded keys, timing attacks |
| 3p-d | `vuln-mobile-code` | Android/iOS hardcoded secrets, insecure storage, WebView, cert pinning |
| 3p-e | `vuln-deployment-security` | Istio AuthorizationPolicy, mTLS, NetworkPolicy, Helm misconfig |

## Parallelism Guidance

Scanners within the same group are independent and can run in parallel. Scanners across groups are also independent unless noted.

**Parallel Group A** (can all run simultaneously — no shared state):
- `vuln-injection`, `vuln-access-control`, `vuln-data-exposure`, `vuln-ssrf`

**Parallel Group B** (can all run simultaneously):
- `vuln-deserialization`, `vuln-misconfig`, `vuln-logic`, `vuln-authn-session`

**Parallel Group C** (can all run simultaneously):
- `vuln-crypto`, `vuln-file-path`, `vuln-client-side`, `vuln-dependency`, `vuln-api`

**Parallel Group D** (all Web3 scanners — independent of each other):
- All `vuln-web3-*` scanners can run in parallel

**Parallel Group E** (systems + platform-specific — independent of each other):
- `vuln-dos`, `vuln-memory`, `vuln-infra`, `vuln-nodejs`, `vuln-spring-boot`, `vuln-custom-crypto`, `vuln-mobile-code`, `vuln-deployment-security`

Groups A–E are all independent of each other. The only ordering constraint is: run `sc1-recon` and `sc2-threat-model` before any scanner.

## Time/Effort Budget

Scale scanner effort to codebase size. These are guidelines — spend more time on threat-model priority targets, less on low-risk areas.

| Codebase Size | Per-Scanner Budget | Total Scan Budget |
|---------------|-------------------|-------------------|
| Small (<10K LOC) | 5–10 min | 1–2 hours |
| Medium (10K–50K LOC) | 10–20 min | 3–5 hours |
| Large (50K–200K LOC) | 15–30 min | 5–8 hours |
| Enterprise (200K+ LOC) | 20–45 min (scoped) | 8–12 hours (scoped) |

**Budget allocation by priority:**
- Priority 1 targets (from threat model): 40% of time
- Priority 2 targets: 30% of time
- Priority 3+ targets: 20% of time
- Exploratory/edge cases: 10% of time

**When to stop a scanner:**
- All priority targets from threat model have been checked
- No new patterns found in the last 5 minutes of searching
- Scanner has exceeded 2× its time budget without findings
- **Max findings per scanner: 7.** If you find more, keep the top 7 by severity and note "N additional lower-severity patterns observed but omitted." This prevents noise that sc4-validate must wade through.

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
/skill vuln-web3-defi
/skill vuln-web3-nft
/skill vuln-web3-evm
/skill vuln-web3-restaking
/skill vuln-web3-aa
/skill vuln-web3-l2
/skill vuln-web3-intents
/skill vuln-dos
/skill vuln-memory
/skill vuln-infra
/skill vuln-nodejs
/skill vuln-spring-boot
/skill vuln-custom-crypto
/skill vuln-mobile-code
/skill vuln-deployment-security
```

Or run only the ones relevant to your threat model's priority targets.

## Scanner Selection by Tech Stack

Before running all scanners, check `./assessment/recon.md` and skip scanners that don't apply:

| Tech Stack | Skip These Scanners | Prioritize These Scanners |
|------------|-------------------|---------------------------|
| No Solidity/Vyper/smart contracts | All `vuln-web3-*` (12 scanners) | — |
| No C/C++/Rust/native code | `vuln-memory` | — |
| No IaC files (no *.tf, Dockerfile, K8s manifests, CI configs) | `vuln-infra` | — |
| No file upload endpoints | `vuln-file-path` (still check path traversal) | — |
| No XML/SOAP processing | `vuln-deserialization` (still check JSON deserialization) | — |
| Pure API (no HTML rendering) | `vuln-client-side` (still check open redirect) | — |
| No third-party dependencies | `vuln-dependency` | — |
| No Node.js/JavaScript | `vuln-nodejs` | — |
| No Spring Boot/Java | `vuln-spring-boot` | — |
| No mobile app code (Android/iOS/RN/Flutter) | `vuln-mobile-code` | — |
| No K8s/Helm/Istio deployment configs | `vuln-deployment-security` | — |
| dangerouslySetInnerHTML/v-html found | — | `vuln-injection` (XSS focus) |
| Raw SQL or string interpolation in queries | — | `vuln-injection` (SQLi focus) |
| RLS policies with USING(true) or role from user input | — | `vuln-access-control` |
| fetch/axios with user-controlled URLs | — | `vuln-ssrf` |
| Admin/service-role client used in user-facing paths | — | `vuln-access-control` |
| Custom auth implementation (not framework-provided) | — | `vuln-authn-session` |

### Web3 Skip-Fast Check

Before invoking any `vuln-web3-*` scanner, run this single check:

```bash
find . -name "*.sol" -o -name "*.vy" | head -1
```

If no results → mark ALL Web3 scanners as `SKIPPED (no smart contract code)` in `scan-progress.md` and skip them entirely. This saves invoking 12 scanners individually just to have each one say "not applicable."

### Pre-Flight Verification Checks

Before running each scanner, do a 30-second heuristic check to confirm the attack surface exists. Skip or deprioritize scanners where the surface is absent:

```bash
# Before XSS-focused scanning (vuln-injection):
grep -r "dangerouslySetInnerHTML\|v-html\|\[innerHTML\]\|bypassSecurity" --include="*.tsx" --include="*.jsx" --include="*.vue" --include="*.html" . | grep -v node_modules | head -1

# Before SQLi scanning (vuln-injection):
grep -r "raw\|rawQuery\|execute.*\${\|\.query.*\${\|sequelize\.literal" --include="*.ts" --include="*.js" . | grep -v node_modules | head -1

# Before SSRF scanning (vuln-ssrf):
grep -r "fetch\|axios\|http\.get\|request(" --include="*.ts" --include="*.js" . | grep -v node_modules | grep -iE "req\.|param\.|body\.|query\." | head -1

# Before file upload scanning (vuln-file-path):
grep -r "multer\|formidable\|busboy\|upload\|multipart" --include="*.ts" --include="*.js" . | grep -v node_modules | head -1

# Before deserialization scanning (vuln-deserialization):
grep -r "xml\|xpath\|parseXml\|DOMParser\|yaml\.load\|pickle\|unserialize\|ObjectInputStream" . | grep -v node_modules | head -1
```

If a check returns no results, the scanner can still run (code patterns vary) but should deprioritize that attack surface and focus time on threat-model priority targets instead.

Each sub-skill appends its findings to `./assessment/vulnerabilities.md`.

## Positive Security Observations

While scanning, track what the application does WELL. Each scanner should note strong security patterns encountered:

```markdown
## Positive Observations
- {scanner}: {what's done well}
```

Append to `./assessment/vulnerabilities.md` at the end, under a `# Positive Security Observations` section:

| Category | What to Note |
|----------|-------------|
| Input validation | Consistent use of schema validation (Zod, Joi, class-validator) |
| SQL safety | All queries via ORM with parameterization, no raw SQL |
| Auth coverage | Every endpoint has auth middleware, no gaps found |
| Secret management | All secrets via env vars / secret manager, none hardcoded |
| Error handling | Generic error messages to users, detailed logs server-side only |
| Crypto | Strong algorithms (bcrypt/argon2 for passwords, AES-256-GCM for data) |
| Dependencies | All pinned to exact versions, no wildcard ranges |
| IaC | Least-privilege IAM, encryption at rest enabled, no public buckets |

These feed directly into sc5-report's "Positive Security Observations" section. Collecting them during scanning (when you're reading the code) is more accurate than trying to recall them at report time.

---

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

### Re-Running a Single Scanner

To re-run one scanner (e.g., after sc4-validate reveals a missed pattern):
1. Invoke the scanner again — its idempotency rule replaces its section in `vulnerabilities.md`
2. Re-run `sc4-validate` to incorporate the new/updated findings
3. Update `scan-progress.md` with the revised finding count

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

## ⚠️ Sub-Agent File Access

If delegating scanners to sub-agents (via subagent pipelines or parallel execution), note that sub-agents may lack file-reading tools. To avoid wasted compute:

- **Option A**: Read relevant file contents in the main agent and pass them in the sub-agent prompt
- **Option B**: Run scanners directly in the main agent context (sequential but reliable)
- **Option C**: Use sub-agents only for analysis of already-read content (pass code snippets, not file paths)

Sub-agents returning "cannot read files" is a common failure mode — plan for it.

## Next Step

After scanning, run `sc4-validate` to confirm findings before generating the final report.

## Context Budget Management

When scanning sequentially through many scanners, context window fills fast. To avoid losing findings to compaction:

- **Write findings to `vulnerabilities.md` immediately** after each scanner completes — don't accumulate in memory
- The file is the source of truth, not your context window
- If running low on context mid-scan, write current findings, then continue with remaining scanners in a fresh context (re-read `vulnerabilities.md` to avoid duplicates)
- Each scanner section is idempotent (see Idempotency Rule above) — safe to re-run after context reset

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
| 3w-a | vuln-web3-reentrancy | PENDING | — | |
| 3w-b | vuln-web3-arithmetic | PENDING | — | |
| 3w-c | vuln-web3-access | PENDING | — | |
| 3w-d | vuln-web3-mev | PENDING | — | |
| 3w-e | vuln-web3-token | PENDING | — | |
| 3w-f | vuln-web3-defi | PENDING | — | |
| 3w-g | vuln-web3-nft | PENDING | — | |
| 3w-h | vuln-web3-evm | PENDING | — | |
| 3w-i | vuln-web3-restaking | PENDING | — | |
| 3w-j | vuln-web3-aa | PENDING | — | |
| 3w-k | vuln-web3-l2 | PENDING | — | |
| 3w-l | vuln-web3-intents | PENDING | — | |
| 3x-a | vuln-dos | PENDING | — | |
| 3x-b | vuln-memory | PENDING | — | |
| 3x-c | vuln-infra | PENDING | — | |
| 3p-a | vuln-nodejs | PENDING | — | |
| 3p-b | vuln-spring-boot | PENDING | — | |
| 3p-c | vuln-custom-crypto | PENDING | — | |
| 3p-d | vuln-mobile-code | PENDING | — | |
| 3p-e | vuln-deployment-security | PENDING | — | |
```

After each scanner completes, update its row:
- `DONE (N findings)` — scanner ran, found N issues
- `SKIPPED (reason)` — not applicable to this codebase
- `FAILED (reason)` — scanner encountered an error

## Automation (Optional)

For automated progress tracking via Python:

```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.kiro/skills/sc3-vuln-scan/scripts"))
from scan_progress import init, done, skip, status, next_scanner

# Initialize (auto-skips inapplicable scanners)
init(".", has_web3=False, has_native=False, has_infra=True)

# After each scanner completes
done(".", "injection", findings=2)
skip(".", "web3-reentrancy", reason="no smart contracts")

# Check progress
status(".")
next_scanner(".")  # returns next pending scanner name
```

## References

Cross-cutting knowledge for deeper scanning:
- `~/.kiro/skills/references/pitfalls-false-positives.md` — FP prevention rules
- `~/.kiro/skills/references/proven-patterns.md` — Patterns that reliably find bugs
- `~/.kiro/skills/references/validation-decision-trees.md` — Framework-specific decision trees
