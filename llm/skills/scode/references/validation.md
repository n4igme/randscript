# Bug Bounty — Step 4: Validate Findings

Re-examine each vulnerability finding from Step 3 by going back to the source code. Confirm exploitability, eliminate false positives, and adjust severity ratings.

## Input

$ARGUMENTS

- If a path is provided, read that as the vulnerabilities file
- If no argument, read `./assessment/vulnerabilities.md`
- Also read `./assessment/recon.md` for entry point context
- If vulnerabilities.md is missing, tell the user to run `sc3-vuln-scan` first

## Process

### 0. Finding ID Renumbering

Sub-scanners use per-category prefixes (`VULN-INJ-001`, `VULN-AC-001`, etc.) for local tracking. During validation, renumber all confirmed findings to a single global sequence: `VULN-001`, `VULN-002`, ... ordered by severity (Critical first).

Maintain a mapping table in the output so findings can be traced back to their original scanner ID:

| Final ID | Original ID | Scanner |
|----------|-------------|---------|
| VULN-001 | VULN-INJ-002 | vuln-injection |
| VULN-002 | VULN-AC-001 | vuln-access-control |

### 1. For Each Finding, Re-read the Code

Do NOT rely on the snippet from vulnerabilities.md alone. Go back to the actual source file and read surrounding context (±50 lines). Check:

- Is the vulnerable code actually reachable from an external request?
- Are there middleware, interceptors, or wrappers that apply sanitization before the code is hit?
- Is there framework-level protection (e.g., ORM parameterization, auto-escaping templates)?
- Does the code path require preconditions an attacker can't easily meet?
- **Can the prerequisite state actually exist?** For workflow bypass findings, trace the data lifecycle: can the "vulnerable" state (e.g., an unpaid order with an invitation) actually be reached given how other endpoints create/modify that data? A missing check is NOT a vulnerability if the precondition is enforced elsewhere in the flow.
- **Does the rendering framework auto-escape?** For XSS findings in React/Vue/Angular, verify the exact rendering method. JSX `{value}` auto-escapes — only `dangerouslySetInnerHTML`/`v-html`/`[innerHTML]` are true sinks.

### 2. Trace Full Data Flow

For each finding, trace the complete path:
1. **Source**: Where does user input enter? (request param, header, body, file upload, etc.)
2. **Propagation**: How does it travel through the code? (variable assignments, function calls, transformations)
3. **Sanitization**: Is it validated, escaped, or transformed along the way?
4. **Sink**: Does tainted data actually reach the dangerous function?

If any step breaks the chain, the finding is a false positive.

#### Multi-Hop Taint Tracking

For complex data flows spanning multiple files/layers:

| Pattern | How to Trace | Example |
|---------|-------------|---------|
| Direct pass-through | A calls B with user input as argument | `controller.js:req.body.name` → `service.js:createUser(name)` → `db.js:query(name)` |
| Store-and-retrieve | Input stored in DB/cache, read later | `POST /profile` stores name → `GET /admin/users` reads and renders it (stored XSS) |
| Event-driven | Input published to queue, consumed elsewhere | `api.js` publishes to SQS → `worker.js` consumes and passes to `exec()` |
| Transform chain | Input transformed through multiple functions | `req.body.url` → `decodeURI()` → `new URL()` → `fetch()` (SSRF) |
| Config/env injection | Input reaches config that's read by another service | Upload `.env` → restart picks up malicious DB_HOST |
| Serialization boundary | Input serialized, deserialized in different context | JSON body → stored as blob → deserialized with `pickle.loads()` |

**Tracing procedure for multi-hop:**
1. Start at the sink (dangerous function)
2. Identify the variable reaching the sink
3. Search for all assignments to that variable (grep/find references)
4. For each assignment, check if it originates from user input or another function
5. Repeat until you reach an external source OR a sanitization point
6. Document each hop with `file:line` references

**When to stop:** If the chain crosses >5 hops without sanitization, it's likely real. If you find sanitization at ANY hop, verify it's sufficient for the specific sink type (e.g., HTML encoding doesn't prevent SQL injection).

### 3. Verify Exploitability

For each confirmed finding, answer:
- Can an unauthenticated attacker trigger it, or is auth required?
- What exact request/payload would exploit it?
- Are there rate limits, WAF rules, or other runtime controls that would block exploitation?
- Is the vulnerable endpoint deployed/enabled in production?

### 4. Re-assess Severity

After validation, re-evaluate:
- **Critical**: Confirmed RCE, full DB access, or auth bypass with no preconditions
- **High**: Confirmed data breach or privilege escalation, minimal preconditions
- **Medium**: Confirmed issue but requires specific conditions or has limited impact
- **Low**: Real issue but difficult to exploit or minimal impact
- **Informational**: Bad practice but no exploitable path found

### 5. Deduplicate Findings

Multiple scanners may report the same underlying issue from different angles. Merge duplicates:
- Same vulnerable code location reported by different scanners → keep the most complete write-up
- Same root cause manifesting in multiple endpoints → consolidate into one finding with multiple affected locations
- Overlapping categories (e.g., oracle manipulation found by both `vuln-web3-mev` and `vuln-web3-defi`) → merge into single finding

For each merged finding, note which scanners originally reported it.

### 6. Normalize Severity

Apply the severity rubric from `sc3-vuln-scan` consistently across all findings:
- **Critical**: RCE, full fund drain, complete auth bypass, protocol insolvency
- **High**: Significant data breach, privilege escalation, partial fund theft, account takeover
- **Medium**: Limited data exposure, restricted escalation, DoS, conditional exploits
- **Low**: Information disclosure, minor misconfig, requires unlikely preconditions

Apply modifiers:
- Upgrade if: unauthenticated, no user interaction, affects all users, automatable
- Downgrade if: requires privileged access, unlikely preconditions, limited blast radius, compensating controls

### 7. Classify Results

Place each finding into one of:
- **Confirmed** — validated, exploitable, keep in report
- **Downgraded** — real issue but lower severity than initially assessed
- **False Positive** — not exploitable, remove from report (document why)
- **Needs Dynamic Testing** — can't confirm statically, flag for manual testing

## Output

Save to `./assessment/validated-vulnerabilities.md`:

```markdown
# Validated Vulnerability Findings

**Date**: {date}
**Based on**: vulnerabilities.md
**Validation method**: Source code re-review and data flow tracing

## Validation Summary

| Original Count | Confirmed | Downgraded | False Positive | Needs Dynamic Testing | Duplicates Merged |
|---------------|-----------|------------|----------------|----------------------|-------------------|
| X | X | X | X | X | X |

## Confirmed Findings

### VULN-001: {Title}

**Severity**: {confirmed or adjusted severity}
**Original Severity**: {if changed}
**Category**: {e.g., SQL Injection}
**Location**: `{file}:{line}`
**CWE**: CWE-{number}

**Validation Notes**:
{What was checked to confirm this is real}

**Data Flow Trace**:
1. Input: {exact source}
2. Through: {path with file:line references}
3. Sink: {dangerous call at file:line}
4. Sanitization: {none / insufficient because...}

**Confirmed PoC**:
{Exact request or steps to exploit}

**Impact**:
{Validated impact}

**Remediation**:
```{lang}
{fixed code}
`` `

---

## Downgraded Findings

### VULN-XXX: {Title}

**Original Severity**: High → **Adjusted**: Medium
**Reason**: {why severity was lowered}

---

## False Positives

| ID | Title | Reason Eliminated |
|----|-------|-------------------|
| VULN-XXX | ... | {sanitization exists at middleware level} |

## Needs Dynamic Testing

| ID | Title | What to Test | Why Static Analysis Is Insufficient |
|----|-------|-------------|-------------------------------------|
| VULN-XXX | ... | ... | ... |

## Merged Duplicates

| Kept Finding | Merged From | Reason |
|-------------|-------------|--------|
| VULN-001 | VULN-012, VULN-018 | Same oracle manipulation root cause reported by vuln-web3-mev and vuln-web3-defi |
```

## Rules

- **Actually re-read the source files** — do not just rubber-stamp the previous step's output.
- **Trace complete data flows** with file:line references at each hop.
- **Be honest about false positives** — removing invalid findings strengthens the report.
- **Document your reasoning** for every classification decision.
- **Save to `./assessment/validated-vulnerabilities.md`** and confirm.
- **Do NOT print the full report to terminal.**