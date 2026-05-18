---
name: sc5-report
description: "Step 5 of bug bounty workflow. Compile validated vulnerability findings into a polished final report. Outputs bug-bounty-report.md."
allowed-tools: Read Bash(cat *) Bash(ls *) Write
argument-hint: <path to validated-vulnerabilities.md, defaults to ./assessment/validated-vulnerabilities.md>
---

# Bug Bounty — Step 5: Final Report

Compile the validated vulnerability findings into a professional bug bounty submission report with executive summary, detailed findings, and remediation roadmap.

## Input

$ARGUMENTS

- If a path is provided, read that as the validated vulnerabilities file
- If no argument, read `./assessment/validated-vulnerabilities.md`
- Also read `./assessment/recon.md` and `./assessment/threat-model.md` for context
- If validated-vulnerabilities.md is missing, tell the user to run `sc4-validate` first

## Process

### 1. Review All Findings

Read validated-vulnerabilities.md and for each confirmed finding:
- Verify severity assignment is consistent
- Ensure descriptions are clear to someone unfamiliar with the codebase
- Check that PoCs are complete and reproducible
- Confirm remediation is actionable

### 2. Compile Executive Summary

- Total findings by severity
- Top risks in business terms (not just technical)
- Overall security posture assessment
- Key recommendations (top 3 actions)

### 3. Structure Final Report

Organize findings by severity, then by category. Add:
- CVSS score estimates
- CWE references
- Business impact context
- Remediation priority and effort estimates

## Output

Save to `./assessment/bug-bounty-report.md`:

```markdown
# Bug Bounty Report

**Target**: {repository}
**Assessment Date**: {date}
**Methodology**: Static source code analysis
**Scope**: {languages, frameworks, components}

---

## Executive Summary

{2-3 paragraphs: what was found, overall risk level, top recommendations}

### Risk Overview

| Severity | Count | Examples |
|----------|-------|----------|
| Critical | X | {brief titles} |
| High | X | {brief titles} |
| Medium | X | {brief titles} |
| Low | X | {brief titles} |

### Top Recommendations

1. {Most impactful fix}
2. {Second priority}
3. {Third priority}

---

## Detailed Findings

### [CRITICAL-001] {Title}

**Severity**: Critical | **CVSS**: {score} | **CWE**: CWE-{id}
**Location**: `{file}:{line}`

**Description**:
{Clear explanation}

**Vulnerable Code**:
```{lang}
{snippet}
`` `

**Attack Scenario**:
{Step-by-step exploitation}

**Impact**:
{Business and technical impact}

**Remediation**:
```{lang}
{fixed code}
`` `

**Effort**: {Low/Medium/High}

---

{Repeat for all findings, grouped: Critical → High → Medium → Low}

## Remediation Roadmap

| Priority | Finding | Fix | Effort | Timeline |
|----------|---------|-----|--------|----------|
| 1 | CRITICAL-001 | ... | Low | Immediate |
| 2 | HIGH-001 | ... | Medium | 1 week |
...

## Methodology

- Step 1: Codebase reconnaissance (assessment/recon.md)
- Step 2: Threat modelling with STRIDE (assessment/threat-model.md)
- Step 3: Targeted vulnerability scanning by priority (assessment/vulnerabilities.md)
- Step 4: Finding validation and false positive elimination (assessment/validated-vulnerabilities.md)
- Step 5: Report compilation

## Scope & Limitations

- Static analysis only — no runtime testing performed
- {Any directories/components excluded}
- {Any areas that need dynamic testing to confirm}
```

## Rules

- **Professional tone** — this is a deliverable for stakeholders.
- **Business context** — explain impact in terms non-security people understand.
- **Actionable remediation** — include code fixes and effort estimates.
- **Consistent severity** — re-validate all severity ratings for consistency.
- **Save to `./assessment/bug-bounty-report.md`** and confirm.
- **Do NOT print the full report to terminal.**
