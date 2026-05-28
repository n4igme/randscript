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

### 3. Map Severity to Platform Rubric

Different bug bounty platforms use different severity scales. Map findings to the target platform:

| Internal Severity | Immunefi | HackerOne | Bugcrowd |
|-------------------|----------|-----------|----------|
| **Critical** | Critical (fund loss >$1M or protocol insolvency) | Critical (CVSS 9.0–10.0) | P1 (Critical) |
| **High** | High (fund loss <$1M, significant impact) | High (CVSS 7.0–8.9) | P2 (High) |
| **Medium** | Medium (limited impact, conditional) | Medium (CVSS 4.0–6.9) | P3 (Medium) |
| **Low** | Low (informational, best practice) | Low (CVSS 0.1–3.9) | P4 (Low) |

**Platform-specific notes:**
- **Immunefi**: Severity is based on "Impact" (what can happen) not "Likelihood." A Critical requires direct fund loss or protocol-breaking impact. Always include a working PoC for Critical/High.
- **HackerOne**: Uses CVSS 3.1 vectors. Include the full vector string. Programs may have custom severity scales — check the policy.
- **Bugcrowd**: Uses VRT (Vulnerability Rating Taxonomy). Map findings to VRT categories for faster triage.
- **Code4rena**: Uses High/Medium/QA/Gas. High = assets at risk. Medium = assets not at direct risk but function/availability impacted. QA = low-risk/non-critical.

If the target platform is known, use their rubric in the report. If unknown, default to CVSS + internal severity.

### 4. Structure Final Report

Organize findings by severity, then by category. Add:
- CVSS score estimates
- CWE references
- Business impact context
- Remediation priority and effort estimates
- Items from `validated-vulnerabilities.md` "Needs Dynamic Testing" section into the report's Scope & Limitations

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

**Severity**: Critical | **CVSS**: {score} ({vector_string}) | **CWE**: CWE-{id}

<!-- CVSS 3.1 Vector Format: CVSS:3.1/AV:{N|A|L|P}/AC:{L|H}/PR:{N|L|H}/UI:{N|R}/S:{U|C}/C:{N|L|H}/I:{N|L|H}/A:{N|L|H}
     Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical
     Always include the vector string so reviewers can verify the score. -->
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

### Requires Dynamic Testing

Items from `validated-vulnerabilities.md` that could not be confirmed statically:

| ID | Title | What to Test | Why Static Analysis Is Insufficient |
|----|-------|-------------|-------------------------------------|
| {from validated-vulnerabilities.md "Needs Dynamic Testing" section} |

### Positive Security Observations

Document what the application does WELL. This builds credibility for the findings and helps stakeholders understand the overall posture:

- {e.g., "Consistent authentication checks across all 27 admin endpoints"}
- {e.g., "Proper use of parameterized queries via ORM — no SQL injection vectors"}
- {e.g., "Secrets managed via environment variables, none hardcoded in source"}
- {e.g., "RLS policies properly configured with appropriate access levels"}

Include 5-8 positive observations covering: auth, authz, input validation, secret management, error handling, and any other areas where the code demonstrates good security practices.
```

## Rules

- **Professional tone** — this is a deliverable for stakeholders.
- **Business context** — explain impact in terms non-security people understand.
- **Actionable remediation** — include code fixes and effort estimates.
- **Consistent severity** — re-validate all severity ratings for consistency.
- **Save to `./assessment/bug-bounty-report.md`** and confirm.
- **Do NOT print the full report to terminal.**
