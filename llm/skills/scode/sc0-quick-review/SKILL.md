---
name: sc0-quick-review
description: "Lightweight 30-min security gut-check. Runs recon + top 5 scanners, outputs quick-review.md. Escalates to full pipeline on High+ findings."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to code repository to scan>
---

# Quick Security Review

Lightweight 30-minute security assessment. Skips threat model, runs only the top 5 highest-ROI scanners.

## When to Use

- Initial triage of a new codebase
- Time-constrained reviews
- PR-level security spot-checks
- Deciding whether a full assessment is warranted

## Input

$ARGUMENTS

- If a path is provided, scan that directory
- If no argument, scan the current working directory

## Flow

```
Recon (5 min) → Top-5 Scan (20 min) → Inline Report (5 min)
```

## Process

### 1. Quick Recon (5 min)

Identify in 5 minutes:
- Languages and frameworks (from config files)
- Entry points (routes, handlers, resolvers)
- Auth mechanism (middleware, decorators, guards)
- Sensitive data stores (DB models, file handling)

Do NOT write a full recon.md — keep notes in memory for scanner targeting.

### 2. Top 5 Scanners (20 min, 4 min each)

Run these in order — they find 80% of real bugs:

| # | Focus | What to Check |
|---|-------|--------------|
| 1 | **Access Control** | Every endpoint with an ID param — does it verify ownership? Missing auth middleware? |
| 2 | **Injection** | Raw SQL/eval/exec with user input? Framework protections in place? |
| 3 | **Data Exposure** | Hardcoded secrets? Verbose errors? PII in logs? |
| 4 | **Auth & Session** | JWT validation? Session fixation? Password reset flaws? |
| 5 | **SSRF** | User-controlled URLs passed to HTTP clients? |

For each scanner:
- Check the 3-5 highest-risk entry points (from recon)
- Apply framework-aware false-positive rules (React auto-escaping, ORM parameterization, etc.)
- If no findings after 4 min, move on

### 3. Report (5 min)

## Output

Save to `./assessment/quick-review.md`:

```markdown
# Quick Security Review

**Target**: {repo path}
**Date**: {date}
**Time spent**: ~30 min
**Method**: Top-5 scanner quick assessment

## Summary

| Severity | Count |
|----------|-------|
| Critical | X |
| High | X |
| Medium | X |
| Low | X |

## Findings

### QR-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Category**: {Access Control / Injection / Data Exposure / Auth / SSRF}
**Location**: `{file}:{line}`
**Confidence**: {High/Medium/Low}

**Description**: {1-2 sentences}

**Evidence**:
```{lang}
{code snippet}
`` `

**Remediation**: {1-2 sentences}

---

## Positive Observations

- {What the codebase does well}

## Recommendation

{ESCALATE to full pipeline / SUFFICIENT for this scope / MONITOR specific areas}
```

## Escalation Rule

If quick-review finds any **High or Critical** finding → recommend full pipeline:

```
Recommend: Run full assessment pipeline
  /skill sc1-recon
  /skill sc2-threat-model
  /skill sc3-vuln-scan
  /skill sc4-validate
  /skill sc5-report
```

## Rules

- **Strict 30-min budget** — don't deep-dive. Note "needs further investigation" and move on.
- **Framework-aware** — same FP prevention rules as full scanners (React, ORM, Supabase, etc.)
- **File:line references** on every finding.
- **Honest about limitations** — state what was NOT checked.
- **Save to `./assessment/quick-review.md`** and confirm.
