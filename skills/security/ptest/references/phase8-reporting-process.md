# Phase 8: Reporting Process Guide

## Automated Setup

Run first when entering this phase:

```python
from hermes_tools import read_file
exec(read_file("~/.hermes/skills/security/ptest/scripts/phase8_report.py")["content"])
```

---

## Overview

The report is the only deliverable the client keeps. A brilliant pentest with a bad report is indistinguishable from a mediocre pentest. This guide covers the process of writing, reviewing, and delivering the report — not just the template structure.

## Report Audiences

Every pentest report has multiple readers. Write for all of them:

| Audience | What They Need | Sections They Read | Language Level |
|----------|---------------|-------------------|----------------|
| CISO / Security Lead | Risk posture, what to fix first, budget justification | Executive Summary, Remediation Roadmap | Business + technical |
| Engineering Team | Exact reproduction steps, code-level fixes | Detailed Findings, Attack Narrative | Deep technical |
| Executive / Board | "Are we safe?" + regulatory implications | Executive Summary only (1 page) | Business only |
| Compliance / Audit | Regulatory mapping, evidence of testing | Scope & Methodology, Risk Matrix | Formal, evidence-based |
| Project Manager | Timeline, effort, what's blocked | Remediation Roadmap, priorities | Action-oriented |

## Writing Process

### Step 1: Findings Assembly (30% of Phase 8 time)

```
1. Collect all findings from findings-log.md
2. Verify each finding has:
   ☐ Complete template (all fields filled)
   ☐ Evidence attached (screenshot, response, command output)
   ☐ Reproducible steps (someone else can follow them)
   ☐ CVSS score calculated (not guessed)
   ☐ Environment tag (prod/nonprod/experiment/all)
   ☐ Verification status = Confirmed
   
3. Remove unverified findings → move to "Potential Issues" appendix
4. Sort by severity (Critical → Info)
5. Check for duplicates (same root cause, different manifestations)
   → Merge into single finding with multiple affected assets
```

### Step 2: Attack Chain Integration (15% of Phase 8 time)

```
1. Read attack-chains.md from Phase 6-7
2. For each chain:
   - Write the narrative version (story form, 2-3 paragraphs)
   - Create the visual flow diagram
   - Map to remediation (which fix breaks which chain?)
3. Identify the "headline chain" — the one for the executive summary
4. Ensure chain findings are cross-referenced in Detailed Findings
```

### Step 3: Remediation Prioritization (20% of Phase 8 time)

**Don't just list fixes. Prioritize them.**

#### Prioritization Matrix

| Factor | Weight | Score 3 | Score 2 | Score 1 |
|--------|--------|---------|---------|---------|
| Severity | 3x | Critical/High | Medium | Low/Info |
| Exploitability | 2x | Trivial (script kiddie) | Moderate (skilled attacker) | Difficult (nation-state) |
| Blast Radius | 2x | All users/systems | Subset of users | Single user/system |
| Fix Complexity | 1x | Config change (hours) | Code change (days) | Architecture change (weeks) |
| Regulatory Risk | 2x | Mandatory disclosure | Audit finding | Best practice |

**Priority = Σ(Factor × Weight) — higher score = fix first**

#### Remediation Tiers

```markdown
## Remediation Roadmap

### Immediate (1-7 days) — MUST fix before next release
<!-- Only Critical findings and chain-breaking fixes -->
| # | Finding | Fix | Owner | Effort |
|---|---------|-----|-------|--------|
| 1 | FINDING-1: Heapdump exposed | Require auth on all actuator endpoints | Platform team | 2h |
| 2 | FINDING-4: Prod credential reuse | Rotate all service account tokens, unique per env | DevOps | 4h |

### Short-term (1-4 weeks) — Next sprint
<!-- High findings and defense-in-depth improvements -->
| # | Finding | Fix | Owner | Effort |
|---|---------|-----|-------|--------|

### Medium-term (1-3 months) — Planned work
<!-- Medium findings and architectural improvements -->
| # | Finding | Fix | Owner | Effort |
|---|---------|-----|-------|--------|

### Long-term (3-6 months) — Strategic improvements
<!-- Low findings, hardening, and process changes -->
| # | Finding | Fix | Owner | Effort |
|---|---------|-----|-------|--------|
```

#### Handling "Fix Everything Immediately" Pressure

When the client asks "which ones do we fix first?" and everything seems urgent:

```
1. Identify chain-breaking fixes — one fix that breaks multiple attack chains
   → These are ALWAYS highest priority (maximum ROI)

2. Identify quick wins — high severity + low fix effort
   → Second priority (visible progress, builds confidence)

3. Identify architectural fixes — one change that prevents entire classes of bugs
   → Third priority (long-term value, but takes time)

4. Everything else — individual fixes for individual findings
   → Prioritize by severity, then by exploitability
```

### Step 4: Executive Summary Writing (15% of Phase 8 time)

The executive summary is the most important page in the report. Most stakeholders read ONLY this.

#### Structure

```markdown
## Executive Summary

### Engagement Overview
{One sentence: who, what, when, scope}

### Key Findings
| Severity | Count |
|----------|-------|
| Critical | X |
| High | X |
| Medium | X |
| Low | X |
| Info | X |

### Critical Risk
{2-3 sentences describing the worst attack chain in business terms. No jargon.}

Example: "An unauthenticated attacker on the internet can access production customer 
data (45,000 records including national ID numbers) through a four-step attack chain 
that exploits exposed debugging endpoints and shared credentials between test and 
production environments."

### Security Posture Assessment

**Strengths:**
- {What the client does well — always include positives}
- {E.g., "Production applications enforce JWT authentication consistently"}
- {E.g., "WAF blocks common attack patterns on primary endpoints"}

**Weaknesses:**
- {Top 3 systemic issues, not individual findings}
- {E.g., "Test environments share credentials with production"}
- {E.g., "Debugging endpoints exposed without authentication"}

### Immediate Actions Required
1. {Most urgent fix — one sentence}
2. {Second most urgent — one sentence}
3. {Third — one sentence}
```

#### Executive Summary Anti-Patterns

| Don't | Do |
|-------|-----|
| "We found 47 vulnerabilities" | "We demonstrated full production access via 4-step attack chain" |
| "CVSS 9.8 Critical" | "An attacker can steal customer data without logging in" |
| "Misconfigured Spring Boot Actuator" | "Debugging tools left accessible on the internet expose internal secrets" |
| "Recommend implementing RBAC" | "Require authentication on all management endpoints (2-hour fix)" |
| Only negatives | Include what's working well — builds trust and credibility |

### Step 5: Technical Review (10% of Phase 8 time)

Before delivery, verify:

```markdown
## Pre-Delivery Checklist

### Accuracy
- [ ] Every finding is reproducible right now (not just when you tested it)
- [ ] CVSS scores are calculated, not guessed (use calculator)
- [ ] Environment tags are correct (prod vs nonprod)
- [ ] No findings based solely on version numbers without verification
- [ ] Attack chains are logically sound (each step actually enables the next)

### Completeness
- [ ] All mandatory techniques from each phase are accounted for
- [ ] Skipped techniques are documented with reasons
- [ ] Scope exclusions are noted
- [ ] Time constraints are documented (what wasn't tested)
- [ ] Positive findings included (what's working well)

### Sensitivity
- [ ] No plaintext production credentials in the report
- [ ] Customer PII redacted in evidence (show structure, not data)
- [ ] Internal IPs/hostnames — check if client wants these redacted
- [ ] Your own test credentials removed
- [ ] Evidence files don't contain more data than needed

### Formatting
- [ ] Consistent severity labels (Critical, not CRITICAL or Crit)
- [ ] Finding IDs sequential and referenced correctly
- [ ] Screenshots are readable (not tiny, not blurry)
- [ ] Code blocks are syntax-highlighted
- [ ] Table of contents matches actual sections
- [ ] Page numbers (if PDF)
```

### Step 6: Delivery & Debrief (10% of Phase 8 time)

#### Delivery Format

| Format | When | Notes |
|--------|------|-------|
| PDF | Formal delivery, compliance, archival | Standard for most engagements |
| Markdown | Technical teams, iterative review | Easy to diff, version control |
| Jira tickets | When client wants findings as actionable items | Use `/parse-finding` for each |
| Presentation | Board/executive debrief | 10-15 slides max, focus on chains |

#### Debrief Meeting Structure (if applicable)

```
1. Executive summary (5 min)
   - Headline finding/chain
   - Overall posture assessment
   
2. Demo of critical chain (10 min)
   - Live or recorded walkthrough
   - Show the business impact, not the technical steps
   
3. Findings walkthrough (20 min)
   - Critical and High only (unless time permits)
   - Group by theme, not by ID number
   
4. Remediation discussion (15 min)
   - Priority order
   - Quick wins vs architectural changes
   - Who owns what
   
5. Q&A (10 min)
   - Expect pushback on severity ratings
   - Expect "but we have a WAF" responses
   - Expect "is this really exploitable?" questions
```

#### Handling Client Pushback

| Pushback | Response |
|----------|----------|
| "This is just a test environment" | "The test environment credential gave us production access. Environment isolation is the finding." |
| "We have a WAF" | "We bypassed the WAF using [technique]. The WAF is a layer, not a solution." |
| "Nobody would find this" | "We found it in [X hours]. Automated scanners find actuator endpoints. This is not obscurity." |
| "Can you lower the severity?" | "The CVSS score is calculated, not subjective. I can add context about mitigating factors in the description." |
| "We're already fixing this" | "Great — I'll note the planned remediation. The finding stays in the report for completeness." |
| "This requires authentication" | "We obtained authentication through [chain]. The auth requirement is bypassed by the earlier finding." |

#### Post-Delivery

```
1. Send report via secure channel (encrypted email, secure portal)
2. Confirm receipt
3. Offer 1-week window for questions/clarifications
4. Schedule retest if requested (typically 2-4 weeks after remediation)
5. Archive engagement materials (see cleanup command)
```

## Report Quality Indicators

### Good Report Signs
- Executive can understand the risk without technical knowledge
- Engineer can reproduce every finding without asking questions
- Remediation roadmap has clear owners and effort estimates
- Attack chains tell a story, not just list findings
- Positive controls are acknowledged (builds trust)

### Bad Report Signs
- All findings are "Critical" (severity inflation)
- Steps to reproduce say "use Burp Suite" without specifics
- Remediation is generic ("implement security best practices")
- No attack narrative — just a list of disconnected findings
- Evidence is screenshots of tool output without explanation
- Report is 100+ pages with no executive summary

## Report Metrics

Track these for continuous improvement:

```markdown
## Engagement Metrics (include in report appendix)

| Metric | Value |
|--------|-------|
| Engagement duration | X days |
| Total findings | X |
| Critical/High/Medium/Low/Info | X/X/X/X/X |
| Attack chains identified | X |
| Longest chain (steps) | X |
| Time to first Critical finding | Xh |
| Phase time allocation (actual vs planned) | See breakdown |
| Techniques skipped (time constraint) | X |
| Scope coverage estimate | X% of assets tested |
```

## Integration with Engagement Workflow

### Continuous Documentation (Phases 1-7)

The report should NOT be written from scratch in Phase 8. Throughout the engagement:

- **Phase 1-5:** Findings documented in real-time using the Finding Template
- **Phase 6:** Attack chains documented as they're discovered
- **Phase 7:** Impact amplification and attack path diagrams created
- **Phase 8:** Assembly, narrative writing, and polish

If you've been documenting throughout, Phase 8 is 70% assembly and 30% writing. If you haven't, Phase 8 is painful and you'll miss details.

### Files That Feed Into the Report

| Source File | Report Section |
|-------------|---------------|
| `findings-log.md` | Section 4 (Summary) + Section 5 (Detailed) |
| `attack-chains.md` | Section 6 (Attack Narrative) |
| `credential-inventory.md` | Section 5 (credential findings) + Section 6 (chain context) |
| `post-exploit/attack-path.md` | Section 6 (diagrams) |
| `post-exploit/data-classification.md` | Section 10 (Risk Matrix) |
| `scope.md` | Section 2 (Scope & Methodology) |
| `state.yaml` (time tracking) | Appendix (Engagement Metrics) |
| Phase checklists | Section 2 (methodology evidence) |

## Pitfalls (Phase 8 Specific)

- **Don't write the report from memory.** Use your findings log, checklists, and evidence files. Memory is unreliable after 5 days of testing.
- **Don't inflate severity to look impressive.** Clients who get burned by severity inflation stop trusting pentest reports entirely. Be honest.
- **Don't skip positive findings.** "Your JWT validation is correctly implemented across all services" builds credibility and helps the client understand what's working.
- **Don't use passive voice for findings.** "The endpoint was found to be accessible" → "An unauthenticated attacker can access the endpoint." Active voice communicates risk.
- **Don't submit without proofreading.** Typos and formatting errors undermine credibility. If you can't get the report right, why should they trust your technical findings?
- **Don't include raw tool output as evidence.** Annotate screenshots, highlight relevant response lines, explain what the reader is looking at.
- **Don't forget the "so what?"** Every finding needs an impact statement that a non-technical person can understand. "Heapdump exposed" means nothing to a CEO. "Internal passwords downloadable from the internet" does.
- **Retest findings before finalizing.** If possible, verify Critical/High findings are still reproducible on the last day. Clients sometimes fix things mid-engagement without telling you.
