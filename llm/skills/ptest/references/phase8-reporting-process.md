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

### Reassessment Re-Verification Checklist (MANDATORY)

Before writing a reassessment report, re-verify ALL previous findings. Do NOT rely on memory or previous session notes — test each one fresh.

**Procedure:**

1. **Load previous findings list** — read the last report's findings summary
2. **For EACH finding, re-test the exact PoC:**

```bash
# Template: replay original PoC verbatim
curl -sk "[original_url]" -w "\n[HTTP %{http_code}]"
# Compare: same response as before? Fixed? Partially fixed?
```

3. **Classify each finding's current status:**

| Status | Criteria | Action |
|--------|----------|--------|
| ✅ Fixed | Returns 401/403/404 where it previously returned 200/data | Document as fixed |
| ⚠️ Partially fixed | Fixed on one gateway but not another, or fixed for GET but not POST | Document as partially fixed — still a finding |
| ❌ Unfixed | Same response as previous round | Document as persistent — severity unchanged or upgraded |
| 🔄 Changed | Different response but still vulnerable (e.g., WAF added but bypassable) | Document new state + bypass |
| 💀 Removed | Host no longer resolves or returns connection refused | Document as decommissioned |

4. **Test ALL gateways/paths to the same backend** — a fix on one gateway doesn't mean all gateways are fixed (BFI lesson: prod.bfi fixed but prod.bravo still vulnerable)

5. **Test adjacent endpoints** — if `/master/v1/general` was fixed, check `/master/v1/bank`, `/master/v1/address/province`

6. **Document in coverage matrix format:**

```markdown
| R(N-1) ID | Title | Previous | Current | Gateway Tested | Notes |
|-----------|-------|----------|---------|----------------|-------|
| F-1 | Unauth API | Critical | ❌ Unfixed | prod.bravo | POST still creates records |
| F-14 | Camunda BPM | Medium | ✅ Fixed | prod.bravo | Returns 404 (removed) |
```

**Exit gate:** Re-verification matrix must be complete (all previous findings tested) before writing the report. Missing re-verification = incomplete reassessment.

**BFI Finance lesson (Round 4, May 2026):** Almost skipped re-verifying e-pmo2 (SQLi), Camunda, and ArangoDB. Turned out 2 were fixed (Camunda removed, e-pmo2 WAF-blocked) — would have incorrectly reported them as unfixed without re-testing.

---

### Report Writing Process

### Step 0: Exclusion Cross-Check (MANDATORY before any submission)

Before writing ANY report, cross-check every finding against the program's exclusion list:

```
For EACH finding:
  1. Read scope.md "Exclusions (Not Eligible)" section
  2. Ask: "Does this finding match ANY exclusion category?"
  3. If YES → flag it, DO NOT submit (or reframe to avoid the exclusion)
  4. If GREY AREA → assess whether the IMPACT exceeds the exclusion scope
```

**Common exclusion traps:**
| Exclusion | What it covers | What it does NOT cover |
|-----------|---------------|----------------------|
| "Exposing application info on server" | Version banners, server headers, path disclosure | Exposed internal infrastructure enabling further attack, leaked credentials, API schema with write operations |
| "Security/CSP header related" | Missing X-Frame-Options, HSTS, CSP | CORS misconfig that enables cross-origin data theft |
| "URL Redirection" | Simple open redirects | OAuth redirect_uri manipulation, SSRF via redirect |
| "Clickjacking" | Basic UI redress | Clickjacking that bypasses auth actions |
| "Page Modulation with Error Pages" | Custom 404 pages | Verbose errors leaking stack traces, DB queries, credentials |

**Decision framework for grey-area findings:**
- Is the finding JUST information, or does it ENABLE something? (enable → report)
- Can the finding be chained with another to produce higher impact? (chain → report the chain)
- Does the finding involve WRITE access or state change? (write → always report)
- Would remediating this finding require code/config change beyond adding a header? (yes → report)

**LINE WORKS example:** "Exposing application info on server" exclusion exists. FINDING-2 (internal URLs) alone might be excluded. But FINDING-3 (GraphQL with write operations reaching backend) and FINDING-4 (arbitrary log injection = write access) are clearly NOT excluded — they demonstrate unauthorized functionality access, not mere information exposure.

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

## Bug Bounty Resubmission Strategy (Rejected Reports)

When a report is rejected or has limited remaining submissions:

### Chain Consolidation Pattern

When individual findings are rejected but the underlying vulnerabilities are valid:

1. **Combine related findings into attack chains** — programs prefer chains over individual low/medium findings
2. **Change the entry point** — if finding X was rejected, use finding Y as the entry point and reference X as "additional impact" within the narrative
3. **Maximize impact per submission** — each report should tell a complete attack story from initial access to business impact
4. **Attach interactive PoCs** — HTML files that demonstrate cross-origin exploitation are more convincing than curl commands alone

### Resubmission Rules

- **Never resubmit the same finding with the same entry point** — triagers remember
- **Reframe rejected findings as supporting evidence** in a larger chain, not as the primary vulnerability
- **Pick a different CWE/vulnerability type** for the primary classification (e.g., "Information Disclosure" rejected → resubmit as "Broken Access Control" if write access exists)
- **Use the strongest finding as Report 1** (highest CVSS, clearest impact)
- **For "Payload" field on forms** — use the chain's entry point, not the rejected finding's endpoint
- **Check program exclusions BEFORE choosing bug type** — if "public API keys" is excluded, frame around what the key DOES (unauthorized write), not what it IS (exposed key)
- **Frame around IMPACT not EXPOSURE** — "I can write to your production analytics" beats "I found a token in a source map"

### Cross-Program Scope Awareness

When a chain spans multiple domains that belong to DIFFERENT bug bounty programs:
- **NEVER combine assets from different programs in one report** — different triagers, different scopes
- **Submit to the program that owns the highest-impact endpoint**
- **Reference other-program assets only as "attack path" context** — e.g., "token was obtained from [other domain]" without making that the primary finding
- **One primary asset per report** — YesWeHack and most platforms enforce this

Example: Source map on `*.gopayapi.com` (GoTo Financial program) yields token that writes to `*.gojekapi.com` (Gojek program) → submit to Gojek program with `*.gojekapi.com` as asset, mention source map as attack vector only.

### Submission Form Field Strategy

| Field | Strategy |
|-------|----------|
| Bug type | Pick the class describing IMPACT, not root cause |
| Vulnerable part | Endpoint where exploitation happens (not where recon started) |
| Payload | For access control: the auth header/token. For CORS: `Origin: https://evil.com` |
| Title | Focus on impact, avoid mentioning excluded vulnerability classes |
| Technical environment | "Any (curl/Python, no special setup)" for server-side issues |
| Asset | Must match the program's scope — verify domain belongs to THIS program |

### Example (GoPay YWH 2026)

Source map reports (1A, 1B) rejected → resubmitted as:
- Chain 1: ArgoCD Config Disclosure + Device Code Flow (entry: POST /api/dex/device/code) — High 8.1, bug type: Auth Bypass
- Chain 2: Unauthorized Write to Event Pipeline (entry: POST /api/v1/events) — bug type: Broken Access Control

Key lessons:
- Source map became "attack vector" context, not the primary finding
- CORS/debug dropped entirely from Chain 2 because it's a different asset/program
- "Information Disclosure" bug type avoided — program excludes "public API keys" and pure disclosure
- Token framed as "grants unauthorized write access" not "exposed in source map"
- Each report targets ONE program with ONE primary asset

## Pitfalls (Phase 8 Specific)

- **Don't write the report from memory.** Use your findings log, checklists, and evidence files. Memory is unreliable after 5 days of testing.
- **Don't inflate severity to look impressive.** Clients who get burned by severity inflation stop trusting pentest reports entirely. Be honest.
- **Don't skip positive findings.** "Your JWT validation is correctly implemented across all services" builds credibility and helps the client understand what's working.
- **Don't use passive voice for findings.** "The endpoint was found to be accessible" → "An unauthenticated attacker can access the endpoint." Active voice communicates risk.
- **Don't submit without proofreading.** Typos and formatting errors undermine credibility. If you can't get the report right, why should they trust your technical findings?
- **Don't include raw tool output as evidence.** Annotate screenshots, highlight relevant response lines, explain what the reader is looking at.
- **Don't forget the "so what?"** Every finding needs an impact statement that a non-technical person can understand. "Heapdump exposed" means nothing to a CEO. "Internal passwords downloadable from the internet" does.
- **Retest findings before finalizing.** If possible, verify Critical/High findings are still reproducible on the last day. Clients sometimes fix things mid-engagement without telling you.

## Platform Submission Checklists

After all phases pass and reports are written, use the appropriate checklist to submit findings. Don't let reports sit idle — submit promptly while findings are still fresh and reproducible.

### IssueHunt Submission

```
Pre-submission:
  □ Verify program UUID URL is correct (https://issuehunt.io/programs/{uuid})
  □ Confirm program is still accepting submissions (open the page in browser — SPA requires JS)
  □ Cross-check each finding against program exclusions one final time
  □ Verify all PoCs still work (re-run scripts, confirm HTTP responses match report)

Per-report submission:
  □ Title: concise impact statement (not vulnerability class name)
  □ Description: Summary → Exploitation → PoC → Risk → Remediation
  □ Severity: matches CVSS score (don't over-inflate)
  □ PoC: include script OR step-by-step with actual tested values
  □ Attach supporting files (HTML PoC, screenshots) if applicable
  □ Asset: exact subdomain/endpoint affected

Post-submission:
  □ Note submission IDs in findings-log.md
  □ Set calendar reminder for 7-day follow-up if no response
  □ Do NOT disclose publicly until resolved or 90-day deadline
```

### YesWeHack Submission

```
Pre-submission:
  □ Verify program slug and scope on platform
  □ Check remaining submission credits (some programs limit)
  □ Cross-check exclusions (URL Redirection, Clickjacking, CSP headers are common)

Per-report submission:
  □ Title: "[Asset] - [Impact]" format
  □ Scope/Asset: select from dropdown (must match program scope exactly)
  □ Bug type: pick impact-based class, not root cause
  □ Description sections: Description, Exploitation, PoC Steps, Risk, Remediation
  □ Technical environment: specify OS/browser/tools used
  □ PoC: Python script (requests library) with real tested values — NOT curl
  □ Payload field: the actual exploit payload or auth token used
  □ For chains: use yeswehack-chain-submission template

Post-submission:
  □ Track status per-report in findings-log.md
  □ If rejected: assess resubmission strategy (see Chain Consolidation Pattern)
```

### HackerOne Submission

```
Pre-submission:
  □ Verify program slug (unpredictable — search directory if unsure)
  □ Confirm program is NOT suspended/paused
  □ Check program policy for special rules (e.g., "email reports only")
  □ Review response_efficiency_percentage — low % = slow triage

Per-report submission:
  □ Title: concise, under 70 chars
  □ Weakness: select CWE from dropdown
  □ Asset: exact domain/URL from scope list
  □ Severity: select CVSS rating (Low/Medium/High/Critical)
  □ Summary: 2-3 sentences of impact (this shows in triage queue)
  □ Steps To Reproduce: numbered, specific, reproducible
  □ Supporting Material/References: bulleted list (screenshots, scripts, URLs)
  □ Impact: included in Summary (no separate section needed per user preference)
  □ PoC script attached as file if complex

Post-submission:
  □ Note report ID in findings-log.md
  □ Monitor for triage questions (usually within 1-5 days for active programs)
  □ Respond to mediations within 7 days or report auto-closes
```

### Intigriti Submission

```
Pre-submission:
  □ Verify program on platform (check Severity/Reward table)
  □ Confirm in-scope domains match your findings
  □ Check "Out of scope" list carefully (often more extensive than other platforms)

Per-report submission:
  □ Title: clear impact statement
  □ Severity: select from dropdown (matches CVSS)
  □ Domain: exact affected domain
  □ Endpoint: specific vulnerable URL/path
  □ Description: clear narrative with impact
  □ Steps to reproduce: numbered
  □ PoC: script or detailed manual steps
  □ Impact: business impact statement
  □ Recommendations: specific fix (not generic)

Post-submission:
  □ Track in findings-log.md
  □ Intigriti has 10-day triage SLA — follow up after that
```

### General Post-Engagement Wrap-Up

```
After ALL reports submitted:
  □ Update state.yaml: engagement.status = "submitted"
  □ Update findings-log.md with submission IDs/URLs per finding
  □ Archive engagement: run `cleanup` command
  □ Sync ptest skill changes to repo (rsync active → randscript/myherms)
  □ Save any new techniques/patterns discovered as skill patches
  □ Optional: set calendar reminders for follow-up (7 days, 30 days, 90 days)
```
