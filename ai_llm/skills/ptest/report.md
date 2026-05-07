---
name: report
description: Compile all findings into a structured penetration test report.
version: 2.0.0
metadata:
  category: reporting
  phase: 5
  requires_toolsets: [read, edit]
---

# Skill: Pentest Report Generation

## When to Use
- After post-exploitation is complete (Gateway 4 passed).
- Final phase of the engagement.

## Report Structure
1. **Executive Summary:** High-level overview for non-technical stakeholders.
2. **Scope & Methodology:** What was tested, rules of engagement, tools used.
3. **Findings Summary:** Table of all findings with severity ratings.
4. **Detailed Findings:** For each vulnerability:
   - Title and severity (Critical/High/Medium/Low/Info)
   - Affected asset
   - Description
   - Steps to reproduce
   - Evidence (screenshots, logs, PoC)
   - Impact
   - Remediation recommendation
   - CVSS score
5. **Attack Narrative:** Story of the engagement from recon to final impact.
6. **Remediation Roadmap:** Prioritized fix list.

## Procedure
1. **Aggregate:** Collect all findings from phase result files.
2. **Deduplicate:** Merge related findings.
3. **Classify:** Assign final severity ratings.
4. **Draft:** Write the report following the structure above.
5. **Review:** Self-check for completeness and accuracy.

## Output
Final report in `pentest-report.md`.

## Exit Criteria
- [ ] All findings included with evidence.
- [ ] Severity ratings assigned (CVSS).
- [ ] Remediation recommendations provided.
- [ ] Executive summary written.
- [ ] Report reviewed for completeness.
