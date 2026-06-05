# Penetration Test Report Structure Template

Adapt sections based on engagement scope and findings.

```markdown
# Penetration Test Report — {Client Name} ({target domain})

## 1. Executive Summary
- Severity breakdown table (Critical/High/Medium/Low/Info)
- Top critical risk (1-2 sentences)
- Security posture: Strengths + Weaknesses
- Immediate actions required (top 3)

## 2. Scope & Methodology
- Scope table (target, type, exclusions, restrictions, authorization)
- 8-phase methodology list with ✅ status
- Tools used table

## 3. Attack Surface Overview
- Infrastructure stats (subdomains, live hosts, IPs, cloud provider)
- Environment exposure matrix (which envs are public vs should be internal)

## 4. Findings Summary
- Table: ID | Title | Severity | CVSS | Asset

## 5. Detailed Findings
- Each finding using the Finding Template (see SKILL.md)
- Ordered by severity (Critical → Low)

## 6. Attack Narrative
- Story-form description of the engagement progression
- Key decision points and breakthroughs

## 7. Remediation Roadmap
- Immediate (1 week) — critical/high findings
- Short-term (1 month) — medium findings
- Medium-term (3 months) — architectural improvements

## 8. Infrastructure Architecture (if discovered)
- K8s/cloud topology
- Service mesh details
- Microservice inventory
- Network segmentation
- Supporting infrastructure

## 9. Advanced Testing Results (if performed)
- SSRF testing summary
- Other specialized testing (e.g., API fuzzing, auth bypass campaigns)

## 10. Risk Matrix & Business Impact
- Industry-specific context (financial, healthcare, etc.)
- Regulatory implications
- Worst-case attack chain scenario

## 11. Appendices
- Links to supporting evidence files

## 12. Conclusion
- Split posture assessment
- Overall risk rating
- Final recommendation
```
