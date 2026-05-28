# Reassessment/Redo Report Template

When the engagement is a reassessment (redo) of previously reported findings, adapt the report structure.

## Additional/Modified Sections

```markdown
## 0. Fix Verification Summary (INSERT BEFORE Executive Summary)

### Remediation Effectiveness

| Metric | Value |
|--------|-------|
| Round 1 findings | {n} |
| Fully fixed | {n} ({%}) |
| Partially fixed | {n} ({%}) |
| Unfixed | {n} ({%}) |
| **Remediation effectiveness** | **{%}** |
| Time since Round 1 report | {days/weeks} |

### Fix Verification Matrix

| R1 ID | Title | Severity | Gateway/Path Tested | Status | Notes |
|-------|-------|----------|--------------------:|--------|-------|
| F-1 | {title} | Critical | microservices.prod.bfi.co.id | ✅ Fixed | Returns 401 |
| F-1 | {title} | Critical | microservices.prod.bravo.bfi.co.id | ❌ Unfixed | Still returns 200 |

### Key Observations

- {Pattern observation, e.g., "Fixes applied to 1 of 4 gateways only"}
- {Root cause, e.g., "Configuration drift between gateway variants"}
- {Positive note if any, e.g., "JWT validation logic properly implemented on primary gateway"}
```

## Modified Executive Summary

```markdown
## 1. Executive Summary

### Remediation Status
- **{n}/{total} findings fixed** from Round 1 ({%} remediation rate)
- **{n} new findings** discovered in Round 2
- **{total} active vulnerabilities** across the estate

### Key Findings (combine old + new)

| Category | Count |
|----------|-------|
| Unfixed Critical (Round 1) | {n} |
| Unfixed High (Round 1) | {n} |
| New Critical (Round 2) | {n} |
| New High (Round 2) | {n} |
| **Total Active** | **{n}** |
```

## Modified Findings Summary (Section 4)

```markdown
## 4. Findings Summary

### Unfixed Round 1 Findings

| R1 ID | Title | Severity | Status | Notes |
|-------|-------|----------|--------|-------|
| F-1 | {title} | Critical | ❌ Still vulnerable | {brief note} |

**Summary: {n}/{total} fixed. {n} partially fixed. {n} still vulnerable.**

### New Findings (Round 2)

| ID | Title | Severity | CVSS | Asset |
|----|-------|----------|------|-------|
| F-1 | {title} | Critical | 9.1 | {asset} |
```

## Additional Appendix

```markdown
## Appendix: Fix Verification Details

For each Round 1 finding, document:
1. Original PoC replayed verbatim
2. All gateways/paths tested (not just the primary)
3. Adjacent endpoints checked
4. Current response vs Round 1 response

| R1 Finding | Test Performed | Expected (if fixed) | Actual | Verdict |
|-----------|---------------|---------------------|--------|---------|
| F-1 GET | curl -sk $URL/master/v1/general | 401 | 200 (4199 records) | UNFIXED |
| F-1 POST | curl -sk -X POST $URL/master/v1/general -d '...' | 401 | 200 (created ID 5668) | UNFIXED |
```

## Framing Guidance

- Lead with remediation effectiveness — this is what stakeholders care about most
- Frame unfixed findings as "remediation failure" not just "vulnerability exists"
- Highlight patterns (e.g., "all fixes applied to one gateway only" = systemic deployment issue)
- Note positive progress even if incomplete (e.g., "primary gateway secured, parallel paths missed")
- Include a "Remediation Process Recommendations" section addressing WHY fixes failed, not just WHAT to fix
- Calculate risk delta: is the organization MORE or LESS secure than Round 1? (can be worse if new findings outweigh fixes)
