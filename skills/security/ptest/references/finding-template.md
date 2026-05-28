# Shared Finding Template

Standard format for security findings across all offensive skills (ptest, mtest, scode, atest, ctest, xdev, w3hunt).

## Per-Finding Format

```markdown
### [SEVERITY] Title of Finding

**ID:** {SKILL}-{ENGAGEMENT}-{NNN}
**Severity:** Critical | High | Medium | Low | Info
**CVSS 3.1:** {score} ({vector string})
**CWE:** CWE-{id} — {name}
**ATT&CK:** {technique ID} (if applicable)
**Status:** Open | Confirmed | Fixed | Accepted Risk

#### Description

Brief explanation of the vulnerability — what it is, where it exists, and why it matters.

#### Affected Component

- **Target:** {URL, endpoint, function, file, service}
- **Parameter/Input:** {specific parameter or input vector}
- **Authenticated:** Yes (role: {role}) | No

#### Steps to Reproduce

1. Step one
2. Step two
3. Step three

#### Proof of Concept

```python
# PoC code (Python preferred, not curl)
import requests

# ... working exploit code ...
```

#### Evidence

- Screenshot/output showing the vulnerability
- Request/response pairs if applicable

#### Impact

What an attacker can achieve by exploiting this vulnerability. Be specific:
- Data exposure (what data, how much)
- Privilege escalation (from what role to what role)
- Financial impact (if quantifiable)
- Business logic abuse (what actions become possible)

#### Remediation

Specific fix recommendation with code example if possible.

**Short-term:** Immediate mitigation
**Long-term:** Proper fix

#### References

- [Link to relevant standard/advisory]
- [CWE reference]
```

## Severity Definitions

| Level | CVSS Range | Criteria |
|-------|-----------|----------|
| Critical | 9.0 - 10.0 | Remote code execution, full system compromise, mass data breach, authentication bypass affecting all users |
| High | 7.0 - 8.9 | Significant data exposure, privilege escalation, account takeover of individual users, stored XSS with session theft |
| Medium | 4.0 - 6.9 | Limited data exposure, CSRF on state-changing actions, IDOR with limited scope, information disclosure enabling further attacks |
| Low | 0.1 - 3.9 | Minor information disclosure, missing headers, verbose errors, issues requiring unlikely preconditions |
| Info | 0.0 | Best practice recommendations, observations, no direct security impact |

## Platform-Specific Adaptations

### Bug Bounty (HackerOne, Bugcrowd)
- Separate findings by endpoint/app
- PoCs in Python (requests/eth_account), NOT curl
- Include actual exploitation, not just theoretical

### Immunefi (w3hunt)
- Format: Brief/Intro, Vuln Details, Impact, References
- Title: "[Vuln] in [func] leads to [impact]"
- Python PoCs, working exploits, honest severity

### YesWeHack
- Format: Description, Exploitation, PoC, Risk, Remediation

### Internal Pentest (Bank Jago)
- Full report with executive summary
- Risk rating aligned with internal risk framework
- Remediation timeline recommendations

## CVSS 3.1 Quick Reference

```
Attack Vector (AV):     Network (N) | Adjacent (A) | Local (L) | Physical (P)
Attack Complexity (AC): Low (L) | High (H)
Privileges Required (PR): None (N) | Low (L) | High (H)
User Interaction (UI):  None (N) | Required (R)
Scope (S):             Unchanged (U) | Changed (C)
Confidentiality (C):   None (N) | Low (L) | High (H)
Integrity (I):         None (N) | Low (L) | High (H)
Availability (A):      None (N) | Low (L) | High (H)

Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical
```
