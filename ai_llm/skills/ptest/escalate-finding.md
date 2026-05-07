---
name: escalate-finding
description: Immediately escalate critical/P1 findings that require urgent client notification.
version: 2.0.0
metadata:
  category: escalation
  requires_toolsets: [read, edit]
---

# Skill: Escalate Finding

## When to Use
- Critical vulnerability discovered (RCE, auth bypass, data breach in progress).
- Finding that poses immediate risk to the client.
- Any finding that per rules of engagement requires immediate disclosure.

## Procedure
1. **Document Finding:** Full description with evidence and reproduction steps.
2. **Classify Severity:** Critical / High / Medium / Low (use CVSS 3.1).
3. **Assess Immediate Risk:** Is data actively being exposed? Is there active exploitation by third parties?
4. **Prepare Notification:** Draft a concise escalation report with:
   - Vulnerability title
   - Affected asset
   - Impact description
   - Immediate remediation recommendation
5. **Alert User:** Flag for immediate client communication.
6. **Pause Gateway:** Current Gateway remains Open until escalation is acknowledged.

## Output
Document in `escalation-[ID].md`:
- Finding details and evidence
- Severity classification
- Recommended immediate action
- Escalation timestamp

## Verification
- [ ] Finding is fully documented with evidence.
- [ ] Severity is classified.
- [ ] User has been notified.
- [ ] Gateway is paused pending acknowledgment.
