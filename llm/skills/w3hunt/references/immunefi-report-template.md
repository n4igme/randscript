# Immunefi Report Template

## Pre-Submission Gate (mandatory)

1. Open program scope → verify target contract/endpoint is listed
2. If not listed: identify in-scope contract that CALLS the vulnerable one
3. Use in-scope contract as "Impacted Asset", explain call chain in report
4. If no in-scope entry point: DO NOT SUBMIT

## Title Format

Vulnerability class + impact. Triager reads 50+ reports/day.

Examples:
- "Missing replay protection and timestamp expiry in updateProfile mutation leads to permanent unauthorized modification of user registration information"
- "Reentrancy in the withdraw function leads to total loss of funds"
- "Lack of access control in uploadMetadata mutation leads to stored XSS and resource abuse"

## Submission Form Structure

```markdown
## Brief/Intro
One paragraph: what the problem is + consequences if exploited in production.

## Vulnerability Details
Detailed explanation. Code snippets where helpful.
Must make it obvious you understand the bug AND that it exists.
Include: affected function/endpoint, root cause, why current validation fails.
PoC goes here as self-contained Python script with actual output in comments.

## Impact Details
Map to program's EXACT impact category.
State selected impact explicitly: "Selected impact: Taking state-modifying
authenticated actions on behalf of other users without any interaction by that user."
If funds at risk, estimate amount or describe loss path.

## References
- Frontend code references (bundle URLs proving scope)
- Relevant EIPs, CWEs, OWASP references
- Documentation links
```

## DO NOT Include

- CVSS scores (Immunefi uses own classification)
- Remediation section (optional, only if program requires "fix suggestion")
- Severity label in title (selected via dropdown)

## PoC Rules (HARD)

- Python only (`requests` + `eth_account`). NEVER curl.
- Single self-contained `#!/usr/bin/env python3` script
- All steps covered with actual output in comments
- Include `Origin` header matching in-scope app URL
- Use exact mutation/endpoint format the app's frontend uses

## Scope Reframing Technique

When scope says only `https://app.example.io/` but findings target backend API:
1. curl app's JS bundles, grep for API URL
2. Find exact mutation/endpoint strings the app calls
3. Reframe title to reference in-scope app URL
4. Add scope justification citing bundle filenames
5. Use `Origin: https://app.example.io` in all PoC requests
6. Use app's exact mutation format (with variables, not inline)

## Web/App Severity Decision Tree (v2.3)

```
Q1: RCE or read sensitive server files? → Critical
Q2: App takedown? → Critical
Q3: State-modifying actions on behalf of OTHER users, NO interaction? → Critical
Q4: Interact with victim's ALREADY-CONNECTED wallet? → Critical
Q5: Persistent XSS through NFT/metadata? → Critical
Q6: Steal/modify SENSITIVE user details (email/password)? → High
Q7: Disclose confidential user info (email/phone/address)? → High
Q8: Subdomain takeover? With wallet → Critical, Without → High
Q9: Change NON-SENSITIVE user details? → Medium
Q10: Redirect to malicious websites? → Medium
Q11: Non-state-modifying actions on behalf of users? → Low
```

## Severity Validation Checklist

1. Is vulnerable contract IN THE ASSET SCOPE LIST?
2. Can attacker TRIGGER the condition themselves?
3. Is there DIRECT fund loss (not theoretical)?
4. Does it require elevated privileges?
5. Is it a known/accepted pattern?
6. Does PoC demonstrate ACTUAL impact?
7. Web: does it affect USERS or just disclose non-sensitive info?

## Common Rejection Reasons (by frequency)

1. "Out of scope asset" — contract not in program's asset list
2. "Requires external conditions outside attacker control"
3. "Known issue / accepted risk"
4. "Centralization risk" (owner-only functions)
5. "Informational / best practice"
6. "No PoC"
7. "Theoretical impact only"

## Impact Framing Tips

- Map to EXACT Immunefi impact categories (program-specific wording)
- Avoid phishing-required framing — frame as interception/cross-protocol reuse
- "Requires elevated privileges" downgrades anything — pre-empt in report
- Profile takeover → reframe as "state-modifying actions on behalf of users"
- Unauth upload → reframe as "stored XSS → wallet drain" if XSS renders
