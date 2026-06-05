# Report Templates by Platform

Use the correct format for each platform. Load this before writing any report.

---

## YesWeHack

```markdown
## Description
[What the vulnerability is — 2-3 sentences max. Include affected asset.]

## Exploitation
[How the vulnerability works technically. Include auth requirements,
preconditions, and attack scenario.]

## Proof of Concept
[Python script using requests library. Must contain REAL tested values.
No placeholders. Script must be self-contained and executable.]

## Risk
[Impact statement. Include: confidentiality/integrity/availability effect,
number of affected users, compliance implications if applicable.
Reference CVSS or OWASP category.]

## Remediation
[Specific fix. Not generic "validate input" — exact implementation guidance.]
```

**Rules:**
- Separate reports per endpoint/app
- PoC in Python (requests), NOT curl
- Real values only — never `YOUR_TOKEN_HERE`
- Asset field: exact URL/endpoint
- Weakness: CWE number

---

## HackerOne

```markdown
## Summary
[What the vulnerability is + what an attacker can achieve. Impact goes HERE,
not in a separate section. 3-5 sentences.]

## Steps To Reproduce
1. [Exact step with full URL/command]
2. [Next step]
3. [Continue until vulnerability is demonstrated]
4. [Final step showing impact]

## Supporting Material/References
- [screenshot1.png] — shows [what it proves]
- [poc.py] — automated PoC script
- [CWE-XXX reference if applicable]
- [Similar disclosed report URL if available]
```

**Rules:**
- NO separate Impact section — include in Summary
- Steps must be numbered and reproducible by triager
- Asset + Weakness (CWE) fields filled on submission form
- Attach files, don't inline giant code blocks

---

## Immunefi

```markdown
## Bug Description
[Technical description of the vulnerability in the smart contract or
web/API component. Reference specific function names, line numbers.]

## Impact
[Funds at risk calculation. Be specific: "X tokens across Y pools"
or "all user deposits in contract Z". For web: data/access impact.]

## Proof of Concept
[For smart contracts: Foundry/Hardhat test or transaction sequence.
For web/API: Python script with real values.
Must be executable standalone.]

## Recommendation
[Specific fix with code suggestion if applicable.]
```

**Rules:**
- Working exploit required (must compile/run)
- Funds at risk = severity (Critical: >$1M, High: $100K-$1M)
- Reference audit reports if vulnerability was missed
- For web scope: same PoC standards as other platforms

---

## Internal (Bank Jago / BFI)

```markdown
# [Finding Title] — [Severity]

## Summary
[1-2 sentence description + business impact]

## Affected Asset
[IP/URL/app name + environment (prod/staging)]

## Technical Details
[Full technical description with request/response evidence]

## Proof of Concept
[Step-by-step reproduction + Python script if automated]

## Risk Assessment
- Confidentiality: [High/Medium/Low/None]
- Integrity: [High/Medium/Low/None]
- Availability: [High/Medium/Low/None]
- Business Impact: [description]

## Remediation
[Specific fix + timeline recommendation (immediate/short/medium)]

## Evidence
[Screenshots, logs, response captures — real proof always]
```

**Rules:**
- Real proof always — never theoretical
- Include environment (don't test prod without authorization)
- Flag if finding affects customer data (triggers incident response)
- Remediation must be actionable by dev team

---

## Dojo CTF

```markdown
## Challenge: [name]
## Flag: [actual flag value]

## Solution
[Step-by-step walkthrough of how you solved it]

## Tools Used
[List tools + commands]
```

---

## IssueHunt

```markdown
## Summary
[What the vulnerability is + what an attacker can achieve. 3-5 sentences.
Include affected asset and impact.]

## Steps To Reproduce
1. [Exact step with full URL/command]
2. [Next step]
3. [Continue until vulnerability is demonstrated]

## Supporting Material/References
- [PoC script or screenshot]
- [CWE-XXX reference]

## Remediation
[Specific fix recommendation]
```

**Rules:**
- Asset field: exact URL/endpoint (Web Service or REST Api)
- Weakness: CWE number
- PoC in Python (requests), NOT curl
- Real tested values only — never placeholders
- One vulnerability per report
- Video/Image-only reports NOT accepted (must have text reproduction steps)
- **CRITICAL: Cross-reference program Out of Scope BEFORE writing report** (WinTicket lesson: email enum + DMARC both excluded)
