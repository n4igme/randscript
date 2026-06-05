# {Title — action-oriented, includes asset + impact}

**Asset:** {exact match from program scope}
**Severity:** {Critical / High / Medium / Low}
**CVSS 3.1:** {score} ({vector string})
**Vulnerability Type:** {platform taxonomy match}

{Optional scope note if asset is borderline — explain relationship to in-scope targets}

## Description

{2-3 paragraphs: what the vulnerability is, which workflow/feature it affects, and WHY the chain works (root cause analysis). Include the "why this happens" explanation here — it justifies severity and shows you understand their architecture.}

{For chain findings: explain how each step enables the next. For single findings: explain the root cause and why it persists (likely reason).}

## Exploitation

### Step 1: {action}

```bash
{copy-pasteable command}
```

{Response with actual output — not placeholder}

### Step 2: {action}

```bash
{copy-pasteable command}
```

{Response}

### Step N: {final verification}

```bash
{command proving impact — e.g., write access confirmed}
```

{Response showing success — HTTP 200, data returned, etc.}

## PoC

```python
#!/usr/bin/env python3
"""
{Target} — {Chain description} PoC
"""
# Full working script that demonstrates the chain end-to-end
# Must be runnable by triage analyst without modification
# Include comments explaining each step
```

{Optional: additional evidence tables, attack flow diagrams, or HTML PoC for CORS/XSS}

## Risk

{Numbered list of concrete business impacts. Use "attacker can..." framing.}

1. **{Impact category}** — {specific consequence in business terms}
2. **{Impact category}** — {specific consequence}
3. ...

{Optional: regulatory context for financial services targets}
{Optional: comparison table showing why combined/chain impact exceeds individual}

## Remediation

**Immediate (within 24 hours):**
1. {Most urgent fix — rotate tokens, disable debug, restrict access}

**Short-term (within 1 week):**
2. {Architectural fix — server-side proxying, pipeline change}

**Medium-term (within 1 month):**
3. {Systemic fix — audit all apps, implement monitoring}

---

## Template Notes (delete before submission)

- Title: max ~100 chars, action-oriented ("X Enables Y" not "X Found")
- Every curl command must be copy-pasteable and produce the shown output
- PoC script must work without modification by triage analyst
- Risk section: business impact, not technical jargon
- Cross-reference related reports: "when combined with [finding] reported separately..."
- Supported markdown: headers, bold, italic, code blocks (bash/json/python/html/http), tables, lists
- Attach screenshots as YWH attachments, reference with {YWH-RXXX}
- NEVER include links to public PoC pages — embed code directly
