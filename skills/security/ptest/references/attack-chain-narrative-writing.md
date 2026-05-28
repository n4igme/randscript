# Attack Chain Narrative Writing

## Overview

An "Attack Chain Narrative" explains WHY a multi-step vulnerability chain works — the root causes, how each step enables the next, and why the combined impact exceeds individual findings. This section is what separates a High-bounty report from a Medium one.

---

## When to Include

Include a "Why This Attack Chain Works" section when:
- Finding involves 2+ steps where one enables another
- Combined severity exceeds individual CVSS scores
- Root cause is a systemic/architectural issue (not just a single misconfiguration)
- You need to justify why "Info + Info = High"

Skip when:
- Single-step vulnerability (SQLi, RCE, direct IDOR)
- Steps are independent (same asset, unrelated vulns)
- Chain is obvious (e.g., credential found → credential used)

---

## Structure Template

### 1. Root Cause Diagram (ASCII Flow)

Show the compounding failures as a pipeline/flow:

```
┌─────────────────────────────────────────────────────────────────────┐
│  FAILURE 1: [System/Process Name]                                    │
│                                                                      │
│  What went wrong:                                                    │
│       • [Specific misconfiguration or design flaw]                   │
│       • [Why it exists — likely reason]                              │
│                                                                      │
│  Effect:                                                             │
│       • [What this exposes to the attacker]                          │
│                                                                      │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  FAILURE 2: [System/Process Name]                                    │
│                                                                      │
│  What went wrong:                                                    │
│       • [Specific misconfiguration or design flaw]                   │
│       • [Why it exists — likely reason]                              │
│                                                                      │
│  Effect:                                                             │
│       • [What this enables given Failure 1's output]                 │
│                                                                      │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  FAILURE 3: [System/Process Name]                                    │
│                                                                      │
│  What went wrong:                                                    │
│       • [Specific misconfiguration or design flaw]                   │
│                                                                      │
│  Final impact:                                                       │
│       • [What the attacker achieves at the end of the chain]         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

**Guidelines:**
- 2-4 boxes maximum (more = too complex for a report)
- Each box = one independent failure/decision
- Arrow between boxes = "enables" or "feeds into"
- Include "likely reason" for each failure (shows you understand their architecture)

### 2. Step-by-Step Enablement Table

| Step | What Happens | Why It's Possible | What It Unlocks |
|------|-------------|-------------------|-----------------|
| 1 | [Action] | [Root cause] | [What attacker gains] |
| 2 | [Action] | [Depends on step 1 output] | [What attacker gains] |
| 3 | [Action] | [Depends on step 2 output] | [Final impact] |

**Guidelines:**
- "Why It's Possible" column is the key — it connects the chain
- Each row should reference the previous row's output
- "What It Unlocks" shows progressive escalation

### 3. Comparison Table (Individual vs Combined)

For chains where CORS + Debug, or Info + Info = High:

| Scenario | Vuln A Only | Vuln B Only | Both Combined |
|----------|------------|------------|---------------|
| Who can exploit? | [Limited] | [Limited] | [Broader] |
| User interaction? | [Yes/No] | [Yes/No] | [Less/None] |
| Detection difficulty | [Easy/Hard] | [Easy/Hard] | [Harder] |
| Impact | [Low] | [Low] | [High] |

**Guidelines:**
- Shows why the combination is worse than either alone
- Useful when individual findings would be Low/Medium but chain is High
- Include "Detection difficulty" — chains that are harder to detect are more dangerous

### 4. Systemic Pattern Identification

When the same vulnerability affects multiple assets:

```markdown
### Systemic Pattern

The same [build pipeline / configuration template / SDK integration] serves 
multiple apps ([list apps]). Each app:
- [Shared characteristic 1]
- [Shared characteristic 2]
- [Shared characteristic 3]

This means **every new app deployed with this [pipeline/template/SDK] inherits 
the same vulnerability** until the [root cause] itself is fixed.

**Known affected:** [App 1], [App 2] (confirmed)
**Likely affected:** [App 3], [App 4] (same infrastructure, not yet tested)
```

**Guidelines:**
- Justifies higher severity (N apps × impact)
- Shows the fix must be architectural, not per-app
- Demonstrates thoroughness (you checked multiple apps)

### 5. "Critical Enabler" Explanation

Identify which step is the linchpin — the one that collapses the attack from difficult to trivial:

```markdown
### Why [Step X] Is the Critical Enabler

Without [step X], exploiting this chain requires:
- [Difficult thing 1]
- [Difficult thing 2]
- [Time estimate]

With [step X], the attack collapses to:
- [Simple thing 1] (seconds)
- [Simple thing 2] (seconds)

[Step X] transforms this from a theoretical risk into a practical exploit 
because it provides [specific knowledge/access that eliminates guesswork].
```

---

## Real-World Examples

### Pattern: Information Disclosure → Token Extraction → Write Access

```
Source Map (Info) → Token Pattern (Info) → Token Value (Low) → Write Access (Medium)
= Chain Severity: High

Critical enabler: Source map (provides variable names, auth patterns, endpoint URLs)
Without it: hours of reverse engineering minified JS
With it: 3 grep commands
```

### Pattern: Debug Mode + CORS Wildcard → Cross-Origin Extraction

```
Debug Mode (Medium) + CORS * (Low) = Cross-Origin Architecture Extraction (Medium-High)

Key insight: Debug mode alone requires direct interaction.
CORS * alone exposes only public data.
Combined: any website silently extracts internal architecture via victim's browser.
Attacker is invisible (victim's IP in logs, not attacker's).
```

### Pattern: Unauthenticated Config + Device Code → Social Engineering → RCE

```
Exposed Config (Medium) + Device Code Flow (Low) + execEnabled (N/A alone)
= Social Engineering → Full Cluster Access (High)

Key insight: Device code phishing uses the REAL domain (not a clone).
Traditional phishing detection fails because the URL IS legitimate.
One click from one engineer = refresh token with pod exec.
```

### Pattern: Credential in Heapdump → Cross-Environment Pivot

```
Heapdump Exposed (High) → Credential Extracted (part of High) → 
Credential Works on Prod (Critical)

Key insight: Lower environments share credentials with production.
The heapdump is on mock/staging, but the credential grants prod access.
```

---

## Writing Tips

### Do

- **Explain "likely reason"** for each misconfiguration — shows you understand their architecture and makes remediation actionable
- **Use concrete numbers** — "3 tokens", "201 source files", "4.8MB" — not "multiple" or "several"
- **Include the "so what" for non-technical readers** — "any website can silently extract internal architecture" not "CORS allows cross-origin reads"
- **Show progressive escalation** — each step should feel like the attacker is getting closer to the crown jewels
- **Name the systemic fix** — "fix the build pipeline" not "remove this one file"

### Don't

- **Don't over-complicate** — if the chain is 2 steps, don't force it into a 5-box diagram
- **Don't speculate** — only include steps you've verified. Theoretical extensions go in "Further Impact" not the chain
- **Don't repeat the Steps to Reproduce** — the narrative explains WHY, not HOW (the PoC already shows HOW)
- **Don't editorialize** — "this is a catastrophic failure" → "this grants unauthenticated write access to production"
- **Don't assume the reader knows your previous findings** — each report must be self-contained

---

## Severity Upgrade Justification

When the chain justifies higher severity than individual CVSS:

```markdown
### Severity Justification

Individual findings:
- Source map exposure: CVSS 5.3 (Medium) — information disclosure only
- Token in client JS: CVSS 3.7 (Low) — token alone doesn't prove impact
- Event API accepts writes: CVSS 5.3 (Medium) — requires valid token

**Chain severity: CVSS 7.5 (High)**

Justification: The source map provides the exact authentication pattern and 
variable names needed to extract the token from minified JS in seconds. The 
token grants confirmed write access to the production event pipeline. The 
chain transforms three individually-moderate issues into a verified production 
compromise achievable by any attacker in under 60 seconds.
```

---

## Integration with Report Structure

Place the "Why This Attack Chain Works" section:
- **After** Impact (reader already understands what's at stake)
- **Before** Remediation (reader understands root cause before seeing fixes)

```markdown
## Impact
[What the attacker achieves]

## Why This Attack Chain Works
[Root cause analysis, diagrams, tables]

## Remediation
[Fixes that address the root causes identified above]
```

This ordering ensures remediation recommendations map directly to the root causes you just explained.
