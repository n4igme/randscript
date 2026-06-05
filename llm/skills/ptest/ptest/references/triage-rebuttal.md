# Triage Rebuttal Guide

How to respond when bug bounty reports get rejected or downgraded.

---

## When to Rebut

REBUT when:
- Triage misunderstood the impact (they see Info, you proved High)
- They dismissed as "public API key" but you demonstrated write access
- They merged with another report but your finding is distinct
- They say "known issue" but you showed new exploitation path

DO NOT REBUT when:
- Finding is genuinely out of scope
- Impact is honestly Low and you agree
- Duplicate of your own earlier report
- You lack evidence to counter their argument

---

## Rebuttal Structure

```
1. Acknowledge their point (1 sentence)
2. State what they missed (1-2 sentences)
3. Provide NEW evidence or clarification
4. Restate actual impact
5. (Optional) Reference similar accepted reports
```

---

## Anti-Rejection Patterns

### "Public API key / known endpoint"
**Counter:** Demonstrate WRITE access, not just READ.
- Show HTTP 200 on POST/PUT with state change
- Show what data can be injected/modified
- Frame as: "attacker can DO X" not "key is exposed"

### "Theoretical impact / no PoC"
**Counter:** Full exploitation chain, every step executable.
- Never say "an attacker could..." — show "this script DOES..."
- Include screenshot/response proving state change
- PoC must run standalone without guessing inputs

### "Informational / low impact"
**Counter:** Chain with other findings or show scale.
- Combine multiple Lows into one High chain report
- Show automation: 1 account = Low, 10000 accounts = High
- Compliance angle: regulatory violation trumps technical severity

### "Duplicate"
**Counter:** Explain why yours is distinct.
- Different root cause (even if same symptom)
- Different endpoint/app
- Your PoC achieves more (they found read, you found write)

### "Won't fix / accepted risk"
**Counter:** Escalate impact description.
- "Accepted risk" for internal team ≠ acceptable for public bounty
- Show customer/regulatory impact
- Reference industry standards (OWASP, CWE severity)

---

## Evidence Format Per Platform

### YesWeHack
- Full HTTP requests/responses in report body
- PoC script (Python requests) embedded
- Screenshot of impact (state change proof)
- Risk section references CVSS or OWASP

### HackerOne
- Steps to Reproduce: numbered, exact commands
- Supporting Material: screenshots + script file
- Impact in Summary paragraph (no separate section)
- Reference similar disclosed reports on same program

### Immunefi
- Working exploit script (must compile/run)
- Exact contract addresses + function calls
- Funds at risk calculation
- Reference audit reports if available

---

## Escalation Path

1. Reply on report thread with rebuttal (wait 3 days)
2. If no response → reply again with "gentle bump"
3. If rejected again → request mediation (platform-specific)
4. If mediation fails → document lessons, move on

Never: get hostile, threaten disclosure, spam replies.

---

## Lessons from GoPay

Original rejection: "public API keys" (Info)
What was missing: write-access demonstration + full chain narrative

Rebuttal included:
- HTTP 200 on POST /api/v1/events = write access (not just read)
- CORS permissive = remotely triggerable
- Chain: CORS + write endpoint + debug info = credential exfil
- PoC HTML page demonstrating cross-origin write

Key lesson: lead with WHAT YOU CAN DO, not what is exposed.
