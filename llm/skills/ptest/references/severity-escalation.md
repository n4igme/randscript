# Severity Escalation Protocol

Run this AFTER every finding, BEFORE writing the report.

---

## Decision Tree

```
FOUND: [vulnerability]
SEVERITY AS-IS: [initial assessment]

ESCALATION QUESTIONS:
│
├─ CAN I CHAIN?
│   └─ What other findings combine with this?
│   └─ Does an Info/Low enable a High elsewhere?
│   └─ Do error messages reveal info that enables other attacks?
│
├─ CAN I AUTOMATE AT SCALE?
│   └─ 1 account affected vs 10,000?
│   └─ Sequential IDs = enumerate all users?
│   └─ No rate limit = mass exploitation viable?
│
├─ COMPLIANCE ANGLE?
│   └─ PCI-DSS: cardholder data exposed?
│   └─ OJK: regulatory flow bypassed?
│   └─ GDPR: PII accessible cross-tenant?
│   └─ SOX: audit trail manipulable?
│
├─ WRITE ACCESS?
│   └─ Read-only leak vs modify state?
│   └─ Can I inject/pollute data?
│   └─ Can I trigger downstream actions?
│   └─ Event ingestion = analytics poisoning?
│
└─ SECOND-ORDER ACCESS?
    └─ Does this finding give me access to find MORE bugs?
    └─ Leaked creds → new attack surface?
    └─ SSRF → internal endpoints to test?
    └─ Admin access → source code / config?
```

---

## Escalation Patterns (proven)

| Initial Finding | Escalation Path | Final Severity |
|----------------|-----------------|----------------|
| Exposed API key (Info) | Key has write access → event injection | High |
| CORS misconfiguration (Low) | + sensitive endpoint → credential theft | High/Critical |
| Debug endpoint (Info) | + CORS → remote data exfil | High |
| OTP oracle (Medium) | + no rate limit → account takeover | Critical |
| Config leak (Low) | Reveals auth mechanism → enables brute-force | High |
| SSRF (Medium) | → cloud metadata → IAM creds → full access | Critical |
| Prerequisite skip (Medium) | Regulatory flow → OJK/compliance violation | High |

---

## Report Writing Rules

**IF escalation possible:**
1. Report as the CHAIN — not individual findings
2. Lead with IMPACT not mechanism
3. PoC demonstrates the FULL path end-to-end
4. Title describes what attacker achieves, not how

**IF NOT escalatable:**
1. Submit as-is with honest severity
2. Mention chain potential in description
3. Note what additional access would be needed to escalate

---

## Anti-Rejection Patterns

Learned from GoPay and other triage rejections:

**Problem:** "Public API key" → rejected as informational
**Fix:** Demonstrate WRITE access. HTTP 200 on POST/PUT = state modification.
Show: what can attacker DO with this access? Not just "key is exposed."

**Problem:** "Known debug endpoint" → rejected as known issue
**Fix:** Chain with CORS or other access vector. Show remote exploitability.
An endpoint that's "known" but remotely exploitable via CORS is NOT the same finding.

**Problem:** "Theoretical impact" → rejected as no PoC
**Fix:** Full exploitation chain in PoC. Every step executable.
Never say "an attacker could..." — show "this script DOES..."

**Problem:** Individual Low findings submitted separately → all rejected
**Fix:** Combine into one report showing the chain. Multiple Lows = one High.

---

## When to Split vs Chain

**SPLIT** (separate reports) when:
- Findings affect different endpoints/apps
- Fixes are independent (fixing A doesn't fix B)
- Different root causes

**CHAIN** (one report) when:
- Finding A enables Finding B
- Same root cause manifests in multiple places
- The real impact only exists when combined
