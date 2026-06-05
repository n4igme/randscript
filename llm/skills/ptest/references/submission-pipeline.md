# Submission Pipeline Tracking

Manage active reports across platforms. Prevents forgotten rebuttals and money left on table.

---

## Report States

```
DRAFTED → SUBMITTED → TRIAGING → [ACCEPTED | REJECTED | NEED_INFO]
                                       ↓          ↓           ↓
                                   RESOLVED    REBUTTAL    RESPONDED
                                       ↓          ↓
                                     PAID    [ACCEPTED | CLOSED]
```

---

## Follow-up Cadence

| State | Action | When |
|-------|--------|------|
| SUBMITTED | Check status | After 3 days |
| TRIAGING (no response >7 days) | Polite bump | Day 7 |
| TRIAGING (no response >14 days) | Second bump + tag program manager | Day 14 |
| NEED_INFO | Reply within 24h | Same day if possible |
| REJECTED | Evaluate rebuttal (load triage-rebuttal.md) | Within 48h |
| REBUTTAL sent (no response >7 days) | Bump | Day 7 |
| REBUTTAL rejected again | Request mediation OR close | Within 3 days |
| ACCEPTED (no payout >30 days) | Ask about timeline | Day 30 |

---

## Weekly Review (5 min Monday)

1. List all reports in non-terminal state
2. For each: is action needed based on cadence above?
3. Priority: NEED_INFO > REBUTTAL pending > stale TRIAGING
4. Update tracking file in project directory

---

## Tracking File Format

Keep in each project dir as `submissions.md`:

```markdown
| ID | Platform | Title | Severity | Submitted | State | Next Action | Due |
|----|----------|-------|----------|-----------|-------|-------------|-----|
| YWH-123 | YWH | CORS+Write Chain | High | 2026-05-20 | REBUTTAL | Wait for response | 2026-06-01 |
| IMM-456 | Immunefi | Role Persistence | High | 2026-05-25 | TRIAGING | Bump if no reply | 2026-06-01 |
```

---

## When to Cut Losses

Stop pursuing a report when:
- Mediation denied and no new evidence available
- Program explicitly marks as "won't fix" with reasoning you agree with
- >60 days with no meaningful response after 3 bumps
- Effort to rebuttal exceeds likely payout

Never: burn bridges, get hostile, threaten disclosure.
Document lesson learned → update triage-rebuttal.md if new pattern.
