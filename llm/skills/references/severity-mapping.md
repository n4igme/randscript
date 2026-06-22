# Cross-Skill Severity Mapping

## Unified Severity Scale

All skills map to this canonical scale. When findings chain across skills, severity must not inflate beyond what the weakest link proves.

| Canonical | ptest | atest | ctest | scode | w3hunt | ttest | xdev |
|-----------|-------|-------|-------|-------|--------|-------|------|
| Critical | P1 | Critical | Critical | Critical | Critical | Critical | Critical |
| High | P2 | High | High | High | High | High | High |
| Medium | P3 | Medium | Medium | Medium | Medium | Medium | Medium |
| Low | P4 | Low | Low | Low | — | Low | Low |
| Info | P5 | Info | Info | Info | — | Info | Info |

## Mapping Rules

1. **Lowest proven link wins.** If chaining requires an unproven prerequisite (e.g., XSS for token theft), report at the lower severity.
2. **Theoretical ≠ Critical.** A chain with one theoretical link is at most High.
3. **w3hunt does not use Low/Info.** Map to Medium if borderline.
4. **ptest P1 = Critical** for consistency with other skills.
5. **scode severity is input-only.** Output uses canonical labels from this table.

## Context-Specific Escalation

| Scenario | Base | Escalate To | Condition |
|----------|------|-------------|-----------|
| BOLA + active session | Medium | High | Proved on sensitive endpoint (PII, financial) |
| SSRF + cloud metadata | High | Critical | IMDSv1 or metadata reachable |
| IDOR + payment data | High | Critical | Proved transaction/balance access |
| Hardcoded key + S3 access | High | Critical | Key has list/read permissions |
| Auth bypass + admin funcs | High | Critical | Proved privilege escalation end-to-end |
| Stored XSS + admin panel | High | Critical | Proved admin session hijack |

## Honesty Rules

- Never claim impact you haven't proven end-to-end
- Email delivery ≠ HTTP 204 (verify in real inbox)
- Client-side keys are useless unless they grant server-side access
- Firebase default behavior is not a vulnerability
