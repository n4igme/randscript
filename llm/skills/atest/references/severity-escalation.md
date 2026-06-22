# Severity Escalation Guide — atest

Reference: See `../../references/severity-mapping.md` for canonical cross-skill severity scale.

## API-Specific Escalation Rules

| Base Finding | Escalate To | Condition |
|--------------|-------------|-----------|
| BOLA (read) | Medium → High | Accesses PII or financial data |
| BOLA (write) | High → Critical | Modifies other users' sensitive data |
| Auth bypass (single endpoint) | Medium → High | Endpoint handles payments/PII |
| Auth bypass (admin) | High → Critical | Full admin access proved |
| SSRF (blind) | Low → Medium | DNS callback confirmed |
| SSRF (read) | Medium → High | Cloud metadata accessible |
| SSRF (read) | High → Critical | IMDSv1 credentials extracted |
| Mass assignment | Medium → High | Privilege escalation achieved |
| Rate limit bypass | Low → Medium | Enables credential stuffing |
| Information disclosure | Info → Low | Internal IPs/versions exposed |
| Information disclosure | Low → Medium | API keys/tokens exposed |

## Chain Escalation

When findings from atest chain with other skills:
- atest BOLA + ptest XSS → report at BOLA severity (XSS is delivery, not impact)
- atest auth bypass + ctest cloud access → report both separately
- atest SSRF + ctest metadata → single Critical (full chain proved)

## De-escalation Rules

- Theoretical chains without end-to-end proof: cap at Medium
- Self-impact only (user can only affect own account): cap at Low
- Requires unlikely preconditions (MitM, physical access): drop one level
