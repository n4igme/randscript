# Severity Escalation Guide — mtest

Reference: See `../../references/severity-mapping.md` for canonical cross-skill severity scale.

## Mobile-Specific Escalation Rules

| Base Finding | Escalate To | Condition |
|--------------|-------------|-----------|
| Insecure storage (non-sensitive) | Info → Low | App preferences only |
| Insecure storage (tokens) | Low → High | Auth tokens in plaintext |
| Insecure storage (PII) | Medium → High | Financial/health data unencrypted |
| Missing SSL pinning | Low → Medium | Banking/financial app |
| Exported activity (non-sensitive) | Low | Settings/about screens |
| Exported activity (auth bypass) | Medium → High | Skips login to sensitive data |
| Deep link (open redirect) | Low → Medium | Chains with phishing |
| Deep link (auth bypass) | Medium → High | Navigates past authentication |
| WebView JS bridge | Medium → High | Exposes native file/DB access |
| Backup extraction (tokens) | Medium → High | Allows account takeover |
| Root/JB detection bypass | Info | Unless it enables another finding |

## Chain Escalation

- mtest exported activity + atest API access → report as auth bypass (High)
- mtest token extraction + atest account takeover → Critical (proved ATO)
- mtest WebView bridge + ptest XSS → High (native code exec via web vuln)

## De-escalation Rules

- Requires root/jailbreak as prerequisite: drop one level
- Only affects the device owner's own data: cap at Medium
- Requires physical device access: cap at Low unless remote vector exists
