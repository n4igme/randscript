# Finding Template

Every finding documented during the engagement MUST follow this format.

## Finding ID Assignment

IDs are auto-incremented from `state.yaml`:
1. Read current `findings_count` from `./ptest-output/state.yaml`.
2. Increment by 1.
3. Use the new value as the finding ID (e.g., `FINDING-1`, `FINDING-2`, ...).
4. Write the updated `findings_count` back to `state.yaml` immediately.

This ensures unique, sequential IDs even across phases and sessions.

## Findings Deduplication Rule

- **Same vulnerability on multiple hosts/gateways** = 1 finding. List all affected assets in the "Affected Asset" field (e.g., `microservices.prod.bfi.co.id, microservices.prod.bravo.bfi.co.id`). Note which are confirmed vs inferred.
- **Same vulnerability class on different endpoints** (e.g., SQLi on `/users` and SQLi on `/orders`) = separate findings (different root cause, different fix).
- **Same root cause, different impact** (e.g., missing auth on GET vs POST of same endpoint) = 1 finding documenting all methods affected.

## Template

```markdown
## [FINDING-{ID}] {Title}

**Severity:** Critical / High / Medium / Low / Info
**CVSS 3.1:** {score} ({vector string})
**Affected Asset:** {host, endpoint, or component}
**Environment:** prod / nonprod / experiment / all
**Phase Discovered:** {phase number and name}
**Phase Confirmed:** {phase number and name, if different from discovered — optional}
**Verification Status:** Confirmed / Unverified

### Description
{What the vulnerability is and why it matters}

### Steps to Reproduce
1. {step}
2. {step}
3. {step}

### Evidence
{Screenshots, request/response logs, command output — MUST include direct proof}

### Impact
{What an attacker can achieve}

### Remediation
{Required fix and defense-in-depth recommendations}
```

## Verification Status Rules

- **Confirmed** — direct evidence proving the issue exists right now. Only confirmed findings go into the final report.
- **Unverified** — suspected based on indirect evidence but not proven. Goes into "Potential Issues" appendix. Does NOT count toward `findings_count`.
