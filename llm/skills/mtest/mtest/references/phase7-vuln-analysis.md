# Phase 7: Vulnerability Analysis (Feature-Driven)

### Gate: All features from Phase 5 attack surface map tested; findings documented per feature

### Methodology

For EACH feature in the attack surface map (Phase 5):
1. Identify entry points (UI, deep links, intents, API calls)
2. Map applicable vulnerability classes (from OWASP Mobile Top 10 + custom)
3. Execute test cases per vuln class
4. Document findings immediately with evidence

This is NOT a flat checklist of vulnerability types. You test **per feature** — the login flow gets auth-specific tests, the payment flow gets business-logic tests, the file upload gets path-traversal tests. Each feature has its own threat model.

### Feature Testing Workflow

```
For each feature in attack-surface-map.md:
  1. Open feature testing file: phase7-vuln-analysis/per-feature/<feature-name>.md
  2. List all entry points for this feature
  3. For each applicable vuln class:
     a. Execute test case
     b. Record result (vulnerable / not vulnerable / inconclusive)
     c. If vulnerable → create finding immediately (MTEST-XXX)
  4. Mark feature as TESTED in attack surface map
```

### Feature Testing Template

Save one file per feature in `phase7-vuln-analysis/per-feature/`:

```markdown
# Feature: [Name] — Vulnerability Analysis

**Risk Priority:** Critical|High|Medium|Low (from Phase 5)
**Entry Points:**
- UI: [path to screen]
- API: [endpoints]
- Deep Link: [scheme://path]
- Intent: [action/component]

## Test Matrix

| Vuln Class | Test Case | Result | Finding |
|-----------|-----------|--------|---------|
| Brute Force | 100 login attempts, check lockout | Not Vuln | — |
| OTP Bypass | Reuse OTP, expired OTP, null OTP | Vulnerable | MTEST-003 |
| Session Fixation | Pre-set session token before auth | Not Vuln | — |
| Token Leakage | Check logcat, analytics, clipboard | Vulnerable | MTEST-004 |
| ... | | | |

## Notes
[Observations, partial findings, things to revisit in Phase 9]
```

> Execution procedures (top 10 vulns) + full vuln classes checklist + per-feature mapping: `references/phase7-execution-procedures.md`
