# Bug Bounty — Step 3g: Business Logic Vulnerabilities

Scan for race conditions, missing rate limiting, workflow bypasses, and numeric manipulation.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for business flows and state-changing operations
- If either is missing, tell the user which step to run first

## Vulnerability Patterns

### Race Conditions
- Check-then-act without locking (TOCTOU)
- Balance/inventory checks followed by deduction without atomic operation
- Concurrent requests to redeem single-use tokens/coupons
- File operations without proper locking

**What to look for**: Read → validate → write sequences without transactions or mutex. Financial operations, inventory management, coupon redemption.

### Missing Rate Limiting
- Login endpoints without brute-force protection
- Password reset without rate limiting
- OTP/2FA verification without attempt limits
- API endpoints without throttling (enumeration possible)
- Email/SMS sending without limits (spam abuse)

**What to check**: Auth endpoints, verification flows, resource-intensive operations.

### Workflow Bypass
- Multi-step processes where steps can be skipped
- Client-side state tracking that server doesn't enforce
- Payment flows where amount/price can be modified mid-flow
- Approval workflows that can be self-approved

**What to look for**: Multi-step APIs where step N doesn't verify step N-1 completed.

**Important**: Before reporting a workflow bypass, verify the data lifecycle. If resource R is only created by endpoint A (which enforces the check), then endpoint B operating on R doesn't need to re-check — the precondition is structurally guaranteed. Only report as a vulnerability if an attacker can create R through an alternative path that skips the check. Otherwise, note it as a defense-in-depth recommendation.

### Numeric/Financial Manipulation
- Integer overflow/underflow in calculations
- Negative quantities accepted (refund abuse)
- Floating point precision issues in financial math
- Price set to 0 or negative via parameter manipulation
- Discount stacking beyond intended limits

**What to check**: Any calculation involving money, quantities, or limits.

### Mass Assignment
- Object properties set directly from request body without allowlist
- Hidden fields (role, isAdmin, balance) modifiable via API
- GraphQL mutations accepting unintended fields

**Grep patterns**: `Object.assign(`, `spread operator ...req.body`, `mass_assignment`, `attr_accessible`, `fillable`

## Process

1. **Identify state-changing operations** — payments, transfers, inventory, account changes
2. **Check atomicity** — are read-check-write sequences protected by transactions/locks?
3. **Review rate limiting** — are sensitive endpoints throttled?
4. **Map multi-step flows** — can steps be skipped or replayed?
5. **Check numeric handling** — are bounds validated? Are negative values rejected?
6. **Review mass assignment** — are request bodies filtered before object updates?

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Business Logic

**Date**: {date}
**Scanner**: vuln-logic

## Findings

### VULN-BL-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Race Condition / Missing Rate Limit / Workflow Bypass / Numeric Manipulation / Mass Assignment}
**Location**: `{file}:{line}`
**CWE**: CWE-{362|770|841|190|915}

**Description**:
{What logic flaw exists and how it can be abused}

**Vulnerable Code**:
```{lang}
{code showing the logic flaw}
`` `

**Attack Scenario**:
{Steps to exploit — e.g., concurrent requests, parameter manipulation}

**Impact**:
{Financial loss, unauthorized state changes, abuse of functionality}

**Remediation**:
{Add locking, rate limiting, server-side validation, atomic operations}

---
```

## Rules

- **Focus on financial/state-changing operations** — these have the highest bounty payouts.
- **Race conditions need atomic operations** — just adding a check isn't enough.
- **Rate limiting must be server-side** — client-side throttling is not a control.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — Business Logic` section, replace it entirely. See `sc3-vuln-scan` idempotency rule.
- **Save to `./assessment/vulnerabilities.md`** and confirm.