---
name: vuln-access-control
description: "Step 3b of bug bounty workflow. Scan for access control vulnerabilities (IDOR, missing authz, privilege escalation). Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Step 3b: Access Control Vulnerabilities

Scan for broken access control: IDOR, missing authorization checks, and privilege escalation paths.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for auth mechanisms and entry points
- If either is missing, tell the user which step to run first

## Vulnerability Patterns

### Insecure Direct Object Reference (IDOR)
- Endpoints that take an object ID (user ID, order ID, file ID) from the request
- Object fetched by ID without verifying the requesting user owns it
- Sequential/predictable IDs making enumeration easy

**What to check**: Every endpoint with `:id`, `?id=`, or path params that fetch a resource — does the handler verify ownership?

### Missing Authorization
- Endpoints with no auth middleware applied
- Admin/privileged routes accessible to regular users
- API endpoints that check authentication but not authorization (role/permission)
- Inconsistent auth: some routes in a group protected, others not

**What to check**: Compare the route definitions against middleware application. Look for gaps.

### Horizontal Privilege Escalation
- User A can access User B's resources by changing an ID parameter
- Shared resources without proper tenant isolation
- API responses leaking other users' data in lists/searches

### Vertical Privilege Escalation
- Regular user accessing admin endpoints
- Role checks that can be bypassed (client-side role, manipulable JWT claims)
- Missing role validation on state-changing operations
- Privilege granted by a field the user can modify

## Process

1. **Map all protected routes** — identify which endpoints have auth/authz middleware
2. **Find unprotected routes** — identify endpoints missing auth that handle sensitive data
3. **Check object-level access** — for each endpoint with an ID param, verify ownership check exists
4. **Check function-level access** — for admin/privileged operations, verify role checks
5. **Test escalation paths** — can a user modify their role, access other tenants, or reach admin functions?

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Access Control

**Date**: {date}
**Scanner**: vuln-access-control

## Findings

### VULN-AC-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Category**: {IDOR / Missing Authorization / Horizontal Escalation / Vertical Escalation}
**Location**: `{file}:{line}`
**CWE**: CWE-{639|862|863|284}

**Description**:
{What the vulnerability is}

**Vulnerable Code**:
```{lang}
{code showing missing check}
`` `

**Attack Scenario**:
1. Attacker authenticates as User A
2. Changes ID parameter to User B's resource
3. Server returns User B's data without ownership check

**Impact**:
{What attacker gains — other users' data, admin access, etc.}

**Remediation**:
```{lang}
{code with proper ownership/role check added}
`` `

---
```

## Rules

- **Check every endpoint with an ID parameter** — IDOR is the #1 bug bounty finding.
- **Compare route definitions to middleware** — find the gaps.
- **Show what check is missing** — not just that it's missing, but what it should be.
- **Append to `./assessment/vulnerabilities.md`** and confirm.
