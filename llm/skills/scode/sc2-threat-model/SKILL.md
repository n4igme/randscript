---
name: sc2-threat-model
description: "Step 2 of bug bounty workflow. Perform threat modelling based on recon.md. Outputs threat-model.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to recon.md, defaults to ./assessment/recon.md>
---

# Bug Bounty — Step 2: Threat Modelling

Analyze the reconnaissance output to identify threats, attack vectors, and prioritize areas for vulnerability scanning.

## Input

$ARGUMENTS

- If a path is provided, read that file as the recon report
- If no argument, read `./assessment/recon.md` from the current directory
- If recon.md doesn't exist, tell the user to run `sc1-recon` first

## Process

### 1. Identify Threat Actors

Based on the application type, define relevant threat actors:
- Unauthenticated external attacker
- Authenticated regular user (horizontal privilege escalation)
- Authenticated privileged user (vertical privilege escalation)
- Malicious insider / compromised dependency

### 2. STRIDE Analysis

For each entry point from recon.md, apply STRIDE:
- **Spoofing** — Can identity be faked? (auth bypass, token forgery)
- **Tampering** — Can data be modified? (parameter manipulation, request forgery)
- **Repudiation** — Can actions be denied? (missing audit logs)
- **Information Disclosure** — Can data leak? (verbose errors, IDOR, injection)
- **Denial of Service** — Can availability be impacted? (resource exhaustion, regex DoS)
- **Elevation of Privilege** — Can access be escalated? (missing authz, role bypass)

### 3. Feature-Level Threat Analysis

For each business feature identified in recon.md:
- **Abuse cases** — how can the workflow be misused? (skip steps, replay, race, parameter tampering)
- **Assets at risk** — what data/money/access is at stake within this feature?
- **Trust assumptions** — what does the feature assume about user behavior that an attacker would violate?
- **Cross-feature attacks** — can exploiting one feature compromise another?

### 4. Attack Tree Construction

For high-value targets identified in recon, build attack trees:
- Goal: What the attacker wants (data theft, RCE, account takeover)
- Paths: Different ways to achieve the goal
- Preconditions: What's needed for each path

### 5. Prioritize Attack Surface

Rank areas by:
1. **Exposure** — unauthenticated > authenticated > internal
2. **Impact** — RCE > data breach > privilege escalation > information disclosure
3. **Complexity** — simple exploitation > multi-step chains
4. **Data sensitivity** — PII/financial > general user data > public data

## Output

Save to `./assessment/threat-model.md` (create the `assessment/` directory if it doesn't exist):

```markdown
# Threat Model

**Based on**: recon.md
**Date**: {date}

## Threat Actors

| Actor | Access Level | Motivation |
|-------|-------------|------------|
| External attacker | None | Data theft, RCE |
| Authenticated user | Standard | Privilege escalation, IDOR |
...

## STRIDE Analysis

### {Entry Point / Component}

| Threat | Category | Risk Level | Attack Vector |
|--------|----------|------------|---------------|
| ... | Spoofing | High | ... |

## Feature Threat Analysis

### {Feature Name, e.g., Order Management}

**Endpoints**: POST /api/orders, PUT /api/orders/:id/cancel, ...
**Assets at Risk**: Financial transactions, inventory state

| Abuse Case | Attack Vector | Impact | Likelihood |
|------------|--------------|--------|------------|
| Skip payment step | Direct call to order-confirm without payment | Free goods | Medium |
| Race condition on stock | Concurrent purchase requests | Overselling | High |
| Replay refund | Resubmit refund request | Double refund | Medium |

**Trust Assumptions Violated**:
- Assumes user follows UI flow sequentially
- Assumes single request per action

---

## Attack Trees

### Goal: {e.g., Account Takeover}

1. Path A: {description}
   - Precondition: ...
   - Steps: ...
2. Path B: {description}
   - ...

## Priority Targets

Ordered list of what to scan first:

| Priority | Target | Why | Expected Vuln Classes |
|----------|--------|-----|----------------------|
| 1 | /api/users/:id | IDOR candidate, returns PII | IDOR, Info Disclosure |
| 2 | /api/upload | File handling, no size check visible | Unrestricted Upload, SSRF |
...

## Trust Boundaries

{Diagram or description of where trust levels change — e.g., public → authenticated → admin}

## Assumptions & Gaps

{What couldn't be determined from static analysis alone}
```

## Rules

- **Read recon.md thoroughly** before starting analysis.
- **Be specific** — reference actual endpoints and files from the recon, not generic threats.
- **Prioritize ruthlessly** — the priority list guides Step 3 scanning order.
- **Save to `./assessment/threat-model.md`** and confirm.
- **Do NOT print the full report to terminal.**
