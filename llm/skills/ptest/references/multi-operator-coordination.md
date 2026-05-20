# Multi-Operator Coordination

## Overview

When running engagements with multiple pentesters (e.g., n4igme + Ardya + Jeremyah), the single-operator ptest framework needs coordination to prevent duplicate work, merge findings, and maintain a coherent attack narrative.

## Coordination Model

### Roles

| Role | Responsibility | Typical Assignment |
|------|---------------|-------------------|
| **Lead** | Scope definition, phase transitions, gateway sign-offs, report assembly, client communication | Most experienced operator |
| **Operator** | Execute assigned techniques, document findings, update shared state | All team members |
| **Reviewer** | Verify findings before report inclusion, check for false positives | Rotates or assigned to Lead |

### Work Splitting Strategies

#### Strategy 1: Phase-Based Split (Sequential)

```
Operator A: Phases 1-3 (Recon + Enumeration)
Operator B: Phases 4-5 (Attack Surface + Vuln Assessment)  
Operator C: Phases 6-7 (Exploitation + Post-Exploitation)
All: Phase 8 (Reporting — Lead assembles, all review)
```

**Pros:** Clear ownership, no overlap, natural handoff points
**Cons:** Sequential bottleneck, later operators idle during early phases
**Best for:** Large scope where each phase takes 1+ days

#### Strategy 2: Target-Based Split (Parallel)

```
Operator A: Targets 1-10 (all phases)
Operator B: Targets 11-20 (all phases)
Operator C: Targets 21-30 (all phases)
```

**Pros:** Fully parallel, no waiting, each operator owns end-to-end
**Cons:** Duplicate recon on shared infrastructure, credential chaining across targets requires coordination
**Best for:** Multiple independent applications/targets with minimal shared infrastructure

#### Strategy 3: Technique-Based Split (Parallel within Phase)

```
Phase 3 (Enumeration):
  Operator A: Directory brute-force + API discovery
  Operator B: JS analysis + parameter discovery
  Operator C: CMS enum + vhost enumeration

Phase 6 (Exploitation):
  Operator A: Credential chaining + auth bypass
  Operator B: Injection attacks + business logic
  Operator C: CVE exploitation + SSRF
```

**Pros:** Maximum parallelism within phases, specialists can focus on strengths
**Cons:** Requires tight coordination, findings from one technique inform another
**Best for:** Time-pressured engagements where speed matters most

#### Strategy 4: Hybrid (Recommended for most engagements)

```
Phases 1-3: All operators work in parallel (technique-based split)
Phase 4: Lead consolidates attack surface (all operators input)
Phase 5: Technique-based split
Phase 6-7: Target-based split (each operator owns a target group)
Phase 8: Lead writes, all review
```

## Shared State Management

### Directory Structure (Multi-Operator)

```
./ptest-output/
  state.yaml                    # SINGLE source of truth — Lead manages
  scope.md                      # Shared — read-only after Phase 1
  findings-log.md               # Shared — append-only, use finding IDs
  credential-inventory.md       # Shared — any operator can add
  attack-chains.md              # Shared — Lead maintains
  
  operators/
    operator-a/                 # Per-operator workspace
      notes.md                  # Personal notes, scratch work
      assigned-techniques.md    # What they're working on
    operator-b/
      notes.md
      assigned-techniques.md
    operator-c/
      notes.md
      assigned-techniques.md
  
  recon-passive/
    checklist.md                # Shared — techniques assigned to operators
  recon-active/
    checklist.md
  enumeration/
    checklist.md
  ...
```

### Checklist Format (Multi-Operator)

```markdown
| # | Technique | Assigned To | Status | Findings | Time Spent |
|---|-----------|-------------|--------|----------|------------|
| 3.1 | Directory Brute-Force | Operator A | DONE | FINDING-4 | 1.5h |
| 3.2 | API Endpoint Discovery | Operator A | IN PROGRESS | | 0.5h |
| 3.3 | Parameter Discovery | Operator B | PENDING | | |
| 3.4 | JS Analysis | Operator B | DONE | FINDING-5,6 | 2.0h |
| 3.5 | CMS Enumeration | Operator C | SKIPPED (no CMS) | | 0.1h |
```

### Finding ID Coordination

**Problem:** Two operators discover findings simultaneously → ID collision.

**Solution:** Pre-allocate ID ranges:

```yaml
# In state.yaml
finding_id_ranges:
  operator_a: [1, 100]      # FINDING-1 through FINDING-100
  operator_b: [101, 200]    # FINDING-101 through FINDING-200
  operator_c: [201, 300]    # FINDING-201 through FINDING-300

# At report assembly, Lead renumbers sequentially
# Mapping: FINDING-101 → FINDING-5 (in final report)
```

**Alternative (simpler for small teams):** Use operator prefix: `FINDING-A1`, `FINDING-B1`, `FINDING-C1`. Renumber at report time.

### Credential Inventory Coordination

**Rule:** Any operator who discovers a credential MUST add it to the shared inventory immediately.

**Conflict prevention:**
- Each operator adds entries (append-only)
- Only Lead removes/modifies entries
- Credential IDs use operator prefix: `C-A1`, `C-B1`, `C-C1`
- Validation results: any operator can add rows to the validation table

**Cross-operator handoff:** When Operator A finds a credential that's relevant to Operator B's targets:

```markdown
## Credential Handoff

| Credential | Found By | Relevant To | Handoff Status |
|-----------|----------|-------------|----------------|
| C-A3: Keycloak SA token | Operator A | Operator B (prod targets) | ✅ Handed off, validated |
| C-B2: DB password | Operator B | Operator C (internal services) | ⏳ Pending validation |
```

## Communication Protocol

### Sync Points

| Event | Action | Who |
|-------|--------|-----|
| Engagement start | Assign techniques, confirm scope understanding | All (Lead facilitates) |
| Phase transition | Review checklist, confirm exit criteria, assign next phase | All (Lead decides) |
| Critical finding | Immediate notification to Lead + all operators | Finder → All |
| New credential | Add to inventory + notify relevant operator | Finder → Relevant |
| Scope question | Escalate to Lead → Lead asks client | Any → Lead |
| Stuck > 30 min | Ask team for ideas before marking FAILED | Any → All |
| End of day | Quick sync: what's done, what's blocked, plan for tomorrow | All |

### Communication Channels

```
Primary: Shared Telegram group (real-time)
Secondary: findings-log.md (async, permanent record)
Escalation: Direct message to Lead (urgent items)
Client: Lead only (single point of contact)
```

### Message Templates

**Finding notification:**
```
🔴 FINDING-A7: Heapdump exposed on bravo-bpm.mock
Severity: Critical
Affects: Operator B's targets (prod gateway uses same creds)
Action needed: Operator B — validate C-A3 against prod Keycloak
```

**Technique handoff:**
```
✅ Technique 3.1 (Dir Brute-Force) complete
Results: 4 new endpoints found, added to shared enumeration results
Relevant for: Operator C — /admin/ path found on target group 3
```

**Blocked notification:**
```
⚠️ Blocked on technique 6.4 (Injection)
Target: api.prod.domain.com
Issue: WAF blocking all payloads, tried Level 1-4 bypasses
Need: Has anyone found a working bypass on this WAF?
Time spent: 25 min (will mark FAILED at 60 min if no solution)
```

## Conflict Resolution

### Duplicate Findings

When two operators find the same issue:

1. Keep the finding with better evidence/reproduction steps
2. Credit both operators in the finding notes
3. Merge any unique details from the duplicate
4. Delete the duplicate, update ID references

### Scope Overlap

When two operators accidentally test the same target:

1. Check who started first (timestamp in checklist)
2. First operator keeps the assignment
3. Second operator's work is merged if it adds value, discarded if redundant
4. Reassign second operator to untested targets

### Disagreement on Severity

When operators disagree on a finding's severity:

1. Both calculate CVSS independently
2. Compare vectors — identify which factors differ
3. Lead makes final call based on:
   - Client context (financial services → higher severity for data exposure)
   - Chain impact (finding enables other findings → higher)
   - Exploitability in practice (not just theoretical)
4. Document the disagreement in finding notes if significant

## Reporting (Multi-Operator)

### Assembly Process

```
1. Lead collects all findings from all operators
2. Renumber finding IDs sequentially (by severity, then by phase)
3. Merge credential inventories
4. Build unified attack chains (may span multiple operators' work)
5. Write executive summary and attack narrative (Lead)
6. Each operator reviews their own findings for accuracy
7. Cross-review: each operator reviews another's findings
8. Lead finalizes and delivers
```

### Attribution (Internal)

For internal tracking (not in client report):

```markdown
## Operator Contributions

| Operator | Findings | Critical | High | Medium | Low | Techniques Completed |
|----------|----------|----------|------|--------|-----|---------------------|
| Operator A | 12 | 2 | 4 | 4 | 2 | 15 |
| Operator B | 8 | 1 | 3 | 3 | 1 | 12 |
| Operator C | 6 | 0 | 2 | 3 | 1 | 10 |
| **Total** | **26** | **3** | **9** | **10** | **4** | **37** |
```

## Scaling Guidelines

| Team Size | Recommended Strategy | Coordination Overhead |
|-----------|---------------------|----------------------|
| 2 operators | Technique-based split within phases | Low — informal sync |
| 3 operators | Hybrid (parallel recon, target-based exploit) | Medium — daily sync needed |
| 4+ operators | Target-based with dedicated Lead (non-testing) | High — Lead coordinates full-time |

**Rule of thumb:** Add 10% overhead per additional operator for coordination. A 3-person team is ~20% less efficient per-person than a solo operator, but covers 2.4x more ground.

## Pitfalls

- **Don't assume the other operator tested something.** If it's not in the checklist as DONE, it wasn't done.
- **Don't modify shared files without notification.** Especially findings-log.md and credential-inventory.md. Append-only unless you're the Lead.
- **Don't test credentials on another operator's targets without telling them.** You might trigger lockouts or alerts they're not expecting.
- **Don't skip the end-of-day sync.** 10 minutes of alignment prevents hours of duplicate work tomorrow.
- **Don't let the Lead become a bottleneck.** If the Lead is the only one who can advance gateways, and they're busy testing, phases stall. Lead should prioritize coordination over personal testing.
- **Don't split attack chains across operators without a handoff.** If Operator A finds the entry point and Operator B needs to chain from it, the handoff must be explicit with all context transferred.
- **Credit findings to the team, not individuals, in the client report.** Internal attribution is fine; client-facing report comes from "the team."
