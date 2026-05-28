# Re-Validation Loops (Mini-Enumeration)

## Overview

The ptest framework enforces strict sequential phases: recon → enumeration → attack surface → vuln assessment → exploitation → post-exploitation. But real engagements aren't linear. When Phase 6 exploitation opens NEW attack surface (new services, new environments, new credentials), you need to enumerate that surface before exploiting it.

Re-validation loops are **time-boxed mini-enumerations** that run WITHIN Phase 6 or 7 without formally restarting earlier phases.

## When to Trigger a Re-Validation Loop

```
TRIGGER CONDITIONS (any one is sufficient):

1. New credential validated → grants access to previously unreachable services
   Example: Heapdump token works on SIT Keycloak → 8 new microservices visible

2. New environment discovered → wasn't in original scope enumeration
   Example: Credential chaining reveals prod gateway that wasn't in DNS

3. WAF bypass achieved → endpoints previously blocked are now reachable
   Example: Case variation bypass → actuator endpoints on 15 hosts now accessible

4. Privilege escalation → higher-privilege view reveals new assets
   Example: Admin token shows internal services not visible to regular users

5. Lateral movement → reached new network segment
   Example: Pod-to-pod access reveals internal services not exposed externally
```

## Loop Structure

### Time Budget

**Hard cap: 15 minutes per re-validation loop.**

If the new surface is large enough to need more than 15 minutes of enumeration, it should be flagged as a scope expansion discussion with the client — not silently absorbed into the current phase.

### Procedure

```
┌─────────────────────────────────────────────────────────────┐
│ RE-VALIDATION LOOP (15 min max)                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ Minute 0-5: DISCOVER                                        │
│   • List all newly accessible endpoints/services            │
│   • Identify what's different from known attack surface     │
│   • Count new assets                                        │
│                                                             │
│ Minute 5-10: ASSESS                                         │
│   • Quick auth check on new endpoints (auth required?)      │
│   • Check for actuator/admin/swagger on new services        │
│   • Identify data sensitivity (PII? financial? config?)     │
│   • Check for MORE credentials in new surface               │
│                                                             │
│ Minute 10-15: PRIORITIZE                                    │
│   • Score new assets using Attack Surface Priority Matrix   │
│   • Add high-priority targets to Phase 6 exploitation queue │
│   • Document new surface in attack-surface addendum         │
│   • If new credentials found → add to credential inventory │
│                                                             │
│ OUTPUT:                                                      │
│   • Updated attack surface (addendum to Phase 4)            │
│   • New targets in Phase 6 priority queue                   │
│   • Updated credential inventory (if applicable)            │
│   • Decision: exploit now or note for later                 │
└─────────────────────────────────────────────────────────────┘
```

## Documentation

### Log Each Loop

Add to `./ptest-output/exploit/re-validation-loops.md`:

```markdown
# Re-Validation Loops

## Loop 1: {Descriptive Name}

**Trigger:** {What caused this loop}
**Time:** {timestamp}
**Duration:** {actual minutes spent}
**Phase:** {6 or 7}

### Trigger Context
{What finding/credential/access opened this new surface}

### New Surface Discovered
| Asset | Type | Auth Required | Data Sensitivity | Priority |
|-------|------|--------------|-----------------|----------|
| /bpm/v1/ | REST API | JWT (have it) | Business process data | High |
| /customer/v1/ | REST API | JWT (have it) | PII — customer records | Critical |
| /scoring/v1/ | REST API | JWT (have it) | Credit scoring rules | Critical |

### Credentials Found
{Any new credentials discovered during this loop — add to inventory}

### Decision
- [ ] Exploit immediately (added to Phase 6 queue)
- [ ] Note for later (time constraint)
- [ ] Out of scope (flag to client)
- [ ] Requires separate engagement (too large)

### Findings Generated
{List any findings that came directly from this loop}
```

## Decision: Exploit Now vs Later

```
New surface discovered. Should I exploit it now?

├── Is it in scope?
│   ├── NO → Document, flag to client, STOP
│   └── YES ↓
│
├── Is it higher priority than current work?
│   ├── YES → Pause current technique, exploit new surface
│   └── NO → Add to queue, continue current work
│
├── Is Phase 6 time budget exhausted?
│   ├── YES → Document in "not tested" section, recommend follow-up
│   └── NO → Add to queue at appropriate priority
│
└── Does it extend an existing attack chain?
    ├── YES → Exploit NOW (chain completion is highest value)
    └── NO → Queue by priority score
```

## Common Re-Validation Scenarios

### Scenario 1: Credential Opens New Services

```
Trigger: JWT obtained from Keycloak works on production gateway
New surface: 8 microservices behind the gateway

Mini-enum (15 min):
1. curl each service root with JWT → which return 200?
2. Check /actuator, /swagger-ui.html, /v3/api-docs on each
3. Identify data types per service (from swagger or sample responses)
4. Prioritize: customer data > financial data > config data

Result: Add top 3 services to exploitation queue
```

### Scenario 2: WAF Bypass Reveals Endpoints

```
Trigger: Case variation bypass works on /Actuator/Health
New surface: Actuator endpoints on 15 hosts previously blocked

Mini-enum (15 min):
1. Test bypass on all live hosts (bulk script)
2. For each successful bypass, check: /env, /configprops, /heapdump, /mappings
3. Identify which hosts have sensitive actuator data
4. Check if heapdump is downloadable (Critical finding)

Result: 3 hosts with heapdump accessible → immediate exploitation
```

### Scenario 3: Lateral Movement in K8s

```
Trigger: Shell in pod, can reach internal services
New surface: Internal service mesh (pod-to-pod communication)

Mini-enum (15 min):
1. List services in namespace (K8s API or DNS enumeration)
2. curl each internal service (often no auth internally)
3. Check for sensitive data endpoints
4. Check for admin/management interfaces

Result: 2 internal services with no auth → document data access
```

### Scenario 4: Privilege Escalation Reveals Admin View

```
Trigger: IDOR gives admin-level API access
New surface: Admin endpoints not visible to regular users

Mini-enum (15 min):
1. Enumerate admin-only endpoints (from swagger or actuator/mappings)
2. Test each for data access (user management, config, audit logs)
3. Check if admin can modify security settings
4. Check if admin can access other environments

Result: Admin can view all user credentials → Critical finding
```

## Integration with Phase 6 Framework

### In the Phase 6 Checklist

When a re-validation loop is triggered, add a row:

```markdown
| # | Technique | Status | Findings | Time Spent | Notes |
|---|-----------|--------|----------|------------|-------|
| 6.11 | Credential Chaining | DONE | FINDING-5,6 | 1.2h | |
| RE-1 | Re-validation: JWT opens 8 services | DONE | FINDING-7,8,9 | 0.25h | Triggered by 6.11 |
| 6.12 | Service-Specific (new targets from RE-1) | DONE | FINDING-10 | 0.5h | |
```

### In the Attack Chain

Re-validation loops often EXTEND existing chains:

```
[FINDING-5: Credential valid on prod]
    │
    ▼
[RE-VALIDATION LOOP 1: 8 services discovered]
    │
    ▼
[FINDING-7: Customer data accessible (45K records)]
    │
    ▼
[IMPACT: Full production data breach]
```

### In state.yaml

```yaml
re_validation_loops:
  count: 2
  total_time_spent: 0.5  # hours
  loops:
    - id: RE-1
      trigger: "JWT from credential chaining (6.11) opens prod gateway"
      phase: 6
      time_spent: 0.25
      new_assets: 8
      findings_generated: [7, 8, 9]
    - id: RE-2
      trigger: "WAF bypass (6.7) reveals actuator on 15 hosts"
      phase: 6
      time_spent: 0.25
      new_assets: 15
      findings_generated: [11]
```

## Scope Expansion vs Re-Validation

**Re-validation loop (do it):**
- New surface is within authorized scope
- Can be enumerated in ≤15 minutes
- Directly extends current attack chain
- Same target organization, same engagement

**Scope expansion (stop, discuss with client):**
- New surface is in a different organization/subsidiary
- Would require >1 hour of enumeration
- Involves different infrastructure team
- Requires additional authorization
- Crosses network boundaries not in original scope

When in doubt, ask: "If I test this and break something, does my authorization cover it?" If no → stop and discuss.

## Pitfalls

- **Don't let re-validation become a new Phase 3.** 15 minutes max. If it needs more, it's scope expansion.
- **Don't skip re-validation because "we're in Phase 6 now."** The strict sequence is for the INITIAL pass. New access legitimately requires new enumeration.
- **Track time separately.** Re-validation time comes from Phase 6/7 budget, not from a magic extra pool. It's part of exploitation.
- **Don't re-validate the same surface twice.** If you already enumerated a service in Phase 3 and now have auth for it, you don't need to re-enumerate — just exploit.
- **Document even if you don't exploit.** "Re-validation revealed 8 services but time constraint prevented testing" is important for the report and follow-up engagement scoping.
- **New credentials ALWAYS go in the inventory.** Even if found during a 15-minute loop. The inventory is the single source of truth.
