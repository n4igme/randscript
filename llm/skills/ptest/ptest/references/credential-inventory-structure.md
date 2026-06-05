# Credential Inventory Structure

## Overview

During a pentest engagement, credentials are discovered at multiple points across multiple phases. Without a centralized inventory, you lose track of what's been found, what's been tested, and what chains are possible.

The credential inventory is created at Phase 6 start but populated retroactively from Phases 1-5 findings.

## Inventory File

Location: `./ptest-output/exploit/credential-inventory.md`

### Template

```markdown
# Credential Inventory

**Engagement:** {name}
**Last Updated:** {ISO timestamp}
**Total Credentials:** {count}
**Validated:** {count} | **Invalid:** {count} | **Untested:** {count}

---

## Summary

| ID | Type | Source | Source Env | Primary Target | Status | Cross-Env Tested | Findings |
|----|------|--------|-----------|----------------|--------|-------------------|----------|
| C-1 | | | | | | | |
| C-2 | | | | | | | |

---

## Detailed Entries

### C-1: {descriptive name}

| Field | Value |
|-------|-------|
| **Type** | db_password / api_key / oauth_secret / user_password / service_token / ssh_key / jwt |
| **Credential** | `{redacted or reference to evidence file}` |
| **Source** | Where discovered (heapdump, JS bundle, actuator/env, CTI, Snyk, GitHub) |
| **Source Phase** | Phase number where discovered |
| **Source Environment** | mock / dev / sit / uat / prod / ci-cd |
| **Discovery Date** | {ISO date} |
| **Associated Service** | What service/system this credential belongs to |
| **Permission Level** | read-only / read-write / admin / service-account / realm-admin |
| **Expiry** | Never / {date} / Unknown |

#### Validation Results

| Target | Environment | Result | Date Tested | Evidence |
|--------|-------------|--------|-------------|----------|
| Keycloak token endpoint | SIT | ✅ Valid — realm-admin token obtained | 2024-01-15 | FINDING-3 |
| Keycloak token endpoint | Prod | ❌ Invalid — "invalid_client_credentials" | 2024-01-15 | — |
| Direct DB connection | SIT | ⏳ Untested — port not exposed | — | — |
| Microservice /api/users | Prod | ✅ Valid — 200 with data | 2024-01-15 | FINDING-7 |

#### Chain Potential

- [ ] Same credential on higher environment?
- [ ] Credential grants access to other services?
- [ ] Can extract MORE credentials from accessed service?
- [ ] Can escalate privilege level?

#### Notes
{Free-form notes about this credential — context, limitations, ideas}

---
```

## Credential Types & Validation Methods

| Type | How to Validate | What Success Looks Like |
|------|----------------|------------------------|
| `db_password` | Direct connection (`psql`, `mysql`, `mongosh`) or SSRF to internal port | Connected, can run queries |
| `api_key` | Include in request header/param to target API | 200 response with data (vs 401/403) |
| `oauth_secret` | `client_credentials` grant to token endpoint | Access token returned |
| `user_password` | `password` grant to token endpoint, or login form | Access token or session cookie |
| `service_token` | Bearer token in Authorization header | 200 response (vs 401) |
| `ssh_key` | `ssh -i key user@host` | Shell access |
| `jwt` | Include as Bearer token, check if still valid | 200 response (not expired/revoked) |
| `snyk_token` | `GET https://api.snyk.io/rest/self` with token | 200 with org info |
| `github_token` | `GET https://api.github.com/user` with token | 200 with user/bot info |

## Cross-Environment Testing Matrix

For each credential, systematically test across environments:

```
┌─────────────────────────────────────────────────────────────┐
│ Credential found in: MOCK                                   │
│                                                             │
│ Test against:                                               │
│   [?] mock.service.domain.com    (same env — baseline)      │
│   [?] sit.service.domain.com     (one level up)             │
│   [?] uat.service.domain.com     (two levels up)            │
│   [?] prod.service.domain.com    (production — highest val) │
│   [?] gateway.domain.com/service (via API gateway)          │
│   [?] other-service same env     (lateral — same cluster)   │
│                                                             │
│ Legend: [✅] Valid  [❌] Invalid  [⏳] Untested  [🚫] N/A    │
└─────────────────────────────────────────────────────────────┘
```

**Priority order for cross-env testing:**
1. Same credential → production (highest impact if valid)
2. Same credential → other services in same env (lateral movement)
3. Same credential → higher environments (escalation path)
4. Derived credentials (e.g., token from cred → access new service → find new cred)

## Credential Chain Tracking

When one credential leads to another, document the chain:

```markdown
## Attack Chains

### Chain 1: Mock Heapdump → Prod Microservices

```
C-1 (SA token from heapdump)
  → SIT Keycloak realm-admin access
    → C-4 (user list with emails)
      → C-5 (CTI password for user X)
        → Prod Keycloak user token
          → 8 microservices with authenticated access
```

**Total Impact:** Unauthenticated internet access → Full production API access
**Findings Generated:** FINDING-3, FINDING-5, FINDING-7, FINDING-8
**Chain Severity:** Critical (individual findings range Medium-High)
```

## Lifecycle Rules

1. **Create inventory at Phase 6 start** — but backfill from all previous phases
2. **Update immediately** when any new credential is discovered (even in Phase 7)
3. **Never store plaintext production credentials in the report** — use references like "credential stored in evidence file E-3" or redact with `{REDACTED-C1}`
4. **Mark expired/rotated credentials** — if a credential stops working during the engagement, note when and why
5. **Track authorization boundaries** — some credentials (CTI/breach) require explicit authorization to test. Mark these clearly.

## Integration with Findings

Each validated credential that demonstrates impact becomes a finding:

- Credential **exists** in an accessible location → Finding (information disclosure)
- Credential **works** on the source system → Finding (validates the exposure)
- Credential **works cross-environment** → Finding (environment isolation failure)
- Credential **chains** to higher access → Finding (privilege escalation)

A single credential can generate multiple findings at different severity levels:
- Heapdump downloadable without auth → Critical (data exposure)
- Extracted token valid on SIT → High (cross-env access)
- Same token valid on prod → Critical (production compromise)

## Pitfalls

- **Don't test CTI credentials without explicit written authorization.** Document the risk without logging in.
- **Rate limiting / account lockout.** Check thresholds before testing. One lockout on a production admin account = engagement over.
- **Token expiry.** Keycloak access tokens expire in 5 minutes by default. Refresh tokens in 30 minutes. Work fast or automate.
- **Credential rotation during engagement.** If a credential stops working, the client may have rotated it (possibly because they detected your testing). Note this.
- **Don't confuse "credential exists" with "credential works."** A password in a heapdump might be old/rotated. Always validate before claiming impact.
- **Scope check.** A credential might give access to systems OUTSIDE your authorized scope. If cross-env testing would hit out-of-scope systems, stop and ask the client.
