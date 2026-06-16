# Phase 4: Attack Surface Mapping

## Automated Setup

Run first when entering this phase:

```python
from hermes_tools import read_file
exec(read_file("~/.hermes/skills/security/ptest/scripts/phase4_attack_surface.py")["content"])
```

---

## When to Use
- After enumeration is complete (Gateway 3 PASSED).
- Before any vulnerability assessment or exploitation begins.
- This is a PLANNING phase — consolidate what you've found and get user confirmation.

## Purpose

This phase is the bridge between discovery (Phases 1-3) and attack (Phases 5-7). It ensures:
1. All discovered assets are inventoried in one place
2. The user confirms what's in-scope for exploitation
3. Entry points are clearly mapped for the threat modeling phase
4. No time is wasted attacking out-of-scope or low-value targets

## Tasks

### 1. Asset Inventory

Consolidate all discoveries from Phases 1-3 into a single asset inventory table:

```markdown
# Asset Inventory

| # | Host/URL | IP | Technology | Auth Mechanism | Business Function | Exposure | Priority |
|---|----------|-----|-----------|----------------|-------------------|----------|----------|
| 1 | www.target.com | 1.2.3.4 | Pimcore/PHP 8.1 | Session-based | Corporate website | Public | High |
| 2 | api.target.com | 1.2.3.5 | Node.js | Bearer token | Customer API | Public | Critical |
| ... | | | | | | | |
```

Fields:
- **Host/URL** — the target
- **IP** — resolved IP address
- **Technology** — identified stack (from Phase 1 fingerprinting + Phase 2 service detection)
- **Auth Mechanism** — how authentication works (from Phase 3 auth mapping)
- **Business Function** — what the application does (inferred from content, naming, context)
- **Exposure** — Public / Restricted (auth required) / Internal (not reachable)
- **Priority** — Critical / High / Medium / Low (based on business value and exposure)

### 2. Scope Confirmation

Present the asset inventory to the user and explicitly confirm:

1. **In-scope for exploitation:** Which assets should be actively attacked?
2. **New exclusions:** Any assets discovered that should NOT be tested (e.g., third-party services, production databases with real customer data)?
3. **Priority targets:** Which assets are most business-critical and should be tested first?
4. **Testing depth:** Full exploitation vs. vulnerability identification only?

**This requires user sign-off before proceeding.** Do not advance to Phase 5 without explicit confirmation.

### 3. Entry Point Map

Document all potential entry points for exploitation:

```markdown
# Entry Point Map

## Unauthenticated Entry Points
| # | URL/Endpoint | Method | Input Type | Notes |
|---|-------------|--------|-----------|-------|
| 1 | /login | POST | Form (user/pass) | Pimcore admin login |
| 2 | /api/v1/public/search | GET | Query param | Public search API |
| ... | | | | |

## Authenticated Entry Points (require valid session)
| # | URL/Endpoint | Method | Input Type | Auth Required | Notes |
|---|-------------|--------|-----------|---------------|-------|
| 1 | /api/v1/users | GET | - | Bearer token | User listing |
| ... | | | | | |

## File Upload Points
| # | URL/Endpoint | Accepted Types | Max Size | Notes |
|---|-------------|---------------|----------|-------|
| ... | | | | |

## User Input Fields (potential injection points)
| # | URL/Endpoint | Parameter | Type | Validation Observed |
|---|-------------|-----------|------|-------------------|
| ... | | | | |
```

### 4. Attack Surface Scoring Workflow

Score each asset from the inventory using the prioritization matrix:

**Step 1:** For each asset, assign scores (1-3) for each factor:

| Factor | Score 3 (High) | Score 2 (Medium) | Score 1 (Low) |
|--------|---------------|-----------------|--------------|
| Auth Status | No auth required | Weak auth (Basic, default creds) | Strong auth (JWT, MFA, IAP) |
| Data Sensitivity | PII, credentials, financial | Business logic, configs | Public/reference data |
| Exposure Level | Internet-facing, no WAF | Internet-facing, behind WAF/CDN | Internal IP only |
| Attack Surface Size | Multiple endpoints, accepts input | Few endpoints, limited input | Single static endpoint |
| Environment | Production | UAT/Staging | Dev/Mock |

**Step 2:** Sum scores → Priority tier:
- 12-15: **Critical** — exploit first
- 8-11: **High** — exploit if time permits
- 5-7: **Medium** — quick checks only
- 3-4: **Low** — skip unless nothing else works

**Step 3:** Cross-check against program exclusions. Mark excluded vectors with score 0.

#### Worked Example

```markdown
# Attack Surface Priority Matrix — BFI Finance (May 2026)

| # | Asset | Auth | Data | Exposure | Surface | Env | Score | Tier |
|---|-------|------|------|----------|---------|-----|-------|------|
| 1 | microservices.prod.bfi.co.id/master/v1/* | 3 (none) | 3 (financial) | 2 (WAF) | 3 (many endpoints) | 3 (prod) | **14** | Critical |
| 2 | e-pmo2.bfi.co.id | 2 (Basic) | 2 (business) | 3 (no WAF) | 2 (few endpoints) | 3 (prod) | **12** | Critical |
| 3 | kiali.prod.bfi.co.id | 1 (IAP) | 2 (infra) | 1 (internal IP) | 2 (dashboard) | 3 (prod) | **9** | High |
| 4 | *.mock.bfi.co.id | 3 (none) | 1 (test data) | 2 (WAF) | 2 (API) | 1 (mock) | **9** | High |
| 5 | grafana.dev.bfi.co.id | 1 (strong) | 1 (metrics) | 1 (internal) | 1 (single) | 1 (dev) | **5** | Medium |

**Decision:** Focus Phase 5-6 on assets #1 and #2. Quick-check #3-4. Skip #5.
```

### 5. Dismissal Verification Procedure

**Before dismissing ANY subdomain group, verify:**

1. ✅ Ran gobuster/ffuf with raft-medium-directories against EACH host (filter catch-all response sizes)
2. ✅ Tested `/actuator`, `/actuator/env`, `/actuator/heapdump` on at least 5 hosts
3. ✅ Tested `/swagger-ui.html`, `/api-docs`, `/v3/api-docs` on at least 3 hosts
4. ✅ Tested `/admin`, `/console`, `/login`, `/graphql` on at least 3 hosts
5. ✅ Tested common path prefixes: `/api/`, `/v1/`, `/v2/`, `/internal/`, `/p/`, region codes (`/jp1/`, `/kr1/`, `/sg1/`)
6. ✅ Baselined with random path to detect SPA catch-alls
7. ✅ Documented what was tested in the dismissal entry

**CRITICAL: A catch-all on the root path (400/403/generic error) does NOT mean the host is empty. Hidden path prefixes routinely expose entire applications behind otherwise "blank" hosts. The 5-minute gobuster run is NON-NEGOTIABLE.**

**Dismissal format:**
```markdown
| # | Pattern | Reason | Verified Paths | Hosts Tested | Caveat |
|---|---------|--------|---------------|--------------|--------|
| 1 | *.mock.bfi.co.id | All return 401, shared IP | /actuator(5), /admin(3), /swagger(3) | 8/12 | None |
| 2 | *.dev.bfi.co.id | Internal IPs, unreachable | dig shows 172.x.x.x | 15/15 | Can't verify — no route |
| 3 | kiali-*.bfi.co.id | Private DNS only | N/A | 3/3 | Would need VPN access |
```

**NEVER dismiss without testing actuator/admin paths.** Application auth and framework endpoint auth are independent — a 401 on `/api/users` does NOT mean `/actuator/env` is also protected.

### 6. Dismissed Assets

Document assets that were discovered but are confirmed NOT exploitable or out-of-scope:

```markdown
# Dismissed Assets

| # | Host | Reason |
|---|------|--------|
| 1 | grafana.prod.target.com | Private IP (172.x.x.x) — not reachable |
| 2 | thirdparty-cdn.com | Third-party service, out of scope |
| ... | | |
```

### 5. Cross-Environment Correlation (MANDATORY)

**Bank Jago re-assessment (June 2026):** Phase 4 was initially marked complete without this step. User asked "did we miss something?" — cross-env correlation and credential inventory were both missing from the checklist despite being in the reference. ALWAYS verify the Phase 4 checklist includes ALL tasks from this reference before claiming done.

Map the same service across development, staging, and production environments to compare security posture. Differences between environments often reveal misconfigurations, forgotten hardening steps, or exploitable gaps.

**What to look for:**
- **Credential reuse** — same passwords, API keys, or service accounts across environments
- **Weaker auth in staging** — disabled MFA, default credentials, or relaxed token expiry
- **Same IP but different WAF rules** — production has WAF enforcement but staging on the same host does not
- **Config drift** — security headers present in prod but missing in dev/stg, debug endpoints left enabled, verbose error messages exposed

```markdown
# Cross-Environment Correlation

| Service | Dev | Staging | Production | Delta |
|---------|-----|---------|------------|-------|
| api.target.com | No WAF, debug enabled | WAF bypass via alt path | Full WAF, hardened | Staging alt path bypasses WAF |
| auth.target.com | Default creds active | MFA disabled | MFA enforced | Dev/Stg credential weakness |
| db.target.com | Public access, no TLS | Internal only, no TLS | Internal, TLS enforced | TLS missing in lower envs |
| ... | | | | |
```

Use deltas to identify attack paths: a weakness confirmed in staging often indicates the same underlying code or config exists in production, just with an additional control layer that may be bypassable.

## Output

Document in `./ptest-output/attack-surface/`:
- `asset-inventory.md` — full asset table
- `scope-confirmation.md` — user sign-off on exploitation scope
- `entry-points.md` — all entry points mapped
- `dismissed.md` — assets excluded with reasons

Write `./ptest-output/attack-surface/checklist.md`:

```markdown
# Attack Surface Mapping Checklist

| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Asset Inventory Compiled | PENDING | |
| 2 | Attack Surface Scoring Matrix | PENDING | |
| 3 | Entry Points Mapped | PENDING | |
| 4 | Cross-Environment Correlation (MANDATORY) | PENDING | |
| 5 | Credential Inventory (consolidate Phases 1-3, MANDATORY) | PENDING | |
| 6 | Scope Confirmed with User | PENDING | |
| 7 | Dismissed Assets Documented | PENDING | |
| 8 | Dismissal Verification (paths tested per group) | PENDING | |
```
Create `./ptest-output/exploit/credential-inventory.md` at Phase 4 exit — NOT Phase 6 entry. By Phase 4, you've already found credentials in Phases 1-3 (default passwords, API keys from JS, tokens from headers, exposed configs). Waiting until Phase 6 means these creds aren't consolidated when you need them for threat modeling (Phase 5). BlueSpider had 5 passDefault values + 67 emails + n8n configs discovered before Phase 5 started — all should have been in a single inventory file for cross-reference during attack tree building.

Format:
```markdown
| # | Type | Value | Source | Phase Found | Validated? |
|---|------|-------|--------|-------------|------------|
| 1 | Default password | 12345678 | /api/get-params/passDefault | P3 | Not yet |
| 2 | User emails | 67 accounts | /api/load-user | P3 | Not yet |
```
| 6 | Scope Confirmed with User | PENDING | |
| 7 | Dismissed Assets Documented | PENDING | |
```

## Exit Criteria
- [ ] Asset inventory documented (all hosts, tech, auth, business function).
- [ ] **Coverage verification: asset inventory count ≥ 80% of Phase 1/2 live subdomain count.** If the inventory has significantly fewer entries than the live-hosts list, the phase is NOT complete — you're cherry-picking, not mapping.
- [ ] Scope explicitly confirmed by user (sign-off received).
- [ ] Entry points mapped and categorized (unauth, auth, upload, input).
- [ ] Dismissed assets documented with reasons.
- [ ] Priority targets identified for Phase 5 threat modeling.

## Pitfall: Wildcard Grouping Hides Coverage Gaps

**BFI lesson (May 2026):** Phase 4 was marked DONE with 22 assets inventoried, but the actual live subdomain count was 186. The gap was hidden by grouping entire environments as single line items (e.g., `*.dev.bravo.bfi.co.id` as one row, `*.mock.bravo.bfi.co.id` as one row). This caused:
- 7 business apps (pinjaman, sobat, merchantacq, surveyor, spvcockpit, dfplatform, mbeat) listed but never entry-point mapped
- `e-pmo2.bfi.co.id` completely missed — later found to have Critical SQLi
- Sharia variants (pembiayaan-syariah, operation-syariah, surveyor-syariah) never inventoried
- `auth.bfi.co.id`, `agency.bfi.co.id`, `e-doc.bfi.co.id` skipped entirely

**Rule:** Every subdomain that returned HTTP 200/302/401/500 in Phase 2 gets its OWN row in the asset inventory — no wildcard grouping for accessible hosts. Wildcards are only acceptable for hosts confirmed unreachable (private IPs, no DNS resolution). When the inventory has <50% of live hosts individually listed, flag it as incomplete before requesting sign-off.

## Lessons Learned Capture

After cleanup, document the following to improve future engagements:

- **New pitfalls** — unexpected blockers, scope creep, environmental issues encountered
- **Tools that worked/failed** — which tools delivered results vs. which were unreliable or incompatible with the target
- **Time allocation accuracy** — how actual time spent compared to estimates per phase; where overruns or underruns occurred
- **Techniques to add/remove** — new attack vectors worth incorporating, and outdated techniques that no longer yield results
- **False positive patterns** — recurring false positives from scanners or manual testing that should be filtered in future runs
