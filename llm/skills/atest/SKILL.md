---
name: atest
version: 1.3.0
description: "Lightweight API penetration testing framework for REST, GraphQL, and gRPC targets. 4 focused phases without full infrastructure recon overhead."
tags: [api, rest, graphql, grpc, pentest, authentication, injection]
trigger: "api pentest, api security test, graphql pentest, grpc pentest, rest api test, api-only engagement"
argument-hint: "<command: start|status|resume|next|report|abort|cleanup>"
notes:
  - "v1.3.0: Added Phase Entry Protocol, time_tracking in state.yaml. Extracted pitfalls to references/pitfalls.md. Deduplicated BlueSpider finding. Fixed mtest handoff (Phase 9→6)."
  - "v1.2.0: Auth-gate-before-parameter-processing pitfall, expanded CORS testing, no-token abandon heuristic with middleware-gate guidance"
  - "v1.1.0: Time budgets, abandon heuristics, bola_scanner.py, state_manager.py, proven patterns, token acquisition moved to Phase 1 gate"
metadata:
  hermes:
    tags: [api, rest, graphql, grpc, pentest]
    related_skills: [ptest, scode, ctest, mtest, w3hunt, ttest, adtest]
---

# API-First Penetration Testing Framework

Focused 4-phase workflow for pure API engagements (REST, GraphQL, gRPC) where no web UI or mobile app is in scope. Skips infrastructure recon and goes straight to API-level testing.

## Quick Reference

```
Phases:  1.Scope&Recon → 2.AuthN/AuthZ → 3.Injection&Logic → 4.Reporting
States:  LOCKED → OPEN → PASSED (sequential)
Commands: start | status | next | resume | report | abort | cleanup

Key rules:
  • BOLA/IDOR is #1 API vulnerability — test on EVERY endpoint with IDs
  • Test both horizontal (user→user) and vertical (user→admin) access
  • GraphQL: always try introspection + batching + nested queries
  • Rate limiting bypass: rotate headers, use array params, change HTTP method
  • Every finding needs reproducible curl/request evidence

Quick Wins (mid-engagement entry with tokens/docs):
  - OpenAPI/Swagger found → batch-test ALL endpoints unauth (2-min Python loop)
  - GraphQL → introspection + batching + depth attack immediately
  - CORS headers present → test origin reflection + allow-credentials
  - Bearer-only API → skip CORS exploitation (tokens not sent cross-origin)
  - Existing tokens → test BOLA on top 5 object-ID endpoints first
```

## Architecture

```
Phase 1: Scope & Recon → Phase 2: AuthN/AuthZ → Phase 3: Injection & Logic → Phase 4: Reporting
```

## When to Use / When NOT to Use

**Use when:**
- Target matches skill scope (see Quick Reference phases)
- You have required access level (credentials, API token, device, etc.)
- Authorization is confirmed (written permission for pentest, own assets for research)

**Avoid when:**
- Target is explicitly out of scope
- No credentials/token/device available and skill requires authenticated testing
- Time budget is insufficient for minimum viable engagement (< 15 min)
- Legal/ToS constraints block required techniques
- No API docs/traffic/tokens available and endpoints are unknown
- Target is pure web app with no API layer (use ptest instead)
- GraphQL introspection disabled and schema unknown

## Error Handling

| Failure Mode | Action |
|--------------|--------|
| Tool exits non-zero | Capture stderr, check if partial output is usable |
| API rate limit (429) | Back off, retry once. If persistent, document and pivot |
| Credential expired | Re-acquire or document as finding (credential rotation issue) |
| Target unreachable | Retry 3x with 30s gap. If still down, mark host UNREACHABLE |
| Permission denied | Try alternative auth method. If blocked, document scope gap |
| WAF blocking | Try 3 bypass techniques max, then document WAF and move on |
| Frida detach | Retry with `-f` spawn mode. 3 failures → anti-Frida, escalate |

**Rules:**
- Never retry blindly — understand the error first
- Save partial results before retrying (power loss, network drop)
- Document blocker findings with evidence (screenshot, HTTP status)
- On repeated failure (>3 attempts): mark as BLOCKED, continue to other surface

| Command | Action |
|---------|--------|
| `start` | Initialize engagement — define API targets, auth mechanism, documentation |
| `status` | Show current phase, progress, findings count |
| `resume` | Resume interrupted engagement from last checkpoint |
| `next` | Advance to next phase (runs exit criteria check) |
| `report` | Generate final report |
| `abort` | Terminate engagement early — records reason, generates partial report |
| `cleanup` | Archive engagement output, remove temporary files |

If no command is given, show current status and suggest next action.

#### Postmortem

After engagement closes, run shared retrospective:
```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/scripts"))
from postmortem import run_postmortem
run_postmortem(workdir, "atest")
```

## Concurrent Execution Safety

See `../references/concurrent-execution-safety.md` for state locking, parallel scanning, and subagent handoff rules.

## Command Procedures

**`start`:**
1. Collect: API type, base URLs, documentation, auth mechanism, authorization model, rate limits, rules of engagement.
2. Run `state_manager.init_state(workdir, name, api_type, auth_mechanism, base_urls, ...)` — creates output directory + state.yaml + scope.md + findings-log.md.
3. Begin Phase 1 recon immediately (documentation discovery, endpoint enumeration).
4. Attempt token acquisition before advancing to Phase 2.

**`status`:** Output current phase, gateway states (4 phases), findings count by severity, time elapsed. If no engagement, suggest `start`.

**`resume`:**
1. Read `state.yaml` to determine active phase.
2. **Staleness:** >7 days → re-verify API is still accessible, tokens not expired. >30 days → re-run Phase 1 (APIs change frequently).
3. Report status and suggest next action.

**`next`:**
1. Verify current phase gate is satisfied.
2. If NOT met: list unmet criteria, suggest what to test.
3. If met: update state.yaml, advance phase.
4. Override allowed with justification.

### Gate Enforcement (MANDATORY before `next`)

```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/atest/scripts"))
from gate_check import check_gate, print_gate_status

result = check_gate(".", phase=None)
print_gate_status(result)
# Only advance if result["passed"] is True
```

### Phase Entry Protocol (ALL phases)

When entering ANY phase, before executing techniques:
1. **Load reference file** — per Phase Routing table (e.g., `references/phase1-scope-recon.md`)
2. **Create/verify checklist** — `atest-output/phase{N}-{name}/checklist.md` must exist with all techniques as PENDING
3. **Record timestamp** — write `phase_N_start` in state.yaml when creating checklist, `phase_N_end` when PASSED is written

**`abort`:**
1. Record reason in state.yaml, mark remaining phases ABORTED.
2. Generate partial report from existing findings.
3. Run cleanup.

**`cleanup`:**
1. Archive `./atest-output/` to `atest-output-{target}-{date}.tar.gz`.
2. Remove test tokens/credentials you created (keep found credentials as evidence).
3. Print summary: findings by severity, phases completed.

---

## Initialization (`start`)

Collect before testing:

1. **API Type** — REST, GraphQL, gRPC, mixed
2. **Base URLs** — all API endpoints in scope
3. **Documentation** — OpenAPI/Swagger URL, GraphQL introspection, `.proto` files
4. **Authentication** — mechanism (JWT, OAuth, API key, session, mTLS), credentials provided?
5. **Authorization Model** — RBAC, ABAC, tenant isolation, role hierarchy
6. **Rate Limits** — known limits, testing restrictions
7. **Rules of Engagement** — write operations allowed? data creation limits?

Create output directory:

```
./atest-output/
├── state.yaml
├── scope.md
├── findings-log.md
├── phase1-recon/
│   ├── endpoints.md
│   └── auth-flow.md
├── phase2-authz/
├── phase3-injection/
└── report/
```

Write `state.yaml`:

```yaml
engagement:
  name: ""
  started: ""
  api_type: ""  # rest, graphql, grpc, mixed
  auth_mechanism: ""  # jwt, oauth, apikey, session, mtls, none

gateways:
  1_recon: OPEN
  2_authn_authz: LOCKED
  3_injection_logic: LOCKED
  4_reporting: LOCKED

time_tracking:
  phase_1_start: ""
  phase_1_end: ""
  phase_2_start: ""
  phase_2_end: ""
  phase_3_start: ""
  phase_3_end: ""
  phase_4_start: ""
  phase_4_end: ""
  total_duration: ""  # Calculated at cleanup

findings_count: 0
current_phase: 1

config:
  base_urls: []
  has_graphql: false
  has_grpc: false
  write_ops_allowed: true
  rate_limit_known: ""
```

---

## API-Type Decision Tree

Your testing priorities shift based on API type. Determine this during initialization:

```
┌─────────────────────────────────────────────────────────────────────┐
│ REST API                                                            │
│ Priority: BOLA/IDOR → Auth bypass → Injection → Mass assignment     │
│ Phase 1: endpoint enumeration (OpenAPI, fuzzing, JS extraction)     │
│ Phase 2: systematic endpoint-by-endpoint BOLA testing               │
│ Phase 3: parameter-level injection on all inputs                    │
├─────────────────────────────────────────────────────────────────────┤
│ GraphQL                                                             │
│ Priority: Introspection → Auth on mutations → Batching/DoS → BOLA  │
│ Phase 1: introspection query (maps entire schema instantly)         │
│ Phase 2: test auth on every mutation, field-level access control    │
│ Phase 3: alias batching, depth attacks, directive abuse             │
├─────────────────────────────────────────────────────────────────────┤
│ gRPC                                                                │
│ Priority: Reflection → Auth per-method → Message manipulation       │
│ Phase 1: server reflection (maps all services/methods)              │
│ Phase 2: test auth on each RPC method independently                 │
│ Phase 3: protobuf field manipulation, type confusion, large msgs   │
├─────────────────────────────────────────────────────────────────────┤
│ Mixed (REST + GraphQL + gRPC)                                       │
│ Priority: GraphQL first (fastest to map), then REST, then gRPC     │
│ Reason: GraphQL introspection gives you the full schema in one      │
│ query — use it to understand the data model, then test REST/gRPC   │
│ endpoints with that knowledge.                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Phases (load reference for full methodology)

| Phase | Gate | Reference |
|-------|------|-----------| 
| 1 Scope & Recon | endpoints mapped, auth flow documented, valid token obtained. **Alt gate:** ptest Phase 3+ OR mtest Phase 4+ PASSED with endpoints + tokens inherited | `references/phase1-scope-recon.md` |
| - | ByteDance/TikTok passport SDK auth patterns (SoundOn, TikTok Shop, etc.) | `references/bytedance-passport-patterns.md` |
| - | Tyk API Gateway config-as-code parsing (YAML → CSV endpoint extraction, whitelist/blacklist analysis, bypass vectors) | `references/tyk-gateway-config-parsing.md` |
| 2 AuthN/AuthZ | auth bypass tested, BOLA on all object endpoints, privesc attempted | `references/phase2-auth.md` |
| 3 Injection & Logic | injection tested on all inputs, business logic assessed, race conditions tested | `references/phase3-injection-logic.md` |
| 4 Reporting | report delivered with all findings + PoCs | see below |

**Usage:** `skill_view(name='atest', file_path='references/phase1-scope-recon.md')` when entering that phase.

**Key rules across all phases:**
- BOLA/IDOR is #1 API vulnerability — test on EVERY endpoint with IDs
- IDOR hunting patterns: load `references/idor-hunting-patterns.md` for parameter manipulation, bypass techniques, blind detection, and platform-specific patterns (GraphQL, gRPC, presigned URLs)
- Test both horizontal (user→user) and vertical (user→admin) access
- GraphQL: always try introspection + batching + nested queries (see `references/graphql-exploitation.md`, `references/graphql-dos-batching.md`)
- WebSocket APIs: load `references/websocket-testing.md` for CSWSH, message-level IDOR, subscription escalation, and Socket.IO/SignalR patterns
- Every finding needs reproducible curl/request evidence
- mtest handoff: if `phase8-handoff.md` exists, skip Phase 1 discovery
- Attack recipes: load ptest `references/attack-recipes.md` at Phase 2/3 entry for proven patterns
- Severity escalation: load ptest `references/severity-escalation.md` after every finding

---

## Phase 4: Reporting

### Pre-Report: Chain & Escalate

Before writing the report, revisit all findings and attempt to chain them for higher severity. See ptest `references/chain-and-escalate-phase.md` for the full protocol. Quick checklist:
- [ ] Can any Info/Low finding be combined with another to escalate impact?
- [ ] Do error messages reveal info that enables attacks on other endpoints?
- [ ] Do config leaks (password policy, auth mechanism) make brute-force viable?
- [ ] Can exposed API docs map authenticated attack surface for future testing?

### Gate: report delivered with all findings documented and PoCs included

**Report Structure:**

```markdown
# API Penetration Test Report — {Target}

## 1. Executive Summary
- API type, endpoints tested, auth mechanism
- Severity breakdown
- Top risk and business impact

## 2. Scope & Methodology
- Base URLs, API version, documentation source
- 4-phase methodology with status
- Tools used, testing constraints

## 3. API Surface Map
- Endpoint inventory (method, path, auth required, parameters)
- Data models identified
- Auth flow diagram

## 4. Findings Summary
| ID | Title | Severity | Category | Endpoint |

## 5. Detailed Findings
- Each finding with: description, endpoint, request/response, impact, remediation

## 6. Remediation Roadmap
- Immediate: auth bypass, injection fixes
- Short-term: BOLA fixes, rate limiting
- Medium-term: architecture improvements

## Appendix: PoC Scripts
- curl commands for each finding
- Race condition scripts
- Token manipulation examples
```

---

## Finding Template

```markdown
## [ATEST-{ID}] {Title}

**Severity:** Critical / High / Medium / Low / Info
**Category:** AuthN / AuthZ / Injection / Logic / Data Exposure / DoS
**Endpoint:** `{METHOD} {path}`
**Parameter:** {affected parameter}

### Description
{What the vulnerability is}

### Request
```http
{Full HTTP request}
`` `

### Response
```http
{Relevant response showing the issue}
`` `

### Impact
{What an attacker can achieve}

### Remediation
{Specific fix}
```

### Cross-Skill Chaining (findings.jsonl)

When recording a finding, append to `./atest-output/findings.jsonl` for cross-skill consumption:

```python
import json
from datetime import datetime
finding = {
    "id": "ATEST-{count:03d}",
    "skill": "atest",
    "severity": "{severity}",
    "type": "{vuln_type}",  # e.g., bola, auth_bypass, sqli, ssrf, rate_limit
    "target": "{endpoint}",
    "summary": "{one-line description}",
    "chain_potential": [],
    "timestamp": datetime.now().isoformat(),
    "phase": "phase{current_phase}",
    "confidence": "confirmed",
    "status": "confirmed"
}
with open("./atest-output/findings.jsonl", "a") as f:
    f.write(json.dumps(finding) + "\n")
```

---

## Mandatory Checks

| Category | Minimum Tests |
|----------|--------------|
| Auth Bypass | Remove token, empty token, expired token, wrong tenant token |
| BOLA | Every endpoint with object reference tested cross-user |
| Mass Assignment | Every POST/PUT/PATCH tested with extra fields |
| Injection | Top 3 input parameters per endpoint tested for SQLi/NoSQLi |
| Rate Limiting | Auth endpoints + sensitive operations tested |
| Data Exposure | All list endpoints checked for over-fetching |

---

### Severity Mapping

Cross-skill severity normalization: `../references/severity-mapping.md`

## Pitfalls

> **Full pitfalls (operational, engagement lessons, auth quirks):** `references/pitfalls.md`

### Key Rules (always active)
- Burp MCP output: NEVER let raw 100-200KB JSON into context — parse via script, print <20 lines
- Write endpoints: test THREE ways — (1) valid session, (2) expired, (3) ZERO cookies/headers (BlueSpider: middleware bypass)
- Multi-step flows: call later steps WITHOUT earlier steps, OUT OF ORDER
- SPA catch-all: ALL paths same status+size = frontend routing, extract routes from JS bundles
- Webhook callbacks: test ALL for missing HMAC/signature (Prometheus `uri=` reveals routes)
- Middleware auth gate: if ALL endpoints return same error → token acquisition is priority, not fuzzing
- BEARER-ONLY + NO CLIENT_CREDENTIALS = DEAD END — when target uses OAuth2 bearer tokens AND public clients (mnzpub.* prefix) can't use client_credentials grant, you CANNOT get a token without completing a full user auth flow (magic link, browser redirect). Don't spend hours fuzzing auth-walled endpoints. Pivot to: (1) register an account, (2) mobile app RE for token extraction, (3) report info-disc and move on. Monzo (June 2026): 20 unauth tests, all properly gated.
- CORS + BEARER AUTH = NOT EXPLOITABLE — CORS origin reflection + allow-credentials:true only matters if auth uses cookies. Bearer tokens are NOT sent cross-origin automatically. Skip CORS exploitation on bearer-only APIs even if it looks "vulnerable" in headers.
- BFI Finance / Capital.com / Uphold patterns: Indonesian P2P lending + European trading platforms use Transmit Security CIS (WebAuthn) + HMAC-SHA256 API auth. CORS misconfigurations often appear with `Access-Control-Allow-Origin: *` + `Allow-Credentials: true` on subdomains. Check bypass via origin header case changes or malformed origins.
- Large file writes: max 300 lines per op, split reports into skeleton + finding patches

### Cross-Skill Handoff

**ptest handoff (ptest → atest):**
- If `../ptest-output/` exists with Phase 3+ PASSED, inherit endpoints + tokens
- Skip Phase 1 — gate satisfied by ptest inheritance
- Tag findings with `source: "atest"` to flow back to ptest findings-log

**mtest handoff (mtest → atest):**
- If `../mtest-output/` exists with Phase 4+ PASSED, inherit endpoint list from traffic capture
- Skip Phase 1 — gate satisfied by mtest traffic analysis
- After atest completes, findings flow back to mtest findings.jsonl
- Return to mtest Phase 6 for mobile-specific exploit chains

**Attestation-heavy targets (mtest → atest):**
- Document forge capability as Phase 1 gate prerequisite
- The forge IS the token acquisition method — without it you can't do Phase 2+

---

---

## Effort Allocation

| Phase | % | 4-hour engagement | 8-hour engagement | Rationale |
|-------|---|-------------------|-------------------|-----------|
| 1 Recon | 15% | 35 min | 70 min | API surface mapping |
| 2 AuthN/AuthZ | 40% | 100 min | 190 min | Highest-value — BOLA is #1 API risk |
| 3 Injection & Logic | 30% | 75 min | 145 min | Broad testing surface |
| 4 Reporting | 15% | 35 min | 75 min | Write-up + PoCs |

## Abandon & Pivot Heuristics

**Phase 1 (Recon):**
- No API docs found after 20 min → switch to blind enumeration (fuzz top 50 paths)
- API returns 403 on everything → check if auth is required first (move token acquisition up)
- Can't get a valid token after 15 min → check if token requires platform-registered credentials (Settings > API key generation, not self-service via API). If so, tell the user what's needed. If still unobtainable, document the blocker and run unauth-only testing in Phase 2. **Important:** when no token is available and all protected endpoints return the same auth error, you are hitting a middleware-level auth gate — BOLA, injection, and mass assignment tests will ALL return the same error code. Do not waste budget fuzzing auth-protected endpoints; focus on public endpoints, CORS, error code enumeration, and rate limiting instead. Document this constraint clearly in the report.

**Phase 2 (AuthN/AuthZ):**
- No BOLA after testing 20+ endpoints → stop BOLA, shift remaining time to injection
- All endpoints enforce auth correctly → document "auth hardened", move to Phase 3 early
- JWT is properly validated (no none/HS256 confusion, short expiry, proper signature) → skip JWT attacks after 10 min, focus on BOLA/privilege escalation

**Phase 3 (Injection & Logic):**
- No injection after testing top 10 input parameters → stop broad injection, focus on business logic only
- WAF blocking all payloads → try 3 bypass techniques max, then document WAF and move on
- No business logic flaws after 30 min → wrap up, move to reporting

**Global abandon rules:**
- **75% of time budget spent, zero findings** → stop testing, write "hardened" report
- **Critical/High found early** → validate PoC immediately, write it up, then continue testing remaining surface
- **Rate limited / IP blocked** → wait 10 min, retry once. If persistent, document and report with partial results

**Pivot triggers:**
- SSRF confirmed → pivot to cloud metadata (169.254.169.254) before continuing API tests
- Unauth GraphQL write ops found (mutations OR write-like queries) → stop other testing, enumerate all operations, test each. Note: some implementations put batch_send/join/forward under queryType with no mutationType at all
- Config endpoint leaks credentials → use them immediately for privilege escalation before they rotate

---

## Postman Collection Output

When generating Postman collections, use v2.1.0 format with: collection-level variables (base_url, tokens, device headers), each step as separate request with full headers/body, query params in url.query array.

---

## Guardrails

- **Write Operations** — confirm with operator before creating/modifying data. Use obviously-fake test data (`PENTEST-PROBE-*`).
- **Rate Limits** — if you trigger a rate limit, back off. Document the limit as a finding if it's too permissive, not as a blocker.
- **Production Data** — never exfiltrate real user data beyond what's needed to prove the finding. Redact PII in report screenshots.
- **Scope Enforcement** — only test documented endpoints. If you discover undocumented internal APIs, confirm they're in scope before testing.
- **No Destructive Operations** — don't DELETE production resources unless explicitly authorized. Prove DELETE works via 400/405 response analysis (see ptest Write Access Response Protocol).
- **GraphQL Depth** — don't crash the server with unbounded nested queries. Test with depth 5-7, document if no depth limit exists.
- **PoC Scripts Must Contain Real Data** — never leave placeholder values like `victim@example.com` or `YOUR_SESSION_COOKIE` in PoC scripts. Always embed the actual tested values (emails, error codes, tickets, timestamps, account names) as comments or defaults. The PoC is evidence — it must be self-contained and reproducible without guessing what to fill in.

---

### Evidence Standards

All findings must follow `../references/evidence-standards.md` for required/optional evidence capture and redaction rules.

## Script Invocation

Scripts are in `~/.hermes/skills/security/atest/scripts/`. Invoke via `execute_code`.

**state_manager.py — engagement lifecycle:**
```python
from hermes_tools import terminal
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/scripts"))
from config import SKILL_CONFIG
import state_manager

workdir = "."  # or specific project directory

# Initialize
state_manager.init_state(workdir, "Target API", api_type="rest", auth_mechanism="jwt",
    base_urls=["https://api.target.com"], has_graphql=True)

# Check status
state_manager.status(workdir)

# Advance phase
state_manager.advance_phase(workdir)

# Add finding
state_manager.add_finding(workdir, "ATEST-001", "BOLA on /api/users/{id}", "High", "AuthZ", "GET /api/users/{id}")

# Check abandon
should, reason = state_manager.should_abandon(workdir, budget_hours=4)

# Abandon
state_manager.abandon(workdir, "75% budget, zero findings")
```

**bola_scanner.py — systematic BOLA/IDOR testing:**
```python
from hermes_tools import terminal
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/atest/scripts"))
import bola_scanner

# Manual endpoint list
results = bola_scanner.scan(
    base_url="https://api.target.com",
    endpoints=[
        {"method": "GET", "path": "/api/users/{id}"},
        {"method": "GET", "path": "/api/orders/{id}"},
        {"method": "PUT", "path": "/api/users/{id}", "body": {"name": "test"}},
    ],
    token_a="eyJ...",       # User A's token
    token_b="eyJ...",       # User B's token
    user_a_id="123",        # User A's resource ID
    user_b_id="456",        # User B's resource ID
)

# Or from OpenAPI spec (auto-extracts endpoints with path params)
results = bola_scanner.scan_from_openapi(
    base_url="https://api.target.com",
    openapi_path="/tmp/openapi.json",
    token_a="eyJ...",
    token_b="eyJ...",
    user_a_id="123",
    user_b_id="456",
)
print(results["summary"])
```

**background_recon.py — parallel recon (fire at Phase 1 exit):**
```python
from hermes_tools import terminal
# Auth diff: find unauth access + BOLA candidates
terminal("python3 ~/.hermes/skills/security/atest/scripts/background_recon.py "
         "--mode auth-diff --base-url https://api.target.com "
         "--endpoints /tmp/endpoints.txt "
         "--token-a 'eyJ...' --token-b 'eyJ...' "
         "--output /tmp/recon/auth-diff.json",
         background=True, notify_on_complete=True)

# Header injection: find bypass via X-Forwarded-For etc.
terminal("python3 ~/.hermes/skills/security/atest/scripts/background_recon.py "
         "--mode header-injection --base-url https://api.target.com "
         "--endpoints /tmp/endpoints.txt "
         "--token-a 'eyJ...' "
         "--output /tmp/recon/header-inject.json",
         background=True, notify_on_complete=True)

# Param pollution: test array/negative/overflow on ID params
terminal("python3 ~/.hermes/skills/security/atest/scripts/background_recon.py "
         "--mode param-pollution --base-url https://api.target.com "
         "--endpoints /tmp/endpoints.txt "
         "--token-a 'eyJ...' "
         "--output /tmp/recon/param-pollution.json",
         background=True, notify_on_complete=True)
```
