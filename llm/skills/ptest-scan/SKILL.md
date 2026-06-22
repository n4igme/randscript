---
name: ptest-scan
version: 1.0.0
description: Architecture, conventions, and pitfalls for developing the ptest VAPT automation platform
triggers:
  - working on ptest project at ~/Project/ptest
  - modifying ptest pipeline, modules, or scoring
  - adding new scan modules or vulnerability checks
  - fixing bugs in ptest
tags: [ptest, vapt, automation, pentest, security-tooling]
---

# ptest-scan

## When to Use / When NOT to Use

**Use when:**
- Modifying the ptest platform codebase (pipeline, modules, scoring)
- Adding new scan modules or vulnerability checks
- Debugging ptest execution or tool integration

**Avoid when:**
- Not working on the ptest codebase itself
- Change is UI/visual (not pipeline/automation)
- Issue is in a skill, not the ptest platform

## Architecture

### Phase Entry Protocol (ALL phases)

When entering ANY phase:
1. **Load reference file** — `skill_view(name='ptest-scan', file_path='references/<phase-file>')`
2. **Record timestamp** — write `phase_N_start` in state.yaml
3. **Check prerequisites** — verify prior phase gate is PASSED
4. **Review findings** — check `findings.jsonl` for chain opportunities before starting

 (v0.1.0+)

```
main.py (Typer CLI)  ←→  api/app.py (FastAPI + SSE)
         ↓                        ↓
   pipeline/__init__.py (run_scan — master orchestrator)
         ↓
   ScanType.WEB → recon → discover → hunt → signals → report
   ScanType.HOST/MOBILE/SCODE → orchestrator → type-specific pipeline → report
```

### Shared Security Skill Libraries

All Hermes security skills use shared base libraries in `security/scripts/`:

| Library | Purpose |
|---------|---------|
| `base_state.py` | `BaseStateManager` — init, advance, abandon, findings, time tracking |
| `base_gate.py` | `BaseGateChecker` — phase gate validation with skill-specific checks |
| `postmortem.py` | Engagement retrospective — hours, findings, payout, ROI |
| `config.py` | **Per-skill** — phases, gateways, output dirs, budget hours |

**Thin wrapper pattern:** Each skill's `scripts/state_manager.py` and `scripts/gate_check.py` are ~30-line config wrappers over the shared bases. All skill-specific logic lives in `config.py` and SKILL.md, not in code.

**Why:** Bug fixes in gate logic, time tracking, or abandon heuristics land in one place instead of 15 copies.

### State.yaml Requirements

Every security skill MUST document its state.yaml schema in SKILL.md. Required fields:
- `engagement` (name, started, target-specific fields)
- `gateways` (phase lock/pass/open keys in snake_case)
- `findings_count` (int)
- `time_tracking` (start/end per phase)
- `notes` (free text)

**Phase naming:** Gateway keys use snake_case with number prefix (`1_passive_recon`). SKILL.md prose uses Title Case (`Phase 1`). State.yaml uses snake_case. Be consistent within each skill.

### Reference Conventions

- Shared docs: `../references/<name>.md` (gitignored from public repos if sensitive)
- Per-engagement docs: `engagement-<target>.md` prefix (auto-skipped by GitHub secret scanning)
- Quick-win tables: embed directly in SKILL.md, not external refs

### Key Design Decisions
- No dedicated API scan type — OpenAPI discovery merged into discover phase
- All scan types share the same hunt engine (19 modules)
- `modules/api.py` (APIModule) handles BOLA/mass-assign/rate-limit/verb-tamper as a hunt module
- `modules/idor.py` skips API-prefixed URLs (`/api/`, `/v1/`, etc.) to avoid overlap with APIModule
- Signal expansion runs AFTER hunt, only on confirmed findings

### Directory Layout
- `pipeline/` — phase orchestration (recon, discover, hunt, signals, report, web, host, mobile, scode, desktop, collection, cve_scan, service_probes)
- `modules/` — individual vulnerability test modules (BaseModule ABC)
- `scoring/` — CVSS, fingerprinting, compliance, response delta
- `payloads/` — WAF-adaptive payload database
- `tools/` — HTTP client, external tool runners, OOB server, wordlists, encoding
- `queue/` — async job queue for API server
- `templates/nuclei/` — custom nuclei templates
- `api/` — FastAPI routes + SSE streaming

## Conventions

### HttpClient Construction
HttpClient takes `cookie: str` (semicolon-separated), NOT `cookies: dict`.
```python
cookie_str = "; ".join(f"{k}={v}" for k, v in target.cookies.items()) if target.cookies else ""
client = HttpClient(rate_limit=config.rate_limit, headers=target.headers, cookie=cookie_str)
```

### Concurrency Control
Always use `config.concurrency` (from profile) as semaphore limit:
```python
sem = asyncio.Semaphore(config.concurrency)
async def _run_module(m):
    async with sem:
        return await asyncio.wait_for(m.run(...), timeout=120)
```

### Finding Deduplication
`reconcile_findings()` deduplicates by `(base_url_no_query, module_category)`:
- `module_category` = part before `:` (e.g., "signal:idor" → "signal")
- Signal expansion findings kept separate from base module findings

### OOB (Out-of-Band) Integration
- `tools/oob.py` provides `OOBClient` with two backends: `InteractshBackend` (default) + `LocalBackend` (fallback)
- Hunt pipeline auto-starts OOB if any loaded module has `needs_oob = True`
- Modules receive `oob: OOBClient | None` as kwarg — gracefully skip blind tests if None
- Payload templates use `{OOB_URL}` and `{OOB_DOMAIN}` placeholders (in `payloads/bypasses.py`)
- Prerequisite: `go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest`
- Blind-capable modules: ssrf, xxe, cmdi (set `needs_oob = True`)

### Security Skill Construction Pattern

When adding a NEW Hermes security skill (not just a ptest module), follow this pattern so it integrates with the family:

1. `security/<skill-name>/scripts/config.py` — `SKILL_CONFIG` dict with NAME, OUTPUT_DIR, PHASES, GATEWAYS, SUBDIRS, BUDGET_HOURS
2. `security/<skill-name>/scripts/state_manager.py` — thin wrapper (~25 lines) importing from `base_state.BaseStateManager`
3. `security/<skill-name>/scripts/gate_check.py` — thin wrapper (~25 lines) importing from `base_gate.BaseGateChecker`
4. `security/<skill-name>/SKILL.md` — must include all mandatory sections (see below)
5. `security/<skill-name>/references/` — phase-specific detail, templates, attack recipes

**Mandatory SKILL.md sections (in order):**
- Frontmatter: `name`, `version`, `description`, `trigger`, `tags`
- `## When to Use / When NOT to Use` — with skill-specific avoid conditions
- `## Quick Wins` or `## Quick Primitives` — mid-engagement entry table
- `## Retry / Timeout Patterns` — operation-specific timeouts and retry counts
- `## Error Handling` — failure modes and recovery actions
- `## Concurrent Execution Safety` — state.yaml locking, subagent handoff, parallel scanning
- `## Commands` or `## Command Procedures` — lifecycle commands

## Findings (findings.jsonl)

**Format:** JSONL, one JSON object per line.

**Required fields:** `finding_id`, `title`, `severity`, `category`, `target`, `confidence` (0.0-1.0), `timestamp`

**Example:**
```json
{"finding_id": "PTEST-SCAN-001", "title": "Missing auth on endpoint", "severity": "High", "category": "auth", "target": "api.target.com", "confidence": 0.95, "timestamp": "2026-06-22T10:00:00Z"}
```

**Mandatory SKILL.md sections (continued):**
- `### Phase Entry Protocol` — load reference, record timestamp, check prerequisites, review findings.jsonl
- `### Evidence Standards` — reference `../references/evidence-standards.md`
- `### Severity Mapping` — reference `../references/severity-mapping.md`
- `### Postmortem` — reference `../scripts/postmortem.py`
- `## Pitfalls` — skill-specific gotchas

**Reference file naming:** prefix target-specific engagement files with `engagement-` (e.g., `engagement-ens.md`). See `../references/engagement-gitignore-template` for the shared gitignore pattern.

**Cross-skill references:** use `../references/<file>.md` for shared docs (evidence-standards, severity-mapping, gitops-security). Never link to `references/` inside your own skill dir for shared docs.

## New Module Checklist
1. Create `modules/<name>.py` with class inheriting `BaseModule`
2. Set `name`, `description` class attributes; set `needs_oob = True` if blind testing needed
3. Implement `async def run(self, target, surface, client, oob=None, evidence=None) -> list[Finding]`
4. Auto-discovered — NO manual registration needed (`tools/plugins.py` scans modules/ dir)
5. Add CWE mapping in `scoring/cvss.py::MODULE_CWE`
6. Optionally add backend priority in `pipeline/hunt.py::BACKEND_MODULE_PRIORITY`
7. Record evidence: `evidence.record_from_httpx(finding_id=f.id, response=resp, module=self.name)`

### Auth Refresh
- `tools/auth.py` — strategies: `JWTRefreshStrategy`, `ReAuthStrategy`, `CookieRefreshStrategy`, `CallbackStrategy`
- `HttpClient` auto-retries on 401 after refreshing token (circuit breaker: max 10 refreshes)
- Config: `refresh_url` + `refresh_token` or `login_url` + `login_credentials`
- `config.build_auth_strategy()` constructs the right strategy from ScanConfig fields

### Evidence Capture
- `tools/evidence.py` — `EvidenceRecorder` writes JSON per finding to `output/<run_id>/evidence/`
- `record_from_httpx(finding_id, response, module, notes)` — captures full req/res from httpx
- Hunt pipeline creates recorder with scan's `run_id`, passes to every module

### WAF Feedback Loop
- `scoring/waf_feedback.py` — `WAFFeedback` tracks payload block/deliver stats
- Payload dies after 3 blocks → `filter_payloads()` skips it on future endpoints
- Tracks encoding effectiveness → `get_best_encoding()` promotes what works

### Reporting
- `reporting/__init__.py` — SARIF 2.1.0 export
- `reporting/templates.py` — HackerOne, YesWeHack, Immunefi per-finding reports
- `reporting/reproduce.py` — standalone Python repro scripts (module-specific generators)
- Pipeline auto-generates all formats in report phase

### Plugin Auto-Discovery
- `tools/plugins.py` — `discover_modules()` scans `modules/` dir for BaseModule subclasses
- `_load_modules()` in hunt.py calls `discover_modules()` — no hardcoded imports
- Supports `extra_dirs` for user plugin directories

### Profile-Driven Test Depth
- `scoring/depth.py` — `TestDepth` dataclass per profile
- Profiles are DAMAGE TIERS, not just speed dials:
  - stealth: passive only (fingerprint, headers, CORS). Zero payloads. No crawl beyond linked.
  - normal: active read-only. Safe reflected checks. No blind, no writes, no OOB.
  - aggressive: blind SQLi, OOB, write IDOR, mass assign, auth bypass. Triggers WAF.
  - brutal: ALL of aggressive + lockout testing, rate exhaustion, DoS probing, data mutation, 10KB payloads.
- Each tier unlocks a CATEGORY of tests that could cause damage, not just more payloads.
- Hunt pipeline gates: `depth.allow_oob`, `depth.allow_blind`, `depth.allow_write_tests`, etc.
- Module filtering: `depth.disabled_modules` removes injection modules in stealth mode

### ScanContext (Cross-Module State)
- `tools/context.py` — shared async-safe state for tokens, IDs, credentials, secrets, endpoints
- Modules can deposit artifacts (CSRF tokens, user IDs) for other modules to reuse
- Thread-safe via asyncio.Lock

### Custom Wordlists
- `tools/wordlist_config.py` — `WordlistLoader` merges builtin + target-specific + custom dir
- Target config: `wordlists/<domain>.yaml` with paths, params, extensions sections

### Mobile Pipeline (`pipeline/mobile.py`)
- Auto-detects APK vs IPA by extension
- Android: apktool (resources/manifest) + jadx (Java source), parallel decompile
- iOS: unzip IPA → Payload/*.app, strings on Mach-O binary, Info.plist parsing
- iOS checks: ATS exceptions, entitlements (get-task-allow, no-sandbox), URL schemes, binary secrets
- Both platforms feed discovered API endpoints into the same `_hunt_api_endpoints()` → full 19-module hunt
- Secret patterns shared between platforms (AWS, Google, Firebase, private keys)
- Prerequisites: Android=apktool+jadx; iOS=unzip+strings+codesign (all preinstalled on macOS)

### Desktop Pipeline (`pipeline/desktop.py`)
- Auto-detects binary type: PE (MZ magic), ELF (\x7fELF), Mach-O (feedface/cafebabe), .app bundle
- Windows PE: imports table (16 suspicious APIs), DLL hijack (LoadLibrary usage), persistence patterns (5), signature check (osslsigncode)
- Linux ELF: PIE check (readelf -h), RELRO, stack canary (__stack_chk_fail), NX/executable stack, SUID, missing shared libs (ldd)
- macOS Mach-O: codesign verification, entitlements (get-task-allow, disable-library-validation), @rpath/@loader_path dylib hijack
- All platforms share: string extraction, secret scanning (7 patterns), insecure comms (5 patterns), endpoint extraction → web hunt
- .app bundles: resolves CFBundleExecutable from Contents/Info.plist → Contents/MacOS/<binary>
- Prerequisites: `strings` (all), `readelf`+`ldd` (Linux), `otool`+`codesign` (macOS), `objdump` (Windows PE)

### Collection Analysis (`pipeline/collection.py`)
- Postman v2.0/v2.1 JSON: recursive item parsing, variable secret scan, auth config audit, header secrets
- Bruno collections: .bru file parsing (method + url extraction), per-file secret/insecure scan
- Detection: `is_postman_collection()` checks for schema.getpostman.com + item/request structure
- Detection: `is_bruno_collection()` checks for .bru files in dir or one level deep
- Routes through scode pipeline: `run_scode_pipeline()` checks collection type before falling through to source code scan
- Unresolved `{{variables}}` converted to `__VAR_name__` placeholders — skipped during active endpoint testing
- Active hunt: valid resolved endpoints grouped by host, reachability-checked, then full 19-module hunt

### CLI Design (`main.py`)
- Auto-detection from target string: domain→web, IP→host, .apk/.ipa→mobile, .exe/.dll/.msi/ELF/.app→desktop, Postman .json→scode, Bruno dir→scode, directory→scode
- No `scan` subcommand required — bare `ptest jago.com` works
- Minimal flags: `-p` (profile), `-c` (cookie), `--cookie-b`, `-m` (modules), `--resume`, `--type`, `--config`
- Per-target config files: `.ptest/<domain>.yaml` auto-discovered by target domain
- Config file holds: profile, cookie, cookie_b, refresh_url, refresh_token, timeout, modules
- CLI flags override config file values
- `tools/target_config.py` — minimal YAML parser (no PyYAML dependency), auto-discovers configs

### Host Pipeline (`pipeline/host.py`)
- Full flow: DNS → nmap -sV (1000 ports) → dangerous port flagging → CVE regex → service probes → searchsploit → nmap NSE → SSL/TLS → web-per-HTTP-port
- `pipeline/cve_scan.py` — `searchsploit_scan()` queries exploit-db JSON, `nmap_nse_scan()` runs targeted vuln scripts per service
- `pipeline/service_probes.py` — FTP anon, SSH version, SMB null session (separate file for clean testing)
- Multi-port web: for each HTTP port found by nmap, runs full discover+hunt pipeline
- `run_tool()` in `tools/runner.py` returns `(stdout: str, stderr: str, code: int)` — always unpack all three
- NSE script selection is service-driven: detected "smb" → ms17-010+ms08-067+sambacry; "ssh" → auth-methods+enum-algos; etc.
- Prerequisites: `nmap`, `searchsploit` (exploit-db). Optional: `smbclient`, `mongosh`

### Response Tracking & Noise Reduction
- `scoring/response_delta.py` — `ResponseTracker` fingerprints responses, auto-detects noise after 3 occurrences
- `scoring/waf_feedback.py` integrates with ResponseTracker — modules should call `tracker.is_noise()` before recording findings
- Response signature = (status_code, content_length_bucket, body_hash[:8], content_type)

### Scode Pipeline — Semgrep + Extended Patterns
- `pipeline/semgrep.py` — `SemgrepScanner` class, primary engine when `semgrep` binary available
- Normal profile: `p/owasp-top-ten`, `p/security-audit`, `p/secrets`
- Aggressive/brutal: adds `p/cwe-top-25`, `p/jwt`, `p/command-injection`, `p/sql-injection`, `p/xss`
- Falls back to regex if semgrep unavailable — 62 patterns total (25 base + 37 extended)
- `pipeline/scode_extended.py` — framework-specific patterns:
  - Node.js (10): path.join traversal, zip slip, dynamic require, prototype pollution, vm escape, ReDoS, HPP
  - Spring Boot (14): actuator exposure, SpEL injection, enableDefaultTyping, mass assignment, SecurityFilterChain order, Keycloak misconfig
  - API (6): mass assignment spread, ORM create(body), excessive data exposure, GraphQL depth
  - Auth (7): localStorage tokens, missing httpOnly/Secure, OAuth state, session not destroyed
- FP suppression (`FP_SKIP_DIRS` + `FP_SKIP_PATTERNS`): skips test dirs, ORM parameterized queries, Django/JPA safe patterns
- Source: patterns adopted from `~/.hermes/skills/security/scode/references/` (vuln-nodejs, vuln-spring-boot, vuln-api, vuln-authn-session, pitfalls-false-positives)

## Code Review Pitfalls (Recurring Patterns)

These are patterns found during code review that tend to recur. Check for them when reviewing or modifying ptest code.

### asyncio Forward Compatibility
- **NEVER** use `asyncio.get_event_loop()` — deprecated 3.10, broken in 3.12+
- **ALWAYS** use `asyncio.get_running_loop()` inside async functions
- Grep check: `grep -r "get_event_loop" pipeline/ tools/` should return zero hits

### Exception Handler Ordering
```python
# CORRECT — CancelledError (BaseException) before Exception
except (KeyboardInterrupt, asyncio.CancelledError):
    session.status = "interrupted"
    ...
except Exception as e:
    mark_failed(session, str(e))
    ...
```
CancelledError inherits BaseException in 3.9+ but putting Exception first catches it on some edge paths. Always put BaseException-derived handlers first.

### Imports in Hot Paths
Move frequently-called imports (`random`, `re`, `json`) to module-level. `import X` inside a function called at 50 req/s adds measurable overhead. Only use deferred imports for circular-dependency breaking or optional heavy deps.

### Boolean Blind Detection Thresholds
- Minimum response length difference: **200+ bytes** (not 50 — dynamic content noise: CSRF tokens, timestamps, ads easily cause 50-byte deltas)
- Normal response must be close to **exactly ONE** side (XOR check, not OR)
- Use proportional distance: `dist < diff * 0.3` rather than absolute comparison

### Crawl Dedup During Collection
Always maintain a `seen_endpoint_keys: set[str]` during endpoint collection. Without it, the endpoints list grows O(pages × forms × links) before final dedup — problematic at brutal profile (500 pages). Key format: `f"{ep.url}|{ep.method}"`.

### Progress Persistence Pattern
**DON'T** do disk I/O (load_session + save_session) inside inner module-completion loops. Instead:
- Accept a `progress_callback: Callable[[int, int], None] | None` parameter
- Caller provides the callback that does the session save
- Avoids redundant JSON parse/serialize per module (23+ times per scan)

### Module Runner Error Handling
`_run_module()` must catch exceptions and return `[]` — otherwise `asyncio.as_completed` propagates them and any `isinstance(result, Exception)` check in the consumer loop is dead code:
```python
async def _run_module(m):
    async with sem:
        try:
            return await asyncio.wait_for(m.run(...), timeout=120)
        except asyncio.TimeoutError:
            return []
        except (httpx.HTTPError, OSError, ConnectionError) as e:
            logger.warning(f"[hunt] module {m.name} failed: {e}")
            return []
```

### Reproduction Script Coverage
`reporting/reproduce.py` MODULE_GENERATORS must cover all high-frequency modules. Missing generators fall through to `_gen_generic` which just does a blind GET. Currently covered: sqli, ssrf, xxe, idor, cmdi, xss, lfi. When adding a new module, add its repro generator too.

### Test API Drift
When refactoring module interfaces (e.g. renaming `set_cookies` → `configure`), grep tests immediately: `grep -r "old_method_name" tests/`. The IDOR module test drift went unnoticed because tests weren't run after the rename.

## Error Handling

| Failure Mode | Action |
|--------------|--------|
| Test fails in CI | Capture full traceback, check if test is flaky vs real regression |
| Pipeline timeout | Increase `timeout` in ScanConfig; check for hanging HTTP connection |
| Auth refresh fails | Verify refresh URL/token in config; fall back to full re-login |
| Module import error | Check plugin discovery path (`extra_dirs`); verify `BaseModule` subclass |
| OOB server unavailable | Fall back to `LocalBackend`; verify interactsh client installed |
| Semgrep not installed | Auto-fallback to regex patterns (62 patterns available) |

**Rules:**
- Capture stderr/stdout separately (do not merge)
- On partial failure: save partial report, note modules that failed
- Retry logic: max 3 attempts with exponential backoff for external calls

## Concurrent Execution Safety

**Async pipeline:**
- Uses `asyncio.Semaphore(config.concurrency)` for bounded parallelism
- Hunt modules run via `asyncio.wait_for(m.run(...), timeout=120)`
- WAF feedback loop is shared state — use `WAFFeedback.track()` from all workers

**ScanContext (cross-module state):**
- Thread-safe via `asyncio.Lock` — modules can deposit/query artifacts
- Do not mutate `ScanContext` outside of lock context
- Evidence recorder writes to `output/{run_id}/evidence/` — safe for concurrent writes

**Queue system:**
- `queue/` async job queue isolates concurrent scan requests
- Each scan gets unique `run_id` — no cross-contamination
- API server uses SSE streaming; multiple clients can consume same scan

## Design Notes & Conventions

- BFS queues: use `collections.deque` not `list.pop(0)` (O(1) vs O(n))
- Time-based SQLi: always measure baseline response time first, flag only on delta
- ScanType enum lives in `models.py` — `config.py` imports it from there
- `config.ScanConfig` is frozen dataclass — fields must be set at construction
- `models.Target` is also frozen — computed properties (`base_url`, `domain`) use `@property`
- `pipeline/__init__.py` imports from `pipeline.orchestrator` — circular import risk if orchestrator imports from __init__
- Profiles: stealth=passive-only, normal=read-only/5rps, aggressive=blind+write/10rps, brutal=destructive+DoS/50rps
- Profile design: each tier unlocks a DAMAGE CATEGORY, not just bigger numbers
- Dual-cookie IDOR: `--cookie-b` enables horizontal privesc testing; IDORModule uses response similarity
- CLI design: auto-detection over explicit --scan-type flags. `ptest jago.com` not `ptest scan jago.com --scan-type web`
- User prefers 'scode' not 'code_repo' for source code scan type
- `execute_code` hermes_tools: `read_file()` returns dict with numbered lines — strip `N|` prefix before matching
- `run_tool()` returns tuple `(stdout, stderr, code)` — always unpack all three
- State management uses shared base libraries with thin per-skill wrappers (local state.yaml minimizes AI cost)
- Source of truth for security skill code: `~/Project/myherms/skills/security`
