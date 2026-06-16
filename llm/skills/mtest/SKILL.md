---
name: mtest
version: 1.0.1
description: "Structured mobile application penetration testing framework with 10 gated phases for Android and iOS"
tags: [mobile, pentest, android, ios, frida, security]
trigger: "mobile pentest, mobile app test, APK test, IPA test, android security, ios security, dexguard bypass, appfence bypass, libaf-android, native root detection, inline svc bypass"
argument-hint: "<command: start|status|next|resume|report|abort|cleanup>"
notes:
  - "v3.0.0: Hub model — SKILL.md is routing + framework rules. All phase content in references/phase*.md"
  - "scripts/ contains Frida bypass scripts and phase automation"
  - "NEVER rewrite full SKILL.md in one tool call — use strReplace for edits"
metadata:
  hermes:
    tags: [mobile, pentest, android, ios, frida, security]
    related_skills: [ptest, retools, scode, atest]
---

# Mobile Application Penetration Testing (mtest)

## Quick Reference

```
Phases:  1.Preflight → 2.Static → 3.Bypass → 4.Traffic → 5.AttackSurface → 6.Runtime → 7.VulnAnalysis → 8.API → 9.Exploit → 10.Report
States:  LOCKED → OPEN → PASSED → N/A (sequential, no skipping)
Commands: start | status | next | resume | report | abort | cleanup

Key rules:
  • Feature-driven testing (by app feature, not by vuln class)
  • Production Validation: Critical requires non-rooted device proof
  • Bypass decision tree: 5 attempts → assess, 10 → hard stop
  • Confidence: Confirmed > Probable > Theoretical (never Critical + Theoretical)
  • Phase 3 is a MEANS to validate findings, not a finding itself
  • N/A phases must be documented with justification (not skipped silently)

Time caps (for 2-day/16hr engagement):
  P1: 45min  P2: 2.5hr  P3: 1.5hr  P4: 1.5hr  P5: 45min
  P6: 2.5hr  P7: 3hr    P8: 1.5hr  P9: 45min  P10: 45min
```

## Commands

| Command | Action |
|---------|--------|
| `start` | Begin new engagement — create output dir, define scope |
| `status` | Show current phase, progress, findings count |
| `resume` | Resume interrupted engagement — read state and continue |
| `next` | Advance to next phase (requires current phase gate satisfied) |
| `report` | Generate findings report (available from Phase 7+) |
| `abort` | Terminate engagement early (device bricked, app removed, client revokes access) |
| `cleanup` | Archive output, sanitize sensitive data |

---

## Phase Routing

When entering a phase, load the corresponding reference file:

| Phase | File | Gate Summary |
|-------|------|-------------|
| 1 | `references/phase1-preflight.md` | scope.md exists, target app identified, tools verified |
| 2 | `references/phase2-static-core.md` + `references/phase2-extended-checks.md` | decompilation complete, secrets scanned, endpoints extracted |
| 3 | `references/phase3-bypass.md` | protections bypassed or documented; Frida attaches |
| 4 | `references/phase4-traffic.md` | proxy intercepting, API mapped, auth flow documented (or N/A) |
| 5 | `references/phase5-attack-surface.md` | feature map with entry points, prioritized by risk |
| 6 | `references/phase6-runtime.md` + `references/phase6-test-categories.md` | Data Storage tested + 2 others; deep links tested |
| 7 | `references/phase7-vuln-analysis.md` + `references/phase7-execution-procedures.md` | all features from attack surface map tested |
| 8 | `references/phase8-api.md` | BOLA + auth bypass + injection tested (or N/A) |
| 9 | `references/phase9-exploitation.md` | all Critical/High have PoC or documented limitation |
| 10 | `references/phase10-reporting.md` | all findings documented, report generated |

**Load only the active phase file(s).** Each contains: gate, steps, commands, references.

**Cross-skill references:**
- Attack recipes (mobile-specific): load ptest `references/attack-recipes.md` — includes deeplink hijacking, exported component abuse, cert pinning bypass patterns
- Severity escalation: load ptest `references/severity-escalation.md` after every finding

---

## Framework Rules

### State Tracking

On `start`, create `state.yaml` in `<workdir>/mtest-output/`:

```yaml
engagement:
  name: ""
  target_app: ""
  package_id: ""
  bundle_id: ""
  started: ""
  platforms: []  # android, ios, or both

platform_progress:  # Only used when platforms has both
  android: {phase: 1, findings: 0, bypass_working: false}
  ios: {phase: 1, findings: 0, bypass_working: false}

gateways:
  1_preflight: OPEN
  2_static_analysis: LOCKED
  3_protection_bypass: LOCKED
  4_traffic_analysis: LOCKED
  5_attack_surface: LOCKED
  6_runtime_testing: LOCKED
  7_vulnerability_analysis: LOCKED
  8_api_testing: LOCKED
  9_exploitation: LOCKED
  10_reporting: LOCKED

findings_count: 0
current_phase: 1
notes: ""
```

### Finding ID Assignment

1. Read `findings_count` from `state.yaml`
2. Increment by 1 → `MTEST-{count:03d}`
3. Write updated count back immediately
4. **Append to `findings.jsonl`** for cross-skill chaining:
```python
import json
from datetime import datetime
finding = {
    "id": "MTEST-{count:03d}",
    "skill": "mtest",
    "severity": "{severity}",
    "type": "{vuln_type}",  # e.g., ssl_bypass, deeplink_hijack, insecure_storage, webview_rce
    "target": "{package_id} / {endpoint_if_applicable}",
    "summary": "{one-line description}",
    "chain_potential": [],  # Fill if applicable: ["atest:api_testing", "ptest:ssrf", "ctest:credential_access"]
    "timestamp": datetime.now().isoformat(),
    "phase": "{current_phase}",
    "status": "confirmed"
}
with open("./mtest-output/findings.jsonl", "a") as f:
    f.write(json.dumps(finding) + "\n")
```

**Cross-skill chain triggers from mtest findings:**
| mtest Finding | Triggers | Action |
|---------------|----------|--------|
| API endpoint without cert pinning | atest | Full API security testing on that endpoint |
| Hardcoded API key/secret in APK | ctest/ptest | Test key scope and access |
| WebView loading arbitrary URLs | ptest | XSS/phishing on trusted app context |
| Insecure deeplink handling | ptest | Open redirect / account takeover chain |
| Backend URL discovered in strings | ptest | Add to attack surface |
| OAuth token in local storage | atest | Token scope testing, replay attacks |

### Command Procedures

**`start`:**
1. Define scope: app name, package/bundle ID, platform(s), version, engagement type (internal/bounty).
2. Create `<workdir>/mtest-output/` with subdirs for each phase.
3. Run `phase1_preflight.run(workdir, target_apk, package_id, platform, engagement_name)` → creates output dirs + state.yaml.
4. Verify tools: Frida server running, proxy configured, device connected (`adb devices` / `ideviceinfo`).
5. Begin Phase 1 preflight immediately.

**`status`:** Show current phase, gateway states, findings count by severity, bypass status, time elapsed.

1. Verify phase gate criteria met (see phase file's Gate section)
2. Ask user: "Phase X complete. N findings. Advance to Phase Y?"
3. Update `state.yaml`: mark current PASSED, unlock next, record timestamps

**If gate NOT met:** list unmet criteria, suggest actions. Allow override with justification.

### Gate Enforcement (MANDATORY before `next`)

Before advancing any phase, run the gate checker:

```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/mtest/scripts"))
from gate_check import check_gate, print_gate_status

result = check_gate(".", phase=None)  # checks current phase from state.yaml
print_gate_status(result)
# Only advance if result["passed"] is True
```

If gate check fails, fix unmet items before advancing. Override only with explicit user justification.

### Resume (`resume`)

1. Read `state.yaml` to determine active phase
2. **Staleness check:**
   - **>3 days:** Re-verify bypass still works (apps push silent updates)
   - **>7 days:** Re-pull APK (version may have changed). Re-run Phase 2 fast-path.
   - **>30 days:** Treat as near-fresh engagement.
3. Report status and suggest next action

### Abort (`abort`)

**Valid reasons:** device bricked/lost, app removed, client revokes access, legal concern.

1. Record reason in state.yaml, mark remaining gateways `ABORTED`
2. Generate partial report if findings exist
3. Run cleanup

### Cleanup (`cleanup`)

1. Archive `./mtest-output/` to `mtest-output-{app}-{date}.tar.gz`
2. Remove YOUR credentials — keep found credentials as evidence
3. Print summary: findings by severity, phases completed, duration

### Script Failure Protocol

| Exit Condition | Action |
|----------------|--------|
| Exit 0 / script runs | Parse output, continue |
| Frida crash / detach | Retry with `-f` (spawn). If 3 crashes → anti-Frida, escalate to Phase 3 |
| Script timeout | Kill, restart app, retry once |
| Total failure | Fall back to manual (adb, objection, or static evidence) |

Phase gates are NOT satisfied by failed scripts.

### N/A Phases

If a phase is not applicable (no API for Phase 8, no pinning for Phase 3), document justification and mark gateway `N/A`. Never skip silently.

### Offline/No-Network App

When app has no internet permission and no HTTP URLs: Phase 4 → N/A, Phase 8 → N/A. Detect in Phase 2.

### Exploit Validation

Critical/High findings MUST be validated dynamically in Phase 9 before final reporting. If not possible, document limitation explicitly.

### When to Stop Chasing a Bypass

1. **5 failed attempts:** Assess — is the finding worth validating?
2. **10 failed attempts:** Hard stop. Submit with static evidence at Probable/Theoretical.
3. **Bypass works but finding doesn't:** Re-analyze code path, identify mitigating control, downgrade.
4. **Cost-benefit:** Time on bypass ∝ finding value. Theoretical Medium ≠ 20+ iterations.
5. **Alternatives:** Non-rooted device, emulator, Frida Gadget (no server), accept static evidence.

---

## Effort Allocation

| Phase | % | Time Cap (16hr) | Rationale |
|-------|---|-----------------|-----------|
| 1 Preflight | 5% | 45 min | Setup |
| 2 Static | 15% | 2.5 hr | Foundation |
| 3 Bypass | 10% | 1.5 hr | Means to an end (cap at decision tree) |
| 4 Traffic | 10% | 1.5 hr | Baseline capture |
| 5 Attack Surface | 5% | 45 min | Organize |
| 6 Runtime | 15% | 2.5 hr | Dynamic validation |
| 7 Vuln Analysis | 20% | 3 hr | Core testing |
| 8 API | 10% | 1.5 hr | Server-side |
| 9 Exploitation | 5% | 45 min | Chain and prove |
| 10 Reporting | 5% | 45 min | Write-up |

**Move-on rule:** Phase exceeds time cap with no findings → advance. Exception: Phase 7 can extend if actively finding bugs.

**Adjustments:**
- Bug bounty: compress P1/4/5/10, expand P7. Phase jumping allowed (see below).
- Banking app: expand P3 (bypass) + P8 (attestation APIs). For apps with Eversafe + Flutter BoringSSL (no known pattern), P3 cap = 3-4hr: root bypass 30min, Flutter SSL RE 2hr, anti-tampering 1hr. If not resolved in 4hr → accept partial bypass (HTTP Toolkit for interception, 53s Frida window for hooks) and advance.
- Offline app: skip P4/P8, expand P6

**Bug bounty phase jumping:** When a high-value lead is found during any phase (e.g., promising deep link in Phase 2), validate immediately — don't wait for sequential gate progression. Track the finding under the phase where it was proven (e.g., Phase 9 for PoC). Resume sequential flow after the lead is resolved. Update `state.yaml` to reflect the highest phase touched and mark intermediate phases as needed.

---

## Dual-Platform Engagement (Android + iOS)

**Execution order:** Android first (easier instrumentation), then iOS (Android findings guide where to look).

**Phase sharing:**
- **Per-platform (run twice):** Phase 2, Phase 3, Phase 6
- **Shared (run once):** Phase 4, Phase 5, Phase 7, Phase 8
- **Merge:** Phase 9 (per-finding per-platform), Phase 10 (unified report)

**Rules:**
- API-level findings only need testing once (same backend)
- Platform-specific findings get separate MTEST-XXX entries tagged `[Android]` or `[iOS]`
- Attack surface map (Phase 5) is unified, entries tagged per platform
- Time adjustment: +40% (not +100%) because shared phases

---

## App-Type Decision Tree

Load full decision tree: `references/app-type-decision-tree.md`

**Quick:** Banking (heavy bypass + IDOR) | Social (deep links + WebView + API) | Utility (local storage + IPC) | Game/Unity (metadata + native RE) | Flutter (libapp.so strings + BoringSSL bypass) | **TWA/WebView wrapper** (config extraction + intent filters, see below) | Meta apps (multi-layer pinning + server-side sig validation, see `references/meta-instagram-bypass.md`) | Meta/Instagram (patched APK + QUIC block + TrustManager hook, see `references/meta-instagram-bypass.md`)

### TWA / WebView Wrapper Apps

**Detection (Phase 2):** App has `LauncherActivity` extending `TwaLauncherActivity` or uses Chrome Custom Tabs to launch a URL. Minimal Java/Kotlin — no custom HTTP client, no native libs, no crypto. The APK is just a shell around a web app.

**Pivot strategy — skip native RE, focus on:**
1. **Config extraction**: Firebase keys, analytics tokens (Adjust, Braze), OAuth client IDs from `Application.java`, `google-services.json`, `strings.xml`, `resources.arsc`
2. **Intent filter analysis**: Deep links, scheme handlers, `assetlinks.json` → test for intent scheme injection
3. **Launch parameters**: TWA query params (`?twa=1`), custom headers injected by the wrapper
4. **SDK tokens**: Embedded third-party tokens (Adjust app_token, Sentry DSN, Datadog client token) → test for write injection
5. **Web attack surface**: The real app is the web origin — pivot to `ptest` for full web testing

**What NOT to waste time on:** Frida hooking (nothing to hook), root detection bypass (irrelevant), native lib RE (none exist), certificate pinning (uses system Chrome).

**TWA identification:** Check for `com.google.androidbrowserhelper.trusted` in decompiled source + `LauncherActivity extends n` (TrustedWebActivityService). XAPK with only config splits + tiny main APK (<1MB) = TWA. WinTicket lesson: 918KB XAPK, LauncherActivity just appends `?twa=1` to URL and launches Chrome Custom Tab. All auth/logic lives in web — APK reversing yields nothing useful.

**TWA auth testing strategy:** Since auth is web-based:
1. Map the web login flow via browser interception (not APK)
2. Check if JS bundles are gzip-compressed (serve as binary, not readable text)
3. Use browser DevTools network interception during real login
4. The `intent://` scheme callbacks are the mobile-specific attack surface
5. Test CSRF on intent-generating endpoints (Apple/Google OAuth callbacks)

### Intent Scheme URL Injection

**When:** Backend returns `Location: intent://...` with user-controlled data in the URL (common in OAuth callback endpoints like `/v1/auth/apple`, `/v1/auth/google`).

**Detection:** POST to OAuth endpoint → check if Location header contains `intent://callback?{YOUR_BODY}#Intent;...;end`.

**Exploitation — fragment boundary injection:**
```bash
# If POST body is reflected before the server's #Intent; fragment:
curl -X POST "https://api.target.com/v1/auth/apple" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary 'code=x#Intent;package=com.nonexistent;S.browser_fallback_url=https://evil.com;end//'
# Result: intent://callback?code=x#Intent;...;S.browser_fallback_url=https://evil.com;end//#Intent;package=real.app;...;end
# Android parses FIRST #Intent; block → attacker controls:
#   - browser_fallback_url (open redirect if app not installed)
#   - package (redirect to different app)
#   - action (override intent action)
```

**Impact:** Open redirect on Android (via fallback URL), phishing, session fixation. If victim doesn't have the app installed, browser navigates to attacker's URL.

**Key:** Use raw `#` (not `%23`) to inject — URL-encoded `%23` stays in query string, raw `#` splits the fragment.

---

## Bug Bounty Fast-Path

Load: `references/bug-bounty-fast-path.md`

**TL;DR:** Static (30min) → Bypass (if pinned) → Traffic (15min) → Skip to Phase 7 highest-value features → Exploit → Submit. Budget: 4-8 hours.

---

## Output Structure

```
<workdir>/mtest-output/
├── state.yaml
├── scope.md
├── phase1-preflight/
├── phase2-static/
├── phase3-protection/
│   └── scripts/
├── phase4-traffic/
├── phase5-attack-surface/
│   └── attack-surface-map.md
├── phase6-runtime/
├── phase7-vuln-analysis/
│   └── per-feature/
├── phase8-api/
├── phase9-exploitation/
│   ├── poc/
│   └── evidence/
├── phase10-reporting/
├── findings/
│   └── MTEST-001.md
└── report.md
```

---


## Pitfalls

> Full pitfalls: `references/pitfalls.md` (mobile-specific, Frida, Flutter, Meta apps, Eversafe, Ghidra, Burp integration)

### Behavioral Rules (always active)

- **Root/jailbreak bypass is NOT a finding** — Phase 3 is a means, not a result
- **Certificate pinning bypass alone is Medium at best** — needs real API abuse to escalate
- **Check `overridePins="true"` in NSC before spending hours on Frida bypass** — saves hours of wasted Phase 3 work
- **Don't over-engineer Frida when you have keys** — write standalone Python instead
- **Flutter 3.22+ breaks ALL known SSL bypass patterns** — needs Ghidra RE approach (see `references/flutter-ssl-bypass.md`)
- **Eversafe TLV token is forgeable (no crypto)** — full API testing without real device possible (see `references/eversafe-attestation.md`)
- **QUIC (UDP 443) bypasses HTTP proxies** — block with iptables to force TCP fallback
- **CRITICAL: Do NOT block `bindService` to EversafeService** — backend requires `x-eversafe-token` for auth. Blocking causes "Sorry, we can't log you in" with zero traffic.

### Technical Quick-Reference (load references/ for details)

- Burp invisible proxy pitfalls (upstream proxy pollution, hostname resolution, Host header with port): see `references/burp-mcp-integration.md`
- Eversafe debugger alert bypass (msg.what=84/100 suppress): see `references/eversafe-bypass.md`
- Eversafe PROD encrypt_token rejection: see `references/eversafe-attestation.md`
- Flutter + redsocks = no HTTP history (use Frida connect() redirect instead): see `references/redsocks-transparent-proxy.md`
- Flutter SSL pattern matching (r-x only, skip wrong functions): see `references/flutter-ssl-bypass.md`
- KernelSU root hiding (no DenyList, needs Frida hooks): see `references/kernelsu-root-hiding.md`
- Magisk systemless CA install path: `/data/adb/modules/*/system/etc/security/cacerts/`
- Burp MCP disconnected → raw socket SSE on port 9876: see `references/burp-mcp-raw-socket.md`

## Cross-Skill Triggers

| Signal | Trigger |
|--------|---------|
| Eversafe/Everspin detected (kr.co.everspin) | `references/eversafe-frida-bypass.md` + `references/eversafe-attestation.md` (token forgery) + `templates/flutter_eversafe_intercept.py` (ready-to-use interceptor). For full bypass writeup template see Jago PROD: `mtest-output/phase3-protection/bypass-writeup.md` |
| KernelSU root detection (KSU overlay in mounts, /data/adb/ksu) | `references/kernelsu-root-hiding.md` + `templates/flutter_eversafe_full_bypass.js` |
| Flutter + Eversafe + root detection combined | `templates/flutter_eversafe_full_bypass.js` (all-in-one: debugger suppress + root hide + connect redirect + SSL bypass) |
| macOS Burp + DNAT not working | `references/redsocks-transparent-proxy.md` |
| Flutter SSL bypass hooks never trigger | `references/phase3-bypass.md` → fallback approaches |
| MHL/CTF challenge walkthrough write-up | `templates/mhl-walkthrough.md` (gist-style: summary → steps → notes → flag) |
| Native .so flag extraction (no plaintext in strings) | `references/native-flag-extraction.md` (XOR emulation, identify real vs decoy buffers) |
| BROWSABLE deep link with create/compose host | `scripts/deeplink_browsable_chain_test.sh` |
| API endpoints in traffic | `atest` — see decision criteria below |

### mtest Phase 8 → atest Decision Criteria

**Stay in mtest Phase 8 (quick 1.5hr):**
- ≤10 API endpoints discovered in traffic
- Simple auth model (single bearer token, no multi-role)
- No GraphQL/gRPC — just REST
- API is secondary — mobile-specific surface (deep links, local storage, IPC, WebView) is higher value
- Time budget remaining < 2hr

**Switch to full atest:**
- >10 endpoints with object IDs (BOLA surface)
- Complex auth: multi-role, tenant isolation, or undocumented privilege levels
- GraphQL or gRPC detected (needs specialized testing)
- Mobile app is a thin client — API IS the app (all logic server-side)
- Eversafe/attestation already bypassed — full API access available

**Handoff procedure:**
1. Complete mtest Phase 4 (traffic captured, endpoints mapped)
2. Start atest at Phase 2 — skip Phase 1, gate satisfied by mtest traffic analysis
3. Carry over: endpoint list from `mtest-output/phase4-traffic/`, auth tokens from intercepted traffic
4. Findings tag with `source: "atest"` and flow back to mtest findings.jsonl
5. After atest completes, return to mtest Phase 9 (exploitation) for mobile-specific chains

| Signal | Trigger |
|--------|---------|
| Flask passive analyzer needed | `references/passive-traffic-analyzer.md` |
| Flutter app entering Phase 4 (traffic) | Skip redsocks→Burp entirely. Use Frida Dart-layer HTTP dumper. See `references/redsocks-transparent-proxy.md` "CRITICAL LIMITATION" |
| Cloud storage URLs (S3/GCS) | `ctest` |
| Web endpoints found | `ptest` |
| Hardcoded secrets/source code | `scode` |
| Web3/smart contract SDK | `w3hunt` |
| API geo-blocked | ptest `references/geo-restriction-bypass.md` |
| Large app (50K+ classes) | delegate Phase 2 to subagent |
| Thick client companion app | `ttest` — desktop app testing |
| AD/domain credentials in app | `adtest` — if domain is in scope |
| Meta/Instagram/Facebook app | `references/meta-instagram-bypass.md` + `references/meta-instagram-testing.md` |
| Meta Threads (barcelona) app | load `references/meta-instagram-testing.md` → "Threads Specifics" |

## Operational Notes

> Full notes: `references/operational-notes.md`

