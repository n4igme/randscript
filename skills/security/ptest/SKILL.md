---
name: ptest
description: "Structured penetration testing framework with gated phases. Guides methodical progression from recon through exploitation to reporting."
version: 4.5.0
author: n4igme
license: MIT
argument-hint: "<command: start|preflight|status|resume|next|escalate|cleanup|recon-passive|recon-active|enumerate|attack-surface|vuln-assess|exploit|post-exploit|report>"
notes:
  - "v4.5.0: Hub model — SKILL.md is routing only, all phase content in references/phase*.md"
  - "scripts/ contains hermes_tools-based phase scripts; see references/execute-code-integration.md for tier definitions and usage"
  - "Shell scripts (bulk-actuator-scan.sh, http-probe-parallel.sh) still usable via terminal() for standalone runs"
metadata:
  hermes:
    tags: [pentest, penetration-testing, security, recon, exploitation, post-exploitation, red-teaming, offensive-security]
    related_skills: [godmode, mtest, scode, osint, xdev]
---

# Penetration Testing Framework

Structured pentest engagement with mandatory quality gates preventing premature phase advancement.

## Quick Reference

```
Phases:  1.Passive → 2.Active → 3.Enumerate → 4.AttackSurface → 5.VulnAssess → 6.Exploit → 7.PostExploit → 8.Report
States:  LOCKED → OPEN → PASSED (sequential, no skipping)
Commands: start | preflight | status | resume | next | escalate | cleanup | recon-passive | recon-active | enumerate | attack-surface | vuln-assess | exploit | post-exploit | report

Mandatory tools by phase:
  P1: dig, curl, whois          P2: nmap              P3: gobuster/feroxbuster, ffuf
  P5: nuclei                    P6: (vector-dependent) P7: (access-dependent)

Key guardrails:
  • Authorization required before ANY testing
  • Human sign-off required at every gateway transition
  • Every finding needs reproducible evidence (not theoretical)
  • Pre-Report Gate 0: (1) attacker can do this NOW? (2) victim loses WHAT? (3) reproducible in 10 min?
  • Environment tag required on all findings (prod/nonprod/experiment)
  • Never skip phases — even for bug bounties
```

## Architecture

`Gateway (Quality Gate)` → `Phase (Pentest Stage)` → `Tasks (Techniques)`

## Commands

$ARGUMENTS
<!-- ↑ Runtime token: the skill framework substitutes this with the user's actual command argument -->

| Command | Action |
|---------|--------|
| `start` | Initialize a new engagement — prompt for scope, targets, and authorization |
| `preflight` | Check mandatory tool availability and install missing tools |
| `status` | Show current gateway state, progress, and pending techniques |
| `resume` | Resume an interrupted engagement — read existing output and continue from last checkpoint |
| `next` | Attempt to advance to the next phase (runs exit criteria check) |
| `escalate` | Trigger critical finding escalation |
| `cleanup` | Archive engagement output, sanitize sensitive data |
| `recon-passive` | Execute passive recon techniques |
| `recon-active` | Execute active recon techniques |
| `enumerate` | Execute application-layer enumeration |
| `attack-surface` | Map and confirm attack surface with user |
| `vuln-assess` | Execute threat modeling and vulnerability assessment |
| `exploit` | Execute exploitation techniques |
| `post-exploit` | Execute post-exploitation techniques |
| `report` | Generate final pentest report |

If no command is given, show current status and suggest next action.

---

# ═══════════════════════════════════════════════════════════════
# SETUP — Tool preparation, engagement initialization, resumption
# ═══════════════════════════════════════════════════════════════

## Preflight Check (`preflight`)

**Run this before starting any engagement.** Verifies all mandatory and recommended tools are available, and installs missing ones.

### Mandatory Tools (engagement cannot proceed without these)

| Tool | Phase | Install Command (macOS) | Install Command (Linux) |
|------|-------|------------------------|------------------------|
| `dig` | 1 | `brew install bind` | `apt install dnsutils` |
| `curl` | 1 | (pre-installed) | `apt install curl` |
| `whois` | 1 | (pre-installed) | `apt install whois` |
| `nmap` | 2 | `brew install nmap` | `apt install nmap` |
| `gobuster` | 3 | `brew install gobuster` | `go install github.com/OJ/gobuster/v3@latest` |
| `ffuf` | 3 | `brew install ffuf` | `go install github.com/ffuf/ffuf/v2@latest` |
| `nuclei` | 5 | `brew install nuclei` | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |

### Recommended Tools (enhance coverage but not blocking)

| Tool | Phase | Install Command (macOS) | Install Command (Linux) |
|------|-------|------------------------|------------------------|
| `subfinder` | 1 | `brew install subfinder` | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `amass` | 1 | `brew install amass` | `go install github.com/owasp-amass/amass/v4/...@master` |
| `theHarvester` | 1 | `pip3 install theHarvester` | `pip3 install theHarvester` |
| `spiderfoot` | 1 | `pip3 install spiderfoot` | `pip3 install spiderfoot` |
| `photon` | 1 | `pip3 install photon` | `pip3 install photon` |
| `gitleaks` | 1 | `brew install gitleaks` | `go install github.com/gitleaks/gitleaks/v8@latest` |
| `trufflehog` | 1 | `brew install trufflehog` | `go install github.com/trufflesecurity/trufflehog/v3@latest` |
| `dnsx` | 2 | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| `puredns` | 2 | `go install github.com/d3mondev/puredns/v2@latest` | `go install github.com/d3mondev/puredns/v2@latest` |
| `massdns` | 2 | `brew install massdns` | `apt install massdns` |
| `dnsrecon` | 2 | `pip3 install dnsrecon` | `pip3 install dnsrecon` |
| `dnsenum` | 2 | `brew install dnsenum` | `apt install dnsenum` |
| `masscan` | 2 | `brew install masscan` | `apt install masscan` |
| `feroxbuster` | 3 | `brew install feroxbuster` | `apt install feroxbuster` |
| `arjun` | 3 | `pip3 install arjun` | `pip3 install arjun` |
| `kiterunner` | 3 | `go install github.com/assetnote/kiterunner/cmd/kr@latest` | `go install github.com/assetnote/kiterunner/cmd/kr@latest` |
| `linkfinder` | 3 | `pip3 install linkfinder` | `pip3 install linkfinder` |
| `wpscan` | 3 | `brew install wpscan` | `gem install wpscan` |
| `nikto` | 5 | `brew install nikto` | `apt install nikto` |
| `testssl.sh` | 5 | `brew install testssl` (binary: `testssl.sh`) | `git clone https://github.com/drwetter/testssl.sh.git` |
| `sslscan` | 5 | `brew install sslscan` | `apt install sslscan` |
| `searchsploit` | 5 | `brew install exploitdb` | `apt install exploitdb` |
| `sqlmap` | 6 | `brew install sqlmap` | `apt install sqlmap` |
| `hydra` | 6 | `brew install hydra` | `apt install hydra` |

### Wordlists

**Platform-aware path resolution:** Detect the SecLists path at preflight and store it for the engagement.

```bash
# Resolve SECLISTS_PATH based on platform
if [ -d "/usr/share/seclists" ]; then
  SECLISTS_PATH="/usr/share/seclists"
elif [ -d "/opt/homebrew/share/seclists" ]; then
  SECLISTS_PATH="/opt/homebrew/share/seclists"
elif [ -d "/usr/local/share/seclists" ]; then
  SECLISTS_PATH="/usr/local/share/seclists"
elif [ -d "$HOME/SecLists" ]; then
  SECLISTS_PATH="$HOME/SecLists"
else
  SECLISTS_PATH=""  # Not found — prompt user
fi
```

Store the resolved path in `state.yaml` under `config.seclists_path`. All subsequent commands use `$SECLISTS_PATH` instead of hardcoded paths.

The following wordlists are expected (from SecLists):
- `$SECLISTS_PATH/Discovery/Web-Content/raft-medium-directories.txt`
- `$SECLISTS_PATH/Discovery/Web-Content/raft-medium-files.txt`
- `$SECLISTS_PATH/Discovery/Web-Content/api/api-endpoints.txt`
- `$SECLISTS_PATH/Discovery/DNS/subdomains-top1million-5000.txt`

Install SecLists if missing:
```bash
# macOS
brew install seclists

# Linux / manual
git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

### Preflight Procedure

1. **Detect platform** (macOS/Linux).
2. **Check mandatory tools** — for each, verify `which <tool>` succeeds.
3. **Report status** — show table of available/missing tools.
4. **Install missing mandatory tools** — prompt user for confirmation, then install.
5. **Check recommended tools** — report which are available, offer to install missing ones.
6. **Check wordlists** — verify SecLists path exists.
7. **Update nuclei templates** — run `nuclei -update-templates` if nuclei is installed.
8. **Write preflight report** — save to `./ptest-output/preflight.md`.

If any mandatory tool cannot be installed, the engagement can still proceed but the gap must be documented in the phase checklist.

---

## Initialization (`start`)

Before any testing begins, collect and document:

1. **Preflight Check** — automatically run `preflight` to verify tool availability. Install missing mandatory tools before proceeding.
2. **Target Scope** — domains, IPs, applications, exclusions
3. **Scope Type** — determines which techniques apply:
   - `web` — web applications, APIs
   - `network` — infrastructure, hosts, services
   - `cloud` — AWS/GCP/Azure resources
   - `mobile` — iOS/Android applications
   - `mixed` — combination (default)
4. **Rules of Engagement** — testing hours, restricted techniques, notification requirements
5. **Authorization** — confirm written authorization exists (do NOT proceed without it)
6. **Output Directory** — create `./ptest-output/` with subdirectories:

```
./ptest-output/
  state.yaml            # Gateway state tracker
  scope.md              # Scope, type, and authorization record
  findings-log.md       # Running log of all findings
  recon-passive/        # Phase 1 results
    checklist.md
  recon-active/         # Phase 2 results
    checklist.md
  enumeration/          # Phase 3 results
    checklist.md
  attack-surface/       # Phase 4 results
    checklist.md
  vuln-assessment/      # Phase 5 results
    checklist.md
  exploit/              # Phase 6 results
    checklist.md
  post-exploit/         # Phase 7 results
    checklist.md
  report/               # Phase 8 — Final report
  escalations/          # Critical finding escalations
```

Write initial `state.yaml`:

```yaml
engagement:
  name: ""
  started: ""
  scope_type: ""

config:
  seclists_path: ""  # Resolved during preflight

gateways:
  1_passive_recon: OPEN
  2_active_recon: LOCKED
  3_enumeration: LOCKED
  4_attack_surface: LOCKED
  5_vuln_assessment: LOCKED
  6_exploitation: LOCKED
  7_post_exploitation: LOCKED
  8_reporting: LOCKED

time_tracking:
  phase_1_start: ""
  phase_1_end: ""
  phase_2_start: ""
  phase_2_end: ""
  phase_3_start: ""
  phase_3_end: ""
  phase_4_start: ""
  phase_4_end: ""
  phase_5_start: ""
  phase_5_end: ""
  phase_6_start: ""
  phase_6_end: ""
  phase_7_start: ""
  phase_7_end: ""
  phase_8_start: ""
  phase_8_end: ""
  total_duration: ""  # Calculated at cleanup

findings_count: 0
escalations_count: 0
```

**Time tracking:** Record ISO timestamps when each phase starts and ends. At cleanup, calculate total duration and per-phase time.

---

## Resume (`resume`)

When resuming an interrupted engagement:

1. Read `./ptest-output/state.yaml` to determine active gateway.
2. Read the active phase's `checklist.md` to see which techniques are done vs. pending.
3. Read `./ptest-output/findings-log.md` for context on what's been found.
4. **Re-orient (if >24h since last activity):**
   - Re-read `scope.md` to refresh scope boundaries and exclusions
   - Re-read `attack-surface/checklist.md` (if exists) for target priority
   - Summarize to operator: "You're in Phase X, Y findings so far, last technique was Z. Next up: W."
5. Report status to user and suggest next technique to execute.

### Recovery (if state.yaml is missing or corrupted)

If `state.yaml` cannot be read:
1. Scan `./ptest-output/*/checklist.md` files to determine which phases have been started.
2. Find the last phase with a checklist containing `DONE` or `FAILED` entries.
3. Count findings in `./ptest-output/findings-log.md` to reconstruct `findings_count`.
4. Count files in `./ptest-output/escalations/` to reconstruct `escalations_count`.
5. Rebuild `state.yaml` — mark completed phases as `PASSED`, current phase as `OPEN`, remaining as `LOCKED`.
6. Inform user of reconstructed state and ask for confirmation before proceeding.

---

# ═══════════════════════════════════════════════════════════════
# FRAMEWORK — Gateway system, quality gates, effort allocation
# ═══════════════════════════════════════════════════════════════

## Gateway Map

| Gateway | Phase | Reference File | Exit Criteria |
|---------|-------|-----------|---------------|
| 1 | Passive Reconnaissance | `references/phase1-passive-recon.md` | Attack surface mapped, subdomains validated, technologies identified. OSINT completeness verified. **Env-prefix quick-win check completed.** |
| 2 | Active Reconnaissance | `references/phase2-active-recon.md` | Subdomain list expanded via active DNS techniques, all hosts port-scanned, services detected, network topology mapped |
| 3 | Enumeration | `references/phase3-enumeration.md` | Applications enumerated, APIs mapped, parameters discovered, Prometheus metrics mined for hidden services |
| 4 | Attack Surface Mapping | `references/phase4-attack-surface.md` | Asset inventory confirmed with user, scope finalized, entry points mapped |
| 5 | Threat Modeling & Vuln Assessment | `references/phase5-vuln-assessment.md` | Attack trees documented, vuln scans complete, CORS reflection tested on all auth endpoints, vectors prioritized |
| 6 | Exploitation | `references/phase6-exploitation-framework.md` | All mandatory techniques executed, credential inventory validated, top 5 vectors attempted, attack chains documented. **Local verification passed.** |
| 7 | Post-Exploitation | `references/phase7-post-exploitation-framework.md` | Access type classified, appropriate playbook completed, data scope documented, attack path diagram created, credentials added to inventory |
| 8 | Reporting | `references/phase8-reporting-process.md` | Final report delivered, pre-delivery checklist passed |

---

## Mandatory Quality Gates

### Pre-Report Gate 0 (MANDATORY before writing any finding)

Before drafting any finding report, answer these 3 questions. One NO = KILL the finding and move on.

1. **Can the attacker do this RIGHT NOW with a real HTTP request?**
   - Not "theoretically possible" — demonstrate with an actual request/response
   - If it requires external conditions outside attacker control (Chainlink malfunction, sequencer downtime, specific server load), it's borderline

2. **What does the victim LOSE?**
   - Map to CIA triad: confidentiality (data exposed), integrity (data modified), availability (data deleted/DoS)
   - "The server responds differently" is NOT impact. Quantify: how many users, what data, what dollar value
   - If the answer is only "information disclosure of non-sensitive data" — severity is Low at best

3. **Can it be reproduced in 10 minutes from scratch?**
   - Fresh browser, no prior state, following only your written steps
   - If it requires lucky timing, specific victim behavior beyond "click a link", or network position — document those dependencies explicitly
   - If you can't demo it reproducibly at least 3/5 attempts, do not file

**Kill signals (instant NO):**
- Finding requires privileged access an attacker can't obtain
- Finding is already known/documented behavior (check program policy)
- Finding is on the program's "never submit" list (self-XSS, logout CSRF, missing headers without impact)
- Impact is purely theoretical with no concrete demonstration

### Local Exploit Verification Gate (Phase 6 → 7 transition, MANDATORY)

Before advancing from Phase 6, every confirmed exploit MUST be locally verified when possible.

**Verification procedure:**
1. **Re-read the actual source/target behavior** — don't rely on notes from earlier analysis. Re-fetch/re-read the code.
2. **Simulate the environment locally** — install the same libraries (yauzl, express, spring-boot, etc.), replicate the file structure, run the exploit against your local simulation.
3. **Verify each chain link independently** — test validation bypass, test payload delivery, test execution separately before combining.
4. **Compare your assumptions vs actual code** — check function signatures, required interfaces, return value handling, error paths.
5. **Document verification result** — add "Locally verified: YES/NO (reason)" to the finding.

**When local verification is NOT possible:**
- Target uses proprietary/closed-source backend (no source available)
- Environment requires specific cloud services that can't be replicated
- Exploit depends on race conditions or timing that can't be simulated

In these cases, document: "Local verification not possible: {reason}. Confidence level: HIGH/MEDIUM/LOW based on {evidence}."

**Real-world save (Dojo #51, May 2026):** Initial exploit had wrong plugin interface (`module.exports = { result: flag }` instead of required `get()`, `getName()`, `run()` methods). Also had wrong first-nibble constraint (`0xA || 0xB` instead of actual `0xA || 0xC`). Local simulation caught both before submission.

---

## Effort Allocation

**Time-box enforcement:** See `references/time-box-enforcement.md` for budget calculation, alert levels, over-budget decision tree, per-technique time caps, and scope adjustment triggers.

| Phase | % of Total Time | Rationale |
|-------|----------------|-----------|
| 1–2 Recon (Passive + Active) | 15% | Discovery, not exploitation |
| 3 Enumeration | 15% | Deep enough to find entry points |
| 4 Attack Surface | 5% | Planning — consolidation only |
| 5 Vuln Assessment | 20% | Scanning + manual verification |
| 6 Exploitation | 25% | Highest-value work |
| 7 Post-Exploitation | 10% | Demonstrate impact |
| 8 Reporting | 10% | Write-up (findings documented throughout) |

Adjust based on scope size. Large scope (50+ hosts) → more recon time. Small scope (single app) → more exploitation time.

**Continuous/internal engagements:** Set `time_budget.mode: "continuous"` in state.yaml. Track time for reporting only — no budget enforcement.

**Move-on heuristic:** If a technique yields no new results after 15–20 minutes of active work, mark it `DONE` (no findings) or `FAILED (diminishing returns)` and proceed. Exception for continuous engagements: vectors showing partial progress deserve extended time.

**Early-finding fast-track (bug bounty):** When a confirmed High/Critical finding is discovered during Phase 1-3, the operator may fast-track: (1) document the finding fully, (2) complete current phase's mandatory checks, (3) skip remaining low-priority techniques, (4) proceed to reporting. Mark skipped phases as "PASSED (fast-tracked — confirmed High finding)". Continue probing other live hosts briefly (10-15 min) for additional quick wins before closing.

---

## Finding Template

Every finding documented during the engagement MUST follow this format:

### Finding ID Assignment

IDs are auto-incremented from `state.yaml`:
1. Read current `findings_count` from `./ptest-output/state.yaml`.
2. Increment by 1.
3. Use the new value as the finding ID (e.g., `FINDING-1`, `FINDING-2`, ...).
4. Write the updated `findings_count` back to `state.yaml` immediately.

This ensures unique, sequential IDs even across phases and sessions.

### Findings Deduplication Rule

- **Same vulnerability on multiple hosts/gateways** = 1 finding. List all affected assets in the "Affected Asset" field (e.g., `microservices.prod.bfi.co.id, microservices.prod.bravo.bfi.co.id`). Note which are confirmed vs inferred.
- **Same vulnerability class on different endpoints** (e.g., SQLi on `/users` and SQLi on `/orders`) = separate findings (different root cause, different fix).
- **Same root cause, different impact** (e.g., missing auth on GET vs POST of same endpoint) = 1 finding documenting all methods affected.

```markdown
## [FINDING-{ID}] {Title}

**Severity:** Critical / High / Medium / Low / Info
**CVSS 3.1:** {score} ({vector string})
**Affected Asset:** {host, endpoint, or component}
**Environment:** prod / nonprod / experiment / all
**Phase Discovered:** {phase number and name}
**Verification Status:** Confirmed / Unverified

### Description
{What the vulnerability is and why it matters}

### Steps to Reproduce
1. {step}
2. {step}
3. {step}

### Evidence
{Screenshots, request/response logs, command output — MUST include direct proof}

### Impact
{What an attacker can achieve}

### Remediation
{Required fix and defense-in-depth recommendations}
```

**Verification Status rules:**
- **Confirmed** — direct evidence proving the issue exists right now. Only confirmed findings go into the final report.
- **Unverified** — suspected based on indirect evidence but not proven. Goes into "Potential Issues" appendix. Does NOT count toward `findings_count`.

---

## Operational Lifecycle

### Execution Loop

1. **Read State** — check `./ptest-output/state.yaml` to determine active gateway.
2. **Read Checklist** — check the phase's `checklist.md` for pending techniques.
3. **Pick Technique** — select next pending technique.
4. **Execute** — run the technique using the tools specified in the phase skill file.
5. **Document** — record findings using the Finding Template above.
6. **Update Checklist** — mark technique status in `checklist.md`:
   - `DONE` — technique executed successfully (findings or no findings)
   - `SKIPPED (reason)` — technique not applicable or tool unavailable
   - `FAILED (reason)` — technique attempted but did not succeed
7. **Update Findings Log** — append to `./ptest-output/findings-log.md`.
8. **Repeat** until phase exit criteria are met.

### Gateway Transition (`next`)

1. **Coverage Audit** — verify checklist shows sufficient technique coverage.
2. **Mandatory Tool Check** — confirm all mandatory tools for the phase were executed.
3. **Evidence Check** — confirm all findings have supporting evidence.
4. **Exit Criteria** — evaluate against the phase's exit criteria (see Gateway Map).
5. **Sign-off** — ask user: *"Phase [X] complete. [N] findings documented. Ready to advance to [next phase]?"*
6. **Update State** — update `./ptest-output/state.yaml`: mark gateway as PASSED, unlock next.

---

## Escalation Protocol

Triggered by `escalate` command OR automatically when a Critical/P1 finding is discovered.

**ID relationship:** An escalation is also a finding. It gets both:
- A **finding ID** from `findings_count` (e.g., `FINDING-5`) — used in findings-log.md and the final report.
- An **escalation ID** from `escalations_count` (e.g., `escalation-1`) — used for the escalation file name and urgent notification.

1. Document finding fully using the Finding Template (assigns a finding ID).
2. Classify severity (CVSS 3.1).
3. Increment `escalations_count` in `state.yaml` (1-indexed, post-increment — first escalation = `escalation-1`).
4. Write to `./ptest-output/escalations/escalation-{escalations_count}.md`, referencing `FINDING-{ID}`.
4. Alert user for immediate client communication.
5. Current gateway pauses until escalation is acknowledged.
6. Increment `escalations_count` in `state.yaml`.

See `escalate-finding.md` for full procedure.

---

## Cleanup (`cleanup`)

Post-engagement housekeeping:

1. **Archive** — compress `./ptest-output/` to `./ptest-output-{engagement-name}-{date}.tar.gz`.
2. **Sanitize** — remove credentials *you used* during testing. Do NOT remove credentials *you found* as findings — those are evidence.
3. **Verify** — confirm report is complete and all findings are documented.
4. **Summary** — print engagement stats (findings by severity, phases completed, duration).

---

# ═══════════════════════════════════════════════════════════════
# PHASES — Phase-specific techniques, checklists, and procedures
# ═══════════════════════════════════════════════════════════════

## Scope-Aware Checklist Generation

When generating phase checklists during `start`, filter techniques by scope type. Techniques that don't apply to the engagement's scope type should be pre-marked as `N/A (scope: {type})` instead of `PENDING`.

| Phase | Technique | web | network | cloud | mobile | mixed |
|-------|-----------|-----|---------|-------|--------|-------|
| 1 | OSINT Gathering | Y | Y | Y | Y | Y |
| 1 | JS Bundle Analysis & Staging Domain Discovery | Y | N | Y | Y | Y |
| 1 | Subdomain Enumeration | Y | Y | Y | N | Y |
| 1 | Internal Asset Inventory Request | Y | Y | Y | N | Y |
| 1 | Knowledge Base / Support Site Scraping | Y | Y | Y | N | Y |
| 1 | Pattern-Based Subdomain Brute-Force | Y | Y | Y | N | Y |
| 1 | Technology Fingerprinting | Y | N | Y | Y | Y |
| 1 | Email & Username Discovery | Y | Y | Y | N | Y |
| 1 | Network Mapping | N | Y | Y | N | Y |
| 1 | Asset Validation | Y | Y | Y | N | Y |
| 2 | Port Scanning (MANDATORY) | Y | Y | Y | Y | Y |
| 2 | Active DNS Expansion — Pattern Permutation (MANDATORY) | Y | Y | Y | N | Y |
| 2 | Active DNS Expansion — DNS-Level Brute-Force (MANDATORY) | Y | Y | Y | N | Y |
| 2 | Active DNS Expansion — Reverse DNS on IP Ranges | N | Y | Y | N | Y |
| 2 | Active DNS Expansion — Virtual Host Enumeration | Y | N | Y | N | Y |
| 2 | Active DNS Expansion — Zone Transfer Attempt | Y | Y | Y | N | Y |
| 2 | Service Detection & Banner Grabbing | Y | Y | Y | Y | Y |
| 2 | OS Fingerprinting | N | Y | N | N | Y |
| 2 | Network Topology Mapping | N | Y | Y | N | Y |
| 3 | Directory & File Brute-Force (MANDATORY) | Y | N | N | N | Y |
| 3 | HTTP Method Testing on Unauth Endpoints (MANDATORY) | Y | N | Y | N | Y |
| 3 | API Endpoint Discovery (MANDATORY) | Y | N | Y | Y | Y |
| 3 | Parameter Discovery | Y | N | N | Y | Y |
| 3 | Virtual Host Enumeration | Y | N | N | N | Y |
| 3 | CMS-Specific Enumeration | Y | N | N | N | Y |
| 3 | JavaScript Analysis | Y | N | N | Y | Y |
| 3 | JavaScript Secret Scanning (MANDATORY) | Y | N | N | Y | Y |
| 3 | Source Map Sweep (MANDATORY when web apps found) | Y | N | N | N | Y |
| 3 | Authentication Endpoint Mapping | Y | N | Y | Y | Y |
| 3 | Bulk Actuator/Admin Scan (MANDATORY) | Y | N | Y | N | Y |
| 5 | Threat Modeling | Y | Y | Y | Y | Y |
| 5 | Nuclei Scan (MANDATORY) | Y | N | Y | N | Y |
| 5 | CORS Origin Reflection Testing (MANDATORY) | Y | N | Y | N | Y |
| 5 | OAuth/OIDC redirect_uri Validation (MANDATORY) | Y | N | Y | N | Y |
| 5 | Nikto Scan | Y | N | N | N | Y |
| 5 | SSL/TLS Assessment | Y | Y | Y | N | Y |
| 5 | CVE Mapping | Y | Y | Y | Y | Y |
| 5 | Manual Verification | Y | Y | Y | Y | Y |
| 5 | Prioritized Vector List | Y | Y | Y | Y | Y |
| 6 | Known CVE Exploitation | Y | Y | Y | Y | Y |
| 6 | Web Application Attacks | Y | N | Y | N | Y |
| 6 | Authentication Bypass | Y | Y | Y | Y | Y |
| 6 | Injection Attacks | Y | N | Y | Y | Y |
| 6 | Logic Flaws | Y | N | Y | Y | Y |
| 6 | Client-Side Attacks | Y | N | N | Y | Y |
| 7 | Privilege Escalation | Y | Y | Y | Y | Y |
| 7 | Lateral Movement | N | Y | Y | N | Y |
| 7 | Persistence (Document Only) | N | Y | Y | N | Y |
| 7 | Data Access | Y | Y | Y | Y | Y |
| 7 | Credential Harvesting | Y | Y | Y | Y | Y |

When scope type is `mixed`, all techniques are `PENDING`. For other scope types, mark `N` entries as `N/A (scope: {type})`.

---

## Phase Routing

When entering a phase, load the corresponding reference file with `skill_view(name='ptest', file_path='references/<file>')`:

| Phase | File | Load When |
|-------|------|-----------|
| 1 | `references/phase1-passive-recon.md` | Entering passive recon |
| 2 | `references/phase2-active-recon.md` | Entering active recon |
| 3 | `references/phase3-enumeration.md` | Entering enumeration |
| 4 | `references/phase4-attack-surface.md` | Entering attack surface mapping |
| 5 | `references/phase5-vuln-assessment.md` | Entering vuln assessment |
| 6 | `references/phase6-exploitation-framework.md` | Entering exploitation |
| 7 | `references/phase7-post-exploitation-framework.md` | Entering post-exploitation |
| 8 | `references/phase8-reporting-process.md` | Entering reporting |
| — | `escalate-finding.md` | Critical finding discovered (any phase) |

**Load only the active phase file.** Each contains: full technique checklist, procedures, commands, exit criteria, and pitfalls specific to that phase.

---

# ═══════════════════════════════════════════════════════════════
# OPERATIONAL — Multi-target, guardrails, cross-skill, pitfalls
# ═══════════════════════════════════════════════════════════════

## Multi-Target Engagement Structure

When a bug bounty program has multiple in-scope assets, organize per-target:

```
./ptest-output/                    # Primary target (first tested)
  state.yaml
  scope.md                         # FULL program scope (all assets)
  findings-log.md
./target2.domain/
  ptest-output/
    state.yaml                     # Independent state per target
    scope.md                       # Target-specific scope subset
    findings-log.md
```

**Rules:**
1. The primary `scope.md` documents ALL program assets and their status (tested/dead/RBAC-blocked/pending)
2. Each target gets its own `state.yaml` with independent phase tracking
3. Finding IDs are unique per-target (F-1 in target A ≠ F-1 in target B)
4. When submitting, reference findings by `{target}:{finding-id}` (e.g., `findaya.co.id:F-4`)
5. Cross-target findings go in the target where they have highest impact
6. Mark targets as completed: `tested (N findings)`, `dead (decommissioned)`, `RBAC-blocked`, `hardened (0 findings)`

**Fast-exit heuristics:**
- Identical Istio RBAC 403 on all paths → "RBAC-blocked", move on (5 min max)
- All subdomains don't resolve → "dead/decommissioned", move on (2 min max)
- Well-known hardened service, all endpoints return proper 401 → "hardened", move on (10 min max)
- Prioritize targets sharing infrastructure with already-vulnerable targets

---

## Guardrails

### Disclosure & Platform Rules

- **Public Disclosure Prohibition** — NEVER publish PoCs on public URLs before vendor fix (or 90-day deadline). Keep PoCs local in `ptest-output/report/`. See `references/bug-bounty-submission-guide.md`.
- **YesWeHack Dojo Challenges** — See `references/yeswehack-dojo-interaction.md` for UI interaction patterns.

### Scope Rules

- **Scope Type Interpretation** — "Web application" (e.g., `mokapos.com`) means ONLY that domain, NOT `*.mokapos.com`. Only "Wildcard" targets include subdomains. Confirm BEFORE Phase 1.
- **Related-Domain Scope Risk** — findings on same-company different-root-domain are borderline. Submit clear-scope findings first, borderline last with scope note.
- **Scope Enforcement** — never test targets outside defined scope. Re-read `scope.md` before each technique.
- **Program Exclusion Cross-Check (Phase 4, MANDATORY)** — cross-reference ALL vectors against the program's exclusion list BEFORE scoring them.

### Evidence Rules

- **Evidence Required** — every finding must have reproducible proof.
- **Verified Findings Only** — DNS resolution or CT log presence alone does NOT constitute a finding. Must include proof of current exploitability.
- **Environment Tagging** — every finding MUST be tagged: `prod`, `nonprod`, `experiment`, or `all`.

### Workflow Rules

- **Strict Sequence & Self-Audit** — never skip a phase. Before requesting gateway sign-off, proactively review what was missed — list gaps honestly and offer to fill them.
- **Phase 1 OSINT Completeness** — verify ALL 10 techniques attempted: (1) WHOIS/DNS/TXT, (2) subdomain enum, (3) Wayback Machine, (4) GitHub/GitLab search, (5) Google dorking, (6) Shodan/Censys, (7) JS bundle analysis, (8) Mobile app identification, (9) Docker Hub check, (10) dark web & breach data OSINT.
- **Mandatory Tool Execution** — mandatory tools per phase must be run. If unavailable, document the gap explicitly.
- **Human Sign-off** — always request user confirmation before passing a gateway.
- **No Time/Schedule Commentary** — never comment on the time or suggest stopping. The operator decides their schedule.
- **Authorization First** — refuse to begin without confirmed authorization.
- **No Deployed Persistence** — document persistence techniques but do not deploy backdoors without explicit authorization.
- **ALWAYS do post-exploitation.** See `references/post-exploitation-rules.md`. Never stop at "proved access exists" — demonstrate actual impact.
- **Scope Type Awareness** — skip techniques that don't apply to the engagement's scope type.

### Target Assessment Heuristics

- **Hardened Target Fast-Exit** — if first 3 vectors fail cleanly, mark as "hardened" and move on (15-20 min max). **Exception:** Always check pre-auth flows (OTP, login, registration, password reset).
- **Zero-Finding Close-Out Path** — if Phase 5 concludes with 0 exploitable vectors, fast-track Phases 6-8 with a close-out report.
- **Captcha-Gated Assessment** — assess within 10 minutes: server-validated? bypass paths? non-prod enforcement? If no bypass, document as blocker.
- **RBAC Mesh Fast-Exit** — 50+ subdomains all returning identical 403 = mesh-blocked. Confirm on 10-15 hosts, then move on (30 min cap).
- **SPA Catch-All Detection** — compare response size of target path vs random nonexistent path. Same size = false positive.
- **False Positive Verification** — check for SPA catch-alls, CORS crashes, 302-to-login. See `references/false-positive-detection.md`.
- **Account Creation Blockers** — document limitation, offer user options (manual signup, OAuth, API registration). Never bypass KYC.

### CTI & Legal

- **CTI-Sourced Credentials** — credentials from breach databases require EXPLICIT authorization to test against production. Document the risk without logging in. May violate local law (e.g., UU ITE in Indonesia) even with general pentest authorization.

---

## Cross-Skill Triggers

See `references/cross-skill-triggers.md` for full table and chains.

| Signal | Trigger Skill |
|--------|--------------|
| Cloud infrastructure (AWS/GCP/Azure) | `ctest` |
| API-heavy target | `atest` |
| Mobile app discovered | `mtest` |
| Web3/blockchain | `w3hunt` |
| Source code available | `scode` |
| Geo-restricted target | `references/geo-restriction-bypass.md` |

---

## Istio/Service Mesh Assessment

> See `references/istio-mesh-assessment.md` for full Istio/Envoy detection indicators, external assessment scope, and security implications to report.

---

## Automation Scripts (execute_code integration)

Phase scripts live in `scripts/`. Two tiers:

**Tier 1 — Phase Setup (run once at phase entry):**
Call via `execute_code` when entering a phase. Reads prior phase state, generates checklist, runs lightweight automation, prints structured summary.

| Script | Phase | What It Does |
|--------|-------|-------------|
| `phase1_passive.py` | 1 | crt.sh + subfinder + amass + env-prefix candidates |
| `phase2_active.py` | 2 | DNS resolution, zone transfer, permutation wordlist, wildcard detection |
| `phase3_enumerate.py` | 3 | Actuator scan, framework detection, auth/GraphQL/WebSocket discovery |
| `phase4_attack_surface.py` | 4 | Asset inventory assembly, entry points, scoring template |
| `phase5_vuln_assess.py` | 5 | CDN/WAF detection, CORS testing, SSL check, nuclei commands |
| `phase6_exploit.py` | 6 | Read prioritized vectors, set up tracking, cred inventory check |
| `phase7_post_exploit.py` | 7 | Access classification, playbook selection, attack-path template |
| `phase8_report.py` | 8 | Findings validation, severity summary, report skeleton |

**Tier 2 — Batch Execution (run mid-phase for bulk operations):**
Call when a technique involves 20+ targets. Returns structured JSON summary.

| Script | Phase | What It Batches |
|--------|-------|-----------------|
| `bulk-actuator-scan.sh` | 3 | Actuator/admin scan on all hosts |
| `http-probe-parallel.sh` | 1-2 | HTTP probe all subdomains |
| `probe-parallel.sh` | 2-3 | Parallel probing |

**Usage pattern:**
```python
from hermes_tools import terminal
# Tier 1: setup
result = terminal("cd ./ptest-output && python3 /path/to/scripts/phase3_enumerate.py", timeout=120)
# Tier 2: bulk operation
result = terminal("bash /path/to/scripts/bulk-actuator-scan.sh live-subs.txt results.txt", timeout=300)
```

**When to use execute_code vs sequential calls:**
- 1-3 targets → direct tool calls
- 4-6 targets → delegate_task
- 10+ targets → execute_code with batch script

---

## Execution Pitfalls (Hermes Agent)

> **Full reference:** See `references/operational-pitfalls.md` for all execution pitfalls including parallel probing, terminal backgrounding, tool-specific workarounds, and target-specific lessons learned from BFI Finance and Bank Jago engagements.

> **Batch operations:** See `references/execute-code-integration.md` for when and how to use `execute_code` to batch bulk operations (HTTP probing, actuator scanning, method testing) instead of sequential tool calls.
