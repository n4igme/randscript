---
name: ptest
description: "Structured penetration testing framework with gated phases. Guides methodical progression from recon through exploitation to reporting."
version: 4.0.0
author: n4igme
license: MIT
argument-hint: "<command: start|preflight|status|resume|next|escalate|cleanup|recon-passive|recon-active|enumerate|attack-surface|vuln-assess|exploit|post-exploit|report>"
metadata:
  hermes:
    tags: [pentest, penetration-testing, security, recon, exploitation, post-exploitation, red-teaming, offensive-security]
    related_skills: [sc1-recon, sc3-vuln-scan]
    tags: [pentest, penetration-testing, security, recon, exploitation, post-exploitation, red-teaming, offensive-security]
    related_skills: [godmode, parse-finding]
---

# Penetration Testing Framework

Structured pentest engagement with mandatory quality gates preventing premature phase advancement.

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
| `masscan` | 2 | `brew install masscan` | `apt install masscan` |
| `feroxbuster` | 3 | `brew install feroxbuster` | `apt install feroxbuster` |
| `arjun` | 3 | `pip3 install arjun` | `pip3 install arjun` |
| `linkfinder` | 3 | `pip3 install linkfinder` | `pip3 install linkfinder` |
| `wpscan` | 3 | `brew install wpscan` | `gem install wpscan` |
| `nikto` | 5 | `brew install nikto` | `apt install nikto` |
| `testssl.sh` | 5 | `brew install testssl` | `git clone https://github.com/drwetter/testssl.sh.git` |
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

### Operational Pitfalls (from real engagements)

**HTTP Probing at Scale (100+ subdomains):**
- Sequential `curl` in a loop is too slow (3-5s per host × 270 hosts = 15+ minutes)
- `xargs -P` with shell `-c` has quoting/variable issues — output often empty
- Background jobs (`&`) are blocked by the terminal tool
- **Working approach:** Write a bash script that spawns background jobs with per-file temp output (`$TMPDIR/live_$i.txt`), then `cat $TMPDIR/live_*.txt > live-subs.txt` after `wait`. Run with `bash script.sh`. See `scripts/http-probe-parallel.sh` for a ready-to-use implementation.
- Limit concurrency to 25-30 to avoid connection exhaustion

**Nuclei:**
- `-t exposures/ -t misconfiguration/` may fail with "no templates provided" if paths don't resolve
- Use `-severity medium,high,critical` with `-silent` for faster targeted scans
- Nuclei can be very slow on Cloudflare-fronted targets (rate limiting, challenges)
- Run against non-CDN targets first (direct nginx/GCP hosts) for faster results
- Templates location: `~/nuclei-templates/`

**Nmap on cloud infrastructure:**
- GCP/AWS hosts typically only expose 80/443 — full port scans waste time
- Use `--top-ports 100 -T4` for initial sweep, then targeted scans on interesting hosts
- Non-cloud hosts (colocation, VPS) are more likely to have additional ports
- Service detection (`-sV`) on GCP load balancers returns "tcpwrapped" — not useful

### Performance Notes (from real engagements)

- **HTTP probing 200+ subdomains**: Sequential curl is too slow. Write a bash script using background jobs (`&`) with `wait` every 25-30 jobs, writing results to individual temp files, then merge. Do NOT use `>>` append in parallel (race condition). Do NOT use xargs with shell variable interpolation (breaks). The working pattern:
  ```bash
  TMPDIR=$(mktemp -d)
  i=0
  while IFS='|' read -r sub ip; do
    i=$((i+1))
    ( curl ... > "$TMPDIR/live_$i.txt" ) &
    [ $((i % 25)) -eq 0 ] && wait
  done < resolving-subs.txt
  wait
  cat "$TMPDIR"/live_*.txt > live-subs.txt
  ```
  Run this as a standalone bash script via `bash script.sh` (not inline with `&` which the terminal tool rejects).

- **nmap on GCP hosts**: All GCP load-balanced IPs only expose 80/443. Don't waste time on full port scans of 34.x/35.x IPs. Focus port scanning on non-cloud hosts (colocation, VPS, on-prem).

- **nuclei timeout**: nuclei with all templates against targets behind Cloudflare/WAF is extremely slow. Use `-timeout 5 -retries 1 -c 25` flags. Run against non-WAF targets first (direct nginx/GCP hosts). Manual testing is often more productive than waiting for nuclei on WAF-protected targets.

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

**Time tracking:** Record ISO timestamps when each phase starts and ends. At cleanup, calculate total duration and per-phase time. This enables:
- Accurate billing/reporting of engagement hours
- Identifying which phases took longer than expected (vs effort allocation guidelines)
- Improving time estimates for future engagements

### Scope-Aware Checklist Generation

When generating phase checklists during `start`, filter techniques by scope type. Techniques that don't apply to the engagement's scope type should be pre-marked as `N/A (scope: {type})` instead of `PENDING`.

| Phase | Technique | web | network | cloud | mobile | mixed |
|-------|-----------|-----|---------|-------|--------|-------|
| 1 | OSINT Gathering | Y | Y | Y | Y | Y |
| 1 | Subdomain Enumeration | Y | Y | Y | N | Y |
| 1 | Pattern-Based Subdomain Brute-Force | Y | Y | Y | N | Y |
| 1 | Technology Fingerprinting | Y | N | Y | Y | Y |
| 1 | Email & Username Discovery | Y | Y | Y | N | Y |
| 1 | Network Mapping | N | Y | Y | N | Y |
| 1 | Asset Validation | Y | Y | Y | N | Y |
| 2 | Port Scanning (MANDATORY) | Y | Y | Y | Y | Y |
| 2 | Service Detection & Banner Grabbing | Y | Y | Y | Y | Y |
| 2 | OS Fingerprinting | N | Y | N | N | Y |
| 2 | Network Topology Mapping | N | Y | Y | N | Y |
| 3 | Directory & File Brute-Force (MANDATORY) | Y | N | N | N | Y |
| 3 | API Endpoint Discovery (MANDATORY) | Y | N | Y | Y | Y |
| 3 | Parameter Discovery | Y | N | N | Y | Y |
| 3 | Virtual Host Enumeration | Y | N | N | N | Y |
| 3 | CMS-Specific Enumeration | Y | N | N | N | Y |
| 3 | JavaScript Analysis | Y | N | N | Y | Y |
| 3 | JavaScript Secret Scanning (MANDATORY) | Y | N | N | Y | Y |
| 3 | Authentication Endpoint Mapping | Y | N | Y | Y | Y |
| 3 | Bulk Actuator/Admin Scan (MANDATORY) | Y | N | Y | N | Y |
| 5 | Threat Modeling | Y | Y | Y | Y | Y |
| 5 | Nuclei Scan (MANDATORY) | Y | N | Y | N | Y |
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

## Resume (`resume`)

When resuming an interrupted engagement:

1. Read `./ptest-output/state.yaml` to determine active gateway.
2. Read the active phase's `checklist.md` to see which techniques are done vs. pending.
3. Read `./ptest-output/findings-log.md` for context on what's been found.
4. Report status to user and suggest next technique to execute.

### Recovery (if state.yaml is missing or corrupted)

If `state.yaml` cannot be read:
1. Scan `./ptest-output/*/checklist.md` files to determine which phases have been started.
2. Find the last phase with a checklist containing `DONE` or `FAILED` entries.
3. Count findings in `./ptest-output/findings-log.md` to reconstruct `findings_count`.
4. Count files in `./ptest-output/escalations/` to reconstruct `escalations_count`.
5. Rebuild `state.yaml` — mark completed phases as `PASSED`, current phase as `OPEN`, remaining as `LOCKED`.
6. Inform user of reconstructed state and ask for confirmation before proceeding.

---

## Gateway Map

| Gateway | Phase | Skill File | Exit Criteria |
|---------|-------|-----------|---------------|
| 1 | Passive Reconnaissance | `recon-passive.md` | Attack surface mapped, subdomains validated, technologies identified |
| 2 | Active Reconnaissance | `recon-active.md` | All hosts port-scanned, services detected, network topology mapped |
| 3 | Enumeration | `enumeration.md` | Applications enumerated, APIs mapped, parameters discovered |
| 4 | Attack Surface Mapping | `attack-surface.md` | Asset inventory confirmed with user, scope finalized, entry points mapped |

### Phase 4: Dismissal Rules

**Before dismissing ANY subdomain group, verify:**

1. ✅ Tested `/actuator` on at least 5 hosts in the group
2. ✅ Tested `/swagger-ui.html`, `/api-docs` on at least 3 hosts
3. ✅ Tested `/admin`, `/console`, `/login` on at least 3 hosts
4. ✅ Documented what was tested in the dismissal entry
5. ✅ Added caveat if full coverage wasn't achieved

**Dismissal format:**
```markdown
| # | Pattern | Reason | Verified Paths | Caveat |
|---|---------|--------|---------------|--------|
| 1 | *.mock.domain.com | API returns 401, shared IP | /actuator (5 hosts), /admin (3 hosts) | None — all checked |
```

**NEVER write:** `"all behind Basic Auth"` without testing actuator/admin paths specifically. Application auth and framework endpoint auth are independent.

### Phase 4: Attack Surface Prioritization Matrix

When mapping the attack surface, score each asset to determine exploitation priority:

| Factor | Score 3 (High) | Score 2 (Medium) | Score 1 (Low) |
|--------|---------------|-----------------|--------------|
| Auth Status | No auth required | Weak auth (Basic, default creds likely) | Strong auth (JWT, MFA, IAP) |
| Data Sensitivity | PII, credentials, financial data | Business logic, configs | Public/reference data |
| Exposure Level | Internet-facing, no WAF | Internet-facing, behind WAF/CDN | Internal IP only |
| Attack Surface Size | Multiple endpoints, accepts input | Few endpoints, limited input | Single static endpoint |
| Environment | Production | UAT/Staging | Dev/Mock |

**Priority = Sum of scores (max 15)**
- 12-15: Critical target — exploit first
- 8-11: High target — exploit if time permits
- 5-7: Medium target — quick checks only
- 3-4: Low target — skip unless nothing else works

This prevents wasting time on hardened low-value targets while missing easy wins on high-value ones.
| 5 | Threat Modeling & Vuln Assessment | `vuln-assessment.md` | Attack trees documented, vuln scans complete, vectors prioritized |
| 6 | Exploitation | `exploit.md` | All mandatory techniques executed, credential inventory validated, top 5 vectors attempted, attack chains documented (see `references/phase6-exploitation-framework.md`) |
| 7 | Post-Exploitation | `post-exploit.md` | Access type classified, appropriate playbook completed, data scope documented, attack path diagram created, credentials added to inventory (see `references/phase7-post-exploitation-framework.md`) |
| 8 | Reporting | `report.md` | Final report delivered, pre-delivery checklist passed (see `references/phase8-reporting-process.md`) |

---

## Effort Allocation

**Time-box enforcement:** See `references/time-box-enforcement.md` for:
- Budget calculation and tracking in state.yaml
- Alert levels (on-track / warning / over-budget / critical)
- Over-budget decision tree with borrowing rules
- Per-technique time caps and move-on heuristics
- End-of-engagement triage procedure
- Scope adjustment triggers

For time-boxed engagements, use these guidelines to avoid over-investing in early phases:

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

**Move-on heuristic:** If a technique yields no new results after 15–20 minutes of active work, mark it `DONE` (no findings) or `FAILED (diminishing returns)` and proceed to the next technique.

---

## Mandatory Tools

Each phase has mandatory tools that MUST be executed (unless unavailable — document why if skipped).

| Phase | Mandatory | Recommended |
|-------|-----------|-------------|
| 1 — Passive Recon | dig, curl, whois | subfinder, amass, theHarvester |
| 2 — Active Recon | nmap | masscan |
| 3 — Enumeration | gobuster/feroxbuster, ffuf | arjun, linkfinder, wpscan |
| 4 — Attack Surface | (planning phase — no tools) | — |
| 5 — Vuln Assessment | nuclei | nikto, testssl.sh, sslscan |
| 6 — Exploitation | (depends on vector) | sqlmap, burp, metasploit |
| 7 — Post-Exploitation | (depends on access) | linpeas, winpeas, crackmapexec |
| 8 — Reporting | (writing phase — no tools) | — |

If a mandatory tool is unavailable, document the gap and use the best available alternative. Never silently skip a mandatory tool.

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
- **Confirmed** — you have direct evidence proving the issue exists right now (HTTP response, command output, screenshot). Only confirmed findings go into the final report.
- **Unverified** — you suspect the issue exists based on indirect evidence (DNS record, CT log, version number) but have not proven it. Unverified items go into a "Potential Issues" appendix and are passed to the next phase for validation. They do NOT count toward `findings_count` in state.yaml.

Individual findings can be formatted for Jira export using `/parse-finding`.

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
   - `FAILED (reason)` — technique attempted but did not succeed (e.g., WAF blocked, tool crashed, target unresponsive)
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

The escalation file references the finding ID for traceability.

1. Document finding fully using the Finding Template (assigns a finding ID).
2. Classify severity (CVSS 3.1).
3. Write to `./ptest-output/escalations/escalation-{escalations_count}.md`, referencing `FINDING-{ID}`.
4. Alert user for immediate client communication.
5. Current gateway pauses until escalation is acknowledged.
6. Increment `escalations_count` in `state.yaml`.

See `escalate-finding.md` for full procedure.

---

## Cleanup (`cleanup`)

Post-engagement housekeeping:

1. **Archive** — compress `./ptest-output/` to `./ptest-output-{engagement-name}-{date}.tar.gz`.
2. **Sanitize** — remove credentials *you used* during testing (your API keys, auth tokens, test account passwords). Do NOT remove credentials *you found* as findings — those are evidence and must remain in the report.
3. **Verify** — confirm report is complete and all findings are documented.
4. **Summary** — print engagement stats (findings by severity, phases completed, duration).

---

## Report Structure Template (`report`)

**Full reporting process:** See `references/phase8-reporting-process.md` for:
- Writing process (6 steps with time allocation)
- Audience-aware writing (CISO vs engineer vs executive vs compliance)
- Remediation prioritization matrix and tier structure
- Executive summary writing guide with anti-patterns
- Pre-delivery checklist (accuracy, completeness, sensitivity, formatting)
- Client debrief meeting structure
- Handling client pushback on findings
- Report quality indicators

**Multi-operator coordination:** See `references/multi-operator-coordination.md` for:
- Role definitions (Lead / Operator / Reviewer)
- Work splitting strategies (phase-based, target-based, technique-based, hybrid)
- Shared state management and directory structure
- Finding ID coordination (pre-allocated ranges)
- Credential inventory coordination and handoff protocol
- Communication protocol and sync points
- Conflict resolution (duplicates, overlap, severity disagreements)
- Report assembly process for multi-person teams

The final report should follow this structure. Adapt sections based on engagement scope and findings.

```markdown
# Penetration Test Report — {Client Name} ({target domain})

## 1. Executive Summary
- Severity breakdown table (Critical/High/Medium/Low/Info)
- Top critical risk (1-2 sentences)
- Security posture: Strengths + Weaknesses
- Immediate actions required (top 3)

## 2. Scope & Methodology
- Scope table (target, type, exclusions, restrictions, authorization)
- 8-phase methodology list with ✅ status
- Tools used table

## 3. Attack Surface Overview
- Infrastructure stats (subdomains, live hosts, IPs, cloud provider)
- Environment exposure matrix (which envs are public vs should be internal)

## 4. Findings Summary
- Table: ID | Title | Severity | CVSS | Asset

## 5. Detailed Findings
- Each finding using the Finding Template (see above)
- Ordered by severity (Critical → Low)

## 6. Attack Narrative
- Story-form description of the engagement progression
- Key decision points and breakthroughs

## 7. Remediation Roadmap
- Immediate (1 week) — critical/high findings
- Short-term (1 month) — medium findings
- Medium-term (3 months) — architectural improvements

## 8. Infrastructure Architecture (if discovered)
- K8s/cloud topology
- Service mesh details
- Microservice inventory
- Network segmentation
- Supporting infrastructure

## 9. Advanced Testing Results (if performed)
- SSRF testing summary
- Other specialized testing (e.g., API fuzzing, auth bypass campaigns)

## 10. Risk Matrix & Business Impact
- Industry-specific context (financial, healthcare, etc.)
- Regulatory implications
- Worst-case attack chain scenario

## 11. Appendices
- Links to supporting evidence files

## 12. Conclusion
- Split posture assessment
- Overall risk rating
- Final recommendation
```

### CVSS Scoring Guidance for Financial Services

For targets in financial services (banking, multi-finance, insurance), consider upgrading severity when:

| Factor | Adjustment |
|--------|-----------|
| Exposed data enables fraud (credit scoring rules, approval thresholds) | +0.5–1.0 to base score |
| Regulatory violation (OJK, PBI, PCI-DSS, SOX) | Upgrade to next severity tier |
| Scope change (compromised service can access other services) | Use S:C (Changed) in CVSS vector |
| Data volume > 1000 records of business logic | Consider Critical even without PII |

**Key principle:** Business logic data (credit rules, approval hierarchies, risk matrices) can be MORE damaging than PII for financial institutions — it enables systematic fraud rather than individual identity theft.

### Regulatory Context (add to report when applicable)

| Country | Regulator | Relevant Rules |
|---------|-----------|---------------|
| Indonesia | OJK (Otoritas Jasa Keuangan) | POJK 11/2022 on IT risk management |
| Indonesia | Bank Indonesia | PBI on payment system security |
| Global | PCI-DSS | If payment card data in scope |
| US | SOX, GLBA | If US-listed or US operations |
| EU | GDPR, DORA | If EU customers or operations |

---

## Phase 6: Exploitation — Structured Framework

**Full framework:** See `references/phase6-exploitation-framework.md` for:
- Mandatory checklist with scope-aware technique matrix (12 techniques)
- Decision tree for exploitation flow (what to do after each technique)
- Time budgets per technique
- Exit criteria for gateway transition
- RE-ENUM trigger (re-validation loops when new access opens new surface)

**Credential inventory:** See `references/credential-inventory-structure.md` for:
- Centralized tracking of all discovered credentials
- Cross-environment validation matrix
- Chain tracking and documentation

**Attack chains:** See `references/attack-chain-framework.md` for:
- Identifying and documenting compound attack paths
- Chain severity scoring (beyond individual CVSS)
- Presentation format for reports
- Common chain patterns in financial services

**Re-validation loops:** See `references/re-validation-loops.md` for:
- When to trigger mini-enumeration during exploitation
- 15-minute time-boxed procedure
- Integration with Phase 6 checklist and attack chains

### Credential Chaining

When credentials are discovered (heapdump, JS files, CTI, Snyk), systematically chain them across environments and services:

```
Discovery → Validation → Escalation → Lateral Movement
```

| Step | Action | Example |
|------|--------|---------|
| 1. Discover | Extract credential from source | Heapdump → `github-actions-sa` token |
| 2. Validate | Confirm credential works in source env | Token valid on SIT Keycloak |
| 3. Escalate | Check if same credential works in higher env | Test token against prod Keycloak |
| 4. Pivot | Use credential to access other services | SA token → enumerate all microservices |
| 5. Chain | Use new access to find more credentials | Microservice config → DB password → more data |

### Cross-Environment Pivoting

Production environments often share credentials, service accounts, or trust relationships with lower environments. Test these pivot paths:

| Source Environment | Pivot Vector | Target |
|-------------------|-------------|--------|
| Mock/Dev heapdump | Service account tokens | SIT/UAT Keycloak |
| SIT Keycloak | Same SA credentials | Prod Keycloak |
| GitHub Actions secrets | CI/CD service accounts | All environments |
| Snyk token | Org-wide vulnerability data | All repos/projects |
| JS bundles (any env) | Hardcoded API keys | Prod APIs |

**Key principle:** Lower environments are often less protected but share credentials with production. A heapdump from mock can yield prod access.

### Token Exchange & Authentication Bypass

When a Keycloak token endpoint is found:

1. **Identify public clients** — try `admin-cli`, `account` (Keycloak defaults), app-specific names
2. **Distinguish client types:**
   - "Public client not allowed to retrieve service account" = valid public client → use password grant
   - "Invalid client or Invalid client credentials" = either doesn't exist OR is confidential (needs secret)
3. **Password grant with public client:**
   ```bash
   curl -X POST "$KEYCLOAK_URL/protocol/openid-connect/token" \
     -d "grant_type=password&client_id=admin-cli&username=$USER&password=$PASS"
   ```
4. **Client credentials with confidential client:**
   ```bash
   curl -X POST "$KEYCLOAK_URL/protocol/openid-connect/token" \
     -d "grant_type=client_credentials&client_id=$CLIENT&client_secret=$SECRET"
   ```
5. **Token introspection** (if accessible):
   ```bash
   curl -X POST "$KEYCLOAK_URL/protocol/openid-connect/token/introspect" \
     -d "token=$TOKEN&client_id=admin-cli"
   ```

### WAF/Ingress Bypass Techniques

When WAF blocks sensitive paths (actuator, swagger, admin), try these in order:

| Technique | Example | Success Indicator |
|-----------|---------|-------------------|
| Case variation | `/Actuator/Health`, `/ACTUATOR/HEALTH` | 403→401 or 403→200 |
| Semicolon path param | `/actuator;.js/health` | 403→200 |
| Tomcat path normalization | `/service/..;/actuator/health` | 403→302→target |
| URL encoding | `/%61ctuator/health` | 403→200 |
| Double URL encoding | `/%2561ctuator/health` | 403→200 |
| HTTP method override | `X-HTTP-Method-Override: GET` on POST | Different response |
| Host header injection | `Host: localhost` | Bypass IP-based rules |
| X-Forwarded-For | `X-Forwarded-For: 127.0.0.1` | Bypass IP allowlist |
| Path addition | `/actuator/health.json`, `/actuator/health/` | Bypass exact-match rules |
| HTTP/1.0 downgrade | `--http1.0` flag | Bypass HTTP/2-only rules |

**Document bypass as a finding** even if you can't get past the application auth layer behind it. WAF bypass + application auth = defense-in-depth failure.

### Exploiting Exposed Keycloak via Gateway

When Keycloak is proxied through an API gateway (common in GKE/Istio):

1. **Discover the path:** Try `/keycloak/`, `/auth/`, `/sso/`, `/oauth/` on the gateway
2. **Enumerate realms:** `/keycloak/realms/{name}/.well-known/openid-configuration`
3. **Find public clients:** Test `admin-cli`, `account`, app-specific names with client_credentials grant
4. **Username enumeration:** Different error messages reveal valid usernames
5. **Password spray:** Use discovered usernames with common/leaked passwords (REQUIRES explicit authorization)
6. **Token analysis:** Decode obtained JWTs to understand roles, permissions, audience

### Production Microservice Exploitation (with valid JWT)

Once a valid JWT is obtained:

```bash
# Test each service with the token
for svc in bpm agent agreement branch customer edoc; do
  curl -sk -H "Authorization: Bearer $JWT" "https://target/$svc/v1/" -w "%{http_code}\n"
done

# Try actuator with auth (may be allowed for authenticated users)
curl -sk -H "Authorization: Bearer $JWT" "https://target/$svc/actuator/"

# Enumerate API endpoints via swagger
curl -sk -H "Authorization: Bearer $JWT" "https://target/$svc/v3/api-docs"
```

### Snyk Data as Attack Intelligence

When Snyk enumeration data is available:

1. **Extract exploitable CVEs** — filter for Critical/High with known exploits
2. **Map CVEs to services** — match package names to discovered microservices
3. **Prioritize by reachability** — focus on CVEs in internet-facing services
4. **Check for open redirect** — common in Spring Boot, enables phishing/token theft
5. **Check for deserialization** — common in Java services, enables RCE
6. **Check for SSRF** — common in services that make outbound calls

```bash
# Extract high-severity CVEs with exploits from Snyk data
cat snyk-enum-data.json | jq '[.[] | select(.severity == "critical" or .severity == "high") | {id: .id, title: .title, package: .packageName, version: .version, exploit: .exploit}]'
```

## Phase 7: Post-Exploitation — Structured Framework

**Full framework:** See `references/phase7-post-exploitation-framework.md` for:
- Access classification (Shell / API / Data / None / Mixed)
- Three distinct playbooks based on access type
- Mandatory checklist with scope-aware technique matrix (10 techniques)
- Exit criteria for gateway transition
- Time management and priority allocation

### No Shell Scenarios

When exploitation achieves data access but NOT remote code execution (common in API-focused engagements), Phase 7 should focus on:

### What to Document

1. **Data access scope** — what was actually exfiltrated, volume, sensitivity classification
2. **Lateral movement paths** — theoretical paths if access were escalated
3. **Credential sources** — where credentials WOULD be found (actuator/env, K8s secrets, .env files)
4. **Attack path diagram** — visual showing confirmed vs theoretical paths
5. **Impact amplification** — how combining findings creates worse outcomes than individual findings

### Phase 7 Checklist (No Shell)

| Technique | Status |
|-----------|--------|
| Document all data accessed (with record counts) | PENDING |
| Classify data sensitivity (PII, business logic, credentials) | PENDING |
| Data classification analysis (see `references/data-classification-framework.md`) | PENDING |
| Map theoretical lateral movement paths | PENDING |
| Identify credential sources (if access escalated) | PENDING |
| Create attack path diagram (confirmed + theoretical) | PENDING |
| Assess combined finding impact (attack chains) | PENDING |
| Document what was NOT accessed (scope of damage) | PENDING |
| Tag all findings with environment (prod/nonprod/experiment) | PENDING |

### Key Principle

Even without a shell, document the BUSINESS IMPACT of what was achieved. A 900KB data dump of credit scoring rules may be more damaging than a low-privilege shell on a dev server.

---

## Istio/Service Mesh Assessment (External)

When Istio is detected (via Kiali subdomains, `x-envoy-upstream-service-time` headers), document:

### Confirmation Indicators

| Indicator | Source |
|-----------|--------|
| `x-envoy-upstream-service-time` header | Any HTTP response |
| `kiali*.domain` subdomains | DNS enumeration |
| `kiali-private*.domain` (internal IP) | DNS — confirms internal-only dashboard |
| Consistent CORS headers across services | Mesh-level CORS policy |
| `x-datadog-*` / `Traceparent` in allowed headers | Distributed tracing integration |

### What You CAN Assess Externally

- Envoy sidecar presence (confirmed by header)
- Whether auth is mesh-level vs app-level (if one service lacks auth, it's app-level)
- Tracing/APM stack (from CORS allowed headers)
- Whether Kiali is externally accessible (try ports 20001, 8080, 8443, 3000)

### What You CANNOT Assess Externally

- mTLS enforcement between pods
- AuthorizationPolicy coverage
- VirtualService/DestinationRule configs
- Service-to-service communication graph
- Namespace isolation

### Security Implications to Report

If auth is app-level (not mesh-level), document that:
- A single misconfigured service = full data exposure (as demonstrated)
- Istio AuthorizationPolicy SHOULD enforce JWT at namespace level
- Recommendation: `RequestAuthentication` + `AuthorizationPolicy` requiring valid JWT for all inbound traffic

---

## Guardrails

- **Hardened Target Fast-Exit** — if the first 3 vectors on a target all fail cleanly (proper error handling, no info leak, auth enforced, no default creds), mark it as "hardened" in the checklist and move on. Maximum 15-20 minutes per hardened target. Document what was tested and why it's considered hardened.
- **Environment Tagging** — every finding MUST be tagged with the environment: `prod`, `nonprod`, `experiment`, or `all`. Findings on nonprod/experiment instances should note "may not apply to production" unless the same configuration is confirmed on prod. This prevents over-reporting experiment-only issues as production risks.
- **False Positive Verification** — before logging a finding, verify it's not a false positive. Check for SPA catch-alls (same bytes for any path), CORS crashes masking endpoints (all 500s with same error), and 302-to-login (auth required, not bypassed). See `references/false-positive-detection.md`.
- **Strict Sequence** — never skip a phase. No exploitation before enumeration and vuln assessment are complete.
- **Scope Enforcement** — never test targets outside defined scope. Re-read `scope.md` before each technique.
- **Evidence Required** — every finding must have reproducible proof.
- **Verified Findings Only** — a finding must be backed by direct evidence of exploitability or exposure. DNS resolution or CT log presence alone does NOT constitute a finding. Every finding must include proof that the issue is currently exploitable or observable (e.g., HTTP response showing an unauthenticated panel, not just a DNS record pointing to it). Unverified potential issues belong in a "Potential Issues" list for the next phase to validate — not in the findings log.
- **Mandatory Tool Execution** — mandatory tools listed per phase must be run. If unavailable, document the gap explicitly. Never substitute manual probing for an available automated scanner.
- **Human Sign-off** — always request user confirmation before passing a gateway.
- **Authorization First** — refuse to begin without confirmed authorization.
- **No Deployed Persistence** — document persistence techniques but do not deploy backdoors without explicit authorization.
- **CTI-Sourced Credentials** — credentials found via Cyber Threat Intelligence (breach databases, dark web) require EXPLICIT authorization to test against production systems. The finding is provable without authentication: (1) credential exists in breach DB, (2) auth endpoint is internet-accessible, (3) no MFA enforced, (4) no credential rotation caught it. Document the risk without logging in. If the client explicitly authorizes credential stuffing against prod, require real-time observation by the client's security team. Never test CTI credentials without confirming scope covers this technique — it may violate local law (e.g., UU ITE in Indonesia) even with a general pentest authorization.
- **Scope Type Awareness** — skip techniques that don't apply to the engagement's scope type.

---

## Execution Pitfalls (Hermes Agent)

- **Parallel HTTP probing race conditions**: When probing 100+ subdomains, do NOT use `>>` append in parallel bash jobs — causes empty output due to file descriptor races. Write each result to an individual temp file (`$TMPDIR/live_$i.txt`), then `cat $TMPDIR/live_*.txt > live-subs.txt` after `wait`. See `scripts/probe-parallel.sh`.
- **crt.sh timeouts**: Certificate Transparency lookups via crt.sh frequently timeout on large domains. Use `subfinder` as primary subdomain source instead.
- **Hermes terminal tool and backgrounding**: The terminal tool rejects commands containing `&` for backgrounding. Write a bash script to disk first, then execute it with `bash script.sh`. The script itself can use `&` and `wait` freely.
- **xargs with shell expansion**: `xargs -I {} sh -c '...'` works for simple commands but fails silently when the inner command uses grep on the same file being iterated. Prefer the temp-file-per-result pattern.
- **nmap on cloud targets**: GCP/AWS hosts behind load balancers only expose 80/443. Full port scans timeout — use `--top-ports 100 -T4` first, then targeted scans on non-cloud IPs. Service detection (`-sV`) on GCP shows "tcpwrapped" for port 80 due to GCLB.
- **Large subdomain lists (200+)**: Sequential curl probing takes 15+ minutes. Always use the parallel bash script approach with concurrency limit of 25-30.
- **Microservice architecture mapping**: When targeting K8s/GKE infrastructure, DNS records + leaked redirects + API path structure can reveal full internal architecture without authenticated access. See `references/microservice-architecture-mapping.md` for the technique.
- **SSRF / Outbound request forcing**: When attempting to force server-side callbacks from K8s infrastructure, use webhook.site as a disposable listener. Test parameter injection, Keycloak OIDC vectors, Envoy header manipulation, and Spring Cloud Gateway route injection. Spring Boot CORS bugs ("Duplicate key Vary") block all POST/PUT before processing — this prevents SSRF on write endpoints but is itself a finding. See `references/ssrf-outbound-forcing.md` for the full methodology.
- **Path traversal confirmation vs exploitation**: When `..;/` bypasses ingress routing (302 → target), always follow the redirect with `-L` to check the final response. A 403 at the final target means there's a secondary ACL — document the traversal as a finding (ingress bypass) even if you can't reach the data. Try double encoding (`%2e%2e;/`), alternate semicolons (`..%3b/`), and different base paths (`/service1/..;/service2/`).
- **Distinguishing real 500s from CORS crashes**: If ALL paths under a prefix return 500 with the same error message (e.g., "Duplicate key Vary"), the error fires before routing. You CANNOT use response codes to enumerate real endpoints. Test with a known-fake path (`/prefix/v1/thispathdoesnotexist12345`) — if it also returns 500, endpoint enumeration via status codes is impossible under that prefix.
- **Webhook.site API**: Create token with `POST /token`, check requests with `GET /token/{uuid}/requests?sorting=newest`. Free tier has rate limits (~500 requests). For high-volume testing, self-host with ngrok.
- **Pattern-based subdomain brute-force**: When you discover a naming pattern (e.g., `bravo-{service}.mock.bravo.bfi.co.id`), immediately build a targeted wordlist and brute-force variations. Sources for the wordlist: (1) service names from API paths (`/v1/surveyor-*` → `bravo-surveyor`), (2) health endpoint components, (3) common microservice names (auth, gateway, notification, payment, billing, collateral, insurance, calculation, scoring), (4) K8s service names from leaked redirects. Passive recon (subfinder/crt.sh) only finds publicly-indexed subdomains — pattern brute-force finds internal services that were never issued public certificates. Use `ffuf` or a custom script with 30 threads and 4s timeout against the discovered pattern.
- **JavaScript secret scanning is MANDATORY**: In Phase 3, collect ALL JS files from ALL live hosts and scan for API keys, tokens, secrets, passwords, and JWTs. This is a 5-minute bulk scan that finds what hours of manual testing misses. Use regex patterns for Google API keys (`AIza...`), AWS keys (`AKIA...`), JWTs (`eyJ...`), and hardcoded secret/password/token assignments. See `references/javascript-secret-scanning.md` for patterns and methodology. Never rely on manual JS review of priority targets only — secrets leak from dev/SIT/UAT environments that share the same JS bundles as production.
- **Financial services targets**: Credit scoring rules, approval hierarchies, and risk matrices are HIGH-value findings even without PII. They enable systematic fraud (gaming automated approvals) which is harder to detect than individual identity theft. Always upgrade severity for business logic exposure on financial targets.
- **Keycloak assessment checklist**: (1) Find realms via `/.well-known/openid-configuration` on common realm names (master, app-name, company-name), (2) Test client registration (usually blocked by trusted hosts), (3) Test token exchange (usually disabled), (4) Check admin console access, (5) Try default creds (admin/admin), (6) Check if backchannel_logout_uri triggers outbound calls. Keycloak is often well-hardened in production — don't spend more than 15 minutes if initial vectors fail. (7) If direct Keycloak is unreachable, check if it's proxied through the API gateway — see `references/keycloak-gateway-exploitation.md`.
- **Phishing simulation platforms (Lucy, GoPhish, KnowBe4)**: `Server: Lucy` header or similar identifies security awareness training platforms. These are often on separate infrastructure (Hetzner, DigitalOcean) with weaker security than the main app. They frequently have `Access-Control-Allow-Origin: *` and PHP sessions. Worth testing — they're admin panels that manage employee email addresses and campaign data.
- **Monitoring tools without IAP**: Dynatrace, Grafana, and similar monitoring dashboards are often accidentally left outside IAP/VPN protection while data tools are properly gated. Always check monitoring subdomains — they may expose login pages where credential stuffing or default creds work.
- **Never dismiss mock/test services without checking actuator**: Mock services often route to real backends (SIT/UAT) and may have actuator endpoints exposed without auth even when API endpoints return 401. Always test `/actuator`, `/actuator/health`, `/actuator/prometheus` on every discovered host — even ones dismissed as "test/mock." A mock subdomain with actuator exposed can reveal the entire backend stack (DB versions, message queues, 100+ API endpoint paths, internal K8s hostnames) that applies to production.
- **Never dismiss wildcard subdomains based on sampling**: Testing a few endpoints on `*.mock.domain.com` and seeing 401 does NOT mean all paths are protected. Actuator, Camunda, Swagger, and other framework endpoints often bypass application-level auth. When dismissing a wildcard group in Phase 4, you MUST test at minimum: `/actuator`, `/actuator/health`, `/swagger-ui.html`, `/api-docs`, `/console`, `/admin` on at least 5 representative hosts. If ANY returns 200, scan ALL hosts in that group for the same path.
- **Actuator scan on ALL live hosts**: During Phase 3 (Enumeration) or Phase 5 (Vuln Assessment), run a bulk actuator check against ALL live subdomains, not just priority targets. Use a simple loop: `for sub in $(cat live-subs.txt); do curl -s -o /dev/null -w "%{http_code}" "https://${sub}/actuator"; done`. This takes minutes and catches systemic misconfigurations that per-target testing misses. A single 200 on `/actuator` can reveal more than hours of manual testing.
- **Phase 4 dismissal anti-pattern**: Never dismiss an entire subdomain group (e.g., `*.mock.*`, `*.dev.*`, `*.sit.*`) as a single line item. Each service behind a wildcard may have different security configurations. The correct approach is: dismiss individual hosts that are confirmed locked down, not entire patterns. If you must dismiss a pattern, document exactly what was tested and add a caveat: "Actuator/admin paths not verified on all hosts."
- **Heapdump extraction requires proper tooling**: `strings` alone is INSUFFICIENT for Java HPROF heapdumps. Resolved Spring config values (passwords, secrets, tokens) are stored in Java object graphs (char[] inside String inside HashMap$Node), not as contiguous ASCII. Use Eclipse MAT, jhat, or heapdump_tool for thorough extraction. Python binary regex search is a middle ground. Even if you can't extract usable credentials, a downloadable heapdump is always Critical — document it and note that deeper analysis would yield secrets. See `references/heapdump-secret-extraction.md`.
- **CORS header intelligence**: The `access-control-allow-headers` response reveals internal header names used by the application. Look for: `x-auth-app-id` (custom auth), `X-Idempotency-Key` (payment safety), `x-datadog-*` (APM), `Traceparent`/`tracestate` (OpenTelemetry), `Context-Trace` (custom tracing). Document these in the report — they reveal auth schemes and observability stack without any exploitation.
- **Camunda BPM on Spring Boot**: When actuator reveals Camunda (jobExecutor in /health), check: (1) `/camunda/app/welcome/default/` for web UI, (2) `/camunda/api/engine/engine` for unauthenticated engine list, (3) `/camunda/api/engine/engine/default/user` with demo:demo and admin:admin, (4) `/camunda/api/engine/engine/default/process-definition` for business process exposure. The engine list endpoint often works without auth even when data endpoints don't. See `references/camunda-bpm-assessment.md`.
- **Mock/SIT services routing to real backends**: Subdomains like `*.mock.bravo.bfi.co.id` may route to actual SIT environment pods (confirmed by `x-envoy-decorator-operation` header showing `bravo-bpm.sit.svc.cluster.local`). Mock services often have weaker security controls than prod but connect to real databases. Always check response headers for internal routing info.
- **Keycloak proxied through API gateway**: When direct Keycloak URLs (keycloak.domain.com, auth.domain.com) resolve to nothing, check if it's proxied through the microservices gateway at paths like `/keycloak/realms/{realm}/protocol/openid-connect/token`. A 405 on GET confirms it — switch to POST. This is common in GKE/Istio setups where Keycloak is an internal service exposed only through the ingress. Once found, enumerate public clients (`admin-cli`, `account` are Keycloak defaults) and use password grant for credential testing.
- **Username enumeration via Keycloak error messages**: When testing password grant against Keycloak, compare error messages. "Invalid user credentials" = user exists but password wrong. "Account not found" = user doesn't exist. This allows confirming valid usernames before attempting credential stuffing. Test with common username formats: `firstname.lastname`, employee IDs, email addresses. See `references/web-bypass-techniques.md` for full enumeration methodology.
- **WAF case-sensitivity bypass**: When WAF/Istio returns 403 on paths like `/actuator/health`, try case variations (`/Actuator/Health`, `/ACTUATOR/HEALTH`). Many WAF regex rules match lowercase only while Tomcat/Spring route case-insensitively. A 403→401 transition proves the WAF is bypassable and the endpoint is only protected by application-level auth. Document as a defense-in-depth failure even if you can't get past the 401.
- **Snyk token enumeration**: If a Snyk API token is found (heapdump, JS files, GitHub Actions secrets), use it to enumerate all organization projects and their known vulnerabilities via `GET https://api.snyk.io/rest/orgs/{org_id}/projects`. This gives attackers a complete roadmap of unpatched CVEs — they know exactly which vulnerabilities exist before testing. The Snyk data reveals repo names, tech stacks, dependency versions, and severity ratings. Document as a Critical finding (information disclosure enabling targeted exploitation). See `references/snyk-token-enumeration.md` for full methodology.
