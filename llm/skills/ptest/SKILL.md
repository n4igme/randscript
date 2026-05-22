---
name: ptest
description: "Structured penetration testing framework with gated phases. Guides methodical progression from recon through exploitation to reporting."
version: 4.1.0
author: n4igme
license: MIT
argument-hint: "<command: start|preflight|status|resume|next|escalate|cleanup|recon-passive|recon-active|enumerate|attack-surface|vuln-assess|exploit|post-exploit|report>"
metadata:
  hermes:
    tags: [pentest, penetration-testing, security, recon, exploitation, post-exploitation, red-teaming, offensive-security]
    related_skills: [godmode, parse-finding, mtest, scode]
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

> **Full reference:** See `references/operational-pitfalls.md` for 50+ battle-tested pitfalls covering tool performance, cloud infrastructure quirks, and Hermes Agent execution patterns. Load when encountering unexpected behavior.

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
| 2 | Active DNS Expansion — DNS-Level Brute-Force dnsx/puredns (MANDATORY) | Y | Y | Y | N | Y |
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
| 1 | Passive Reconnaissance | `recon-passive.md` | Attack surface mapped, subdomains validated, technologies identified. OSINT completeness verified per `references/osint-completeness-checklist.md`. **Env-prefix quick-win check completed** (see below). |
| 2 | Active Reconnaissance | `recon-active.md` | Subdomain list expanded via active DNS techniques (including env-prefix mutation on ALL discovered subdomains), all hosts port-scanned, services detected, network topology mapped |
| 3 | Enumeration | `enumeration.md` | Applications enumerated, APIs mapped, parameters discovered, Prometheus metrics mined for hidden services |
| 4 | Attack Surface Mapping | `attack-surface.md` | Asset inventory confirmed with user, scope finalized, entry points mapped |

### Phase 4: Dismissal Rules

### Env-Prefix Quick-Win Check (END of Phase 1, MANDATORY)

Before transitioning to Phase 2, scan ALL discovered subdomains for environment indicators and immediately generate prod equivalents. This is a 5-minute check that catches forgotten production assets.

**Process:**
1. Grep your merged subdomain list for env patterns: `grep -iE '\.(dev|staging|stg|sit|uat|mock|sandbox|test|qa|preprod|nonprod|demo|lab)\.' subdomains-merged.txt`
2. For EACH match, generate the bare-domain equivalent (strip the env segment)
3. Resolve the bare-domain equivalents with `dig +short`
4. If any resolve — add to master list, flag as **HIGH PRIORITY** targets (forgotten prod assets)

**Example (BFI, May 2026):**
```
Found in passive recon:  e-pmo2.dev.bfi.co.id → 172.22.32.94
Quick-win derivation:    e-pmo2.bfi.co.id     → 34.111.225.150 ← LIVE PROD!
Result:                  Forgotten PHP app with SQLi → 21 databases compromised
```

**Why at end of Phase 1 (not Phase 2):** Phase 2 does full permutation brute-force which takes time. This quick-win check takes seconds and catches the most common blind spot — a dev subdomain in CT logs whose production equivalent has no certificate (uses wildcard) and was never publicly indexed. Don't wait for Phase 2 to find these.

**Exit gate addition:** Document in Phase 1 output: "Env-prefix quick-win: X subdomains with env indicators found, Y bare-domain equivalents tested, Z new live hosts discovered."

---

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
| 5 | Threat Modeling & Vuln Assessment | `vuln-assessment.md` | Attack trees documented, vuln scans complete, CORS reflection tested on all auth endpoints, vectors prioritized |
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

**Continuous/internal engagements:** When the operator is a full-time internal pentester (no time-box), set `time_budget.mode: "continuous"` in state.yaml. Track time spent for reporting purposes only — no budget enforcement. The effort allocation percentages still guide sequencing priority but don't trigger over-budget alerts.

**Move-on heuristic:** If a technique yields no new results after 15–20 minutes of active work, mark it `DONE` (no findings) or `FAILED (diminishing returns)` and proceed to the next technique.

**Continuous engagement override:** For internal/continuous engagements (`time_budget.mode: "continuous"`), the 15-20 min heuristic is a GUIDELINE, not a hard rule. Vectors that show partial progress (e.g., JWT algorithm identified but secret not yet cracked, heapdump downloaded but not fully analyzed with MAT) deserve extended time. Use judgment: if the technique is producing incremental intelligence (even without a confirmed finding), continue. The heuristic exists to prevent spinning on dead-end vectors, not to cut short promising leads.

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

### Reassessment/Redo Report Adaptations

When the engagement is a reassessment (redo) of previously reported findings, adapt the report structure:

**Additional/modified sections:**

```markdown
## 0. Fix Verification Summary (INSERT BEFORE Executive Summary)

### Remediation Effectiveness

| Metric | Value |
|--------|-------|
| Round 1 findings | {n} |
| Fully fixed | {n} ({%}) |
| Partially fixed | {n} ({%}) |
| Unfixed | {n} ({%}) |
| **Remediation effectiveness** | **{%}** |
| Time since Round 1 report | {days/weeks} |

### Fix Verification Matrix

| R1 ID | Title | Severity | Gateway/Path Tested | Status | Notes |
|-------|-------|----------|--------------------:|--------|-------|
| F-1 | {title} | Critical | microservices.prod.bfi.co.id | ✅ Fixed | Returns 401 |
| F-1 | {title} | Critical | microservices.prod.bravo.bfi.co.id | ❌ Unfixed | Still returns 200 |

### Key Observations

- {Pattern observation, e.g., "Fixes applied to 1 of 4 gateways only"}
- {Root cause, e.g., "Configuration drift between gateway variants"}
- {Positive note if any, e.g., "JWT validation logic properly implemented on primary gateway"}
```

**Modified Executive Summary:**
```markdown
## 1. Executive Summary

### Remediation Status
- **{n}/{total} findings fixed** from Round 1 ({%} remediation rate)
- **{n} new findings** discovered in Round 2
- **{total} active vulnerabilities** across the estate

### Key Findings (combine old + new)

| Category | Count |
|----------|-------|
| Unfixed Critical (Round 1) | {n} |
| Unfixed High (Round 1) | {n} |
| New Critical (Round 2) | {n} |
| New High (Round 2) | {n} |
| **Total Active** | **{n}** |
```

**Modified Findings Summary (Section 4):**
```markdown
## 4. Findings Summary

### Unfixed Round 1 Findings

| R1 ID | Title | Severity | Status | Notes |
|-------|-------|----------|--------|-------|
| F-1 | {title} | Critical | ❌ Still vulnerable | {brief note} |

**Summary: {n}/{total} fixed. {n} partially fixed. {n} still vulnerable.**

### New Findings (Round 2)

| ID | Title | Severity | CVSS | Asset |
|----|-------|----------|------|-------|
| F-1 | {title} | Critical | 9.1 | {asset} |
```

**Additional Appendix:**
```markdown
## Appendix: Fix Verification Details

For each Round 1 finding, document:
1. Original PoC replayed verbatim
2. All gateways/paths tested (not just the primary)
3. Adjacent endpoints checked
4. Current response vs Round 1 response

| R1 Finding | Test Performed | Expected (if fixed) | Actual | Verdict |
|-----------|---------------|---------------------|--------|---------|
| F-1 GET | curl -sk $URL/master/v1/general | 401 | 200 (4199 records) | UNFIXED |
| F-1 POST | curl -sk -X POST $URL/master/v1/general -d '...' | 401 | 200 (created ID 5668) | UNFIXED |
```

**Framing guidance for reassessments:**
- Lead with remediation effectiveness — this is what stakeholders care about most
- Frame unfixed findings as "remediation failure" not just "vulnerability exists"
- Highlight patterns (e.g., "all fixes applied to one gateway only" = systemic deployment issue)
- Note positive progress even if incomplete (e.g., "primary gateway secured, parallel paths missed")
- Include a "Remediation Process Recommendations" section addressing WHY fixes failed, not just WHAT to fix
- Calculate risk delta: is the organization MORE or LESS secure than Round 1? (can be worse if new findings outweigh fixes)

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

### HTTP Method Testing on Unauthenticated Endpoints (MANDATORY)

**When you find an unauthenticated GET endpoint, ALWAYS test other HTTP methods.** This is the single highest-ROI exploitation technique for API-focused engagements.

```bash
# For every unauthenticated endpoint discovered in Phase 3/5:
for method in POST PUT PATCH DELETE OPTIONS; do
  curl -sk -X $method -w " [%{http_code}]" "$ENDPOINT" \
    -H "Content-Type: application/json" -d '{"name":"pentest-probe","code":"PT"}'
done
```

**Interpretation:**
- 200/201 on POST → **CRITICAL: unauthenticated record creation**
- 200 on PATCH/PUT → **CRITICAL: unauthenticated data modification**
- 200 on DELETE → **CRITICAL: unauthenticated data destruction**
- 405 Method Not Allowed → safe (method explicitly blocked)
- 401/403 → safe (auth enforced per-method)
- 500 → ambiguous (may be unimplemented OR may be a payload format issue — try different bodies)

**Why this matters:** Many Spring Boot APIs use `@GetMapping` without auth but forget that the same controller may have `@PostMapping`/`@PatchMapping` that also lacks auth. The WAF/gateway may only enforce auth on specific paths, not methods.

**Real-world example (BFI Finance, May 2026):**
- `/master/v1/general` GET returned 4,199 records without auth (reported as High — read-only)
- Testing POST created a new record: `{"id":5661,"name":"test","code":"TEST"}` — no auth required
- Testing PATCH modified record #1 (production credit scoring rule) — no auth required
- Finding upgraded from High (7.5) to **Critical (9.1)** — unauthenticated write on production financial data
- Attack chain: modify NST approval thresholds → fraudulent loans auto-approved → revert to hide evidence

**Checklist (add to Phase 6 technique 6.5):**
- [ ] Test POST on all unauthenticated GET endpoints
- [ ] Test PATCH on all unauthenticated GET endpoints with `/{id}` suffix
- [ ] Test PUT on all unauthenticated GET endpoints with `/{id}` suffix
- [ ] Test DELETE on all unauthenticated GET endpoints with `/{id}` suffix
- [ ] If write succeeds: follow Write Access Response Protocol below

### Write Access Response Protocol

When write access (POST/PUT/PATCH/DELETE) succeeds on an unauthenticated endpoint, follow this decision tree:

```
Write Access Confirmed
├── Is this PRODUCTION?
│   ├── YES → Minimize impact. ONE record is sufficient proof.
│   │   ├── Use obviously-fake data: {"name":"PENTEST-PROBE-DELETE","code":"PT-DELETE"}
│   │   ├── Do NOT test PATCH/PUT on existing records (risk of corrupting real data)
│   │   ├── Prove PATCH exists without corrupting: test on the record YOU just created
│   │   └── Document record ID immediately for client cleanup
│   └── NO (nonprod) → More latitude, but still document for cleanup
│
├── Can you DELETE the test record?
│   ├── YES → Delete immediately, screenshot before/after as evidence
│   └── NO (no DELETE endpoint or DELETE returns 405/403)
│       ├── Can you PATCH it to a flagged state?
│       │   ├── YES → PATCH name to "PENTEST-DELETE-ME-{date}" so client can find it
│       │   └── NO → Leave as-is, document in cleanup appendix
│       └── Add to "Test Records Created" cleanup table
│
├── Is the write DESTRUCTIVE? (overwrites/deletes existing data)
│   ├── YES → DO NOT EXECUTE on real records
│   │   ├── Prove the method is accepted: send request with empty/malformed body
│   │   ├── Document: "PUT /resource/1 returns 400 (bad body) not 401/405 — write method accepted"
│   │   ├── Or: test on YOUR created record only
│   │   └── This is sufficient evidence without corrupting production data
│   └── NO (creates new record) → Safe to execute once as proof
│
└── Documentation requirements:
    ├── Screenshot/save the response showing successful write
    ├── Record the exact ID/key of created records
    ├── Add to report "Appendix: Test Records (Client Cleanup Required)"
    ├── Format: | Environment | Endpoint | Record ID | Data Written | Action Needed |
    └── Notify client in debrief that cleanup is needed
```

**Test payload conventions:**
- Always use obviously-fake data that's easy to find and delete
- Include "PENTEST" or "DELETE-ME" in the name/description field
- Use code/identifier like "PT-{date}" (e.g., "PT-20260521")
- Never use real-looking data that could be confused with legitimate records
- Never write offensive/inappropriate content (it's production)

**Proving write without writing (when risk is too high):**
```bash
# Method 1: OPTIONS check
curl -sk -X OPTIONS "$ENDPOINT" -D- | grep "Allow:"
# If Allow: GET, POST, PUT, DELETE → methods accepted

# Method 2: Empty body (triggers 400, not 401/405)
curl -sk -X POST "$ENDPOINT" -H "Content-Type: application/json" -d '{}' -w "[%{http_code}]"
# 400 = endpoint accepts POST but body is invalid (PROVES write access exists)
# 401/403 = auth required (safe)
# 405 = method not allowed (safe)

# Method 3: Invalid content-type (triggers 415, not 401)
curl -sk -X POST "$ENDPOINT" -H "Content-Type: text/plain" -d 'test' -w "[%{http_code}]"
# 415 = Unsupported Media Type (PROVES endpoint processes POST requests)
```

**Cleanup appendix format (add to report):**
```markdown
## Appendix: Test Records Created (Client Cleanup Required)

| # | Environment | Endpoint | Record ID | Data Written | Date | Action |
|---|-------------|----------|-----------|-------------|------|--------|
| 1 | PROD | /master/v1/general | 5668 | {"name":"PENTEST-PROBE","code":"PT"} | 2026-05-21 | DELETE |
| 2 | SIT | /master/v1/general | 8078 | {"name":"PENTEST-PROBE","code":"PT"} | 2026-05-21 | DELETE |
```

### Fix Verification (Redo/Reassessment Engagements)

When redoing a pentest or reassessing previously reported findings:

1. **Test ALL gateways/paths to the same backend** — a fix applied to one gateway (e.g., `microservices.prod.bfi.co.id`) may NOT be applied to another gateway routing to the same service (e.g., `microservices.prod.bravo.bfi.co.id`). In the BFI redo, F-1 was "fixed" on one gateway but the Bravo gateway remained fully vulnerable.
2. **Test the exact same PoC** — don't assume the fix works. Replay the original exploit steps verbatim.
3. **Test adjacent endpoints** — if `/master/v1/general` was fixed, check `/master/v1/address/province`, `/master/v1/bank`, etc.
4. **Document fix status per gateway:**
   ```markdown
   | Gateway | Endpoint | Previous Status | Current Status |
   |---------|----------|----------------|----------------|
   | microservices.prod.bfi.co.id | /master/v1/general | Vuln (GET/POST/PATCH) | Fixed (401) |
   | microservices.prod.bravo.bfi.co.id | /master/v1/general | Vuln (GET/POST/PATCH) | STILL VULNERABLE |
   ```
5. **Incomplete fixes are findings** — document as "Incomplete Remediation" with reference to the original finding ID. Severity remains the same (or higher if the incomplete fix creates false confidence).

### Credential Chaining & Cross-Environment Pivoting

**Full reference:** See `references/credential-chaining.md` and `references/credential-inventory-structure.md` for:
- Discovery → Validation → Escalation → Lateral Movement workflow
- Cross-environment pivot paths (mock heapdump → prod access)
- Credential inventory tracking and chain documentation

**Key principle:** Lower environments are often less protected but share credentials with production. A heapdump from mock can yield prod access.

### JWT Attack Techniques (Full Reference)

**Full reference:** See `references/jwt-attack-techniques.md` for:
- Decision tree (what to try based on what you have)
- 12-technique checklist with priority order
- Signature bypass (alg:none, unverified signatures)
- Header injection (jwk, jku, kid traversal, kid SQLi, x5c)
- Algorithm confusion (RS256→HS256 with public key)
- Secret brute-force (hashcat, jwt_tool, custom Python)
- Token endpoint abuse (Keycloak public clients, device code, CIBA)
- Post-exploitation with forged tokens

### Token Exchange & Authentication Bypass

**Full reference:** See `references/keycloak-assessment.md` and `references/oauth-sso-attack-chains.md` (Keycloak-Specific Chains) for:
- Public client identification and enumeration
- Password grant vs client credentials grant
- Token introspection and exchange
- Service account escalation and impersonation

### CORS Origin Reflection Testing (MANDATORY Phase 5)

**Full reference:** See `references/oauth-sso-attack-chains.md` (Chain 3: CORS Misconfiguration) for:
- Complete origin test payloads and rationale (7 bypass variants)
- Interpretation guide (ACAO + ACAC combinations → severity)
- Exploitation PoC templates (XHR, sandboxed iframe, XSS chain)
- Key targets and reporting guidance for financial services

**Minimum checklist:** Test ALL auth endpoints with `Origin: https://evil.com` + check for `Access-Control-Allow-Credentials: true`. If reflected → Critical. Load full reference for bypass variants and PoC templates.

### OAuth/OIDC redirect_uri Validation Testing (MANDATORY Phase 5/6)

**Full reference:** See `references/oauth-sso-attack-chains.md` for:
- Complete redirect_uri bypass payloads (8 variants including parse differentials)
- Client enumeration methodology (defaults + JS bundle extraction)
- PKCE enforcement check (determines if stolen code is usable)
- Full attack chain documentation (phishing URL → code theft → token exchange → ATO)
- Keycloak-specific chains (admin-cli, realm confusion, service account escalation)
- Severity guidance (public client + no PKCE + open redirect = Critical 8.1+)

**Minimum checklist:**
- [ ] Discover all OAuth/OIDC authorization endpoints (.well-known)
- [ ] Enumerate all client_ids (defaults + JS bundle extraction)
- [ ] Test arbitrary redirect_uri on each client
- [ ] If accepted: confirm public client + no PKCE
- [ ] Document full attack chain with PoC URL

### OTP/2FA Endpoint Testing (MANDATORY when OTP endpoints exist)

**Full reference:** See `references/otp-endpoint-testing.md` for:
- Rate limit bypass via purpose/type rotation (OTP flooding)
- User enumeration via forgot_password response differentiation
- Email header injection in OTP email fields
- Phone number parameter discovery
- Timing-based user enumeration

**Key insight:** OTP endpoints are almost always unauthenticated (they're the pre-auth step). They're quick wins (5-10 minutes) that produce Medium-severity findings even without an account. Test these BEFORE declaring "unauthenticated testing exhausted."

**Minimum checklist:**
- [ ] Enumerate OTP-related endpoints (send_otp, resend_otp, verify_otp, forgot_password)
- [ ] Test rate limiting per-endpoint
- [ ] Test rate limit bypass via purpose/type rotation
- [ ] Test user enumeration via forgot_password (response differentiation)
- [ ] Test OTP to arbitrary recipients (spam potential)

### WAF/Ingress Bypass Techniques (Conditional)

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

**Full reference:** See `references/keycloak-gateway-exploitation.md` and `references/keycloak-assessment.md` for:
- Gateway path discovery (/keycloak/, /auth/, /sso/)
- Realm enumeration and public client identification
- Username enumeration and password spray (with authorization)
- Token analysis and service account escalation

### Production Microservice Exploitation (with valid JWT)

**Full reference:** See `references/authenticated-testing-playbook.md` for:
- Systematic service enumeration with valid token
- Actuator/swagger access with auth (reveals more than unauth)
- Cross-service token validation testing
- Data exfiltration scope documentation

### Snyk Data as Attack Intelligence

**Full reference:** See `references/snyk-token-enumeration.md` for:
- Extracting exploitable CVEs from Snyk data
- Mapping CVEs to discovered microservices
- Prioritization by reachability and exploit availability

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

- **Account Creation Blockers (Bug Bounty)** — some targets require identity verification (KYC, PAN card, national ID) or region-specific phone numbers for account creation. Browser automation is often blocked by Cloudflare/reCAPTCHA. When unauthenticated testing is exhausted and account creation is blocked: (1) document the limitation clearly, (2) offer the user options (manual signup, Google OAuth, API-based registration if available), (3) if user creates account manually, request the auth token from DevTools (Authorization header or cookie). Never attempt to bypass KYC or create fraudulent accounts.
- **Hardened Target Fast-Exit** — if the first 3 vectors on a target all fail cleanly (proper error handling, no info leak, auth enforced, no default creds), mark it as "hardened" in the checklist and move on. Maximum 15-20 minutes per hardened target. Document what was tested and why it's considered hardened.
- **Environment Tagging** — every finding MUST be tagged with the environment: `prod`, `nonprod`, `experiment`, or `all`. Findings on nonprod/experiment instances should note "may not apply to production" unless the same configuration is confirmed on prod. This prevents over-reporting experiment-only issues as production risks.
- **False Positive Verification** — before logging a finding, verify it's not a false positive. Check for SPA catch-alls (same bytes for any path), CORS crashes masking endpoints (all 500s with same error), and 302-to-login (auth required, not bypassed). See `references/false-positive-detection.md`.
- **Strict Sequence** — never skip a phase. No exploitation before enumeration and vuln assessment are complete. Even for bug bounties where "fast-tracking to exploitation" seems tempting, the framework exists to prevent blind spots. Never suggest skipping phases to the operator.
- **Self-Audit Before Advancing** — before requesting gateway sign-off, proactively review what was missed in the current phase. List gaps honestly (e.g., "we didn't decompile the APK", "we didn't scrape the API docs"). Offer to fill gaps before moving forward. The operator expects thoroughness over speed. Never suggest skipping phases even for bug bounties or "efficiency" — the framework exists to prevent blind spots. Each phase builds on the previous one; shortcuts create gaps that cost more time later.
- **Phase 1 OSINT Completeness** — before declaring Phase 1 complete, verify ALL of these were attempted: (1) WHOIS/DNS/TXT, (2) subdomain enum (multi-source), (3) Wayback Machine, (4) GitHub/GitLab code search, (5) Google dorking, (6) Shodan/Censys on discovered IPs, (7) JS bundle analysis from accessible apps, (8) Mobile app identification (package names, APK endpoints), (9) Docker Hub/container registry check, (10) breach/paste site check (if tools available). Missing any of these is a gap that should be filled before advancing. Never SUGGEST skipping phases either — even for bug bounties where "time to bounty" feels urgent. The user has explicitly stated: "never skip the phase. because it's a fundamental thing." Each phase builds on the previous; shortcuts produce blind spots.
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

> **Full reference:** See `references/operational-pitfalls.md` for all execution pitfalls including parallel probing, terminal backgrounding, tool-specific workarounds, and target-specific lessons learned from BFI Finance and Bank Jago engagements.
