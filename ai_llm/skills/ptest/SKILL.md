---
name: ptest
description: "Structured penetration testing framework with gated phases. Guides methodical progression from recon through exploitation to reporting."
version: 3.0.0
author: n4igme
license: MIT
allowed-tools: Read Write Edit Bash(*)
argument-hint: <command: start|preflight|status|resume|next|escalate|cleanup|recon-passive|recon-active|enumerate|attack-surface|vuln-assess|exploit|post-exploit|report>
metadata:
  hermes:
    tags: [pentest, penetration-testing, security, recon, exploitation, post-exploitation, red-teaming, offensive-security]
    related_skills: [godmode, parse-finding]
---

# Penetration Testing Framework

Structured pentest engagement with mandatory quality gates preventing premature phase advancement.

## Architecture

`Gateway (Quality Gate)` → `Phase (Pentest Stage)` → `Tasks (Techniques)`

## Commands

$ARGUMENTS

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

The following wordlists are expected (from SecLists):
- `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt`
- `/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt`
- `/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt`
- `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`

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
3. **Rules of Engagement** — testing hours, restricted techniques, notification requirements
4. **Authorization** — confirm written authorization exists (do NOT proceed without it)
5. **Output Directory** — create `./ptest-output/` with subdirectories:

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

gateways:
  1_passive_recon: OPEN
  2_active_recon: LOCKED
  3_enumeration: LOCKED
  4_attack_surface: LOCKED
  5_vuln_assessment: LOCKED
  6_exploitation: LOCKED
  7_post_exploitation: LOCKED
  8_reporting: LOCKED

findings_count: 0
escalations_count: 0
```

---

## Resume (`resume`)

When resuming an interrupted engagement:

1. Read `./ptest-output/state.yaml` to determine active gateway.
2. Read the active phase's `checklist.md` to see which techniques are done vs. pending.
3. Read `./ptest-output/findings-log.md` for context on what's been found.
4. Report status to user and suggest next technique to execute.

---

## Gateway Map

| Gateway | Phase | Skill File | Exit Criteria |
|---------|-------|-----------|---------------|
| 1 | Passive Reconnaissance | `recon-passive.md` | Attack surface mapped, subdomains validated, technologies identified |
| 2 | Active Reconnaissance | `recon-active.md` | All hosts port-scanned, services detected, network topology mapped |
| 3 | Enumeration | `enumeration.md` | Applications enumerated, APIs mapped, parameters discovered |
| 4 | Attack Surface Mapping | `attack-surface.md` | Asset inventory confirmed with user, scope finalized, entry points mapped |
| 5 | Threat Modeling & Vuln Assessment | `vuln-assessment.md` | Attack trees documented, vuln scans complete, vectors prioritized |
| 6 | Exploitation | `exploit.md` | Prioritized vulnerabilities exploited with PoC |
| 7 | Post-Exploitation | `post-exploit.md` | Privilege escalation & lateral movement attempted |
| 8 | Reporting | `report.md` | Final report delivered |

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

```markdown
## [FINDING-{ID}] {Title}

**Severity:** Critical / High / Medium / Low / Info
**CVSS 3.1:** {score} ({vector string})
**Affected Asset:** {host, endpoint, or component}
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
6. **Update Checklist** — mark technique as done in `checklist.md`.
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

1. Document finding fully using the Finding Template.
2. Classify severity (CVSS 3.1).
3. Write to `./ptest-output/escalations/escalation-{ID}.md`.
4. Alert user for immediate client communication.
5. Current gateway pauses until escalation is acknowledged.
6. Increment `escalations_count` in `state.yaml`.

See `escalate-finding.md` for full procedure.

---

## Cleanup (`cleanup`)

Post-engagement housekeeping:

1. **Archive** — compress `./ptest-output/` to `./ptest-output-{engagement-name}-{date}.tar.gz`.
2. **Sanitize** — remove any credentials, tokens, or sensitive data from output files.
3. **Verify** — confirm report is complete and all findings are documented.
4. **Summary** — print engagement stats (findings by severity, phases completed, duration).

---

## Guardrails

- **Strict Sequence** — never skip a phase. No exploitation before enumeration and vuln assessment are complete.
- **Scope Enforcement** — never test targets outside defined scope. Re-read `scope.md` before each technique.
- **Evidence Required** — every finding must have reproducible proof.
- **Verified Findings Only** — a finding must be backed by direct evidence of exploitability or exposure. DNS resolution or CT log presence alone does NOT constitute a finding. Every finding must include proof that the issue is currently exploitable or observable (e.g., HTTP response showing an unauthenticated panel, not just a DNS record pointing to it). Unverified potential issues belong in a "Potential Issues" list for the next phase to validate — not in the findings log.
- **Mandatory Tool Execution** — mandatory tools listed per phase must be run. If unavailable, document the gap explicitly. Never substitute manual probing for an available automated scanner.
- **Human Sign-off** — always request user confirmation before passing a gateway.
- **Authorization First** — refuse to begin without confirmed authorization.
- **No Deployed Persistence** — document persistence techniques but do not deploy backdoors without explicit authorization.
- **Scope Type Awareness** — skip techniques that don't apply to the engagement's scope type.
