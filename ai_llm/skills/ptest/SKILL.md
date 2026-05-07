---
name: ptest
description: "Structured penetration testing framework with gated phases. Guides methodical progression from recon through exploitation to reporting."
version: 2.1.0
author: n4igme
license: MIT
allowed-tools: Read Write Edit Bash(*)
argument-hint: <command: start|status|resume|next|escalate|cleanup|recon-passive|recon-active|exploit|post-exploit|report>
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
| `status` | Show current gateway state, progress, and pending techniques |
| `resume` | Resume an interrupted engagement — read existing output and continue from last checkpoint |
| `next` | Attempt to advance to the next phase (runs exit criteria check) |
| `escalate` | Trigger critical finding escalation |
| `cleanup` | Archive engagement output, sanitize sensitive data |
| `recon-passive` | Execute passive recon techniques |
| `recon-active` | Execute active recon/enumeration techniques |
| `exploit` | Execute exploitation techniques |
| `post-exploit` | Execute post-exploitation techniques |
| `report` | Generate final pentest report |

If no command is given, show current status and suggest next action.

---

## Initialization (`start`)

Before any testing begins, collect and document:

1. **Target Scope** — domains, IPs, applications, exclusions
2. **Scope Type** — determines which techniques apply:
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
    checklist.md        # Technique execution tracker
  recon-active/         # Phase 2 results
    checklist.md
  exploit/              # Phase 3 results
    checklist.md
  post-exploit/         # Phase 4 results
    checklist.md
  report/               # Final report
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
  3_exploitation: LOCKED
  4_post_exploitation: LOCKED
  5_reporting: LOCKED

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
| 1 | Passive Reconnaissance | `recon-passive.md` | Attack surface mapped, targets identified |
| 2 | Active Recon & Enumeration | `recon-active.md` | Services enumerated, versions fingerprinted |
| 3 | Exploitation | `exploit.md` | Vulnerabilities exploited with PoC |
| 4 | Post-Exploitation | `post-exploit.md` | Privilege escalation & lateral movement attempted |
| 5 | Reporting | `report.md` | Final report delivered |

---

## Finding Template

Every finding documented during the engagement MUST follow this format:

```markdown
## [FINDING-{ID}] {Title}

**Severity:** Critical / High / Medium / Low / Info
**CVSS 3.1:** {score} ({vector string})
**Affected Asset:** {host, endpoint, or component}
**Phase Discovered:** {phase number and name}

### Description
{What the vulnerability is and why it matters}

### Steps to Reproduce
1. {step}
2. {step}
3. {step}

### Evidence
{Screenshots, request/response logs, command output}

### Impact
{What an attacker can achieve}

### Remediation
{Required fix and defense-in-depth recommendations}
```

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
2. **Evidence Check** — confirm all findings have supporting evidence.
3. **Exit Criteria** — evaluate against the phase's exit criteria:
   - Gateway 1: Attack surface documented, OSINT gathered, subdomains/IPs listed.
   - Gateway 2: Open ports/services enumerated, versions identified, potential vectors listed.
   - Gateway 3: At least one vulnerability exploited with PoC, or documented why exploitation was not feasible.
   - Gateway 4: Privilege escalation attempted, lateral movement explored, persistence assessed.
   - Gateway 5: Report compiled with all findings, severity ratings, and remediation advice.
4. **Sign-off** — ask user: *"Phase [X] complete. [N] findings documented. Ready to advance to [next phase]?"*
5. **Update State** — update `./ptest-output/state.yaml`: mark gateway as PASSED, unlock next.

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

- **Strict Sequence** — never skip a phase. No exploitation before recon is complete.
- **Scope Enforcement** — never test targets outside defined scope. Re-read `scope.md` before each technique.
- **Evidence Required** — every finding must have reproducible proof.
- **Human Sign-off** — always request user confirmation before passing a gateway.
- **Authorization First** — refuse to begin without confirmed authorization.
- **No Deployed Persistence** — document persistence techniques but do not deploy backdoors without explicit authorization.
- **Scope Type Awareness** — skip techniques that don't apply to the engagement's scope type.
