# ptest — Penetration Testing Skill for Hermes Agent

Structured pentest framework with gated phases. Enforces methodical progression from reconnaissance through exploitation to reporting, with mandatory quality gates and human sign-off at each transition.

## Install

```bash
# Install from local directory
hermes skills install ./hunting/ptest/SKILL.md --name ptest

# Or tap this repo as a skill source
hermes skills tap add <github-user>/<repo-name>
```

## Usage

Load the skill in a Hermes session, then issue commands:

```
/skill ptest

> start              # Initialize new engagement (scope, targets, authorization)
> preflight          # Check tool availability
> status             # Show current gateway state
> next               # Advance to next phase (checks exit criteria)
> escalate           # Escalate a critical finding
> recon-passive      # Run passive recon techniques
> recon-active       # Run active enumeration
> enumerate          # Run application-layer enumeration
> attack-surface     # Map attack surface
> vuln-assess        # Run vulnerability assessment
> exploit            # Run exploitation techniques
> post-exploit       # Run post-exploitation
> report             # Generate final report
> cleanup            # Archive and sanitize
```

Or preload on launch:

```bash
hermes -s ptest
```

## Phases

| # | Phase | Gate Requirement |
|---|-------|-----------------|
| 1 | Passive Recon | Attack surface mapped without target contact |
| 2 | Active Recon | All hosts port-scanned, services detected |
| 3 | Enumeration | Applications enumerated, APIs mapped, parameters discovered |
| 4 | Attack Surface Mapping | Asset inventory confirmed with user, scope finalized |
| 5 | Vuln Assessment | Attack trees documented, vuln scans complete, vectors prioritized |
| 6 | Exploitation | At least one vuln exploited with PoC |
| 7 | Post-Exploitation | Privesc and lateral movement assessed |
| 8 | Reporting | Final report with all findings delivered |

## Output

All engagement data is written to `./ptest-output/` in the current project directory:

```
./ptest-output/
  state.yaml
  scope.md
  findings-log.md
  recon-passive/
  recon-active/
  enumeration/
  attack-surface/
  vuln-assessment/
  exploit/
  post-exploit/
  report/
  escalations/
```

## Requirements

- Hermes Agent
- Standard pentest tools as needed (nmap, gobuster, curl, nuclei, etc.)
- Written authorization for the target engagement
