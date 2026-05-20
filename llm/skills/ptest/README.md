# ptest — Penetration Testing Skill for Claude Code

Structured pentest framework with gated phases. Enforces methodical progression from reconnaissance through exploitation to reporting, with mandatory quality gates and human sign-off at each transition.

## Install

```bash
mkdir -p ~/.claude/skills/ptest
cp SKILL.md README.md recon-passive.md recon-active.md enumeration.md attack-surface.md vuln-assessment.md exploit.md post-exploit.md report.md escalate-finding.md ~/.claude/skills/ptest/
```

Or if cloning from this repo:

```bash
cp -r ai_llm/skills/ptest/* ~/.claude/skills/ptest/
```

## Usage

```
/ptest start          # Initialize new engagement (scope, targets, authorization)
/ptest status         # Show current gateway state
/ptest next           # Advance to next phase (checks exit criteria)
/ptest escalate       # Escalate a critical finding
/ptest recon-passive  # Run passive recon techniques
/ptest recon-active   # Run active enumeration
/ptest exploit        # Run exploitation techniques
/ptest post-exploit   # Run post-exploitation
/ptest report         # Generate final report
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

- Claude Code CLI
- Standard pentest tools as needed (nmap, gobuster, curl, nuclei, etc.)
- Written authorization for the target engagement
