---
name: gateway-orchestrator
description: Manages transitions between pentest phases and enforces quality gates.
version: 2.0.0
metadata:
  category: orchestration
  requires_toolsets: [read, edit]
---

# Skill: Pentest Gateway Orchestrator

## 🎯 Purpose
Manage phase transitions during a penetration test, ensuring each phase has sufficient coverage before advancing.

## 🛠️ Execution Workflow
1. **Identify Current Gateway:** Read `gateway-index.md` to find the active phase.
2. **Assess Coverage:** Review findings and techniques executed in the current phase.
3. **Evaluate Exit Criteria:**
   - Gateway 1: Attack surface documented, OSINT gathered, subdomains/IPs listed.
   - Gateway 2: Open ports/services enumerated, versions identified, potential vectors listed.
   - Gateway 3: At least one vulnerability exploited with PoC, or documented why exploitation was not possible.
   - Gateway 4: Privilege escalation attempted, lateral movement explored, persistence assessed.
   - Gateway 5: Report compiled with all findings, severity ratings, and remediation advice.

## 🚪 Gateway Exit Protocol
1. **Evidence Audit:** Verify all findings have supporting evidence.
2. **Coverage Check:** Confirm key techniques for the phase were attempted.
3. **Sign-off:** Ask user: *"Phase [X] complete. [N] findings documented. Ready to advance to [next phase]?"*
4. **State Update:** Mark Gateway as ✅ Passed, unlock next Gateway.

## ⚠️ Guardrails
- **No Skipping:** Cannot exploit without completing recon.
- **Blocked on Critical:** P1/Critical findings trigger immediate escalation via `escalate-finding.md`.
- **Scope Lock:** Never expand scope without explicit user authorization.
