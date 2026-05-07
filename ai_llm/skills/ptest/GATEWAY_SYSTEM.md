# 🎯 Penetration Testing Framework (PTF)

This document defines the architectural framework for structured penetration testing engagements. The PTF ensures methodical progression through pentest phases with mandatory quality gates preventing premature advancement.

## 📐 The Hierarchy
`Gateway (Quality Gate)` → `Phase (Pentest Stage)` → `Tasks (Techniques)`

---

## 1. The Gateway (The Quality Gate)
A Gateway is a binary state: **Open** or **Passed**.
- **Purpose:** Prevent advancing to the next pentest phase until the current phase yields sufficient coverage.
- **Rule:** No task in Gateway N+1 can begin until Gateway N is "Passed."
- **Control File:** `skills/hunting/gateway-index.md`

## 2. The Phase (The Pentest Stage)
Each Gateway maps to one pentest phase.
- **Phases:** Recon → Enumeration → Exploitation → Post-Exploitation → Reporting
- **Contents:**
  - Phase Objective
  - Technique/Task Table (ID, Description, Status)
  - Exit Criteria (minimum coverage to pass the Gateway)

## 3. The Tasks (The Techniques)
Tasks are specific pentest techniques executed within a phase.
- **Passive Recon:** `skills/hunting/recon-passive.md`
- **Active Recon/Enumeration:** `skills/hunting/recon-active.md`
- **Exploitation:** `skills/hunting/exploit.md`
- **Post-Exploitation:** `skills/hunting/post-exploit.md`
- **Finding Escalation:** `skills/hunting/escalate-finding.md`
- **Reporting:** `skills/hunting/report.md`

---

## 🔄 Operational Lifecycle

### Phase A: Scope & Initialization
1. **Load Index:** Read `skills/hunting/gateway-index.md` to determine active phase.
2. **Confirm Scope:** Verify target scope, rules of engagement, and authorization.
3. **Initialize Workspace:** Set up output directories and logging.

### Phase B: Execution Loop
1. **Pick Technique:** Select next pending technique for the current phase.
2. **Execute:** Run the technique using the appropriate skill file.
3. **Document:** Record all findings with evidence (screenshots, logs, PoCs).
4. **Update:** Mark technique as `Completed` with results.

### Phase C: Gateway Transition
1. **Coverage Audit:** Verify sufficient techniques were executed for the phase.
2. **Finding Review:** Confirm all findings are documented with evidence.
3. **Sign-off:** Request user confirmation before advancing.
4. **Unlock Next:** Update `gateway-index.md` and proceed to next phase.

---

## 🛡️ System Guardrails
- **Strict Sequence:** Never skip a phase (e.g., no exploitation before recon).
- **Scope Enforcement:** Never test targets outside defined scope.
- **Evidence Required:** Every finding must have reproducible proof.
- **Human Sign-off:** Always request user confirmation before passing a Gateway.
- **Blocked State:** If a finding requires immediate escalation, the Gateway pauses.
