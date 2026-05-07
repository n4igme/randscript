# Pentest Gateway Index

Master authority for engagement progression. A Gateway must be "Passed" before advancing to the next phase.

## 🗺️ Gateway Map

| Gateway | Phase | Status | Skill File | Exit Criteria |
| :--- | :--- | :--- | :--- | :--- |
| **Gateway 1** | Passive Reconnaissance | 🔴 Open | `recon-passive.md` | Attack surface mapped, targets identified |
| **Gateway 2** | Active Recon & Enumeration | ⚪ Locked | `recon-active.md` | Services enumerated, versions fingerprinted |
| **Gateway 3** | Exploitation | ⚪ Locked | `exploit.md` | Vulnerabilities exploited with PoC |
| **Gateway 4** | Post-Exploitation | ⚪ Locked | `post-exploit.md` | Privilege escalation & lateral movement attempted |
| **Gateway 5** | Reporting | ⚪ Locked | `report.md` | Final report delivered |

## ⚙️ Operational Instructions
1. **Check Status:** Always read this index at session start to determine the active Gateway.
2. **Enforce Sequence:** Do not execute techniques from a "Locked" phase.
3. **Transition Logic:** When current phase exit criteria are met, invoke the Gateway Exit Protocol in `gateway-orchestrator.md`.
4. **Update State:** Upon passing a Gateway, update Status from 🔴 to ✅ and unlock the next.
5. **Escalation:** Critical/P1 findings trigger immediate `escalate-finding.md` regardless of current phase.
