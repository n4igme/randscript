---
name: adtest
version: 1.1.0
description: "Active Directory penetration testing framework — domain recon, user enumeration, Kerberos attacks, relay/delegation, ADCS abuse, privilege escalation to Domain Admin."
tags: [active-directory, ad, kerberos, ntlm, windows, internal, pentest]
trigger: "AD pentest, active directory test, domain pentest, kerberos attack, ntlm relay, internal network pentest, domain controller, ADCS"
argument-hint: "<command: start|status|resume|next|report|abort|cleanup>"
notes:
  - "v1.1.0: Added Phase Entry Protocol, credential-driven discovery loop-back, findings.jsonl procedure, N/A phase guidance. Aligned with skill family patterns."
  - "v1.0.1: Extracted pitfalls to references/pitfalls.md. Added command procedures, state.yaml schema, gate enforcement, script invocation, finding template."
metadata:
  hermes:
    tags: [active-directory, ad, kerberos, ntlm, windows, internal, pentest]
    related_skills: [ptest, ctest, xdev, osint, scode]
---

# Active Directory Penetration Testing Framework

6-phase gated workflow for domain-joined Windows environments. From initial foothold to Domain Admin.

## Quick Wins (check FIRST when entering mid-engagement with creds)

| Check | Command | If Found |
|-------|---------|----------|
| Constrained Delegation | `findDelegation.py DOMAIN/user:pass -dc-ip <DC>` | S4U2Proxy → impersonate DA |
| ADCS Vulnerable | `certipy find -vulnerable -u user@domain -p pass -dc-ip <DC>` | ESC1/ESC4 → DA cert |
| LDAP signing disabled | `ldap3.Connection` NTLM bind without signing | Coerce DC → relay → DCSync |
| GenericAll on DA user | BloodHound or dacledit.py | Reset password → DA |
| GPP passwords | `crackmapexec smb <DC> -u user -p pass -M gpp_autologin` | Cleartext DA creds |
| Kerberoast RC4 SPN | `GetUserSPNs.py DOMAIN/user:pass -dc-ip <DC>` | Crack → service account |
| AS-REP roastable | `GetNPUsers.py DOMAIN/ -dc-ip <DC> -usersfile users.txt` | Crack → user creds |

If any of these hit, pursue immediately before running the full 6-phase workflow.

## Quick Reference

```
Phases:  1.Recon&Enum → 2.CredHarvest → 3.Kerberos → 4.Relay&Delegation → 5.PrivEsc&Lateral → 6.Report
States:  LOCKED → OPEN → PASSED (sequential)
Commands: start | status | next | resume | report | abort | cleanup

Key rules:
  • BloodHound FIRST — always collect before attacking
  • Stealth matters — avoid account lockouts, noisy scans
  • Credential spray = max 2 attempts per account per lockout window
  • Every cred found → test immediately (credentials rotate)
  • Document EVERY hop in attack path (report needs full chain)
  • ADCS is the #1 privesc vector in modern AD — always check

Tools (must-have):
  Impacket | BloodHound/SharpHound | CrackMapExec/NetExec | Certipy
  Rubeus | Responder | ntlmrelayx | mimikatz | ldapsearch
```

## Architecture

```
Phase 1: Recon & Enum → Phase 2: Credential Harvest → Phase 3: Kerberos Attacks →
Phase 4: Relay & Delegation → Phase 5: PrivEsc & Lateral → Phase 6: Reporting
```

## Commands

| Command | Action |
|---------|--------|
| `start` | Initialize — define scope, verify connectivity, create output dir |
| `status` | Show current phase, creds collected, paths found |
| `resume` | Resume interrupted engagement |
| `next` | Advance to next phase (gate check) |
| `report` | Generate attack path report |
| `abort` | Terminate early |
| `cleanup` | Archive output, remove planted artifacts |

## Phase Routing

| Phase | Gate | Reference |
|-------|------|-----------|
| 1 Recon & Enum | Domain info collected, BloodHound data imported, users/computers enumerated | `references/phase1-recon-enum.md` |
| 2 Credential Harvest | At least one valid credential obtained (password, hash, or ticket) | `references/phase2-cred-harvest.md` |
| 3 Kerberos Attacks | Kerberoast/AS-REP completed, tickets cracked or delegated | `references/phase3-kerberos.md` |
| 4 Relay & Delegation | NTLM relay tested, delegation paths exploited | `references/phase4-relay-delegation.md` |
| 5 PrivEsc & Lateral | Domain Admin achieved OR all paths documented as blocked | `references/phase5-privesc-lateral.md` |
| 6 Reporting | Full attack path documented with evidence | (inline below) |

### Phase Entry Protocol (ALL phases)

When entering ANY phase, before executing techniques:
1. **Load reference file** — per Phase Routing table above
2. **Record timestamp** — write `phase_N_start` in state.yaml
3. **Check credential inventory** — review all creds collected so far, test new ones against current phase's attack paths

### Credential-Driven Discovery Loop-Back (ALL phases)

AD testing constantly discovers new identities. When ANY phase yields a new credential (password, hash, ticket, certificate):
1. Append to `./adtest-output/phase2-creds/credential-inventory.md` with source phase and method
2. Immediately test against: Kerberoast (is it an SPN?), delegation (has delegation attributes?), ACL paths (BloodHound shortest paths from this identity)
3. At phase exit, verify all credentials have been tested against all applicable attack vectors
4. Prevents "captured relay hash in Phase 4 but never checked if it had delegation" pattern

### N/A Phases

If a phase is not applicable (no Kerberos SPNs for Phase 3, signing enforced everywhere for Phase 4), document justification in state.yaml and mark gateway `N/A`. Never skip silently.

## Effort Allocation

| Phase | % | 8-hour | 16-hour |
|-------|---|--------|---------|
| 1 Recon & Enum | 20% | 100 min | 3 hr |
| 2 Cred Harvest | 15% | 70 min | 2.5 hr |
| 3 Kerberos | 20% | 100 min | 3 hr |
| 4 Relay & Delegation | 20% | 100 min | 3 hr |
| 5 PrivEsc & Lateral | 15% | 70 min | 2.5 hr |
| 6 Reporting | 10% | 50 min | 1.5 hr |

## Cross-Skill Triggers

| Signal | Target Skill | Action |
|--------|-------------|--------|
| Web app on domain-joined server | ptest | Web pentest → credential chaining back |
| Cloud sync (Azure AD Connect, ADFS) | ctest | Azure AD / Entra ID exploitation |
| Source code on file share | scode | Scan for hardcoded creds, connection strings |
| Custom service binary found | xdev / retools | RE for vulns or credential extraction |
| API endpoint on internal host | atest | API security testing |
| Thick client on domain workstation | ttest | Desktop app testing |

## Abandon & Pivot Heuristics

- **No creds after Phase 2 (2hr):** Pivot to Responder/relay or request creds from client
- **ADCS check is Phase 1 mandatory:** Query `(objectClass=pKIEnrollmentService)` in AD — if empty, skip ESC1-8. If present, run `certipy find` immediately.
- **dacledit.py from Linux host:** Most reliable ACL enumeration tool when BloodHound isn't available. Check domain object, DA group, and all user objects for WriteDACL/GenericAll from owned principals.
- **All Kerberoast tickets uncrackable (30min GPU):** Move to Phase 4 relay attacks
- **No delegation paths:** Skip Phase 4, focus on BloodHound shortest paths in Phase 5
- **75% budget, no DA:** Document highest privilege achieved, report as partial compromise
- **Account lockouts triggered:** STOP spraying immediately, switch to passive methods

## Pitfalls

> Grouped by category, deduplicated: `references/pitfalls.md`

## Output Structure

```
./adtest-output/
├── state.yaml
├── scope.md
├── phase1-recon/
│   ├── bloodhound/
│   ├── users.txt
│   ├── computers.txt
│   └── domain-info.md
├── phase2-creds/
│   └── credential-inventory.md
├── phase3-kerberos/
├── phase4-relay/
├── phase5-privesc/
│   └── attack-path.md
└── report/
```

## Command Procedures

**`start`:**
1. Collect: domain name, DC IP, access level (unauthenticated/domain-user/local-admin), scope type (full/quickwin/adcs-only), authorization proof.
2. Run `state_manager.init_state(workdir, name, domain, dc_ip, access_level, scope_type)` — creates output dirs + state.yaml + scope.md + findings-log.md + credential-inventory.md.
3. Verify connectivity: `ldapsearch` or `crackmapexec smb <DC>`.
4. Begin Phase 1 immediately. Run Quick Wins table if creds provided.

**`status`:** Output current phase, gateway states (6 phases), findings count by severity, credentials collected, time elapsed, abandon check. If no engagement, suggest `start`.

**`resume`:**
1. Read `state.yaml` to determine active phase.
2. **Staleness:** >3 days → re-verify credentials still valid. >14 days → re-run BloodHound (AD changes frequently). >30 days → treat as fresh engagement.
3. Report status and suggest next action.

**`next`:**
1. Run gate check (see Gate Enforcement below).
2. If NOT met: list unmet criteria, suggest what to test.
3. If met: `state_manager.advance_phase(workdir)`.
4. Override allowed with justification.

**`abort`:**
1. `state_manager.abandon(workdir, reason)` — marks remaining phases ABANDONED.
2. Generate partial report if findings exist.
3. Run cleanup.

**`cleanup`:**
1. Archive `./adtest-output/` to `adtest-output-{domain}-{date}.tar.gz`.
2. Remove planted artifacts (tickets, certs, registry keys).
3. Print summary: findings by severity, creds harvested, phases completed, DA achieved (yes/no).

## State Schema

```yaml
engagement:
  name: ""
  started: ""
  domain: ""
  dc_ip: ""
  access_level: ""  # unauthenticated, domain-user, local-admin
  scope_type: ""    # full, quickwin, adcs-only

gateways:
  1_recon_enum: OPEN
  2_cred_harvest: LOCKED
  3_kerberos: LOCKED
  4_relay_delegation: LOCKED
  5_privesc_lateral: LOCKED
  6_reporting: LOCKED

findings_count: 0
findings_by_severity: {critical: 0, high: 0, medium: 0, low: 0, info: 0}
credentials_count: 0
current_phase: 1
time_tracking:
  phase_1_start: ""
  phase_1_end: ""
  # ...through phase_6...
notes: ""
```

## Gate Enforcement (MANDATORY before `next`)

```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/adtest/scripts"))
from gate_check import check_gate, print_gate_status

result = check_gate(".", phase=None)
print_gate_status(result)
```

## Script Invocation

```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/adtest/scripts"))
import state_manager

workdir = "."
state_manager.init_state(workdir, "CorpAD", domain="corp.local", dc_ip="10.0.0.1",
    access_level="domain-user", scope_type="full")

state_manager.status(workdir)
state_manager.advance_phase(workdir)
state_manager.add_finding(workdir, "ADTEST-001", "Kerberoastable SPN", "High", "Kerberos", "svc_backup")
state_manager.add_credential(workdir, "hash", "svc_backup", "Kerberoast")
state_manager.abandon(workdir, "Client terminated engagement")
```

## Finding Template

```markdown
## [ADTEST-{ID}] {Title}

**Severity:** Critical / High / Medium / Low / Info
**Category:** Recon / Credential / Kerberos / Relay / PrivEsc / Config
**Target:** `{hostname / account / service}`
**Attack Path:** {previous hop} → {this finding} → {next potential hop}

### Description
{What the vulnerability is and why it matters}

### Reproduction
{Exact commands used — copy-paste reproducible}

### Evidence
{Hash, ticket, screenshot, or command output}

### Impact
{What an attacker gains — be specific about privilege level}

### Remediation
{Fix with priority: immediate / short-term / architectural}
```

### Cross-Skill Chaining (findings.jsonl)

When recording a finding, append to `./adtest-output/findings.jsonl` for cross-skill consumption:

```python
import json
from datetime import datetime
finding = {
    "id": "ADTEST-{count:03d}",
    "skill": "adtest",
    "severity": "{severity}",
    "type": "{vuln_type}",  # e.g., kerberoast, delegation_abuse, ntlm_relay, adcs_esc1, dcsync
    "target": "{hostname_or_account}",
    "summary": "{one-line description}",
    "chain_potential": [],  # e.g., ["ptest:web_exploitation", "ctest:azure_ad", "xdev:binary_exploit"]
    "timestamp": datetime.now().isoformat(),
    "phase": "{current_phase}",
    "status": "confirmed"
}
with open("./adtest-output/findings.jsonl", "a") as f:
    f.write(json.dumps(finding) + "\n")
```
