---
name: adtest
version: 1.0.0
description: "Active Directory penetration testing framework — domain recon, user enumeration, Kerberos attacks, relay/delegation, ADCS abuse, privilege escalation to Domain Admin."
tags: [active-directory, ad, kerberos, ntlm, windows, internal, pentest]
trigger: "AD pentest, active directory test, domain pentest, kerberos attack, ntlm relay, internal network pentest, domain controller, ADCS"
argument-hint: "<command: start|status|resume|next|report|abort|cleanup>"
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

- NEVER spray more than 2 passwords per lockout window — check policy FIRST
- BloodHound collection with SharpHound triggers AV — use BOF version or Python collector
- Responder: only poison in authorized subnet — can disrupt production
- NTLM relay: signing enabled = relay blocked. Check LDAP signing + SMB signing first
- Mimikatz on modern Windows: needs SeDebugPrivilege + bypass AMSI/ETW + avoid Defender
- Kerberoast: RC4 tickets crack fast, AES tickets are nearly impossible — prioritize RC4
- ADCS: ESC1-ESC8 each have different prereqs — Certipy `find` maps them all
- Golden/Silver tickets: powerful but loud — use for proof, not persistence in pentests
- Domain trust: child→parent trust is exploitable (SID History) — always check trust relationships
- GPP passwords: still found in legacy environments — `Get-GPPPassword` or CrackMapExec
- NTLMRELAYX SEGFAULTS (v0.13.x) — impacket v0.13.1 ntlmrelayx segfaults on some Linux hosts after accepting SMB connection. Fix: `pip3 install impacket==0.10.0`. Always validate coercion with smbserver.py BEFORE setting up relay. Proven workflow: (1) smbserver.py to capture hash → confirms coercion works, (2) kill smbserver, start ntlmrelayx, (3) re-trigger coercion.
- COERCION VALIDATION — mimikatz `misc::spooler` "Access is denied (can be OK)" DOES trigger auth. Always capture with smbserver.py first to PROVE the callback arrives before investing in relay setup.
- LDAP SIGNING CHECK FIRST — use `ldap3.Connection` with NTLM auth (no signing). If bind succeeds = signing not required = relay viable. Do this BEFORE any relay attempt.
- DPAPI DECISION TREE — Domain user masterkey: needs domain backup key (requires DA) OR user's cleartext password. Local user masterkey: needs user's cleartext password (NTLM hash alone insufficient on newer Windows with SHA-512/AES-256 masterkeys). If you can't get the required key within 30 min, SKIP and pursue other escalation paths.
- findDelegation.py FIRST — run immediately after getting domain creds. Unconstrained delegation on DC is default but constrained delegation on other accounts = instant privesc path.
- IMPACKET VERSION COMPATIBILITY — v0.10.0 is most stable for relay attacks. v0.13.x segfaults on ntlmrelayx SMB handler. v0.9.24 missing dsinternals (LDAP attack fails). Quick check: `python3 -c "import impacket; print(impacket.__version__)"`. Downgrade: `pip3 install impacket==0.10.0`.
- PRINTERBUG RELAY TOPOLOGY: SpoolSvc accessible ≠ exploitable. The DC must be able to CONNECT BACK to your listener on port 445. In segmented exam networks, DC may only reach the member server (.8) which already has SMB bound — no relay possible without port conflict resolution.
- Golden/Silver tickets: powerful but loud — use for proof, not persistence in pentests
- Domain trust: child→parent trust is exploitable (SID History injection) — always check trust relationships
- GPP passwords: still found in legacy environments — `Get-GPPPassword` or CrackMapExec
- SSH TUNNEL FOR IMPACKET CUSTOM PORTS: impacket tools don't support custom SMB ports. Use SSH local port forwarding (e.g., `-L 4445:DC:445`) then connect via Python SMBConnection with `sess_port=4445`. secretsdump.py cannot use custom ports natively — use the Python API directly for custom-port operations.
- RBCD silent failure: PowerShell SetInfo() on msDS-AllowedToActOnBehalfOfOtherIdentity returns NO ERROR even without write access — always verify with read-back. Machine accounts can't write RBCD on DCs.
- dacledit.py credential quoting: when password contains $ characters, use single-quotes with \$ escaping in SSH commands (e.g., 'secops.local/Alex:\$mypassword\$12')
- Server 2022 DPAPI: SHA-512/AES-256 masterkeys resist NTLM-hash-only decryption. Need cleartext password or domain backup key. DPAPI_SYSTEM only decrypts backup portion.
- Mimikatz vault::cred /patch: works for SYSTEM-context vault credentials without needing DPAPI masterkey decryption. Best quick-win for stored cmdkey credentials.
- Machine account DCSync: PRODSERVER$ with standard WORKSTATION_TRUST_ACCOUNT (UAC 4096) does NOT have replication rights — error 0x20f7. Only DCs and accounts with explicit DS-Replication-Get-Changes ACE can DCSync.

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
