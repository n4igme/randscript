# Phase 1: Recon & Enumeration

## Gate: Domain info collected, BloodHound imported, users/computers enumerated

## Steps

### 1.0 MANDATORY First-5-Minutes (run IMMEDIATELY after getting domain creds)
```bash
# 1. Find delegation paths (unconstrained/constrained/RBCD)
findDelegation.py -dc-ip <DC> DOMAIN/user:pass

# 2. Check LDAP signing (relay viability)
python3 -c "import ldap3; c=ldap3.Connection(ldap3.Server('<DC>'),user='DOMAIN\\\\user',password='pass',authentication=ldap3.NTLM); print('SIGNING NOT REQUIRED' if c.bind() else 'FAILED')"

# 3. Check for ADCS
certipy find -u user@domain -p pass -dc-ip <DC> -stdout 2>/dev/null || echo "certipy not available"

# 4. Check SMB signing on all hosts
crackmapexec smb <subnet>/24 --gen-relay-list relay-targets.txt 2>/dev/null
```

### 1.1 Domain Discovery (no creds)
```bash
# Find domain controller via DNS
nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>
dig SRV _ldap._tcp.<domain>

# NBT-NS / mDNS discovery
nbtscan -r <subnet>/24
crackmapexec smb <subnet>/24 --gen-relay-list targets.txt

# Identify domain from DHCP/DNS suffix
ipconfig /all  # Windows
cat /etc/resolv.conf  # Linux on domain network

# Anonymous LDAP bind (if allowed)
ldapsearch -x -H ldap://<DC> -b "DC=corp,DC=local" -s base namingcontexts
```

### 1.2 Domain Enumeration (with initial access)
```bash
# Full domain dump via LDAP
ldapdomaindump -u 'DOMAIN\user' -p 'password' <DC> -o ./ldap-dump/

# Users
crackmapexec smb <DC> -u user -p pass --users > users.txt
# Or: impacket-GetADUsers -all -dc-ip <DC> DOMAIN/user:pass

# Computers
crackmapexec smb <DC> -u user -p pass --computers > computers.txt

# Groups (focus on privileged)
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net group "Schema Admins" /domain

# Password policy (CRITICAL — need before spraying)
crackmapexec smb <DC> -u user -p pass --pass-pol
# Note: lockout threshold, observation window, complexity
```

### 1.3 BloodHound Collection
```bash
# Python collector (from Linux, less AV detection)
bloodhound-python -u user -p 'pass' -d corp.local -ns <DC> -c all

# SharpHound (from Windows — more complete but triggers AV)
.\SharpHound.exe -c All --outputdirectory C:\temp\bh

# Import to BloodHound
# neo4j console → BloodHound GUI → drag drop ZIP

# Key queries after import:
# - Shortest path to Domain Admin
# - Kerberoastable users
# - AS-REP roastable users
# - Users with DCSync rights
# - Unconstrained delegation computers
# - ADCS ESC1-ESC8 paths
```

### 1.4 Service Enumeration
```bash
# SMB shares (null session + authenticated)
crackmapexec smb <subnet>/24 -u '' -p '' --shares
crackmapexec smb <subnet>/24 -u user -p pass --shares

# MSSQL instances
crackmapexec mssql <subnet>/24 -u user -p pass

# Find SPNs (service accounts)
impacket-GetUserSPNs -dc-ip <DC> DOMAIN/user:pass

# ADCS (Certificate Authority)
certipy find -u user@corp.local -p 'pass' -dc-ip <DC> -stdout
```

### 1.5 Output
Document in `phase1-recon/domain-info.md`:
- Domain name, functional level, forest structure
- DC hostnames and IPs
- Password policy (lockout threshold!)
- Trust relationships
- Key groups and membership counts
- ADCS presence and templates
