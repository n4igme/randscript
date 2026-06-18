# AD Pentest Pitfalls

Grouped by attack phase. Check here before attempting a technique.

## Credential Spraying

- NEVER spray more than 2 passwords per lockout window — check policy FIRST
- Account lockouts triggered → STOP immediately, switch to passive methods (Responder, relay)

## Enumeration & Collection

- BloodHound collection with SharpHound triggers AV — use BOF version or Python collector (bloodhound-python)
- findDelegation.py FIRST — run immediately after getting domain creds. Constrained delegation on non-DC accounts = instant privesc path
- dacledit.py credential quoting: when password contains `$`, use single-quotes with `\$` escaping (e.g., `'secops.local/Alex:\$mypassword\$12'`)

## Relay & Coercion

- LDAP SIGNING CHECK FIRST — `ldap3.Connection` with NTLM auth (no signing). Bind succeeds = signing not required = relay viable. Do this BEFORE any relay attempt.
- NTLM relay: signing enabled = relay blocked. Check LDAP signing + SMB signing before investing in relay setup.
- Responder: only poison in authorized subnet — can disrupt production
- COERCION VALIDATION — mimikatz `misc::spooler` "Access is denied (can be OK)" DOES trigger auth. Always capture with smbserver.py first to PROVE the callback arrives before investing in relay setup. Proven workflow: (1) smbserver.py to capture hash, (2) kill smbserver + start ntlmrelayx, (3) re-trigger coercion.
- PRINTERBUG RELAY TOPOLOGY: SpoolSvc accessible ≠ exploitable. The DC must CONNECT BACK to your listener on port 445. In segmented networks, DC may only reach the member server which already has SMB bound — no relay possible without port conflict resolution.
- RBCD silent failure: PowerShell `SetInfo()` on `msDS-AllowedToActOnBehalfOfOtherIdentity` returns NO ERROR even without write access — always verify with read-back. Machine accounts can't write RBCD on DCs.

## Kerberos

- Kerberoast: RC4 tickets crack fast, AES tickets are nearly impossible — prioritize RC4 SPNs
- Golden/Silver tickets: powerful but loud — use for proof, not persistence in pentests

## ADCS

- ESC1-ESC8 each have different prereqs — `certipy find -vulnerable` maps them all in one command

## DPAPI

- Domain user masterkey: needs domain backup key (requires DA) OR user's cleartext password
- Local user masterkey: needs user's cleartext password (NTLM hash alone insufficient on newer Windows with SHA-512/AES-256 masterkeys)
- Server 2022: SHA-512/AES-256 masterkeys resist NTLM-hash-only decryption. Need cleartext password or domain backup key. DPAPI_SYSTEM only decrypts backup portion.
- If you can't get the required key within 30 min, SKIP and pursue other escalation paths
- Mimikatz `vault::cred /patch`: works for SYSTEM-context vault credentials without needing DPAPI masterkey decryption. Best quick-win for stored cmdkey credentials.

## Privilege Escalation

- Domain trust: child→parent trust is exploitable via SID History injection — always check trust relationships
- Machine account DCSync: WORKSTATION_TRUST_ACCOUNT (UAC 4096) does NOT have replication rights — error 0x20f7. Only DCs and accounts with explicit DS-Replication-Get-Changes ACE can DCSync.
- GPP passwords: still found in legacy environments — `crackmapexec smb <DC> -u user -p pass -M gpp_autologin`

## Tooling (Impacket)

- **Recommended version:** v0.10.0 (most stable for relay attacks)
- v0.13.x: ntlmrelayx segfaults on SMB handler after accepting connection
- v0.9.24: missing dsinternals (LDAP attack fails)
- Version check: `python3 -c "import impacket; print(impacket.__version__)"`
- Downgrade: `pip3 install impacket==0.10.0`
- Custom SMB ports: impacket tools don't support them natively. Use SSH local port forwarding (`-L 4445:DC:445`) then connect via Python SMBConnection with `sess_port=4445`. secretsdump.py cannot use custom ports — use the Python API directly.

## Tooling (Mimikatz)

- Modern Windows: needs SeDebugPrivilege + bypass AMSI/ETW + avoid Defender
- Use for proof/extraction, not as primary attack vector on hardened hosts
