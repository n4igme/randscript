# Phase 3: Local Analysis

## Gate: Storage audited, secrets scanned, DLL hijack tested

## Steps

### 3.1 File System Analysis

**Windows paths to check:**
```
%AppData%\{app}\           # Roaming app data
%LocalAppData%\{app}\      # Local app data
%ProgramData%\{app}\       # Shared app data
%ProgramFiles%\{app}\      # Install directory
%TEMP%\{app}*              # Temp files (often leaked data)
```

**What to look for:**
- SQLite databases (`.db`, `.sqlite`, `.sqlite3`)
- Config files (`.ini`, `.config`, `.json`, `.xml`, `.yaml`)
- Log files (credentials in debug logs)
- Cache files (auth tokens, session data)
- License files (crack targets)

```bash
# Quick secrets scan on install dir
strings -n 8 *.dll *.exe | grep -iE "password|secret|api.?key|token|connectionstring"

# Find SQLite databases
find /path/to/app -name "*.db" -o -name "*.sqlite*" 2>/dev/null

# Scan config files
grep -rl "password\|secret\|key\|token" /path/to/app/config/
```

### 3.2 Registry Analysis (Windows)

```powershell
# Export app registry keys
reg export "HKCU\Software\{vendor}\{app}" app_registry.reg
reg export "HKLM\Software\{vendor}\{app}" app_registry_machine.reg

# Search for secrets
reg query "HKCU\Software\{vendor}" /s | findstr /i "password secret key token"
```

**Common findings:**
- Plaintext credentials in registry values
- License keys stored in cleartext
- Server URLs (internal endpoints)
- User preferences revealing functionality

### 3.3 DPAPI / Credential Storage

**.NET ProtectedData:**
```csharp
// If you find base64 blobs in config, try DPAPI decrypt:
// Only works as same user on same machine
byte[] decrypted = ProtectedData.Unprotect(blob, null, DataProtectionScope.CurrentUser);
```

**Windows Credential Manager:**
```powershell
# List stored credentials
cmdkey /list
# Or via PowerShell
Get-StoredCredential -Target "{app}*"
```

### 3.4 DLL Hijacking / Sideloading

**Testing methodology:**
1. Use Process Monitor (Sysinternals) — filter: `Process Name = app.exe`, `Result = NAME NOT FOUND`, `Path ends with .dll`
2. Any DLL loaded from a writable path = DLL hijack vector
3. Create proof DLL (calc.exe popup or write file)

```c
// Minimal proof DLL (compile with mingw)
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // PoC: create evidence file
        HANDLE h = CreateFile("C:\\temp\\dll_hijack_proof.txt",
            GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        WriteFile(h, "DLL hijacked", 12, NULL, NULL);
        CloseHandle(h);
    }
    return TRUE;
}
```

**Severity:**
- App runs as SYSTEM/admin + DLL hijack = High (privilege escalation)
- App runs as user + DLL hijack from user-writable path = Medium (persistence/code exec)
- App runs as user + DLL in Program Files = Low (requires admin already)

### 3.5 Memory Analysis

```bash
# Dump process memory and search for secrets
procdump -ma app.exe app_dump.dmp
strings app_dump.dmp | grep -iE "password|bearer|session|token"

# Or use Process Hacker → Properties → Memory → Strings
```

### 3.6 Temp File / IPC Analysis
- Monitor %TEMP% during app operations
- Check named pipes: `[IO.Directory]::GetFiles("\\.\pipe\") | findstr {app}`
- Check shared memory sections
- Log files often contain sensitive data in debug mode

## Handoff
If source code recovered via decompilation → invoke scode for full review.
