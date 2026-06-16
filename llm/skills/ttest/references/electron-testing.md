# Electron App Testing

## Quick Start

```bash
# Extract source (plaintext JS/HTML/CSS)
npx asar extract resources/app.asar ./extracted/

# If app.asar doesn't exist, check resources/app/ directory (unpacked)

# Launch with debug + proxy
./app --inspect=9229 --proxy-server="http://127.0.0.1:8080" --ignore-certificate-errors

# Open DevTools in running app (if not disabled)
# Ctrl+Shift+I or --remote-debugging-port=9222
```

## Key Attack Vectors

### 1. nodeIntegration XSS → RCE
If `nodeIntegration: true` in BrowserWindow config:
```javascript
// Any XSS becomes RCE
require('child_process').exec('calc.exe')
```
Check: `grep -r "nodeIntegration" extracted/ | grep -v "false"`

### 2. contextIsolation Disabled
If `contextIsolation: false`:
```javascript
// Renderer process can access Node.js via preload script globals
window.myAPI.exec('id')  // If preload exposes dangerous APIs
```
Check: `grep -r "contextIsolation" extracted/ | grep -v "true"`

### 3. Preload Script Analysis
```bash
# Find preload scripts
grep -r "preload" extracted/ | grep -v node_modules
# Review what APIs they expose to renderer
grep -r "contextBridge.exposeInMainWorld" extracted/
```

### 4. IPC Message Abuse
```bash
# Find IPC handlers
grep -r "ipcMain.handle\|ipcMain.on" extracted/
# Find IPC sends (what renderer can request)
grep -r "ipcRenderer.invoke\|ipcRenderer.send" extracted/
# Look for dangerous operations: file read/write, exec, shell
```

### 5. Protocol Handler Hijacking
```bash
# Custom protocol registration
grep -r "protocol.register\|app.setAsDefaultProtocolClient" extracted/
# Test: open malicious deep link → code execution?
```

### 6. Local Storage / Credentials
```bash
# Electron stores data in:
# Linux: ~/.config/{app}/
# macOS: ~/Library/Application Support/{app}/
# Windows: %AppData%/{app}/

# Check for:
ls ~/Library/Application\ Support/{app}/
# - Local Storage/          (localStorage data)
# - IndexedDB/             (structured data)
# - Cookies                (session tokens)
# - GPUCache/              (sometimes leaks URLs)
```

## Severity Map

| Finding | Severity | Condition |
|---------|----------|-----------|
| nodeIntegration:true + XSS sink | Critical | Any user input rendered = RCE |
| contextIsolation:false + dangerous preload | High | Preload exposes file/exec APIs |
| IPC handler without validation | High | Renderer can trigger privileged ops |
| Hardcoded API keys in source | Medium-High | Depends on key scope |
| Insecure update (HTTP, no signature) | High | MitM → code execution |
| Protocol handler without sanitization | Medium-High | Deep link → command injection |

## Pitfalls

- `app.asar` is NOT encrypted — just a tar-like archive
- Some apps use `asarIntegrity` — patching asar triggers integrity check (bypass by removing the check)
- Electron v12+ defaults to `contextIsolation: true` — older apps are more vulnerable
- `sandbox: true` on BrowserWindow restricts renderer significantly — check if actually set
- DevTools may be disabled via `Menu.setApplicationMenu(null)` — bypass with `--inspect` flag
