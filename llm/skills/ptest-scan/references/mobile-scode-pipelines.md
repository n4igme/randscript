# Mobile & Scode Pipeline Reference

## Mobile Pipeline (`pipeline/mobile.py`)

### Flow
```
apktool + jadx (parallel decompile)
  → manifest analysis
  → endpoint extraction (URL regex on .java files)
  → secret scanning (8 patterns: AWS keys, API keys, passwords, etc.)
  → weak crypto detection (8 patterns: DES, ECB, MD5, custom TrustManager)
  → deeplink extraction (custom URI schemes)
  → insecure storage (SharedPrefs, embedded SQLite)
  → API hunt (group endpoints by host, run web modules on reachable ones)
```

### Prerequisites
- `apktool` — decompile resources + manifest
- `jadx` — decompile to Java source

### CLI
```bash
ptest scan app --scan-type mobile --apk-path ./app.apk --cookie "Bearer ..."
```

### Key Design
- Parallel decompile: apktool (resources) + jadx (source) run concurrently
- Endpoint extraction filters out noise (schemas.android.com, play.google.com, images)
- API hunt caps at 5 hosts, does reachability check before full module scan
- Manifest checks: debuggable, allowBackup, cleartextTraffic, exported without permission, dangerous permissions

## Scode Pipeline (`pipeline/scode.py`)

### Flow
```
language detection (Python/JS/TS/Java/Go/Ruby/PHP/C#)
  → dependency scanning (9 known vuln package patterns)
  → vulnerability pattern scanning (25 patterns across all files)
```

### CLI
```bash
ptest scan repo --scan-type scode --repo-path ./myapp
```

### Vuln Pattern Categories (25 total)
- SQL Injection (3): concatenation, f-string, format
- Command Injection (3): Python os.system/subprocess, JS child_process, Java Runtime.exec
- Path Traversal (1): file ops with user input
- SSRF (1): HTTP client with user-controlled URL
- Insecure Deserialization (2): pickle, yaml.load, unserialize
- XSS (2): unescaped templates, DOM manipulation
- Hardcoded Secrets (3): generic, AWS keys, private keys
- Weak Crypto (2): MD5/SHA-1, DES/RC4/ECB
- Auth Issues (2): JWT none alg, hardcoded JWT secret
- CORS (1): wildcard origin
- Debug/Info (2): debug mode, stack trace exposure
- Open Redirect (1): user-controlled redirect
- XXE (2): Java DocumentBuilderFactory, Python etree

### Dependency Patterns (9)
lodash, express, serialize-javascript, node-serialize, PyYAML, Django, Flask, Spring, handlebars

### Skip Dirs
node_modules, .git, __pycache__, venv, vendor, target, build, dist, test, migrations

### ScanType Rename
- Previously: `ScanType.CODE_REPO` / `--scan-type code_repo`
- Now: `ScanType.SCODE` / `--scan-type scode`
- User preference: "scode" is shorter and matches the existing `scode` security skill name
