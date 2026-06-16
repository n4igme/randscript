# Proven Patterns — Thick Client

Patterns that generalize across thick client engagements. Add real engagement lessons here.

## High-Yield Patterns

| Trigger | Technique | Expected Yield |
|---------|-----------|---------------|
| Electron app | `npx asar extract` → full JS source in 10 seconds | Hardcoded keys, API endpoints, auth logic |
| .NET app | dnSpy decompile → search "password\|connectionstring\|secret" | Plaintext creds in 60% of internal apps |
| Java desktop | Check launcher .bat/.sh for `-D` flags | Trust store paths, proxy config, debug flags |
| Any Windows app | Process Monitor → filter NAME NOT FOUND + .dll | DLL hijack in writable path (common in installer dirs) |
| App with "Remember me" | Check %AppData%/{app}/ for SQLite/JSON | Tokens stored in plaintext |
| App with update check | Intercept update URL | HTTP update = MitM code execution |
| .NET with license | Search IL for "license\|trial\|expire" | Client-side check only (patch return value) |
| App writing temp files | Monitor %TEMP% during operations | Sensitive data in temp (deleted but recoverable) |

## Anti-Patterns (Things That Waste Time)

- RE'ing native obfuscated license on internal pentest — low severity, high effort
- Trying to proxy apps that use certificate pinning before checking if `--ignore-certificate-errors` flag works
- Fuzzing thick client inputs before mapping the API — proxy traffic first, fuzz the API directly
- DLL hijack in Program Files — requires admin already (Low severity)
