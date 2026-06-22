# Attack Recipes — mtest

## Static Analysis Patterns

| Vector | Tool | Target |
|--------|------|--------|
| Hardcoded secrets | grep/semgrep | API keys, tokens, passwords in APK/IPA |
| Insecure storage | objection | SharedPrefs, Keychain, SQLite |
| Debug flags | jadx | `android:debuggable`, `NSAppTransportSecurity` |
| Exported components | manifest | Activities, providers, receivers |

## Runtime Patterns

| Vector | Technique | Notes |
|--------|-----------|-------|
| SSL pinning bypass | Frida script | Use objection or custom hooks |
| Root/jailbreak bypass | Frida | Patch detection functions |
| Biometric bypass | Frida | Hook authentication callbacks |
| Intent injection | adb | `am start -n pkg/.Activity --es key val` |

## API Discovery via Traffic

| Technique | Tool | Output |
|-----------|------|--------|
| Passive intercept | Burp/mitmproxy | Full API map from app usage |
| Certificate unpin + browse | Frida + Burp | Hidden admin endpoints |
| WebSocket monitoring | Burp | Real-time data channels |
| GraphQL introspection | curl | Full schema if enabled |

## Common Mobile Vulns

1. **Insecure data storage** — plaintext tokens in SharedPreferences
2. **Missing certificate pinning** — MitM on sensitive traffic
3. **Exported activities** — bypass authentication screens
4. **Deep link injection** — navigate to privileged screens
5. **WebView JavaScript bridge** — access native functions from web
6. **Clipboard leakage** — sensitive data copied to clipboard
7. **Backup extraction** — `android:allowBackup=true` data theft

## Geo-Restriction Bypass

See `references/geo-restriction-bypass.md` for dedicated techniques.

[Expand with engagement-specific recipes as discovered]
