# ptest Tool Architecture (June 2026)

## CLI

Auto-detects scan type from target — no `--scan-type` flag needed:

```
ptest <target> [OPTIONS]

Auto-detection:
  domain/URL           → web      (jago.com, https://api.jago.com)
  IP/CIDR              → host     (10.10.1.1, 192.168.1.0/24)
  .apk file            → mobile   (./app.apk)
  .ipa file            → mobile   (./app.ipa)
  .exe/.dll/.msi       → desktop  (./app.exe)
  .app bundle          → desktop  (./App.app)
  ELF binary           → desktop  (./binary — magic bytes check)
  Postman JSON         → scode    (./collection.json)
  Bruno dir (.bru)     → scode    (./bruno-api/)
  Directory            → scode    (./src/)

Options:
  -p --profile    stealth|normal|aggressive|brutal
  -c --cookie     Auth token
     --cookie-b   Second user (IDOR)
  -m --modules    Filter specific modules
     --resume     Resume from phase
     --type       Override auto-detection
     --config     Explicit config YAML
```

## Config Files

`.ptest/<target>.yaml` auto-discovered by domain:

```yaml
profile: aggressive
cookie: "Bearer eyJ..."
cookie_b: "Bearer eyJuserB..."
refresh_url: "https://api.target.com/v1/auth/refresh"
refresh_token: "eyJrefresh..."
timeout: 7200
modules:
  - sqli
  - ssrf
  - idor
```

## Profiles (Damage Tiers)

Each tier unlocks a CATEGORY of test, not just bigger numbers:

| Profile | Philosophy | Unlocks |
|---------|-----------|---------|
| stealth | Don't touch anything | Passive only. Zero payloads. |
| normal | Test but don't break | Active read-only. No blind/write. |
| aggressive | Full test, break what I need | Blind, OOB, write IDOR, auth bypass. |
| brutal | Availability impact accepted | Lockout, rate exhaust, DoS probe, data mutation. |

## Scan Pipelines

### Web (4-phase)
recon → discover → hunt → report
- 19 attack modules (auto-discovered from modules/ dir)
- WAF-adaptive payloads
- Extended: actuator scan, prometheus batch, broken auth detection, source maps

### Host
DNS → nmap -sV → service probes → searchsploit → NSE → SSL → per-port web

### Mobile
- Android: apktool + jadx → manifest → secrets → crypto → WebView/JS bridge → deeplink traversal → content providers → native libs → network config → deserialization → Semgrep → API hunt
- iOS: unzip → Info.plist → entitlements → binary strings → frameworks → ATS → URL schemes → API hunt

### Desktop
- PE: imports (16 suspicious), DLL hijack, persistence (5 patterns), secrets, endpoints → web hunt
- ELF: PIE, NX, RELRO, stack canary, SUID, missing libs, secrets
- macOS: codesign, entitlements, @rpath dylib hijack, secrets

### Scode
- Semgrep primary (8 rulesets for aggressive), regex fallback (62 patterns)
- Extended: Node.js (10), Spring Boot (14), API (6), Auth/Session (7)
- FP suppression: skips test dirs, ORM parameterized queries
- Collection mode: Postman v2.x parsing + Bruno .bru parsing → secrets + endpoint hunt

## Key Modules

### web_extended.py (proven techniques)
- `spring_boot_actuator_scan()` — 14 actuator paths, per-prefix
- `_prometheus_uri_batch()` — extract URIs from metrics, test each unauth
- `broken_auth_detection()` — "500 not 401" pattern (systematic BAC)
- `spa_proxy_prefix_bypass()` — test API paths via SPA base prefix
- `detect_spa_catchall()` — same size all paths = skip (FP prevention)
- `rate_limit_bypass_test()` — XFF + device-id rotation
- `predictable_reset_token_test()` — MD5/SHA1/SHA256(email) as token
- `nextjs_source_map_scan()` — /_next/static/chunks/*.js.map

### mobile_extended.py (from mtest skill)
- `detect_framework()` — Flutter/RN/Xamarin/Unity detection
- `check_webview_js_bridge()` — @JavascriptInterface exposure
- `check_deeplink_traversal()` — Intent.parseUri, getLastPathSegment
- `check_content_providers()` — SQL injection in query(), openFile traversal
- `check_intent_redirect()` — forwarded parcelable intents
- `check_native_libs()` — system/exec/popen, strcpy/sprintf in .so
- `check_network_security_config()` — cleartext, user CAs, no pinning
- `check_deserialization()` — ObjectInputStream, Jackson, SnakeYAML
- `check_crypto_depth()` — ECB, hardcoded key/IV, PIN keyspace
- `check_binary_protections()` — ProGuard/R8 obfuscation detection

## File Layout

```
ptest/
  main.py               CLI (typer) + auto-detection
  config.py             ScanConfig, Profile, rates
  models.py             Target, Finding, ScanResult, ScanType enum
  sessions.py           Session persistence/resume
  pipeline/
    __init__.py         run_scan() — 4-phase orchestration
    orchestrator.py     Route by scan type
    recon.py            Subdomains, DNS, fingerprint
    discover.py         Crawl, JS, OpenAPI, brute
    hunt.py             Module dispatch + OOB + evidence
    signals.py          Signal expansion
    report.py           JSON/MD/SARIF/templates/repro
    host.py             Port scan + services + SSL
    mobile.py           APK/IPA pipelines
    mobile_extended.py  10 extended checks
    desktop.py          PE/ELF/Mach-O pipelines
    scode.py            Source code + collection routing
    scode_extended.py   37 framework-specific patterns
    semgrep.py          Semgrep engine wrapper
    collection.py       Postman/Bruno parsing
    web_extended.py     7 proven attack techniques
    cve_scan.py         searchsploit + NSE
    service_probes.py   FTP/SSH/SMB probes
  modules/              19 auto-discovered BaseModule subclasses
  tools/                HTTP client, auth, OOB, evidence, plugins
  scoring/              CVSS, fingerprint, WAF feedback, depth
  reporting/            SARIF, H1/YWH/Immunefi templates, repro scripts
```
