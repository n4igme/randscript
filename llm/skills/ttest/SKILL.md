---
name: ttest
version: 1.0.0
description: "Thick client (desktop application) penetration testing — .NET, Java, Electron, native Win/Mac apps. Proxy, local storage, business logic, DLL hijacking."
tags: [thick-client, desktop, pentest, dotnet, electron, java, windows]
trigger: "thick client pentest, desktop app test, .NET app test, Electron test, Java desktop test, WinForms test, WPF test"
argument-hint: "<command: start|status|resume|next|report|abort|cleanup>"
metadata:
  hermes:
    tags: [thick-client, desktop, pentest, dotnet, electron, java, windows]
    related_skills: [ptest, retools, xdev, atest, scode]
---

# Thick Client Penetration Testing Framework

5-phase workflow for desktop application security testing. Fills the gap between web (ptest), mobile (mtest), and binary exploitation (xdev).

## Quick Reference

```
Phases:  1.Recon&Setup → 2.Traffic → 3.LocalAnalysis → 4.BusinessLogic → 5.Report
States:  LOCKED → OPEN → PASSED (sequential)
Commands: start | status | next | resume | report | abort | cleanup

Key rules:
  • Identify app type FIRST — .NET/Java/Electron/Native dictate toolchain
  • Traffic interception is harder than web — expect non-HTTP protocols
  • Local storage is the #1 source of findings in thick clients
  • Client-side logic bypass is almost always possible — prove it
  • DLL hijacking / sideloading = easy High finding on Windows

Cross-skill integration:
  • HTTP/API traffic found → hand to atest
  • Source code recovered (.NET/Java decompile) → hand to scode
  • Memory corruption found → hand to xdev
  • Binary RE needed → hand to retools
```

## Architecture

```
Phase 1: Recon & Setup → Phase 2: Traffic Analysis → Phase 3: Local Analysis → Phase 4: Business Logic → Phase 5: Reporting
```

## Commands

| Command | Action |
|---------|--------|
| `start` | Initialize engagement — identify app type, setup proxy, create output dir |
| `status` | Show current phase, progress, findings count |
| `resume` | Resume interrupted engagement from last checkpoint |
| `next` | Advance to next phase (runs exit criteria check) |
| `report` | Generate final report |
| `abort` | Terminate engagement early |
| `cleanup` | Archive output, remove test artifacts |

## App-Type Decision Tree

```
What type of thick client?
│
├── .NET (WinForms / WPF / MAUI)
│   ├── Decompile: dnSpy, ILSpy, dotPeek
│   ├── Patch: dnSpy (edit + recompile IL)
│   ├── Proxy: Fiddler (auto .NET proxy), Burp (manual proxy settings)
│   ├── Local: %AppData%/Local, registry, SQLite, ProtectedData (DPAPI)
│   └── Key findings: hardcoded creds, DPAPI blobs, DLL hijack, license bypass
│
├── Java (Swing / JavaFX / Eclipse RCP)
│   ├── Decompile: JADX, JD-GUI, CFR, Procyon
│   ├── Patch: recaf, reassemble JAR
│   ├── Proxy: -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=8080
│   ├── Local: ~/.app/, preferences API, serialized objects
│   └── Key findings: hardcoded keys, deserialization, trust-all-certs, license bypass
│
├── Electron (Node.js + Chromium)
│   ├── Decompile: asar extract (plaintext JS/HTML/CSS)
│   ├── Patch: modify app.asar directly
│   ├── Proxy: --proxy-server="http://127.0.0.1:8080" flag
│   ├── Local: %AppData%/{app}/, IndexedDB, localStorage, keytar
│   ├── Key findings: nodeIntegration XSS→RCE, preload script abuse, IPC abuse
│   └── Reference: `references/electron-testing.md`
│
├── Native (C/C++ / Delphi / Qt)
│   ├── Decompile: Ghidra, IDA, x64dbg
│   ├── Patch: binary patching (x64dbg, Ghidra)
│   ├── Proxy: Proxifier (system-wide), custom hosts file
│   ├── Local: registry, AppData, custom file formats
│   └── Key findings: buffer overflow, DLL hijack, hardcoded crypto keys
│
└── Hybrid (CEF / WebView2 / Qt WebEngine)
    ├── Treat as web app in a shell — Chrome DevTools often available
    ├── Proxy: Proxifier or --proxy-server flag
    ├── DevTools: --remote-debugging-port=9222
    └── Key findings: same as web (XSS, CSRF) + local file access escalation
```

## Phase Routing

| Phase | Gate | Reference |
|-------|------|-----------|
| 1 Recon & Setup | App type identified, proxy working, tools ready | `references/phase1-recon-setup.md` |
| 2 Traffic Analysis | All protocols intercepted, API surface mapped | `references/phase2-traffic.md` + `references/non-http-protocol-testing.md` |
| 3 Local Analysis | Storage audited, secrets scanned, DLL hijack tested | `references/phase3-local-analysis.md` |
| 4 Business Logic | Client-side controls bypassed, license/auth tested | `references/phase4-business-logic.md` |
| 5 Reporting | All findings documented with PoCs | (inline below) |

## Effort Allocation

| Phase | % | 4-hour engagement | 8-hour engagement |
|-------|---|-------------------|-------------------|
| 1 Recon & Setup | 15% | 35 min | 70 min |
| 2 Traffic | 25% | 60 min | 120 min |
| 3 Local Analysis | 25% | 60 min | 120 min |
| 4 Business Logic | 25% | 60 min | 120 min |
| 5 Reporting | 10% | 25 min | 50 min |

## Cross-Skill Triggers

| Signal | Target Skill | Action |
|--------|-------------|--------|
| HTTP/REST API traffic captured | atest | Full API pentest Phase 2+ |
| .NET/Java source recovered | scode | Code review (scope_type: desktop) |
| Buffer overflow in native lib | xdev | Exploit development |
| Binary needs deep RE | retools | Ghidra/IDA analysis |
| Web endpoints discovered | ptest | Standard web pentest |
| Cloud storage/API keys found | ctest | Cloud access testing |

## Pitfalls

- .NET `ProtectedData` (DPAPI): decryptable only as same user on same machine — prove it, don't assume
- Electron `app.asar`: NOT encrypted. `npx asar extract app.asar ./extracted/` gives full source
- Java `-Djavax.net.ssl.trustStore`: custom trust stores bypass system proxy — find and add your CA
- DLL hijacking: test in ISOLATED environment — wrong DLL path can crash production systems
- Proxifier: process-level rules, not system-wide. Match exact executable name.
- Non-HTTP protocols: Wireshark first to identify, THEN choose interception tool
- License bypass alone is often "accepted risk" for internal apps — chain with data access for impact
