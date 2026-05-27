# mtest References Index

Quick lookup for which reference file to load based on what you're working on.

## By Discovery

| What you found | Load reference |
|---|---|
| Starting a new engagement / app type unknown | `app-type-decision-tree.md` |
| Bug bounty (not internal pentest) | `bug-bounty-fast-path.md` |
| Deep links routing to WebViews | `deeplink-webview-hijack.md`, `deeplink-webview-bridge-attacks.md` |
| Deep link with path/file parameters | `deep-link-path-traversal.md` |
| WebView with `addJavascriptInterface` | `webview-js-bridge-attacks.md` |
| DexGuard / AppFence / root detection | `dexguard-appfence-bypass.md`, `ghidra-mcp-workflow.md`, `operational-notes.md` |
| Native .so libraries with JNI | `native-re-mcp.md`, `native-buffer-overflow.md` |
| `System.load()` from writable path | `android-path-traversal-rce.md` |
| SnakeYAML `yaml.load()` | `yaml-deserialization-rce.md` |
| ObjectInputStream / XMLDecoder / polymorphic JSON | `deserialization-attacks.md` |
| Exported ContentProvider | `content-provider-attacks.md` |
| Hardcoded encryption keys / small keyspace | `crypto-key-cracking.md` |
| Banking/fintech app patterns | `banking-app-patterns.md` |
| API endpoints extracted | `api-testing.md` |
| SSL pinning / proxy setup needed | `traffic-analysis.md`, `dynamic-setup.md`, `flutter-ssl-bypass.md` |
| Eversafe SDK / device attestation | `eversafe-attestation.md` |
| Need Frida hook templates | `frida-scripts.md` |
| OWASP classification needed | `owasp-mobile-top10.md` |

## By Phase (v2.0.0 — 10 phases)

| Phase | Relevant references |
|---|---|
| Phase 1 (Preflight) | `preflight-checklist.md` |
| Phase 2 (Static Analysis) | `static-analysis.md`, `native-re-mcp.md`, `android-path-traversal-rce.md`, `crypto-key-cracking.md`, `native-buffer-overflow.md`, `deserialization-attacks.md`, `yaml-deserialization-rce.md`, `content-provider-attacks.md`, `deeplink-webview-hijack.md`, `deeplink-webview-bridge-attacks.md`, `webview-js-bridge-attacks.md`, `deep-link-path-traversal.md` |
| Phase 3 (Protection Bypass) | `dynamic-setup.md`, `dexguard-appfence-bypass.md`, `frida-scripts.md`, `flutter-ssl-bypass.md`, `eversafe-attestation.md` |
| Phase 4 (Traffic Analysis) | `traffic-analysis.md`, `banking-app-patterns.md`, `burp-mcp-integration.md` |
| Phase 5 (Attack Surface Mapping) | — (uses output from Phases 2+4) |
| Phase 6 (Runtime Testing) | `runtime-testing.md`, `frida-scripts.md`, `deep-link-path-traversal.md`, `deeplink-webview-hijack.md`, `native-buffer-overflow.md` |
| Phase 7 (Vuln Analysis) | `owasp-mobile-top10.md`, `content-provider-attacks.md`, `webview-js-bridge-attacks.md` |
| Phase 8 (API Testing) | `api-testing.md`, `banking-app-patterns.md` |
| Phase 9 (Exploitation) | `android-path-traversal-rce.md`, `native-buffer-overflow.md`, `crypto-key-cracking.md` |
| Phase 10 (Reporting) | `owasp-mobile-top10.md` |

## All Reference Files (alphabetical)

| File | Description |
|---|---|
| `android-path-traversal-rce.md` | Path traversal via deep links leading to native library hijack and RCE |
| `api-testing.md` | Server-side API testing techniques for mobile backends |
| `app-type-decision-tree.md` | App categorization (banking/social/utility/game/Flutter) with per-type testing priorities |
| `banking-app-patterns.md` | Common patterns in banking/fintech apps (auth, pinning, attestation) |
| `bug-bounty-fast-path.md` | Speed-run workflow for finding one Critical/High fast (4-8 hour budget) |
| `content-provider-attacks.md` | Exported ContentProvider exploitation (SQL injection, path traversal, brute-force) |
| `crypto-key-cracking.md` | Offline cracking of hardcoded/weak encryption keys and small keyspaces |
| `deep-link-path-traversal.md` | Path traversal via deep link parameters to read/write arbitrary files |
| `deeplink-webview-bridge-attacks.md` | Chaining deep links → WebView → JavaScript bridge for RCE |
| `deeplink-webview-hijack.md` | Deep link handlers that pass unvalidated URLs to WebViews |
| `deserialization-attacks.md` | Java/Android deserialization exploitation (ObjectInputStream, XMLDecoder, Jackson) |
| `dexguard-appfence-bypass.md` | Bypassing DexGuard/AppFence root and Frida detection (includes RE methodology) |
| `dynamic-setup.md` | Device setup, proxy config, CA installation, and bypass preparation |
| `eversafe-attestation.md` | Eversafe SDK token architecture, replay technique, staging vs production behavior |
| `flutter-ssl-bypass.md` | Flutter BoringSSL pinning bypass via pattern scanning in libflutter.so |
| `frida-scripts.md` | Reusable Frida script templates for common hooks |
| `ghidra-mcp-workflow.md` | Ghidra MCP workflow for AppFence native library RE |
| `native-buffer-overflow.md` | Buffer overflow exploitation in Android native libraries |
| `native-re-mcp.md` | Native library reverse engineering using Ghidra/r2 MCP integration |
| `operational-notes.md` | Battle-tested patterns: DexGuard, Eversafe, Flutter SSL, hluda, Frida pitfalls, device connectivity, attack patterns, Unity/IL2CPP |
| `owasp-mobile-top10.md` | OWASP Mobile Top 10 mapping and classification guidance |
| `preflight-checklist.md` | Tool verification and environment setup checklist |
| `runtime-testing.md` | Dynamic runtime testing techniques (data storage, IPC, biometrics) |
| `static-analysis.md` | Static analysis methodology and automated scanning |
| `traffic-analysis.md` | Network traffic interception, API mapping, and auth flow analysis |
| `webview-js-bridge-attacks.md` | Exploiting @JavascriptInterface methods exposed to WebView |
| `yaml-deserialization-rce.md` | SnakeYAML arbitrary object instantiation and RCE chains |
