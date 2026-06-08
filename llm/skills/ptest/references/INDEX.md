# Reference File Index

Quick lookup: what you found → which reference to load.

**Stats:** 212 reference files. Last updated: 2026-06-05.

---

## By Discovery (what you encountered)

| You Found | Load This Reference |
|-----------|---|
| Valid credentials / JWT token / authenticated access | `authenticated-testing-playbook.md` |
| Spring Boot / actuator endpoint | `bulk-actuator-scanning.md`, `heapdump-secret-extraction.md`, `framework-specific-attacks.md` §7 |
| Keycloak / OAuth / OIDC | `keycloak-assessment.md`, `keycloak-gateway-exploitation.md`, `jwt-attack-techniques.md`, `oauth-sso-attack-chains.md` |
| Dynatrace instance | `dynatrace-cluster-probing.md`, `operational-pitfalls.md` (Dynatrace section) |
| Lucy / phishing platform | `lucy-security-assessment.md` |
| Camunda BPM | `camunda-bpm-assessment.md` |
| GraphQL endpoint | `graphql-websocket-testing.md` §1, `framework-specific-attacks.md` §6 |
| WebSocket endpoint | `graphql-websocket-testing.md` §2, `advanced-web-attacks.md` §1 |
| Serialized data (base64 blob, Java/PHP/.NET) | `insecure-deserialization.md` |
| XML input / SOAP / SAML / Content-Type: xml | `xxe-injection.md` |
| SAML / SSO login page | `saml-sso-assessment.md`, `xxe-injection.md` §11 |
| Cloudflare WAF / 403 | `cloudflare-bypass-techniques.md` |
| Cloudflare API Shield error | `cloudflare-bypass-techniques.md` §2 |
| Cloudflare Worker | `cloudflare-bypass-techniques.md` §3 |
| HTTP Request Smuggling indicators (CL/TE mismatch, H2 downgrade) | `http-request-smuggling.md` |
| Web cache (cf-cache-status, Age, X-Cache headers) | `web-cache-poisoning.md` |
| Host header reflection / password reset | `host-header-attacks.md` |
| File upload functionality | `file-upload-attacks.md` |
| Node.js / Express / Next.js backend | `prototype-pollution.md` |
| GCP IAP redirect | `cloud-infrastructure-enumeration.md` §1 |
| AWS CNAME (S3, Transfer, CloudFront) | `cloud-infrastructure-enumeration.md` §2, `s3-bucket-enumeration.md` |
| S3 bucket listing (ListBucketResult XML, application/xml large response) | `s3-bucket-enumeration.md` |
| CI/CD tool (ArgoCD, Atlantis, Airflow, n8n, Jenkins) | `cicd-pipeline-exploitation.md`, `cicd-devops-assessment.md`, `kubernetes-management-tooling.md` |
| ArgoCD / Grafana / Prometheus / Vault / Harbor exposed | `kubernetes-management-tooling.md` |
| Teleport remote access proxy exposed | `teleport-assessment.md` |
| Signed URL (GCS/S3) in API response | `signed-url-exploitation.md` |
| Callback / webhook / integration endpoint | `unauthenticated-callback-testing.md` |
| Alibaba Cloud WAF (Tengine, acw_tc cookie) | `intel-alibaba-cloud-infrastructure.md` |
| Kubernetes / GKE / container environment | `kubernetes-container-attacks.md`, `microservice-architecture-mapping.md` |
| Istio / Envoy headers | `kubernetes-container-attacks.md` §Istio, `operational-pitfalls.md` (Istio section) |
| SFTP / SSH port open | `non-http-protocol-testing.md` §2 |
| SMTP port open | `non-http-protocol-testing.md` §1 |
| OpenVPN-AS | `non-http-protocol-testing.md` §3 |
| Next.js application | `framework-specific-attacks.md` §1 |
| Laravel application | `framework-specific-attacks.md` §2 |
| Django application | `framework-specific-attacks.md` §3 |
| WordPress site | `framework-specific-attacks.md` §4 |
| Ruby on Rails application | `framework-specific-attacks.md` §5 |
| Mobile app (Android/iOS) | **Use `mtest` skill** (dedicated mobile pentest workflow) |
| Ghidra / binary RE / extension version mismatch | `ghidra-extension-building.md` |
| AI/LLM chatbot feature | `llm-ai-feature-testing.md` |
| DMARC p=none / SPF ~all | `dns-record-intelligence.md` §1-2 |
| Dangling CNAME / subdomain takeover | `subdomain-takeover.md` |
| Race condition opportunity | `advanced-web-attacks.md` §4 |
| User management testing (registration, auth, session, reset) | `web-testing-checklist.md` §1 |
| Application logic / business logic flaws | `web-testing-checklist.md` §2 |
| Security headers audit | `web-testing-checklist.md` §4 |
| CAPTCHA bypass | `web-testing-checklist.md` §2 (CAPTCHA) |
| WebAuthn / Passkeys / FIDO2 authentication | `webauthn-passkeys-testing.md` |
| Browser extension in scope | `browser-extension-security.md` |
| Internal network access / AD environment | `internal-ad-attacks.md` |
| Kerberos / Active Directory | `internal-ad-attacks.md` (Kerberoast, ASREPRoast, Golden/Silver ticket, delegation) |
| NTLM relay / Responder | `internal-ad-attacks.md` (LLMNR/NBT-NS poisoning, relay) |
| Windows privilege escalation | `internal-ad-attacks.md` (token impersonation, CVEs) |
| Cloud credentials found (AWS/GCP/Azure keys, tokens) | `cloud-privilege-escalation.md`, `credential-chaining.md` |
| Person / researcher / employee OSINT | `person-osint.md` |
| Google product (*.google.com SPA) | `google-spa-recon.md` |
| ByteDance / TikTok product (TLB, Goofy Deploy, Garfish, Arco Design) | `intel-bytedance-tiktok-infrastructure.md` |
| Source map (.js.map) accessible | `source-map-token-exploitation.md`, `js-bundle-recon.md` (Source Map section) |
| Clickstream / telemetry token in JS | `source-map-token-exploitation.md` (Telemetry Token section) |
| CORS `*` + Debug mode combined | `source-map-token-exploitation.md` (CORS + Debug section) |
| Flutter Web app (main.dart.js) | `source-map-token-exploitation.md` (Flutter/Proto section), `js-bundle-recon.md` |
| Protobuf bundle in JS (*-protos*.js) | `source-map-token-exploitation.md` (Flutter/Proto section) |
| Node.js library vuln (yauzl, adm-zip, require, path.join) | `nodejs-library-attacks.md` |
| Zip upload / archive extraction | `nodejs-library-attacks.md` §2, `web-vuln-bypass-tables.md` (Zip Slip) |
| Custom crypto / license key / proprietary validation | `proprietary-crypto-reversing.md` |
| SPA returning 200 for all paths (false positives) | `spa-false-positive-detection.md` |
| OAuth authorize endpoint / redirect_uri testing | `oauth-redirect-uri-testing.md`, `oauth-sso-attack-chains.md` |
| Need session cookies from Burp browser (MCP not working) | `burp-cookie-extraction.md` |
| Source code obtained (source map, git, debug, white-box) | **Invoke `scode` skill** (see main SKILL.md § Source Code Review Integration) |
| CSP report-uri with internal app name (`/_/{AppName}/cspreport`) | `js-bundle-recon.md` (technology fingerprinting), `framework-specific-attacks.md` |
| SPA / React / Angular / Vue frontend | `web-vuln-bypass-tables.md` (DOM XSS sources/sinks, postMessage, DOM clobbering) |
| SPA returning 200 for all paths (enumeration false positives) | `spa-false-positive-detection.md`, `false-positive-detection.md` §1 |
| CDN-fronted target (Akamai/Fastly/CF, port scan useless) | `cdn-fronted-js-recon.md`, `js-bundle-recon.md` |
| Bug bounty submission / report writing | `bug-bounty-submission-guide.md` |
| Multi-step attack chain (need to explain WHY) | `attack-chain-narrative-writing.md` |
| Telemetry token found (Clickstream, Faro, NR, Sentry) | `source-map-token-exploitation.md` (Telemetry Token Severity Classification) |
| Scope boundary question (related domain, same company) | `bug-bounty-submission-guide.md` (Scope Boundary Decisions) |
| Combining multiple findings into one report | `bug-bounty-submission-guide.md` (Multi-Finding Consolidation) |
| Public disclosure risk / PoC hosting | `bug-bounty-submission-guide.md` (Disclosure Policy) |
| Cache / CDN in front | `advanced-web-attacks.md` §2-3 |
| Partner API gateway (shared IP, 403) | `cloudflare-bypass-techniques.md` §4 |
| Microservice architecture | `microservice-architecture-mapping.md`, `kubernetes-container-attacks.md` |
| Credential found (heapdump, JS, CTI) | `credential-chaining.md`, `credential-inventory-structure.md` |
| MongoDB / NoSQL backend (JSON APIs) | `web-vuln-bypass-tables.md` (NoSQL injection), `graphql-websocket-testing.md` |
| CSRF / state-changing actions without token | `csrf-attacks.md` |
| JWT / token-based auth | `jwt-attack-techniques.md`, `keycloak-gateway-exploitation.md` |
| Snyk token found | `snyk-token-enumeration.md` |
| Path traversal / ingress bypass | `path-traversal-actuator-bypass.md`, `web-vuln-bypass-tables.md` (14 bypasses) |
| Access control / privilege escalation | `web-vuln-bypass-tables.md` (12 techniques), `phase6-exploitation-framework.md` §6.6 |
| Login / authentication / brute-force | `web-vuln-bypass-tables.md` (14 auth techniques), `jwt-attack-techniques.md`, `keycloak-assessment.md` |
| SSRF opportunity | `ssrf-outbound-forcing.md`, `web-vuln-bypass-tables.md` (SSRF) |
| API-heavy target / microservices / Swagger/OpenAPI | `api-first-methodology.md`, `authenticated-testing-playbook.md` |
| SSO/MFA login page with legacy endpoints | `legacy-protocol-bypass.md` |
| Multiple gateways / ingress / config drift | `gateway-misconfiguration-patterns.md` |
| OAuth / social login / "Login with..." | `web-vuln-bypass-tables.md` (10 OAuth attacks), `keycloak-assessment.md`, `csrf-attacks.md`, `oauth-sso-attack-chains.md` |
| Business logic (pricing, coupons, workflows) | `web-vuln-bypass-tables.md` (12 flaw categories), `signal-hunting-table.md` |

---


---

## By Phase (what you're doing)

| Phase | Relevant References |
|-------|-------------------|
| 1 — Passive Recon | `dns-record-intelligence.md`, `js-bundle-recon.md`, `source-map-token-exploitation.md`, `operational-pitfalls.md`, `person-osint.md` |
| 2 — Active Recon | `pattern-subdomain-bruteforce.md`, `nmap-cloud-targets.md`, `source-map-token-exploitation.md`, `operational-pitfalls.md` |
| 3 — Enumeration | `bulk-actuator-scanning.md`, `javascript-secret-scanning.md`, `source-map-token-exploitation.md`, `framework-specific-attacks.md`, `api-first-methodology.md` |
| 4 — Attack Surface | `depth-vs-breadth-decisions.md`, `cloud-infrastructure-enumeration.md` |
| 5 — Vuln Assessment | `web-vuln-bypass-tables.md`, `web-testing-checklist.md`, `false-positive-detection.md`, `web-cache-poisoning.md`, `host-header-attacks.md`, `http-request-smuggling.md` |
| 6 — Exploitation | `phase6-exploitation-framework.md`, `web-testing-checklist.md`, `jwt-attack-techniques.md`, `signal-hunting-table.md`, `attack-chain-framework.md`, `credential-chaining.md`, `re-validation-loops.md`, `advanced-web-attacks.md`, `insecure-deserialization.md`, `parameter-pollution.md`, `graphql-websocket-testing.md`, `kubernetes-container-attacks.md`, `cicd-pipeline-exploitation.md`, `prototype-pollution.md`, `file-upload-attacks.md`, `http-request-smuggling.md`, `host-header-attacks.md`, `oauth-sso-attack-chains.md`, `gateway-misconfiguration-patterns.md` |
| 7 — Post-Exploitation | `phase7-post-exploitation-framework.md`, `data-classification-framework.md` |
| 8 — Reporting | `phase8-reporting-process.md`, `time-box-enforcement.md`, `bug-bounty-submission-guide.md`, `attack-chain-narrative-writing.md` |

---


---

## By Vulnerability Class

| Vuln Class | Reference |
|-----------|-----------|
| SSRF | `web-vuln-bypass-tables.md` (11 IP bypasses), `ssrf-outbound-forcing.md` |
| IDOR | `web-vuln-bypass-tables.md` (8 variants), `signal-hunting-table.md` |
| Access Control | `web-vuln-bypass-tables.md` (12 techniques), `phase6-exploitation-framework.md` §6.6 |
| Path Traversal | `web-vuln-bypass-tables.md` (14 bypasses), `path-traversal-actuator-bypass.md` |
| XSS (reflected/stored) | `web-vuln-bypass-tables.md` (filter bypasses, encoding) |
| XSS (DOM-based) | `web-vuln-bypass-tables.md` (sources, sinks, postMessage, DOM clobbering, jQuery) |
| NoSQL Injection | `web-vuln-bypass-tables.md` (10 MongoDB techniques, $regex extraction, timing-based blind) |
| SQLi | `web-vuln-bypass-tables.md` |
| File Upload | `web-vuln-bypass-tables.md` (10 bypasses) |
| Open Redirect | `web-vuln-bypass-tables.md` (11 techniques) |
| Deserialization | `insecure-deserialization.md` (Java/PHP/.NET/Python/Ruby, gadget chains, type juggling) |
| Parameter Pollution | `parameter-pollution.md` |
| Race Condition | `graphql-websocket-testing.md` §Race, `advanced-web-attacks.md` §4 |
| Cache Poisoning | `advanced-web-attacks.md` §2 |
| HTTP Smuggling | `advanced-web-attacks.md` §3 |
| WebSocket | `graphql-websocket-testing.md` §2, `advanced-web-attacks.md` §1 |
| GraphQL | `graphql-websocket-testing.md` §1, `framework-specific-attacks.md` §6 |
| Container Escape | `kubernetes-container-attacks.md` |
| CI/CD Compromise | `cicd-pipeline-exploitation.md` |
| SSTI | `web-vuln-bypass-tables.md` (6 engines) |
| Authentication | `web-vuln-bypass-tables.md` (14 brute-force/bypass techniques), `jwt-attack-techniques.md` |
| JWT | `web-vuln-bypass-tables.md` (none/confusion), `jwt-attack-techniques.md` |
| OAuth 2.0 | `web-vuln-bypass-tables.md` (10 attacks), `keycloak-assessment.md`, `csrf-attacks.md` |
| Business Logic | `web-vuln-bypass-tables.md` (12 flaw categories), `signal-hunting-table.md` |
| CORS | `web-vuln-bypass-tables.md` |
| WAF Bypass | `web-bypass-techniques.md`, `cloudflare-bypass-techniques.md`, `parameter-pollution.md` |
| Credential Chaining | `credential-chaining.md`, `credential-inventory-structure.md` |
| Subdomain Takeover | `subdomain-takeover.md` |
| LLM/AI Attacks | `llm-ai-feature-testing.md` |

---


---

## All Reference Files (alphabetical)

```
advanced-web-attacks.md                            — Advanced Web Attacks
intel-alibaba-cloud-infrastructure.md                    — Alibaba Cloud / Ant Group Infrastructure Patterns
api-first-methodology.md                           — API-First Testing Methodology
api-fuzzing-methodology.md                         — API Fuzzing & Parameter Manipulation
attack-chain-framework.md                          — Attack Chain Documentation Framework
attack-chain-narrative-writing.md                  — Attack Chain Narrative Writing
attack-recipes.md                                  — Attack Recipes — Proven Patterns
authenticated-testing-playbook.md                  — Authenticated Testing Playbook
engagement-bfi.md                                  — BFI Finance Engagement Notes (2026-05-29)
engagement-bitbank.md                              — Bitbank.cc Engagement Intel
engagement-bitbank-issuehunt.md                    — bitbank.cc — IssueHunt Bug Bounty Engagement Intel
bounty-targets-data.md                             — Bounty Targets Data - Structured Scope for Bug Bounty Platforms
browser-extension-security.md                      — Browser Extension Security Testing
bug-bounty-osint-checklist.md                      — Bug Bounty OSINT Checklist
bug-bounty-program-enumeration.md                  — Bug Bounty Program Enumeration
bug-bounty-recon-pitfalls.md                       — Bug Bounty Recon Pitfalls & Tricks
bug-bounty-submission-guide.md                     — Bug Bounty Submission Guide
bugbounty-platform-selection.md                    — Bug Bounty Platform Selection Guide
bulk-actuator-scanning.md                          — Bulk Actuator & Admin Endpoint Scanning
burp-cookie-extraction.md                          — Burp Browser Cookie Extraction (macOS)
intel-bytedance-tiktok-infrastructure.md                 — ByteDance / TikTok Infrastructure Patterns
camunda-bpm-assessment.md                          — Camunda BPM Assessment (Black-Box)
cdn-aware-phase5.md                                — CDN-Aware Phase 5 Workarounds
cdn-fronted-js-recon.md                            — CDN-Fronted Target Enumeration via JS Bundle Analysis
chain-and-escalate-phase.md                        — Chain & Escalate Phase (Phase 5.5)
chain-hunting-methodology.md                       — Chain Hunting Methodology
cicd-devops-assessment.md                          — CI/CD & DevOps Tool Assessment Reference
cicd-pipeline-exploitation.md                      — CI/CD Pipeline Exploitation
cloud-infrastructure-enumeration.md                — Reference for discovering and mapping cloud infrastructure during external penet
cloud-privilege-escalation.md                      — Cloud Privilege Escalation & Exploitation
cloudflare-api-shield-bypass.md                    — Cloudflare API Shield Bypass Patterns
cloudflare-api-shield.md                           — Cloudflare API Shield / API Gateway Assessment
cloudflare-bypass-techniques.md                    — Cloudflare Bypass & Assessment Techniques
cloudflare-targets.md                              — Pentesting Cloudflare-Protected Targets
cloudflare-zone-parsing.md                         — Cloudflare Zone File Parsing
command-injection-filter-bypasses.md               — Command Injection — Filter Bypass Techniques
credential-chaining.md                             — Credential Chaining & Cross-Environment Pivoting
credential-inventory-structure.md                  — Credential Inventory Structure
cross-skill-triggers.md                            — See `references/cross-skill-triggers.md` for full table and chains.
csrf-attacks.md                                    — CSRF Attacks Reference — Keycloak SSO / Banking Apps
dark-web-breach-osint.md                           — Dark Web & Breach Data OSINT
data-classification-framework.md                   — Data Classification Framework (Post-Exploitation)
depth-vs-breadth-decisions.md                      — Depth vs Breadth Decision Framework
engagement-digitalocean-intigriti.md               — DigitalOcean Bug Bounty (Intigriti) — Engagement Notes (2026-05-27)
intel-digitalocean-program.md                      — DigitalOcean Bug Bounty Program Intel
dns-record-intelligence.md                         — DNS Record Intelligence Analysis
intel-dropbox-infrastructure.md                          — Dropbox Infrastructure & Program Intel
dynatrace-cluster-probing.md                       — Dynatrace Managed Cluster Probing
elementor-dom-xss-lightbox.md                      — CVE-2022-29455: Elementor DOM XSS via Lightbox
escalate-finding.md                                — Escalate Finding
execute-code-integration.md                        — Execute Code Integration
exploit-validation-checklist.md                    — Exploit Validation Checklist (MANDATORY before reporting)
exploitation-first-mindset.md                      — Exploitation-First Mindset
exploitation-mindset.md                            — Exploitation Mindset — Pitfalls & Patterns
false-positive-detection.md                        — False Positive Detection Patterns
false-positive-filter.md                           — False Positive Filter — 2-Minute Validation
file-upload-attacks.md                             — File Upload Attacks Reference
financial-services-scoring.md                      — CVSS Scoring Guidance for Financial Services
intel-findaya-goto-financial.md                    — Findaya / GoTo Financial — Engagement Intelligence
finding-escalation-techniques.md                   — Finding Escalation Techniques
finding-template-full.md                           — Finding Template
finding-template.md                                — Shared Finding Template
findings-jsonl-convention.md                       — Cross-Skill Findings Convention
firebase-auth-bypass.md                            — Firebase Authentication Bypass Patterns
firebase-auth-emulator.md                          — Firebase Email-Link Auth Session Emulator
fix-verification.md                                — Fix Verification (Redo/Reassessment Engagements)
flutter-web-app-analysis.md                        — Flutter Web App Analysis
framework-specific-attacks.md                      — Framework-Specific Attack Playbooks
gateway-misconfiguration-patterns.md               — Gateway Misconfiguration Patterns Reference
gcp-gke-patterns.md                                — GCP/GKE Penetration Testing Patterns
gcp-port-scan-pitfalls.md                          — GCP Port Scan Pitfalls
geo-restriction-bypass.md                          — Geo-Restriction Detection & Bypass
ghidra-extension-building.md                       — Building Ghidra Extensions for Mismatched Versions
gojek-gobiz-auth-patterns.md                       — GoTo/Gojek/GoBiz Authentication Patterns
google-maps-ssrf-kml.md                            — Google Maps SSRF Testing via KML Import
google-pitchfork-testing.md                        — Google Pitchfork Framework Testing
google-spa-recon.md                                — Google SPA Reconnaissance Patterns
intel-goto-financial-program.md                    — GoTo Financial — Bug Bounty Program Intelligence
intel-grab-infrastructure.md                             — Grab Infrastructure Patterns (HackerOne)
graphql-websocket-testing.md                       — GraphQL & WebSocket Security Testing
guardrails.md                                      — - **Public Disclosure Prohibition** — NEVER publish PoCs on public URLs before v
heapdump-secret-extraction.md                      — Heapdump Secret Extraction
host-header-attacks.md                             — Host Header Attacks Reference
http-request-smuggling.md                          — HTTP Request Smuggling Reference
hub-refactor-plan.md                               — ptest Hub Model Refactor Plan
identity-sdk-endpoint-extraction.md                — Identity SDK Endpoint Extraction
insecure-deserialization.md                        — Insecure Deserialization Reference
intent-injection-login-csrf.md                     — Intent:// Injection Login CSRF — Full PoC Pattern
internal-ad-attacks.md                             — Internal Pentest & Active Directory Attacks
internal-logging-injection.md                      — Internal Logging Endpoint Injection
intigriti-recon.md                                 — Intigriti Platform Recon Reference
istio-mesh-assessment.md                           — Istio/Service Mesh Assessment (External)
javascript-secret-scanning.md                      — JavaScript Secret Scanning
js-bundle-recon.md                                 — JS Bundle Analysis — Phase 1 Recon
jwt-algorithm-enumeration.md                       — JWT Algorithm Enumeration via Error Messages
jwt-attack-techniques.md                           — JWT Attack Techniques
keycloak-assessment.md                             — Keycloak Assessment (Black-Box)
keycloak-gateway-exploitation.md                   — Keycloak Exploitation via API Gateway Proxy
kubernetes-container-attacks.md                    — Kubernetes & Container Security Testing
kubernetes-management-tooling.md                   — Kubernetes Management Tooling Exposure
laravel-debug-exploitation.md                      — Laravel Debug Mode Detection & Exploitation
large-scope-guidance.md                            — When scope has 100+ subdomains, define "phase complete" explicitly:
legacy-protocol-bypass.md                          — Legacy Protocol Authentication Bypass
intel-line-works-ly-corp.md                        — LINE Works / LY Corporation Program Intel
engagement-lineworks.md                            — LINE WORKS Engagement Intel (IssueHunt, June 2026)
llm-ai-feature-testing.md                          — Security Testing AI/LLM Features in Web Applications
lucy-security-assessment.md                        — Lucy Security Platform Assessment
meta-auth-surface.md                               — Meta Bug Bounty — Auth Attack Surface
intel-meta-instagram-infrastructure.md                   — Meta/Instagram Infrastructure Intelligence
microservice-architecture-mapping.md               — Microservice Architecture Mapping (Black-Box)
mobile-app-testing.md                              — Mobile Application Penetration Testing
multi-operator-coordination.md                     — Multi-Operator Coordination
multi-target-structure.md                          — Multi-Target Engagement Structure
n8n-exploitation.md                                — n8n Exploitation Reference
n8n-mcp-oauth-exploitation.md                      — n8n MCP OAuth Exploitation
n8n-workflow-assessment.md                         — n8n Workflow Automation Assessment
nextjs-proxy-pattern.md                            — Next.js Server-Side Proxy Pattern (SSR API Routes)
nginx-case-sensitivity-bypass.md                   — Nginx Case-Sensitivity Bypass
nmap-cloud-targets.md                              — Nmap on Cloud-Hosted Targets (GCP/AWS/Azure)
nodejs-library-attacks.md                          — Node.js Library-Level Attack Patterns
non-http-protocol-testing.md                       — Non-HTTP Protocol Testing Reference
oauth-redirect-uri-testing.md                      — OAuth redirect_uri Testing Methodology
oauth-sso-attack-chains.md                         — OAuth/SSO Attack Chains
open-redirect-chains.md                            — Open Redirect Chains
operational-lifecycle.md                           — 1. **Read State** — check `./ptest-output/state.yaml` to determine active gatewa
operational-pitfalls.md                            — Operational Pitfalls & Performance Notes
osint-completeness-checklist.md                    — OSINT Completeness Checklist
osint-credential-hunting.md                        — OSINT Credential Hunting via GitHub & Public Sources
otp-bruteforce-pattern.md                          — OTP/Verification Code Brute-Force via Authenticated Oracle
otp-endpoint-testing.md                            — OTP Endpoint Testing
parallel-http-probing.md                           — Parallel HTTP Probing for Asset Validation
parameter-pollution.md                             — HTTP Parameter Pollution (HPP)
partner-gateway-probing.md                         — Partner Gateway Probing
path-traversal-actuator-bypass.md                  — Path Traversal + Actuator Bypass Techniques
pattern-subdomain-bruteforce.md                    — Pattern-Based Subdomain Brute-Force
person-osint.md                                    — Person OSINT Methodology
phase1-passive-recon.md                            — Phase 1: Passive Recon
phase2-active-recon.md                             — Phase 2: Active Reconnaissance
phase3-enumeration.md                              — Phase 3: Enumeration
phase4-attack-surface.md                           — Phase 4: Attack Surface Mapping
phase5-vuln-assessment.md                          — Phase 5: Threat Modeling & Vulnerability Assessment
phase6-exploitation-framework.md                   — Phase 6: Exploitation Framework
phase6-per-host-coverage-template.md               — Phase 6: Per-Host Coverage Template
phase7-post-exploitation-framework.md              — Phase 7: Post-Exploitation Framework
phase8-reporting-process.md                        — Phase 8: Reporting Process Guide
pitfalls.md                                        — - **TOKEN ≠ ATO, ENDPOINT ≠ AUTH (critical):** WinTicket lesson (June 2026): Cla
post-exploitation-rules.md                         — Post-Exploitation Rules (MANDATORY)
pre-engagement.md                                  — Pre-Engagement Phase
preflight.md                                       — Preflight Check
program-exclusion-validation.md                    — Program Exclusion Validation (Bug Bounty)
proprietary-crypto-reversing.md                    — Proprietary Crypto & Validation Reversing
prototype-pollution.md                             — Prototype Pollution Reference
proven-patterns.md                                 — Proven Pentest Patterns
quality-gates.md                                   — Before drafting any finding report, answer these 3 questions. One NO = KILL the 
race-condition-hunting.md                          — Race Condition Hunting Reference
rce-exploitation-chains.md                         — RCE Exploitation Chains
re-validation-loops.md                             — Re-Validation Loops (Mini-Enumeration)
reassessment-report-template.md                    — Reassessment/Redo Report Template
report-structure-template.md                       — Penetration Test Report Structure Template
report-templates-by-platform.md                    — Report Templates by Platform
s3-bucket-enumeration.md                           — S3 Bucket Enumeration & Testing
saml-sso-assessment.md                             — SAML/SSO Attack Surface Assessment
scope-expansion.md                                 — Scope Expansion Techniques
scope-matrix.md                                    — Scope-Aware Checklist Matrix
second-look-protocol.md                            — Second Look Protocol
severity-escalation.md                             — Severity Escalation Protocol
signal-hunting-table.md                            — Signal Hunting Table: A→B→C Reference
signature-based-auth-testing.md                    — Signature-Based Authentication Testing
signed-url-exploitation.md                         — GCS/S3 Signed URL Analysis & Exploitation
snyk-token-enumeration.md                          — Snyk Token Enumeration & Exploitation
source-map-token-exploitation.md                   — Source Map → Token Exploitation Chain
spa-config-extraction.md                           — SPA Site-Config Extraction Technique
spa-false-positive-detection.md                    — SPA False Positive Detection in Web Enumeration
spa-js-endpoint-extraction.md                      — SPA JS Bundle Endpoint Extraction
spa-recon-techniques.md                            — SPA Recon Techniques
sqli-payloads-and-bypass.md                        — SQLi Payloads & Bypass Techniques
ssrf-outbound-forcing.md                           — SSRF & Outbound Request Forcing (Black-Box)
ssti-engine-payloads.md                            — SSTI Engine-Specific Payloads
stripe-webhook-exploitation.md                     — Stripe Webhook Signature Bypass Exploitation
stuck-playbook.md                                  — Stuck Playbook — When Standard Checks Find Nothing
subdomain-takeover-csp.md                          — Subdomain Takeover & CSP Bypass
subdomain-takeover.md                              — Subdomain Takeover Assessment
submission-pipeline.md                             — Submission Pipeline Tracking
supabase-testing.md                                — Supabase Backend Testing Methodology
target-heuristics.md                               — Target Assessment Heuristics
target-selection-scoring.md                        — Target Selection Scoring
target-selection.md                                — Bounty Target Selection Heuristic
telegram-webapp-auth.md                            — Telegram WebApp (Mini App) Authentication
teleport-assessment.md                             — Teleport Remote Access Proxy Assessment
tight-scope-bounty-testing.md                      — Tight-Scope Bug Bounty Testing (3 or fewer domains)
time-box-enforcement.md                            — Time-Box Enforcement Mechanism
token-format-oracle.md                             — Token Format Oracle Pattern
transmit-security-cis-testing.md                   — Transmit Security CIS (Customer Identity Service) Testing
triage-rebuttal.md                                 — Triage Rebuttal Guide
tyk-gateway-enumeration.md                         — Tyk API Gateway Enumeration
unauthenticated-callback-testing.md                — Unauthenticated Integration/Callback/Webhook Endpoint Testing
waf-bypass-techniques.md                           — WAF Bypass Techniques
wayback-osint-alternatives.md                      — Wayback Machine & Alternative OSINT for Dorking
web-bypass-techniques.md                           — Web ACL/WAF Bypass Techniques
web-cache-poisoning.md                             — Web Cache Poisoning & Cache Deception Reference
web-testing-checklist.md                           — Web Testing Checklist (Cross-Reference)
web-vuln-bypass-tables.md                          — Web Vulnerability Bypass Tables — Quick Reference
webauthn-passkeys-testing.md                       — WebAuthn & Passkeys Security Testing
webhook-signature-bypass.md                        — Webhook Signature Bypass Testing
engagement-winticket-issuehunt.md                  — WinTicket IssueHunt Engagement
wordpress-enumeration.md                           — WordPress Penetration Testing Checklist
wordpress-headless-cors.md                         — WordPress Headless CMS — CORS Misconfiguration Pattern
write-access-protocol.md                           — Write Access Response Protocol
xss-filter-bypass-techniques.md                    — XSS Filter Bypass Techniques
xss-filter-bypass.md                               — XSS Filter Bypass Methodology
xxe-injection.md                                   — XXE Injection Reference
yeswehack-dojo-interaction.md                      — YesWeHack Dojo Challenge Interaction
```
