# Reference File Index

Quick lookup: what you found → which reference to load.

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
| AWS CNAME (S3, Transfer, CloudFront) | `cloud-infrastructure-enumeration.md` §2 |
| CI/CD tool (ArgoCD, Atlantis, Airflow, n8n, Jenkins) | `cicd-pipeline-exploitation.md`, `cicd-devops-assessment.md` |
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
| SPA / React / Angular / Vue frontend | `web-vuln-bypass-tables.md` (DOM XSS sources/sinks, postMessage, DOM clobbering) |
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

## By Phase (what you're doing)

| Phase | Relevant References |
|-------|-------------------|
| 1 — Passive Recon | `dns-record-intelligence.md`, `js-bundle-recon.md`, `operational-pitfalls.md` |
| 2 — Active Recon | `pattern-subdomain-bruteforce.md`, `nmap-cloud-targets.md`, `operational-pitfalls.md` |
| 3 — Enumeration | `bulk-actuator-scanning.md`, `javascript-secret-scanning.md`, `framework-specific-attacks.md`, `api-first-methodology.md` |
| 4 — Attack Surface | `depth-vs-breadth-decisions.md`, `cloud-infrastructure-enumeration.md` |
| 5 — Vuln Assessment | `web-vuln-bypass-tables.md`, `web-testing-checklist.md`, `false-positive-detection.md`, `web-cache-poisoning.md`, `host-header-attacks.md`, `http-request-smuggling.md` |
| 6 — Exploitation | `phase6-exploitation-framework.md`, `web-testing-checklist.md`, `jwt-attack-techniques.md`, `signal-hunting-table.md`, `attack-chain-framework.md`, `credential-chaining.md`, `re-validation-loops.md`, `advanced-web-attacks.md`, `insecure-deserialization.md`, `parameter-pollution.md`, `graphql-websocket-testing.md`, `kubernetes-container-attacks.md`, `cicd-pipeline-exploitation.md`, `prototype-pollution.md`, `file-upload-attacks.md`, `http-request-smuggling.md`, `host-header-attacks.md`, `oauth-sso-attack-chains.md`, `gateway-misconfiguration-patterns.md` |
| 7 — Post-Exploitation | `phase7-post-exploitation-framework.md`, `data-classification-framework.md` |
| 8 — Reporting | `phase8-reporting-process.md`, `time-box-enforcement.md` |

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

## All Reference Files (alphabetical)

```
advanced-web-attacks.md              — WebSocket, cache poisoning, HTTP smuggling, race conditions
api-first-methodology.md             — API-centric testing approach
api-fuzzing-methodology.md           — Parameter discovery, type/boundary fuzzing, auth manipulation, mass assignment, rate limit bypass, Content-Type switching, SpEL injection, GraphQL fuzzing
attack-chain-framework.md            — Compound attack path documentation
bug-bounty-osint-checklist.md         — Bug bounty OSINT techniques
browser-extension-security.md        — Chrome/Firefox extension static+dynamic analysis, message passing, CORS proxy, privesc chains
bulk-actuator-scanning.md            — Bulk /actuator check across all hosts
camunda-bpm-assessment.md            — Camunda BPM web UI and API testing
cicd-devops-assessment.md            — ArgoCD, Atlantis, Airflow, n8n, Jenkins, Vault, Grafana
cloud-infrastructure-enumeration.md  — GCP/AWS/Azure project mapping, bucket enum
cloud-privilege-escalation.md        — AWS/GCP/Azure post-compromise privesc, IAM abuse, S3/Lambda/EC2 exploitation
cloudflare-api-shield.md             — CF API Shield vs Access distinction
cloudflare-bypass-techniques.md      — Origin IP discovery, CF product identification
command-injection-filter-bypasses.md — 20+ filter bypass techniques: no-space, no-slash, keyword evasion, hex/octal, brace expansion, argument injection, WorstFit, blind exfil, polyglots
credential-chaining.md               — Discovery → Validation → Escalation → Pivot
credential-inventory-structure.md    — Centralized credential tracking
dark-web-breach-osint.md             — Breach databases, dark web search, threat intel feeds, credential leak methodology
data-classification-framework.md     — Data sensitivity classification
depth-vs-breadth-decisions.md        — When to stop vs dig deeper
dns-record-intelligence.md           — SPF/DMARC/MX/TXT analysis
false-positive-detection.md          — SPA catch-alls, CORS crashes, 302-to-login
framework-specific-attacks.md        — Next.js, Laravel, Django, WordPress, Rails, GraphQL, Spring Boot
gateway-misconfiguration-patterns.md — Parallel gateway drift, CDN bypass, config inconsistency detection
ghidra-extension-building.md         — Build Ghidra extensions from source for version mismatches
heapdump-secret-extraction.md        — Java HPROF analysis with Eclipse MAT
insecure-deserialization.md          — Java/PHP/.NET/Python deserialization exploitation
internal-ad-attacks.md               — AD enumeration, Kerberos attacks, credential dumping, lateral movement, Windows privesc
javascript-secret-scanning.md        — Bulk JS secret scanning patterns
js-bundle-recon.md                   — Phase 1 JS bundle analysis for recon (URLs, configs, architecture)
keycloak-assessment.md               — Keycloak realm/client enumeration
keycloak-gateway-exploitation.md     — Keycloak behind API gateway
legacy-protocol-bypass.md            — Legacy auth endpoints that bypass SSO/MFA (20+ platforms)
llm-ai-feature-testing.md            — Prompt injection, AI IDOR/SSRF, OWASP LLM Top 10
lucy-security-assessment.md          — Lucy phishing platform testing
microservice-architecture-mapping.md — K8s/GKE architecture from external signals
mobile-app-testing.md                — SUPERSEDED: use `mtest` skill for mobile testing
graphql-websocket-testing.md         — GraphQL introspection, batching, IDOR; WebSocket auth, CSWSH, injection
kubernetes-container-attacks.md      — K8s API, kubelet, etcd, container escape, GKE metadata, Istio mesh
cicd-pipeline-exploitation.md        — Jenkins RCE, GitLab CI variables, GitHub Actions injection, ArgoCD
multi-operator-coordination.md       — Team coordination for multi-person engagements
nmap-cloud-targets.md                — Nmap behavior on GCP/AWS load balancers
oauth-sso-attack-chains.md           — OAuth/OIDC attack chains, token analysis, Keycloak-specific attacks
non-http-protocol-testing.md         — SMTP, SFTP/SSH, OpenVPN, DNS
operational-pitfalls.md              — 50+ battle-tested tool/target pitfalls
parallel-http-probing.md             — Parallel bash probing pattern
parameter-pollution.md               — HPP server behavior, WAF bypass
path-traversal-actuator-bypass.md    — ..;/ ingress bypass techniques
pattern-subdomain-bruteforce.md      — Pattern-based DNS brute-force
phase6-exploitation-framework.md     — Structured exploitation checklist
phase7-post-exploitation-framework.md — Access classification and playbooks
phase8-reporting-process.md          — Report writing, audience, delivery
re-validation-loops.md               — Mini-enumeration during exploitation
saml-sso-assessment.md               — SAML metadata, IdP enum, SSO attacks
signal-hunting-table.md              — A→B→C finding signal lookup (30+ pairs)
snyk-token-enumeration.md            — Snyk API exploitation
ssrf-outbound-forcing.md             — Server-side callback forcing
subdomain-takeover.md                — Dangling CNAME detection
time-box-enforcement.md              — Budget tracking and over-budget decisions
web-bypass-techniques.md             — WAF/auth bypass techniques
web-testing-checklist.md             — User management, app logic, input handling, security headers, infra checks
webauthn-passkeys-testing.md         — FIDO2/WebAuthn/Passkey registration, auth, fallback, counter, origin testing
web-vuln-bypass-tables.md            — SSRF, path traversal, access control, authentication, OAuth, business logic, NoSQL injection, DOM XSS, XSS, IDOR, file upload, SSTI, MFA, ATO, race condition, mass assignment bypass payloads (1941 lines)
```
