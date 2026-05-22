# claude-hunter

One-stop Claude Code skill bundle for **bug bounty hunting**, **external red team**, and **web application pentesting**.

55 skills · 14 slash commands · 574+ disclosed-report patterns · enterprise platform attack chains · red team operator discipline · 7-Question validation gate.

## Start Here

```bash
claude                          # open Claude Code
/recon target.com               # map the target
/hunt target.com                # test for vulnerabilities
/triage                         # validate before reporting
/report                         # generate submission-ready report
```

## Engagement Modes

| Mode | Trigger | Severity Gate | Report Format |
|------|---------|---------------|---------------|
| Bug Bounty | `/hunt target.com` → select "WAPT / BugHunting" | All severities | H1 / Bugcrowd / Intigriti / Immunefi |
| Red Team | `/hunt target.com` → select "Red Team Assessment" | Critical/High only (Medium if chained) | Client-facing DOCX deliverable |
| Pentest | `/hunt target.com` → select "WAPT / BugHunting" + grey box | Full OWASP coverage | Standard pentest report |

## Commands

| Command | Usage |
|---------|-------|
| `/recon target.com` | Full recon pipeline — subdomains, live hosts, URLs, nuclei |
| `/hunt target.com` | Start hunting — picks mode, loads skills, tests vulns |
| `/triage` | Quick 7-Question Gate on current finding |
| `/validate` | Full 7-Question Gate + 4-gate checklist |
| `/report` | Write submission-ready report for platform |
| `/chain` | Build A→B→C exploit chain for higher payouts |
| `/autopilot target.com` | Autonomous hunt loop with checkpoints |
| `/surface target.com` | Ranked attack surface from recon + memory |
| `/pickup target.com` | Resume previous hunt |
| `/scope <asset>` | Check if asset is in scope |
| `/intel target.com` | CVE + disclosed report intel |
| `/remember` | Log finding to hunt memory |
| `/memory-gc` | Inspect/rotate hunt-memory files |
| `/token-scan <contract>` | Meme coin/token rug pull scanner |
| `/web3-audit <contract>` | Smart contract 10-class checklist |

## Skill Domains

### Web Application Hunting (28 hunt-* skills)
Auto-load by keyword — describe what you're testing and the right skill loads.

| Skill | Coverage |
|-------|----------|
| `hunt-idor` | IDOR — 8 variants, 26 H1 reports, chain escalation |
| `hunt-xss` | XSS — DOM sinks, CSP bypass, 174 H1 reports |
| `hunt-ssrf` | SSRF — 11 IP bypass techniques, cloud metadata |
| `hunt-sqli` | SQLi — classic, blind, time-based, NoSQL |
| `hunt-rce` | RCE — deserialization, code injection, 67 H1 reports |
| `hunt-auth-bypass` | Auth bypass — sibling rule, missing middleware |
| `hunt-oauth` | OAuth/OIDC — missing PKCE, 11 redirect bypasses |
| `hunt-saml` | SAML — XSW1-XSW8, comment injection, sig stripping |
| `hunt-mfa-bypass` | MFA bypass — 7 patterns |
| `hunt-ato` | Account takeover — 9 paths |
| `hunt-file-upload` | File upload — 10 bypass techniques |
| `hunt-graphql` | GraphQL — introspection, alias batching, node IDOR |
| `hunt-csrf` | CSRF — chain-required impact |
| `hunt-business-logic` | Business logic — coupon abuse, state machine |
| `hunt-race-condition` | Race conditions — TOCTOU, double-spend |
| `hunt-cache-poison` | Cache poisoning + deception |
| `hunt-http-smuggling` | HTTP smuggling — CL.TE, TE.CL, H2 |
| `hunt-ssti` | SSTI — Jinja2, Twig, Freemarker, ERB, Spring |
| `hunt-xxe` | XXE — in-band, OOB, via DOCX |
| `hunt-subdomain` | Subdomain takeover — 27+ provider fingerprints |
| `hunt-cloud-misconfig` | Cloud misconfig — S3, Lambda, IMDS, Firebase |
| `hunt-api-misconfig` | API — mass assignment, JWT, prototype pollution, CORS |
| `hunt-llm-ai` | LLM/AI — prompt injection, ASI01-ASI10 |
| `hunt-misc` | Catch-all — 225 H1 reports |
| `hunt-waf-bypass` | WAF bypass — 20 techniques, origin discovery, TLS evasion |
| `hunt-deserialization` | Deserialization — Java/PHP/.NET/Python/Node gadget chains |
| `hunt-parameter-pollution` | HPP — duplicate params, gateway precedence, WAF bypass |
| `hunt-aspnet` | ASP.NET ViewState, machineKey, WebForms |
| `hunt-ntlm-info` | NTLM Type-2 AD topology disclosure |
| `hunt-sharepoint` | SharePoint on-prem ToolShell + SOAP |
| `chain-hunting` | A→B signal method — cluster hunting, chain tables |

### Enterprise Platform Attack (7 skills)
| Skill | Coverage |
|-------|----------|
| `m365-entra-attack` | M365/Entra ID — AADSTS, user enum, CA bypass, ROPC |
| `okta-attack` | Okta — tenant discovery, push fatigue, FastPass |
| `enterprise-vpn-attack` | SSL VPN — Cisco, Fortinet, Citrix, PAN, Pulse, SonicWall, F5 |
| `vmware-vcenter-attack` | vCenter/Workspace ONE/Aria CVE chains |
| `cloud-iam-deep` | AWS/Azure/GCP IAM priv-esc — 24+ patterns |
| `supply-chain-attack-recon` | Dep-confusion, GH Actions, SBOM mining |
| `apk-redteam-pipeline` | Android APK — jadx, secrets, Frida |

### Red Team Tradecraft (2 skills)
| Skill | Coverage |
|-------|----------|
| `redteam-mindset` | Operator discipline — DO NOT STOP directive |
| `mid-engagement-ir-detection` | SOC-patch + attacker activity detection |

### Recon & OSINT (4 skills)
| Skill | Coverage |
|-------|----------|
| `offensive-osint` | 15-reference probe arsenal |
| `web2-recon` | Subdomain enum, host discovery |
| `osint-methodology` | 5-stage pipeline, asset graph |
| `bb-local-toolkit` | Pipeline router for local repos |

### Workflow & Validation (5 skills)
| Skill | Coverage |
|-------|----------|
| `bug-bounty` | Master orchestrator — 17 critical rules |
| `bb-methodology` | 5-phase non-linear workflow |
| `hunt-dispatch` | /hunt two-track dispatcher (RT vs WAPT) |
| `security-arsenal` | Payloads, bypass tables, wordlists |
| `triage-validation` | 7-Question Gate + 4 validation gates |

### Reporting & Hygiene (4 skills)
| Skill | Coverage |
|-------|----------|
| `report-writing` | H1/Bugcrowd/Intigriti/Immunefi templates |
| `bugcrowd-reporting` | VRT mapping, OOS rebuttals |
| `evidence-hygiene` | Cookie redaction, PII black-bar, HAR sanitization |
| `redteam-report-template` | Client-facing deliverable format |

### Specialized (3 skills)
| Skill | Coverage |
|-------|----------|
| `web3-audit` | Smart contract — 10 DeFi bug classes |
| `meme-coin-audit` | Token rug-pull, LP lock bypass |
| `chain-hunting` | A→B signal method, cluster hunting |

## The 7-Question Gate

Before drafting any report — `/triage` runs every finding through:

1. Can an attacker use this RIGHT NOW with a real HTTP request?
2. Is the impact on the program's accepted-impact list?
3. Is the asset in scope?
4. Does it work without privileged access an attacker can't get?
5. Is this not already known or documented behavior?
6. Can impact be proved beyond "technically possible"?
7. Is this not on the never-submit list?

One NO = KILL. Move on.

## Critical Rules (Always Active)

1. READ FULL SCOPE before touching any asset
2. NEVER hunt theoretical bugs — "Can attacker do this RIGHT NOW?"
3. Run 7-Question Gate BEFORE writing any report
4. KILL weak findings fast — N/A hurts your validity ratio
5. 5-minute rule — nothing after 5 min = move on
6. ONE-HOUR RULE — stuck for an hour? SWITCH CONTEXT
7. IMPACT-FIRST — hunt the worst-case scenario first

## MCP Integrations (Optional)

- **Burp Suite MCP** — live HTTP traffic visibility. See `mcp/burp-mcp-client/`
- **HackerOne MCP** — search disclosed reports, program stats, policy. See `mcp/hackerone-mcp/`

## Authorization

These skills are for assets you **own** or have **written authorization to assess** (bug-bounty in-scope assets, pentest engagement letters, CTF challenges, your own infrastructure).
