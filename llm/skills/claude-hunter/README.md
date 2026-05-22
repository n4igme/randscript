# claude-hunter

One-stop Claude Code skill bundle for bug bounty hunting, external red team assessments, and web application pentesting.

**55 skills · 14 slash commands · 574+ disclosed-report patterns · 27 vulnerability classes · enterprise platform attack chains · red team operator discipline · 7-Question validation gate**

Merges the best of [claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) (workflow, validation, reporting) and [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) (granular hunt skills, enterprise attacks, red team tradecraft) into a single pure-skills bundle.

---

## What Is This?

A drop-in skill bundle for [Claude Code](https://claude.ai/claude-code). Install once and Claude stops being a chatbot and starts behaving like a senior bug-hunting researcher or red-team operator.

**Three engagement modes:**
- **Bug Bounty** — web apps, APIs, SaaS, full OWASP coverage, platform-specific reporting
- **External Red Team** — enterprise perimeter, identity fabric attacks, operator discipline
- **Web App Pentest** — systematic OWASP-aligned testing with grey-box support

**What it does:**
- Auto-loads the right skills based on what you describe in plain English
- Provides per-class detection patterns, payloads, bypass tables, and chain templates
- Validates findings through a 7-Question Gate before you waste time reporting
- Generates platform-specific reports (H1, Bugcrowd, Intigriti, Immunefi, client DOCX)

---

## Quick Start

### Prerequisites

- [Claude Code CLI](https://claude.ai/claude-code) with Pro/Team/Max plan
- macOS or Linux (Windows: use WSL2)
- Optional: Burp Suite Pro/Community for HTTP traffic capture

### Install

```bash
git clone <this-repo>
cd claude-hunter
./install.sh
```

### Your First Hunt

```bash
# Scaffold an engagement folder
source ~/.zshrc    # or open new terminal
hunt my-target
cd ~/Targets/my-target

# Open Claude Code
claude

# Run the workflow
/recon target.com
/hunt target.com
/triage
/report
```

---

## Commands

### Core 4 (start here)

| Command | What It Does |
|---------|--------------|
| `/recon target.com` | Map subdomains, live hosts, URLs, run nuclei |
| `/hunt target.com` | Start hunting — picks mode, loads skills |
| `/triage` | 7-Question Gate — validates finding before report |
| `/report` | Generate submission-ready report |

### Power Commands

| Command | What It Does |
|---------|--------------|
| `/autopilot target.com` | Autonomous hunt loop with checkpoints |
| `/chain` | Build A→B→C exploit chain |
| `/surface target.com` | Ranked attack surface |
| `/pickup target.com` | Resume previous hunt |
| `/validate` | Full 7-Question Gate + 4-gate checklist |
| `/scope <asset>` | Check if asset is in scope |
| `/intel target.com` | CVE + disclosed report intel |
| `/remember` | Log finding to memory |
| `/memory-gc` | Inspect/rotate memory files |
| `/token-scan <contract>` | Token rug-pull scanner |
| `/web3-audit <contract>` | Smart contract audit |

---

## Skill Coverage

### Web Application (31 skills)
IDOR, XSS, SSRF, SQLi, RCE, auth bypass, OAuth, SAML, MFA bypass, ATO, file upload, GraphQL, CSRF, business logic, race conditions, cache poisoning, HTTP smuggling, SSTI, XXE, subdomain takeover, cloud misconfig, API misconfig, LLM/AI, ASP.NET, NTLM, SharePoint, chain hunting, WAF bypass, deserialization, parameter pollution, and 225-report catch-all.

### Enterprise Platform (7 skills)
M365/Entra ID, Okta, SSL VPN (Cisco/Fortinet/Citrix/PAN/Pulse/SonicWall/F5), VMware vCenter, Cloud IAM (AWS/Azure/GCP), supply chain, Android APK.

### Red Team Tradecraft (2 skills)
Operator discipline (DO NOT STOP directive), mid-engagement IR detection.

### Recon & OSINT (4 skills)
Offensive OSINT, subdomain enum, 5-stage methodology, local toolkit.

### Workflow & Validation (5 skills)
Master orchestrator, 5-phase methodology, hunt dispatcher, payload arsenal, 7-Question Gate.

### Reporting (4 skills)
H1/Bugcrowd/Intigriti/Immunefi templates, VRT mapping, evidence hygiene, red team deliverable.

### Specialized (3 skills)
Web3 audit, meme coin audit, chain hunting.

---

## The 7-Question Gate

Before any report, every finding must pass:

1. Can an attacker use this RIGHT NOW with a real HTTP request?
2. Is the impact on the program's accepted-impact list?
3. Is the asset in scope?
4. Does it work without privileged access an attacker can't get?
5. Is this not already known or documented behavior?
6. Can impact be proved beyond "technically possible"?
7. Is this not on the never-submit list?

One NO = KILL. This prevents the most common mistake: reporting findings that get rejected as N/A.

---

## Engagement Flow

```
1. SCOPE     → hunt <target> scaffolds folder, parse program rules
2. RECON     → /recon maps subdomains, endpoints, tech stack
3. HUNT      → /hunt tests bug-class hypotheses per skill
4. VALIDATE  → /triage runs 7-Question Gate
                 PASS → report
                 DOWNGRADE → report at lower severity
                 CHAIN REQUIRED → go find the other half
                 KILL → move on
5. CAPTURE   → evidence-hygiene redacts cookies/PII
6. REPORT    → /report generates platform-specific submission
```

---

## Optional Integrations

### Burp Suite MCP
Connect Claude to your Burp proxy for live HTTP traffic visibility.
See `mcp/burp-mcp-client/README.md` for setup.

### HackerOne MCP
Search disclosed reports, get program stats and policy.
See `mcp/hackerone-mcp/config.json` for setup.

---

## Structure

```
claude-hunter/
├── skills/          53 SKILL.md bundles (auto-load by keyword)
├── commands/        15 slash commands
├── rules/           Always-active hunting + reporting rules
├── mcp/             Burp + HackerOne MCP configs
├── wordlists/       Recon wordlists
├── scripts/         hunt.sh engagement scaffolder
├── install.sh       Single-step installer
├── CLAUDE.md        Project guide (loaded by Claude Code)
└── README.md        This file
```

---

## Authorization

These skills are for assets you **own** or have **written authorization to assess**:
- Bug bounty in-scope assets
- Pentest engagement letters
- CTF challenges
- Your own infrastructure

The bundle includes validation gates that check scope (Q3) and accepted-impact (Q2) before any report is drafted.

**Explicitly excluded:** weaponizing 0-days against unauthorized targets, post-exploitation tooling, malware development, mass-targeting infrastructure.

---

## Credits

- **[shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty)** — methodology, validation, reporting, payload library, MCP integrations, memory system design
- **[elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)** — 51 granular skills, enterprise platform attacks, red team tradecraft, engagement flow
- **[ProjectDiscovery](https://github.com/projectdiscovery)** — subfinder, dnsx, httpx, katana, nuclei
- **[PortSwigger](https://portswigger.net/burp)** — Burp Suite + MCP Server

---

## License

MIT — use freely, attribution appreciated.
