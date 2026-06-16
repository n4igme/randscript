---
name: intuition-engine
description: "Meta-cognitive dispatch: skill chaining, situation fingerprinting, parallel execution for security work."
tags: [meta, dispatch, chaining, pentesting, bug-bounty, forensics]
trigger: "Load on ANY security/research task. Activates skill chains instead of single skills."
---

# Intuition Engine — Meta-Cognitive Dispatch

## Core Principle

Never load a single skill. Every task activates a CHAIN of 2-5 skills in pipeline.
Think 3 steps ahead. Parallelize across MCP + terminal + subagents.

## ① Situation Fingerprinting

Before ANY action, identify in <10 seconds:

| Signal | Situation | Skill Chain |
|--------|-----------|-------------|
| URL/domain | Web app target | ptest → atest (if API) → report |
| APK/IPA | Mobile test | mtest (phases 1-10) |
| Binary/ELF/PE | Reverse engineering | retools → xdev |
| CVE-XXXX-XXXX | Vuln research | cve_intel MCP → xdev |
| IP/CIDR | Network recon | ptest phase 1-2 |
| AD/Kerberos | Windows domain | adtest |
| Docker/K8s | Container | ctest |
| Smart contract | Web3 | w3hunt |
| "research X" | Academic | arxiv MCP + semantic_scholar MCP |
| Cloud AWS/Azure | Cloud pentest | ctest |
| Bug bounty program | Hunting | w3hunt → ptest or atest |
| Source code | Code review | scode |
| Thick client | Desktop app | ttest |
| OSINT target | Reconnaissance | osint |
| Write report | Deliverable | platform-specific format (HackerOne/YesWeHack/internal) |

## ② Skill Chains (Your Actual Skills)

```
Bug Bounty Web:
  ptest (recon) → ptest (enumeration) → [vuln-specific] → PoC script → report

Bug Bounty API:
  atest (4 phases) → PoC script → report

Mobile App:
  mtest (phase 1-10) → xdev (if exploit needed) → report

Web3/DeFi:
  w3hunt → scode (contracts) → PoC → report

Active Directory:
  adtest → lateral movement → privesc → report

Cloud/Container:
  ctest (5 phases) → report

Source Code Review:
  scode (5 steps: recon, threat model, scanning, validation, report)

Red Team:
  osint → ptest → xdev → report

Reverse Engineering:
  retools (Ghidra/radare2/IDA) → xdev → report
```

## ③ Preemptive Reasoning

For every finding, immediately compute:
1. What does this ENABLE next? (attack path extension)
2. What EVIDENCE do I need? (screenshot, HTTP request/response, PoC)
3. What PARALLEL probes can I spawn? (delegate_task)
4. What's the REPORT value? (severity, impact)
5. What would I chain with? (SSRF→cloud metadata, SQLi→data exfil, IDOR→ATO)

## ④ Parallel Execution

Use all channels simultaneously:
- MCP: cve_intel (CVE/EPSS/KEV lookup), arxiv (paper search), semantic_scholar
- Terminal: nmap, nuclei, ffuf, sqlmap, frida
- Browser: examine web interface, intercept flows
- execute_code: write PoC scripts (Python requests, NOT curl)
- delegate_task: 3-12 parallel subagent workers

## ⑤ Evidence Standards (Your Rules)

- PoCs in Python (requests library), NEVER curl
- Real tested values, NEVER placeholders
- Separate findings by endpoint/app
- Screenshots/HTTP logs as proof
- Report format per platform:
  - HackerOne: Summary, Steps To Reproduce, Supporting Material
  - YesWeHack: Description, Exploitation, PoC, Risk, Remediation
  - Internal: real proof always

## ⑥ Anti-Patterns

| Bad | Good |
|-----|------|
| Load one skill | Chain 3-5 skills |
| Wait for instructions | Anticipate next steps |
| Sequential tools | Parallel MCP + terminal + subagents |
| Generic scanning | Targeted based on fingerprint |
| Placeholder PoC values | Real tested values |
| Unproven findings | Working exploit or drop it |
| Report without evidence | Screenshot + HTTP + PoC script |

## ⑦ MCP Servers Available

- `cve_intel`: CVE lookup, EPSS scoring, CISA KEV, MITRE ATT&CK, Exploit-DB
- `arxiv`: Search/analyze academic papers, fetch LaTeX source
- `semantic_scholar`: 200M+ papers, citation graphs
- `google_scholar`: Broad academic search (free scraping)
- `pubmed`: Biomedical literature (free NCBI API)
- `wikipedia`: Knowledge retrieval
- `jupyter`: Computation, data analysis, visualization
- `zotero`: Reference management (local mode)
- `neo4j`: Knowledge graphs (when Neo4j running)
- `burpsuite`: Proxy integration (when running)
- `ghidra`: Binary RE (when running)
- `jadx-mcp-server`: Android APK decompilation

## ⑧b Cross-Domain Amplification

Load `hyper-intuition` skill alongside this one for non-security tasks.
It extends the same meta-cognitive patterns to research, code, and creative work.

## ⑧ macOS MCP Server Setup

MCP servers need Python 3.11+ but macOS ships 3.9.6. Use `uv tool install`:
- `uv tool install <pkg> --python 3.11` (most servers)
- `uv tool install cve-mcp-server --python 3.12` (needs 3.12)
- Config must use FULL PATHS: `/Users/<user>/.local/bin/<server-name>`
- Reload in-session: `/mcp reload` or ask "reload mcp servers"
- Verify: `ls ~/.local/bin/{arxiv-mcp-server,cve-mcp-server,semantic-scholar-mcp,wikipedia-mcp}`

## References

- `references/macos-mcp-install.md` — macOS MCP server installation via uv tool (Python version handling, full paths, pitfalls)
