---
name: intuition-engine
version: 1.0.0
description: "Meta-cognitive dispatch: skill chaining, situation fingerprinting, parallel execution for security work."
tags: [meta, dispatch, chaining, pentesting, bug-bounty, forensics]
trigger: "Load on ANY security/research task. Activates skill chains instead of single skills."
---

# Intuition Engine — Meta-Cognitive Dispatch

## When to Use / When NOT to Use

**Use when:**
- Task requires reasoning across multiple security domains
- Need to chain 2-5 skills in pipeline
- Parallel execution across MCP + terminal + subagents is appropriate

**Avoid when:**
- Task is trivial single-step (overhead exceeds value)
- Only one skill is needed (no chaining required)
- User explicitly asked for single-tool approach

## Core Principle

**state.yaml schema:**
```yaml
engagement:
  name: string
  started: ISO8601
  task: string
current_phase: int
gateways:
  1_fingerprint: OPEN|PASSED|LOCKED
  2_dispatch: ...
  3_execute: ...
  4_verify: ...
time_tracking:
  phase_1_start: ISO8601
findings_count: int
notes: string
```

### Phase Entry Protocol (ALL phases)

When entering ANY phase:
1. **Load reference file** — `skill_view(name='intuition-engine', file_path='references/<phase-file>')`
2. **Record timestamp** — write `phase_N_start` in state.yaml
3. **Check prerequisites** — verify prior phase gate is PASSED
4. **Review findings** — check `findings.jsonl` for chain opportunities before starting

Think 3 steps ahead. Parallelize across MCP + terminal + subagents.

## ① Situation Fingerprinting

## Retry / Timeout Patterns

| Operation | Timeout | Retry | Backoff |
|-----------|---------|-------|---------|
| MCP tool call | 60s | 2x | 10s |
| Subagent spawn | 120s | 1x | restart |
| Web fetch | 30s | 3x | 5s linear |
| Terminal command | 300s | 1x | restart with higher timeout |

**Rules:**
- On timeout: retry once with same parameters. If persistent, escalate or pivot.
- On tool failure: check if partial output is usable before retrying.
- Background processes: use `notify_on_complete=true` instead of polling.

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

## Error Handling

| Failure Mode | Action |
|--------------|--------|
| MCP tool unavailable | Fall back to terminal equivalent (`curl` instead of web_search) |
| Subagent fails | Capture error, retry with simpler goal or smaller scope |
| Context overflow | Summarize and compact conversation history; continue from checkpoint |
| Tool rate limit | Back off exponentially; if persistent, notify user and pivot |

**Rules:**
- Never retry blindly — understand the error first
- On repeated failure: document blocker, continue with alternative approach
- Subagent failures do not crash parent — capture and report summary

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

## Concurrent Execution Safety

**Subagent orchestration:**
- Each subagent gets isolated context — no shared state
- Parent agent should document intent before spawning (goal, context, toolsets)
- Results are self-reports — verify externally before acting on claims
- Max depth 4 for this user; leaf subagents cannot delegate further

**Parallel tool calls:**
- Batch independent reads (web, terminal, file) in single turn when possible
- Serialize calls when later call depends on earlier result
- MCP servers are shared resources — don't hammer single endpoint with >3 concurrent calls

**State safety:**
- Session history is shared — subagents do NOT inherit conversation memory
- Pass all required context via `context` field
- Cross-skill chaining via `findings.jsonl` is append-only, safe for concurrent writers

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

## ⑧ Skill Maintenance & Architecture Standards

When working on any security skill, enforce these standards:

### Shared Libraries (MANDATORY)
- **state_manager.py** in every skill must be a thin wrapper over `../scripts/base_state.py`
- **gate_check.py** in every skill must be a thin wrapper over `../scripts/base_gate.py`
- Skill-specific config goes in `../scripts/config.py` (PHASES, GATEWAYS, OUTPUT_DIR, BUDGET_HOURS)
- Never duplicate state_manager or gate_check logic across skills

### Required Sections
Every SKILL.md must have:
- Quick Wins table (mid-engagement entry with existing context)
- Evidence Standards reference → `../references/evidence-standards.md`
- Severity Mapping reference → `../references/severity-mapping.md`
- Postmortem section with shared `../scripts/postmortem.py` invocation
- findings.jsonl confidence field in cross-skill templates

### Phase Reference Mapping
If a skill compresses or renames phases (like mtest 10→7), add a mapping table:
```markdown
Reference file mapping (vX.Y.Z compression):
  Phase 1 → references/phase1-*.md
  Phase 2 → references/phase2-*.md
```

### Naming Conventions
- Output dirs: `<skill>-output/` (e.g., `atest-output/`, `mtest-output/`)
- State file: `<skill>-output/state.yaml`
- Findings log: `<skill>-output/findings-log.md`
- Evidence dir: `<skill>-output/evidence/<FINDING-ID>/`
- Engagement files: prefix with `engagement-` (gitignore via `../references/engagement-gitignore-template`)

## ⑧b Cross-Domain Amplification

Load `hyper-intuition` skill alongside this one for non-security tasks.
It extends the same meta-cognitive patterns to research, code, and creative work.

## ⑧c Skill Maintenance Patterns

When entering any security skill:
- If the skill lacks a Quick Wins section, drop to the bottom of the Quick Reference and add one
- If state_manager.py/gate_check.py are duplicated across skills, reference `ptest-scan/references/state-manager-consolidation.md`
- If phase reference mapping is unclear, add a mapping table (see mtest v4.0.0 pattern)

## ⑧ macOS MCP Server Setup

MCP servers need Python 3.11+ but macOS ships 3.9.6. Use `uv tool install`:
- `uv tool install <pkg> --python 3.11` (most servers)
- `uv tool install cve-mcp-server --python 3.12` (needs 3.12)
- Config must use FULL PATHS: `/Users/<user>/.local/bin/<server-name>`
- Reload in-session: `/mcp reload` or ask "reload mcp servers"
- Verify: `ls ~/.local/bin/{arxiv-mcp-server,cve-mcp-server,semantic-scholar-mcp,wikipedia-mcp}`

## References

- `references/macos-mcp-install.md` — macOS MCP server installation via uv tool (Python version handling, full paths, pitfalls)
- `../references/evidence-standards.md` — required/optional evidence capture, redaction rules, storage convention
- `../references/severity-mapping.md` — cross-skill severity normalization table
- `../references/gitops-security.md` — git commit history OPSEC, exposure audit, remediation
- `../references/engagement-gitignore-template` — shared gitignore for engagement artifacts and secrets
