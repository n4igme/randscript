# Hermes Security Skills — Bootstrap Guide

## Installation

### Required System Tools
```bash
# macOS
brew install nmap sqlmap jq yq python3

# Optional but recommended
brew install ghidra radare2 binwalk
brew install --cask burp-suite
```

### Python Dependencies
```bash
pip install requests pyyaml python-dotenv httpx asyncio
pip install -r ~/.hermes/skills/security/requirements.txt 2>/dev/null || true
```

### MCP Servers (Optional)
```bash
uv tool install arxiv-mcp-server --python 3.11
uv tool install cve-mcp-server --python 3.11
uv tool install semantic-scholar-mcp --python 3.11
# Config paths must be absolute:
# /Users/<user>/.local/bin/<server-name>
```

## Skill Dependency Graph

```
ptest (web pentest)
├── atest (API pentest)
│   └── w3hunt (Web3/DeFi)
├── scode (code review)
│   └── w3hunt (contracts)
├── ctest (cloud/container)
├── adtest (Active Directory)
├── mtest (mobile)
│   ├── atest (API layer)
│   ├── retools (native RE)
│   └── xdev (exploit dev)
├── ttest (thick client)
│   ├── atest (API traffic)
│   ├── scode (decompiled source)
│   └── retools (binary RE)
├── retools (RE tooling)
│   └── xdev (exploit dev)
├── osint (offensive recon)
│   └── opsec (defensive OPSEC)
└── xdev (exploit dev)
```

## Recommended Learning Order

1. **ptest** — foundation: recon, enumeration, exploitation, reporting
2. **atest** — API-first testing (BOLA is #1 risk)
3. **scode** — secure coding review patterns
4. **osint** — reconnaissance methodology
5. **opsec** — defensive counterpart to osint
6. **mtest** — mobile app testing (requires device/emulator)
7. **ctest** — cloud/container (requires cloud access)
8. **adtest** — Active Directory (requires domain access)
9. **ttest** — thick client (requires app binary)
10. **xdev** — exploit development (most advanced)
11. **w3hunt** — DeFi bug bounty (requires web3 + web skills)
12. **intuition-engine** — load this on ALL security tasks

## Tool Requirements by Skill

| Skill | Required Tools | Optional Tools |
|-------|---------------|----------------|
| ptest | nmap, nuclei, ffuf, sqlmap, httpx | Burp Suite, nuclei-templates |
| atest | curl, python-requests | Postman, GraphQL Playground |
| ctest | aws-cli / gcloud / az, kubectl, docker | ScoutSuite, Pacu, trivy |
| adtest | Impacket, BloodHound, CrackMapExec, Certipy | Rubeus, mimikatz, LDAPSearch |
| mtest | adb/idevice, Frida, Burp/MCP | apktool, jadx, objection |
| scode | semgrep, grep, python | SonarQube, CodeQL, MobSF |
| ttest | Wireshark, Fiddler/Burp | dnSpy, JADX, Proxifier |
| w3hunt | python, foundry, hardhat | Slither, Mythril |
| xdev | gdb, ghidra, pwntools | AFL++, radare2, WinAFL |
| retools | Ghidra, radare2, IDA/Binary Ninja | x64dbg, JADX, FLOSS |
| osint | gh, jq, curl | sherlock, maigret, theHarvester |
| opsec | gh, jq, curl | Holehe, DeHashed API |
| intuition-engine | (meta-skill) | All MCP servers |

## Quick Start

```python
# Example: start any skill
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/scripts"))
from config import SKILL_CONFIG

# See config for skill-specific constants
print(SKILL_CONFIG)
```

## Troubleshooting

- **"Module not found"**: Ensure `~/.hermes/skills/security/scripts/` is in `sys.path`
- **Frida not attaching**: Check `frida-server` running on device, try `-f` spawn mode
- **Burp MCP disconnected**: Check port 8080, restart Ghidra/Burp bridge
- **GitHub API 403**: Rate limited; use `gh auth login` or set `GITHUB_TOKEN`
- **AWS CLI not found**: Install via `pip install awscli` or `brew install awscli`

## Validation

Run the full validation suite to check all skill infrastructure:

```bash
cd ~/.hermes/skills/security
make check    # full validation (configs, imports, SKILL.md sections, cross-refs, findings.jsonl)
make refs     # cross-reference integrity only
make clean    # remove __pycache__ directories
```

Or directly: `python3 scripts/validate_all.py`

The suite checks:
1. Config PHASES/GATEWAYS/SUBDIRS alignment across all 15 skills
2. Wrapper script imports (state_manager.py, gate_check.py)
3. SKILL.md required sections (postmortem, evidence-standards, severity-mapping, findings.jsonl)
4. Cross-reference file existence
5. findings.jsonl schema validation (if any exist)

## Known Issues

- **Phase naming mixed case**: `Phase 1` (Title Case) and `phase_1` (snake_case) are used interchangeably across skill docs. State.yaml uses snake_case gateway keys. This is cosmetic but can confuse when loading references.
- **state_manager.py wrappers**: All `scripts/state_manager.py` files are now thin wrappers over `scripts/base_state.py`. Skill-specific logic should extend `BaseStateManager` in `base_state.py`, not individual wrappers.
- **gate_check.py wrappers**: All `scripts/gate_check.py` files are thin wrappers over `scripts/base_gate.py`. Add skill-specific gate checks in the `checks` dict parameter during instantiation.

## Contributing

When adding a new security skill:
1. Add `scripts/config.py` with skill constants (PHASES, GATEWAYS, SUBDIRS must have equal length)
2. Add `scripts/state_manager.py` — thin wrapper extending `base_state.py`
3. Add `scripts/gate_check.py` — thin wrapper extending `base_gate.py`
4. Extend `scripts/base_state.py` if new lifecycle methods needed
5. Extend `scripts/base_gate.py` if new gate checks needed
6. Add skill to `skills/` list in this README
7. Add quick-win table to SKILL.md
8. Run `python3 scripts/check_cross_refs.py` to validate references

Phase-specific utility scripts (e.g., `opsec/scripts/exposure_check.py`,
`osint/scripts/domain_recon.py`) are acceptable alongside the standard wrappers
for automation that doesn't fit the base class pattern.
