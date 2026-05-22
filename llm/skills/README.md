# LLM Skills

Structured prompt-based skills for AI-assisted security testing. Each skill is a gated workflow that enforces methodical progression through phases, with quality gates and human sign-off at transitions.

## Skills

| Skill | Description | Phases | Target |
|-------|-------------|--------|--------|
| [scode](scode/) | Source code security review — 5 steps + 23 vuln sub-scanners | 5 | Source code (web, API, web3) |
| [ptest](ptest/) | Penetration testing — recon through exploitation to reporting | 8 | Live targets (web apps, infra) |
| [mtest](mtest/) | Mobile app pentest — static, dynamic, Frida instrumentation | 6 | Android/iOS apps |
| [parse-finding](parse-finding/) | Security finding → Jira-ready HTML report | 1 | Raw finding docs |

## Relationships

```
scode (code review) ──┐
                      ├──► parse-finding (format for Jira)
ptest (live pentest) ─┤
                      │
mtest (mobile)  ──────┘
```

- **scode** finds vulnerabilities in source code; **ptest** validates them against live targets
- **mtest** covers mobile-specific concerns (APK/IPA analysis, Frida hooks, traffic interception)
- **parse-finding** takes output from any of the above and formats it for Jira Cloud

## Install

Skills are installed into the Kiro/Hermes skills directory:

```bash
# Install a single skill
cp -r llm/skills/scode ~/.kiro/skills/scode
cp -r llm/skills/ptest ~/.kiro/skills/ptest
cp -r llm/skills/mtest ~/.kiro/skills/mtest
cp -r llm/skills/parse-finding ~/.kiro/skills/parse-finding
```

Or symlink for development:

```bash
ln -s "$(pwd)/llm/skills/scode" ~/.kiro/skills/scode
```

## Structure Convention

Each skill follows this layout:

```
<skill-name>/
├── SKILL.md              # Main skill definition (required)
├── README.md             # Human-readable docs
├── references/           # Supporting knowledge docs
└── <sub-skills>/         # Sub-skill directories (optional)
    └── SKILL.md
```

## Requirements

- Kiro CLI or Hermes Agent
- For ptest/mtest: standard pentest tools (nmap, Frida, Burp, etc.)
- Written authorization for any live target engagement
