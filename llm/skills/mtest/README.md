# mtest — Mobile Application Penetration Testing

Gated linear workflow for mobile application security testing. Covers Android and iOS with static analysis, dynamic instrumentation (Frida), traffic interception, and API testing.

## Install

```bash
cp -r llm/skills/mtest ~/.kiro/skills/mtest
```

## Usage

```
> start     # Begin engagement — define scope, target app
> status    # Show current phase and findings count
> resume    # Resume interrupted engagement
> next      # Advance to next phase (gate must be satisfied)
> report    # Generate findings report (Phase 5+)
> cleanup   # Archive and sanitize
```

## Phases

| # | Phase | Focus |
|---|-------|-------|
| 1 | Preflight | Tool setup verification (Frida, objection, jadx, etc.) |
| 2 | Static Analysis | Decompilation, secrets, hardcoded endpoints |
| 3 | Dynamic Setup | Bypass scripts, proxy config, cert pinning bypass |
| 4 | Traffic Analysis | Intercepted requests, API mapping |
| 5 | Runtime Testing | Frida hooks, data storage, deep links |
| 6 | API Testing | Server-side API vulnerabilities |

## Output

```
./mtest-output/
├── state.yaml
├── scope.md
├── phase1-preflight/
├── phase2-static/
├── phase3-dynamic-setup/
│   └── scripts/           # Frida scripts used
├── phase4-traffic/
├── phase5-runtime/
│   ├── screenshots/
│   └── frida-output/
├── phase6-api/
├── findings/
│   ├── MTEST-001.md
│   └── ...
└── report.md
```

## References

9 reference docs covering Frida scripts, static analysis patterns, banking app patterns, OWASP Mobile Top 10, API testing, traffic analysis, runtime testing, dynamic setup, and preflight checklists.

## Related Skills

- **ptest** — broader pentest workflow (mtest focuses on mobile-specific concerns)
- **parse-finding** — format findings for Jira
