#!/usr/bin/env python3
"""Add missing operational sections to remaining skills."""
import os

skills_dir = os.path.expanduser("~/.hermes/skills/security")

# Sections to add
RETRY = """
## Retry / Timeout Patterns

| Operation | Timeout | Retry | Backoff |
|-----------|---------|-------|---------|
| HTTP requests | 30s | 3x | 5s linear |
| nuclei scan | 300s | 2x | 30s |
| Frida attach | 10s | 3x | 5s |
| Burp request | 60s | 2x | 10s |
| Cloud CLI | 120s | 2x | 30s |

**Rules:**
- On timeout: wait for backoff, retry once. If persistent, document as blocker.
- On 429/503: exponential backoff (5s → 25s → 125s), max 3 attempts.
- On partial output: save what you have, note the gap, continue.
"""

ERROR = """
## Error Handling

| Failure Mode | Action |
|--------------|--------|
| Tool exits non-zero | Capture stderr, check if partial output is usable |
| API rate limit (429) | Back off, retry once. If persistent, document and pivot |
| Credential expired | Re-acquire or document as finding (credential rotation issue) |
| Target unreachable | Retry 3x with 30s gap. If still down, mark host UNREACHABLE |
| Permission denied | Try alternative method. If blocked, document scope gap |
| WAF blocking | Try 3 bypass techniques max, then document WAF and move on |
"""

CONCURRENCY = """
## Concurrent Execution Safety

**State conflicts:**
- `state.yaml` is not atomic — serialize `advance_phase` and `add_finding` calls
- Use file lock if running multiple agents: `with open(state_path + '.lock', 'w') as lock:`
- Temp files: use `{finding-id}-{timestamp}.tmp` to avoid collisions

**Parallel scanning:**
- Run independent targets in parallel (different directories per target)
- Share evidence via `../{skill}-output/evidence/` symlinks or copies
- Rate-limit flagging: after 3 blocked payloads across workers, pause all

**Subagent handoff:**
- Document phase status before spawning subagents (state.yaml must be consistent)
- Subagents read state only — they should not advance phases or write findings directly
- Parent agent validates subagent output before marking phase PASSED
"""

# Skills and what they need
skills = {
    "opsec": ["retry", "error", "concurrency"],
    "intuition-engine": ["retry", "error", "concurrency"],
    "ptest-scan": ["error", "concurrency"],
    "tyk-gateway-audit": ["retry", "error", "concurrency"],
    "w3hunt": ["concurrency"],
    "osint": ["concurrency"],
}

for skill, needs in skills.items():
    path = os.path.join(skills_dir, skill, "SKILL.md")
    with open(path) as f:
        content = f.read()
    
    original = content
    
    # Add retry
    if "retry" in needs and "## Retry / Timeout Patterns" not in content:
        marker = "## Error Handling" if "## Error Handling" in content else "## Command Procedures"
        if marker in content:
            content = content.replace(marker, RETRY + "\n" + marker, 1)
    
    # Add error handling
    if "error" in needs and "## Error Handling" not in content:
        marker = "## Concurrent Execution Safety" if "## Concurrent Execution Safety" in content else "## Command Procedures"
        if marker in content:
            content = content.replace(marker, ERROR + "\n" + marker, 1)
    
    # Add concurrency
    if "concurrency" in needs and "## Concurrent Execution Safety" not in content:
        marker = "## Command Procedures" if "## Command Procedures" in content else "## Workflow"
        if marker in content:
            content = content.replace(marker, CONCURRENCY + "\n" + marker, 1)
    
    if content != original:
        with open(path, "w") as f:
            f.write(content)
        print(f"Patched {skill}: added {', '.join(needs)}")
    else:
        print(f"No changes for {skill}")
