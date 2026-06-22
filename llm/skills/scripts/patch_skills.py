#!/usr/bin/env python3
"""Patch all security skill SKILL.md files with missing operational guidance."""
import os
import re

skills_dir = os.path.expanduser("~/.hermes/skills/security")
skills = ["adtest", "atest", "ctest", "mtest", "scode", "ttest", "w3hunt", "xdev", "opsec", "osint", "retools", "intuition-engine", "ptest-scan", "tyk-gateway-audit", "ptest"]

# Content blocks to inject
WHEN_TO_USE = """
## When to Use / When NOT to Use

**Use when:**
- Target matches skill scope (see Quick Reference phases)
- You have required access level (credentials, API token, device, etc.)
- Authorization is confirmed (written permission for pentest, own assets for research)

**Avoid when:**
- Target is explicitly out of scope
- No credentials/token/device available and skill requires authenticated testing
- Time budget is insufficient for minimum viable engagement (< 15 min)
- Legal/ToS constraints block required techniques
"""

WHEN_NOT_ONLY = """
## When NOT to Use

**Avoid when:**
- Target is explicitly out of scope
- No credentials/token/device available and skill requires authenticated testing
- Time budget is insufficient for minimum viable engagement (< 15 min)
- Legal/ToS constraints block required techniques
- Prior engagement already covered this surface with no findings (hardened)
"""

RETRY_TIMEOUT = """
## Retry / Timeout Patterns

| Operation | Timeout | Retry | Backoff |
|-----------|---------|-------|---------|
| HTTP requests | 30s | 3x | 5s linear |
| nuclei scan | 300s | 2x | 30s |
| Frida attach | 10s | 3x | 5s |
| Burp request | 60s | 2x | 10s |
| Cloud CLI | 120s | 2x | 30s |
| Git clone | 60s | 2x | 10s |

**Rules:**
- On timeout: wait for backoff, retry once. If persistent, document as blocker.
- On 429/503: exponential backoff (5s → 25s → 125s), max 3 attempts.
- On partial output: save what you have, note the gap, continue.
- Long-running scans: use background terminal with `notify_on_complete=true`.
"""

ERROR_HANDLING = """
## Error Handling

| Failure Mode | Action |
|--------------|--------|
| Tool exits non-zero | Capture stderr, check if partial output is usable |
| API rate limit (429) | Back off, retry once. If persistent, document and pivot |
| Credential expired | Re-acquire or document as finding (credential rotation issue) |
| Target unreachable | Retry 3x with 30s gap. If still down, mark host UNREACHABLE |
| Permission denied | Try alternative auth method. If blocked, document scope gap |
| WAF blocking | Try 3 bypass techniques max, then document WAF and move on |
| Frida detach | Retry with `-f` spawn mode. 3 failures → anti-Frida, escalate |

**Rules:**
- Never retry blindly — understand the error first
- Save partial results before retrying (power loss, network drop)
- Document blocker findings with evidence (screenshot, HTTP status)
- On repeated failure (>3 attempts): mark as BLOCKED, continue to other surface
"""

CONCURRENCY = """
## Concurrent Execution Safety

**State conflicts:**
- `state.yaml` is not atomic — serialize `advance_phase` and `add_finding` calls
- Use file lock if running multiple agents: `with open(state_path + '.lock', 'w') as lock:`
- Temp files: use `{finding-id}-{timestamp}.tmp` to avoid collisions

**Parallel scanning:**
- Run independent hosts in parallel (different directories per host)
- Share evidence via `../{skill}-output/evidence/` symlinks or copies
- WAF/rate-limit flagging: after 3 blocked payloads across workers, pause all

**Subagent handoff:**
- Document phase status before spawning subagents (state.yaml must be consistent)
- Subagents read state only — they should not advance phases or write findings directly
- Parent agent validates subagent output before marking phase PASSED
"""

# Skill-specific "when to use" customizations
WHEN_CUSTOM = {
    "adtest": "\n**Avoid when:**\n- No domain access or credentials (unless doing unauthenticated recon only)\n- Target is workgroup, not Active Directory\n",
    "atest": "\n**Avoid when:**\n- No API docs/traffic/tokens available and endpoints are unknown\n- Target is pure web app with no API layer (use ptest instead)\n- GraphQL introspection disabled and schema unknown\n",
    "ctest": "\n**Avoid when:**\n- No cloud provider credentials or access\n- Target is on-premise only (use ptest instead)\n- Scope is limited to single service with no IAM component\n",
    "mtest": "\n**Avoid when:**\n- No device/emulator available\n- App requires physical hardware (NFC, biometric, Bluetooth)\n- Jailbreak/root is strictly prohibited and pinning is unpatchable\n",
    "scode": "\n**Avoid when:**\n- No source code access (binary only — use retools/xdev)\n- Codebase is minified/obfuscated with no source maps\n- PR is trivial (< 20 lines changed) — manual review is faster\n",
    "ttest": "\n**Avoid when:**\n- No app binary or installer\n- App is web-only (use ptest/atest)\n- Thin wrapper around web app with no client-side logic\n",
    "w3hunt": "\n**Avoid when:**\n- No web + smart contract hybrid scope (pure SC → scode only)\n- Program is paused or out of scope\n- Prior contest exhausted high-value bugs\n",
    "xdev": "\n**Avoid when:**\n- No crash PoC or fuzzer output\n- Target is userland app with no binary access (use ptest/scode)\n- Bug is in unreachable code (no attacker-controlled trigger)\n",
    "opsec": "\n**Avoid when:**\n- No identifiable public presence (handle, email, domain)\n- Assessment scope is third-party (use osint on external targets)\n",
    "osint": "\n**Avoid when:**\n- No seed data (handle, email, domain) — common names alone are insufficient\n- Target is offline-only (no public digital footprint)\n- Legal constraints prohibit platform enumeration\n",
    "retools": "\n**Avoid when:**\n- No binary file to analyze\n- Binary is interpreted script (JS/Python) — read source directly\n- Source code is available (use scode instead)\n",
    "intuition-engine": "\n**Avoid when:**\n- Task is trivial single-step (overhead exceeds value)\n- Only one skill is needed (no chaining required)\n- User explicitly asked for single-tool approach\n",
    "ptest-scan": "\n**Avoid when:**\n- Not working on the ptest codebase itself\n- Change is UI/visual (not pipeline/automation)\n- Issue is in a skill, not the ptest platform\n",
    "tyk-gateway-audit": "\n**Avoid when:**\n- No Tyk gateway config or OJK audit sheets\n- Target uses different API gateway (Kong, Apigee, AWS API Gateway)\n- Scope is endpoint behavior, not gateway policy\n",
    "ptest": "\n**Avoid when:**\n- Target is API-only (use atest)\n- Target is mobile app (use mtest)\n- Target is pure cloud infra with no network layer (use ctest)\n",
}

# Apply patches
patched = []
for skill in skills:
    path = os.path.join(skills_dir, skill, "SKILL.md")
    if not os.path.exists(path):
        continue
    
    with open(path) as f:
        content = f.read()
    
    original = content
    
    # Add "When to use" block
    if "use when" not in content.lower() and "when to use" not in content.lower():
        marker = "## Commands\n"
        if marker in content:
            custom = WHEN_CUSTOM.get(skill, "")
            block = WHEN_TO_USE + "\n" + custom
            content = content.replace(marker, block + marker, 1)
    
    # Add "When NOT to use" if needed and not already covered
    if ("don't use" not in content.lower() and "not use" not in content.lower() and "avoid" not in content.lower()):
        if "## When NOT to Use" not in content:
            marker = "## Commands\n"
            if marker in content:
                content = content.replace(marker, WHEN_NOT_ONLY + "\n" + marker, 1)
    
    # Add retry/timeout
    if "retry" not in content.lower() and "timeout" not in content.lower():
        if "## Retry / Timeout Patterns" not in content:
            if "## Error Handling" in content:
                content = content.replace("## Error Handling", RETRY_TIMEOUT + "\n## Error Handling", 1)
            elif "## Commands\n" in content:
                content = content.replace("## Commands\n", "## Commands\n\n" + RETRY_TIMEOUT, 1)
    
    # Add error handling
    if "error handling" not in content.lower() and "on error" not in content.lower():
        if "## Error Handling" not in content:
            if "## Retry / Timeout Patterns" in content:
                content = content.replace("## Retry / Timeout Patterns", ERROR_HANDLING + "\n## Retry / Timeout Patterns", 1)
            elif "## Commands\n" in content:
                content = content.replace("## Commands\n", "## Commands\n\n" + ERROR_HANDLING, 1)
    
    # Add concurrency
    if "concurrent" not in content.lower() and "parallel" not in content.lower():
        if "## Concurrent Execution Safety" not in content:
            if "## Error Handling" in content:
                content = content.replace("## Error Handling", ERROR_HANDLING + "\n## Concurrent Execution Safety", 1)
            elif "## Commands\n" in content:
                content = content.replace("## Commands\n", "## Commands\n\n" + CONCURRENCY, 1)
    
    if content != original:
        with open(path, "w") as f:
            f.write(content)
        patched.append(skill)
        print(f"Patched {skill}")
    else:
        print(f"No changes needed for {skill}")

print(f"\nTotal patched: {len(patched)}")
