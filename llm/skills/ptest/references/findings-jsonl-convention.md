# Cross-Skill Findings Convention

## File: `./engagement/findings.jsonl`

All offensive skills append findings to a single JSONL file for cross-skill chaining. Each skill checks this file on `resume` or phase transitions for escalation opportunities.

## Schema

```json
{
  "id": "PTEST-001",
  "skill": "ptest",
  "severity": "high",
  "type": "idor",
  "target": "api.example.com/users/{id}",
  "summary": "Horizontal IDOR on user profile endpoint via sequential ID",
  "evidence": "Changed user_id param from 123 to 124, got other user's PII",
  "chain_potential": ["atest:privesc", "ctest:data_exfil"],
  "timestamp": "2026-06-02T18:30:00+07:00",
  "phase": "exploit",
  "status": "confirmed"
}
```

## Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | `{SKILL_PREFIX}-{NNN}` |
| `skill` | string | Originating skill name |
| `severity` | string | `critical\|high\|medium\|low\|info` |
| `type` | string | Vulnerability class (idor, sqli, ssrf, leaked_key, iam_misconfig, etc.) |
| `target` | string | Affected asset/endpoint |
| `summary` | string | One-line description |
| `timestamp` | string | ISO 8601 |

## Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `evidence` | string | Brief proof |
| `chain_potential` | array | `["{skill}:{attack_type}"]` — what other skills should try |
|| `phase` | string | Phase where found |
|| `confidence` | string | `confirmed\|probable\|theoretical` |
|| `status` | string | `confirmed\|theoretical\|escalated\|submitted` |
|| `credentials` | object | `{"type":"aws_key","value":"AKIA..."}` (reference only, not full secret) |

## Chain Triggers

When a skill reads findings.jsonl and sees `chain_potential` entries matching its domain:

| Finding Type | Triggers Skill | Follow-up Action |
|-------------|----------------|------------------|
| `leaked_key` (AWS) | ctest | Run IAM enumeration with discovered key |
| `leaked_key` (API) | atest | Test API access scope |
| `idor` | atest | Test for privilege escalation patterns |
| `ssrf` | ctest | Probe cloud metadata endpoints |
| `rce` | ptest | Post-exploitation (pivot, lateral) |
| `source_code` | scode | Full code review |
| `subdomain_takeover` | ptest | Exploit for cookie/session theft |
| `breached_creds` | ptest | Credential stuffing (if authorized) |
| `internal_url` | ptest | Add to attack surface |

## Usage

### Appending (any skill)
```python
import json
from datetime import datetime

def append_finding(workdir, finding):
    finding["timestamp"] = datetime.now().isoformat()
    path = f"{workdir}/findings.jsonl"
    with open(path, "a") as f:
        f.write(json.dumps(finding) + "\n")
```

### Checking for chains (on resume/next)
```python
import json

def check_chains(workdir, my_skill):
    path = f"{workdir}/findings.jsonl"
    chains = []
    try:
        with open(path) as f:
            for line in f:
                finding = json.loads(line)
                for chain in finding.get("chain_potential", []):
                    if chain.startswith(f"{my_skill}:"):
                        chains.append(finding)
    except FileNotFoundError:
        pass
    return chains
```

## Rules

- Append-only. Never modify existing lines.
- One finding per line (valid JSON per line).
- Skills check this file at: `resume`, `next`, and start of each phase.
- Don't duplicate — check `id` field before appending.
- Secrets: reference by type and prefix only (e.g., `AKIA...XXXX`), never store full credentials in this file.
