# findings.jsonl — Shared Schema

Cross-skill finding interchange format. Each skill appends one JSON object per line.

## Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Skill-prefixed ID: `{SKILL}-{NNN}` (e.g., `PTEST-001`, `MTEST-014`) |
| `skill` | string | Originating skill name (lowercase) |
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `type` | string | Vulnerability/finding type (skill-specific, see below) |
| `target` | string | `{component}:{version}` or `{host}:{port}/{path}` |
| `summary` | string | One-line description |
| `chain_potential` | array | List of `"{skill}:{action}"` strings indicating where this finding feeds next |
| `timestamp` | string | ISO 8601 datetime |
| `phase` | string | Phase/step where finding was discovered |
| `status` | string | Finding lifecycle state (see Status Values) |

## Optional Fields

| Field | Type | Used By | Description |
|-------|------|---------|-------------|
| `reliability` | string | xdev | Exploit success rate (e.g., `"85%"`, `"9/10"`) |
| `cvss` | float | ptest, mtest | CVSS 3.1 base score |
| `cve` | string | ptest, mtest, xdev | CVE identifier if known |
| `evidence` | string | all | File path to supporting evidence |
| `credentials` | object | adtest | `{"type": "...", "scope": "..."}` — no plaintext passwords |
| `chain_from` | string | all | ID of upstream finding that led to this one |

## Status Values

| Status | Meaning |
|--------|---------|
| `confirmed` | Validated, exploitable or verified |
| `potential` | Likely exists, not yet validated |
| `escalated` | Handed off to another skill for further work |
| `resolved` | Remediated or no longer exploitable |
| `false_positive` | Investigated and determined not exploitable |

## Type Values by Skill

| Skill | Valid Types |
|-------|------------|
| ptest | `rce`, `sqli`, `ssrf`, `auth_bypass`, `idor`, `deserialization`, `ssti`, `lfi`, `xxe`, `info_disclosure` |
| mtest | `insecure_storage`, `ssl_bypass`, `exported_component`, `native_vuln`, `auth_weakness`, `data_leak` |
| atest | `bola`, `broken_auth`, `mass_assignment`, `injection`, `rate_limit_bypass`, `info_disclosure` |
| ctest | `iam_escalation`, `public_exposure`, `secret_leak`, `container_escape`, `misconfig`, `lateral_movement` |
| adtest | `kerberoast`, `asreproast`, `relay`, `delegation_abuse`, `dcsync`, `gpo_abuse`, `credential_access` |
| w3hunt | `reentrancy`, `flash_loan`, `access_control`, `oracle_manipulation`, `logic_flaw`, `frontrun` |
| ttest | `dll_hijack`, `insecure_ipc`, `memory_corruption`, `hardcoded_cred`, `local_privesc`, `insecure_update` |
| xdev | `lpe`, `rce`, `sandbox_escape`, `info_leak`, `kernel_exec`, `arbitrary_write` |
| scode | `injection`, `auth_flaw`, `crypto_weakness`, `logic_bug`, `hardcoded_secret`, `unsafe_deserialization` |

## Consumer Expectations

Skills consuming findings.jsonl from other skills should:

1. Filter by `chain_potential` containing their skill name
2. Only process `confirmed` or `potential` status entries
3. Update `status` to `escalated` in the source file after picking up
4. Create their own finding with `chain_from` referencing the upstream ID

## Example

```json
{"id":"PTEST-003","skill":"ptest","severity":"high","type":"ssrf","target":"api.example.com:443/internal/fetch","summary":"Blind SSRF via url parameter allows internal network scanning","chain_potential":["ctest:cloud_metadata","atest:internal_api"],"timestamp":"2026-06-15T14:30:00Z","phase":"4","status":"confirmed","cvss":8.6}
```
