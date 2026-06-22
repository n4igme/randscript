---
name: ctest
version: 1.2.0
description: "Cloud and container penetration testing framework with 5 gated phases covering AWS/GCP/Azure IAM, container escape, K8s exploitation, and serverless abuse."
tags: [cloud, aws, gcp, azure, kubernetes, container, iam, serverless, pentest]
trigger: "cloud pentest, aws pentest, gcp pentest, azure pentest, kubernetes pentest, container escape, iam escalation, cloud security"
argument-hint: "<command: start|status|resume|next|report|abort|cleanup>"
notes:
  - "v1.2.0: Added Quick Reference, Phase Entry Protocol, discovery loop-back, findings.jsonl procedure, N/A phase guidance. Aligned with ptest/mtest/atest patterns."
  - "v1.1.1: Pitfalls extracted to references/pitfalls-and-guardrails.md. Abandon heuristics added."
metadata:
  hermes:
    tags: [cloud, aws, gcp, azure, kubernetes, container, pentest]
    related_skills: [ptest, atest, mtest, ttest, adtest]
---

# Cloud & Container Penetration Testing Framework

Structured 5-phase workflow for engagements where cloud infrastructure is the primary target. Covers AWS, GCP, and Azure with dedicated phases for IAM, services, containers, and post-exploitation.

## Quick Reference

```
Phases:  1.Scope&Discovery → 2.IAM&Access → 3.ServiceExploitation → 4.Container&Orchestration → 5.Reporting
States:  LOCKED → OPEN → PASSED → N/A (sequential, no skipping)
Commands: start | status | resume | next | report | abort | cleanup

Key rules:
  • Scope-type determines approach (External/Authenticated/Internal)
  • Loop-back: new creds/endpoints from any phase → re-analyze IAM (Phase 2)
  • Attack path chaining after every phase (individual Low → chained Critical)
  • N/A phases documented with justification (not skipped silently)
  • Phase 4 → N/A if no K8s/containers in scope (document why)
  • Confidence: Confirmed > Probable > Theoretical

Time caps (8-hour engagement):
  P1: 70min  P2: 120min  P3: 120min  P4: 95min  P5: 75min

Discovery loop-back:
  • Any phase finding new creds/endpoints → append to discovery-queue.md
  • At phase exit, drain queue with targeted re-testing before advancing
  • Prevents "found keys in Phase 3 but never tested IAM scope" pattern
```

## Architecture


**state.yaml schema:**
```yaml
engagement:
  name: string
  started: ISO8601
  target: string
current_phase: int
gateways:
  1_discovery: OPEN|PASSED|LOCKED
  2_iam_access: ...
  3_service_exploitation: ...
  4_containers: ...
  5_report: ...
time_tracking:
  phase_1_start: ISO8601
  phase_1_end: ISO8601
findings_count: int
findings_by_severity:
  critical: int
  high: int
  medium: int
  low: int
notes: string
```


```
Phase 1: Scope & Discovery → Phase 2: IAM & Access → Phase 3: Service Exploitation → Phase 4: Container & Orchestration → Phase 5: Reporting
```

## Scripts

Scripts in `~/.hermes/skills/security/ctest/scripts/`:
- **state_manager.py**: `init_state()`, `status()`, `advance_phase()`, `add_finding()`, `mark_na()`, `abandon()`, `should_abandon()`
- **gate_check.py**: `check_gate(workdir, phase)`, `print_gate_status(result)` — run before advancing

### Gate Enforcement (MANDATORY before `next`)

```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/ctest/scripts"))
from gate_check import check_gate, print_gate_status

result = check_gate(".", phase=None)
print_gate_status(result)
```

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
- No cloud provider credentials or access
- Target is on-premise only (use ptest instead)
- Scope is limited to single service with no IAM component

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

## Concurrent Execution Safety

See `../references/concurrent-execution-safety.md` for state locking, parallel scanning, and subagent handoff rules.

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

| Command | Action |
|---------|--------|
| `start` | Initialize engagement — define scope, cloud provider, access level |
| `status` | Show current phase, progress, findings count |
| `resume` | Resume interrupted engagement from last checkpoint |
| `next` | Advance to next phase (runs exit criteria check) |
| `report` | Generate final report |
| `abort` | Terminate engagement early — records reason, generates partial report |
| `cleanup` | Archive engagement output, remove temporary files |

If no command is given, show current status and suggest next action.

#### Postmortem

After engagement closes, run shared retrospective:
```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/scripts"))
from postmortem import run_postmortem
run_postmortem(workdir, "ctest")
```

## Command Procedures

**`start`:**
1. Collect: cloud provider, scope type, target assets, access level, rules of engagement, authorization proof.
2. Create output directory (`./ctest-output/` with subdirs for each phase).
3. Write `state.yaml` with engagement metadata.
4. Write `scope.md` with all target details.
5. Begin Phase 1 discovery immediately based on scope type:
   - External → credential hunting + public resource enumeration
   - Authenticated → map reachable resources with provided creds
   - Internal → systematic service enumeration

**`status`:** Output current phase, gateway states (5 phases), findings count by severity, cloud provider, time elapsed. If no engagement, suggest `start`.

**`resume`:**
1. Read `state.yaml` to determine active phase.
2. **Staleness:** >3 days → re-verify credentials still valid (tokens expire). >14 days → re-run Phase 1 discovery (cloud resources change frequently). >30 days → treat as fresh engagement.
3. Report status and suggest next action.

**`next`:**
1. Verify current phase gate is satisfied.
2. If NOT met: list unmet criteria, suggest what to test.
3. If met: update state.yaml, advance phase.
4. Override allowed with justification.

**`abort`:**
1. Record reason in state.yaml, mark remaining phases ABORTED.
2. Generate partial report from existing findings.
3. Run cleanup.

**`cleanup`:**
1. Archive `./ctest-output/` to `ctest-output-{target}-{date}.tar.gz`.
2. Remove test credentials/tokens you created (keep found credentials as evidence).
3. Revoke any temporary IAM roles/policies created during testing.
4. Print summary: findings by severity, phases completed.

---

## Initialization (`start`)

Collect before testing:

1. **Cloud Provider(s)** — AWS, GCP, Azure, multi-cloud
2. **Scope Type** — external (black-box), authenticated (grey-box with creds), internal (white-box with console access)
3. **Target Assets** — account IDs, project names, subscription IDs, IP ranges, domains
4. **Access Level** — no credentials, leaked keys, compromised user, service account
5. **Rules of Engagement** — production restrictions, regions, services excluded
6. **Authorization** — confirm written authorization exists

Create output directory:

```
./ctest-output/
├── state.yaml
├── scope.md
├── discovery-queue.md
├── findings-log.md
├── findings.jsonl
├── phase1-discovery/
├── phase2-iam/
├── phase3-services/
├── phase4-containers/
├── phase5-report/
└── escalations/
```

Write `state.yaml`:

```yaml
engagement:
  name: ""
  started: ""
  provider: ""  # aws, gcp, azure, multi
  scope_type: ""  # external, authenticated, internal
  access_level: ""  # none, leaked_keys, compromised_user, service_account

gateways:
  1_discovery: OPEN
  2_iam_access: LOCKED
  3_service_exploitation: LOCKED
  4_containers: LOCKED
  5_reporting: LOCKED

findings_count: 0
escalations_count: 0

time_tracking:
  phase_1_start: ""
  phase_1_end: ""
  phase_2_start: ""
  phase_2_end: ""
  phase_3_start: ""
  phase_3_end: ""
  phase_4_start: ""
  phase_4_end: ""
  phase_5_start: ""
  phase_5_end: ""
```

---

## Scope-Type Decision Tree

Your approach fundamentally changes based on access level. Before starting Phase 1, determine which path you're on:

```
┌─────────────────────────────────────────────────────────────────────┐
│ EXTERNAL (black-box, no creds)                                      │
│ Priority: leaked creds → public resources → SSRF to metadata        │
│ Phase 1: heavy (credential hunting, public resource enum)           │
│ Phase 2: skip unless creds found                                    │
│ Phase 3: limited to public-facing services                          │
│ Phase 4: only if registry/K8s API exposed externally                │
├─────────────────────────────────────────────────────────────────────┤
│ AUTHENTICATED (grey-box, limited creds/role)                        │
│ Priority: policy analysis → escalation → lateral movement           │
│ Phase 1: light (you already have access, map what you can reach)    │
│ Phase 2: heavy (this is where critical findings live)               │
│ Phase 3: test everything your role can touch                        │
│ Phase 4: if EKS/GKE/AKS in scope                                   │
├─────────────────────────────────────────────────────────────────────┤
│ INTERNAL (white-box, console access)                                │
│ Priority: misconfigurations → blast radius → data exposure          │
│ Phase 1: minimal (you have full visibility)                         │
│ Phase 2: audit all roles/policies systematically                    │
│ Phase 3: comprehensive — test every service category                │
│ Phase 4: full cluster assessment                                    │
└─────────────────────────────────────────────────────────────────────┘
```

**Bug bounty note:** Most bug bounty cloud targets are EXTERNAL. You're hunting for public resources and leaked credentials. If you find creds, you shift to AUTHENTICATED path mid-engagement.

---

## Phases (load reference for full methodology)

| Phase | Gate | Reference |
|-------|------|-----------|
| 1 Scope & Discovery | cloud accounts enumerated, services mapped, network topology documented | `references/phase1-scope-discovery.md` |
| 2 IAM & Access | IAM policies reviewed, privilege escalation paths mapped, cross-account trust analyzed | `references/phase2-iam-access.md` |
| 3 Service Exploitation | exposed services exploited, SSRF→metadata tested, secrets from storage extracted | `references/phase3-service-exploitation.md`, `references/cwl-mcrta-multi-cloud-lab.md` (full flag write-up with HTTP req/res) |
| 4 Container & Orchestration | container escapes tested, K8s RBAC abused, pod-to-node pivots attempted | `references/phase4-container-orchestration.md` |
| 5 Reporting | report delivered with attack path diagrams | see below |

**Additional references:**
- CI/CD pipeline attacks: `references/cicd-pipeline-attacks.md` (load during Phase 3 if pipelines in scope)
- Firebase Auth testing: `references/firebase-auth-testing.md` (load when Firebase Auth detected — covers email-link flow, referer bypass, session emulator pattern)

**Usage:** `skill_view(name='ctest', file_path='references/phase1-scope-discovery.md')` when entering that phase.

### Phase Entry Protocol (ALL phases)

When entering ANY phase, before executing techniques:
1. **Load reference file** — per Phases table above
2. **Create/verify checklist** — `ctest-output/phase{N}-{name}/checklist.md` must exist with all techniques listed as PENDING
3. **Record timestamp** — write `phase_N_start` in state.yaml

### Discovery Loop-Back (ALL phases)

When any phase reveals NEW credentials, endpoints, or access paths:
1. Append to `./ctest-output/discovery-queue.md` with source finding ID
2. At phase exit, before advancing: drain queue with targeted re-testing
3. Credential findings → always loop back to Phase 2 IAM analysis
4. Prevents "found keys in Phase 3 but never tested their IAM scope" pattern

### N/A Phases

If a phase is not applicable (no K8s/containers for Phase 4, no IAM access for Phase 2 in external scope), document justification in state.yaml and mark gateway `N/A`. Never skip silently.

---

## Cross-Skill Handoffs

**Into ctest (from other skills):**
- ptest/atest finds SSRF → invoke ctest Phase 3 (cloud metadata, internal services)
- ptest finds cloud storage URLs → invoke ctest Phase 1 (S3/GCS/Blob misconfig)
- scode finds hardcoded AWS/GCP creds → invoke ctest Phase 2 (IAM access analysis)

**Out of ctest (to other skills):**
- Cloud web app found via recon → hand to ptest (standard web pentest)
- API gateway discovered → hand to atest (API-focused testing)
- Container has source code → hand to scode (code review)
- K8s CronJob runs exploitable binary → hand to xdev (exploit dev)

## Attack Path Chaining

Findings in isolation are often Low/Medium. Chained together, they become Critical. After each phase, ask: "Can I combine this with something I already found?"

### Common Cloud Attack Chains

```
Chain 1: Public Bucket → Account Compromise
  Public S3 listing (Low) → terraform.tfstate found (Medium) → 
  AWS keys in state file (High) → iam:CreatePolicyVersion (Critical)

Chain 2: SSRF → Cloud Takeover
  SSRF in web app (Medium) → IMDSv1 metadata access (High) → 
  Instance role credentials → iam:PassRole + Lambda (Critical)

Chain 3: GitHub Leak → Data Exfiltration
  Leaked service account key on GitHub (Medium) → 
  SA has storage.objects.list (Low alone) → 
  Bucket contains PII/backups (Critical)

Chain 4: Container → Cloud Account
  Unauthenticated kubelet (High) → pod exec → 
  SA token with cloud IAM permissions → 
  Cloud metadata → account-level access (Critical)

Chain 5: CI/CD → Supply Chain
  Public repo with GitHub Actions (Info) → 
  OIDC federation to AWS with broad subject (Medium) → 
  Workflow injection → assume production role (Critical)
```

### Chaining Checklist (run after each phase)

After finding something, check if it unlocks:
- [ ] **Credentials** — does this give me keys/tokens for another service?
- [ ] **Network access** — does this let me reach internal services?
- [ ] **Identity** — does this let me become a more privileged principal?
- [ ] **Data** — does this expose secrets that chain to other systems?
- [ ] **Code execution** — does this let me run code in a trusted context?

**Cross-reference:** ptest `references/chain-and-escalate-phase.md` for general chaining methodology.

---

## Phase 5: Reporting

### Gate: report delivered with all findings documented

**Report Structure:**

```markdown
# Cloud Penetration Test Report — {Client} ({Provider})

## 1. Executive Summary
- Provider(s) tested, scope type, access level
- Critical findings count and top risk
- Overall cloud security posture assessment

## 2. Scope & Methodology
- Accounts/projects/subscriptions in scope
- 5-phase methodology with status
- Tools used

## 3. Attack Path Diagram
- Visual showing: initial access → escalation → lateral movement → data access
- Confirmed vs theoretical paths

## 4. Findings Summary
| ID | Title | Severity | Service | Impact |

## 5. Detailed Findings
- Each finding with: description, affected resource ARN/URI, evidence, impact, remediation
- CIS Benchmark mapping where applicable

## 6. Remediation Roadmap
- Immediate (IAM key rotation, public access removal)
- Short-term (policy tightening, network segmentation)
- Medium-term (architecture improvements, zero-trust adoption)

## 7. Compliance Mapping
- CIS Benchmarks (AWS/GCP/Azure)
- SOC 2 controls
- ISO 27001 Annex A
- PCI-DSS (if applicable)
```

---

### Evidence Standards

All findings must follow `../references/evidence-standards.md` for required/optional evidence capture and redaction rules.

## Finding Template

```markdown
## [CTEST-{ID}] {Title}

**Severity:** Critical / High / Medium / Low / Info
**Provider:** AWS / GCP / Azure
**Service:** {IAM, S3, EC2, EKS, Lambda, etc.}
**Resource:** {ARN, URI, or resource identifier}
**CIS Benchmark:** {reference if applicable}

### Description
{What the misconfiguration or vulnerability is}

### Evidence
{CLI output, API response, screenshot}

### Impact
{What an attacker can achieve — data access, escalation, persistence}

### Remediation
{Specific fix — policy change, configuration update, architecture recommendation}
```

### Finding ID Assignment

1. Read `findings_count` from `state.yaml`
2. Increment by 1 → `CTEST-{count:03d}`
3. Write updated count back immediately
4. **Append to `findings.jsonl`** for cross-skill chaining:

```python
import json
from datetime import datetime
finding = {
    "id": "CTEST-{count:03d}",
    "skill": "ctest",
    "severity": "{severity}",
    "type": "{vuln_type}",  # e.g., iam_escalation, public_bucket, ssrf_metadata, container_escape
    "target": "{resource_arn_or_uri}",
    "summary": "{one-line description}",
    "chain_potential": [],  # e.g., ["ptest:ssrf", "atest:api_testing", "adtest:lateral_movement"]
    "timestamp": datetime.now().isoformat(),
    "phase": "{current_phase}",
    "confidence": "confirmed",  # confirmed / probable / theoretical
    "status": "confirmed"
}
with open("./ctest-output/findings.jsonl", "a") as f:
    f.write(json.dumps(finding) + "\n")
```

---

### Severity Mapping

Cross-skill severity normalization: `../references/severity-mapping.md`

## Pitfalls

> Full pitfalls: `references/pitfalls-and-guardrails.md`

Key: IMDSv2 needs PUT+token, K8s SA ≠ cluster-admin, terraform.tfstate has plaintext secrets, GCP metadata needs Metadata-Flavor header, Azure IMDS needs Metadata:true header.

### Severity Honesty Rules (Bug Bounty)
- **Theoretical ≠ Hackable.** If an attack chain requires a prerequisite you haven't proven (e.g., XSS for token theft → ATO), report at the LOWER severity of the weakest link. "ATO via email change that requires victim's idToken" is Low/Medium info disclosure, NOT Critical ATO.
- **Email delivery ≠ HTTP 204.** When testing email flooding/bombing, ALWAYS verify delivery in a real inbox (mail.tm API). Count actual received messages. HTTP status codes lie.
- **Client-side keys are mostly useless.** Datadog client tokens, Braze SDK keys, Sentry DSNs, GMO public keys — these are designed to be public. Only report if the key grants server-side access (REST API, admin panel, data read/write). Test before reporting.
- **Firebase default behavior is not a vulnerability.** Account creation, email enumeration, password reset — these are standard Firebase features. Only reportable if: (a) platform is invite-only and signUp should be disabled, (b) email-link platform has password provider enabled (pre-reg ATO), or (c) you can prove app-layer access from Firebase-layer manipulation.

## Mandatory Tools

| Phase | Mandatory | Recommended |
|-------|-----------|-------------|
| 1 — Discovery | aws-cli/gcloud/az, dig, curl | ScoutSuite, Prowler, cloudfox, cloud_enum |
| 2 — IAM | aws-cli/gcloud/az, enumerate-iam | Pacu, ROADtools, gcpbucketbrute |
| 3 — Services | aws-cli/gcloud/az, nmap | s3scanner, CloudMapper, Cartography |
| 4 — Containers | kubectl, docker/crictl | kubeaudit, kube-hunter, trivy |
| 5 — Reporting | (writing phase) | — |

---

## Effort Allocation

| Phase | % | 4-hour engagement | 8-hour engagement | Rationale |
|-------|---|-------------------|-------------------|-----------|
| 1 Discovery | 15% | 35 min | 70 min | Scope mapping, not exploitation |
| 2 IAM & Access | 25% | 60 min | 120 min | Highest-value — IAM misconfig = game over |
| 3 Services | 25% | 60 min | 120 min | Broad surface, many quick wins |
| 4 Containers | 20% | 50 min | 95 min | Deep technical work (skip if no K8s) |
| 5 Reporting | 15% | 35 min | 75 min | Write-up + remediation roadmap |

## Abandon & Pivot Heuristics

**Phase 1 (Discovery):**
- No credentials found after 20 min (external scope) → shift to public resource enumeration only
- All buckets/storage return AccessDenied → move to Phase 2 with whatever access you have
- Can't identify cloud provider after 15 min → check if target is actually cloud-hosted (may be on-prem)

**Phase 2 (IAM & Access):**
- No escalation paths after testing top 10 IAM patterns → document current privilege level, move to Phase 3
- Credentials expired/rotated mid-test → re-acquire (check if original source still works), if not → report as finding + move on
- All roles have least-privilege → document "IAM hardened", shift time to Phase 3 services

**Phase 3 (Services):**
- No public storage after checking all regions → stop storage, focus on compute/serverless
- Lambda/Functions all have no env vars and proper IAM → skip serverless after 15 min
- No findings after 3 service categories tested → move to Phase 4 (or Phase 5 if no containers)

**Phase 4 (Containers):**
- K8s API requires auth + RBAC is tight → cap at 30 min, focus on registry access and image scanning
- No privileged containers, no mounted sockets → document "container hardened", move to reporting
- etcd not exposed, kubelet requires auth → skip cluster-level attacks after 20 min

**Global abandon rules:**
- **75% of time budget spent, zero findings** → stop testing, write "hardened" report
- **Critical found early (leaked keys, public admin access)** → validate immediately, document, then continue for additional findings
- **Rate limited / account locked** → stop, wait 30 min. If persistent, report with partial results
- **Credentials revoked mid-engagement** → document the revocation as evidence of detection, report current findings

**Pivot triggers:**
- SSRF found (from ptest/atest) → immediately test cloud metadata (169.254.169.254), skip remaining Phase 1
- Leaked AWS keys found → stop discovery, jump to Phase 2 IAM analysis with those keys
- Public terraform.tfstate found → extract all secrets/keys, pivot to Phase 2 with extracted credentials
- Container registry public → pull images, extract secrets, feed back to Phase 2/3

---

## Guardrails

> Full guardrails: `references/pitfalls-and-guardrails.md`

Key: Authorization first, read-only by default, never deploy backdoors, test ALL regions, evidence preservation before remediation talks.
