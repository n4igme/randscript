---
name: ctest
version: 1.1.0
description: "Cloud and container penetration testing framework with 5 gated phases covering AWS/GCP/Azure IAM, container escape, K8s exploitation, and serverless abuse."
tags: [cloud, aws, gcp, azure, kubernetes, container, iam, serverless, pentest]
trigger: "cloud pentest, aws pentest, gcp pentest, azure pentest, kubernetes pentest, container escape, iam escalation, cloud security"
argument-hint: "<command: start|status|resume|next|report|abort|cleanup>"
metadata:
  hermes:
    tags: [cloud, aws, gcp, azure, kubernetes, container, pentest]
    related_skills: [ptest, atest, mtest]
---

# Cloud & Container Penetration Testing Framework

Structured 5-phase workflow for engagements where cloud infrastructure is the primary target. Covers AWS, GCP, and Azure with dedicated phases for IAM, services, containers, and post-exploitation.

## Architecture

```
Phase 1: Scope & Discovery → Phase 2: IAM & Access → Phase 3: Service Exploitation → Phase 4: Container & Orchestration → Phase 5: Reporting
```

## Commands

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

### Command Procedures

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
├── findings-log.md
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
| 3 Service Exploitation | exposed services exploited, SSRF→metadata tested, secrets from storage extracted | `references/phase3-service-exploitation.md` |
| 4 Container & Orchestration | container escapes tested, K8s RBAC abused, pod-to-node pivots attempted | `references/phase4-container-orchestration.md` |
| 5 Reporting | report delivered with attack path diagrams | see below |

**Additional references:**
- CI/CD pipeline attacks: `references/cicd-pipeline-attacks.md` (load during Phase 3 if pipelines in scope)
- Firebase Auth testing: `references/firebase-auth-testing.md` (load when Firebase Auth detected — covers email-link flow, referer bypass, session emulator pattern)

**Usage:** `skill_view(name='ctest', file_path='references/phase1-scope-discovery.md')` when entering that phase.

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

---

## Pitfalls

- AWS metadata v2 (IMDSv2) requires PUT with token header — simple GET to 169.254.169.254 won't work
- K8s service account tokens in pods ≠ cluster-admin — check RBAC before assuming full access
- Container escape via /var/run/docker.sock only works if socket is mounted (check `ls -la /var/run/`)
- Terraform state files contain secrets in plaintext — check S3 buckets for .tfstate before moving on
- GCP metadata requires `Metadata-Flavor: Google` header — missing it returns 403
- Azure IMDS requires `Metadata: true` header — curl without it looks like the endpoint doesn't exist
- EKS/GKE managed clusters patch fast — kernel exploits rarely work, focus on misconfig/RBAC instead

## Mandatory Tools

| Phase | Mandatory | Recommended |
|-------|-----------|-------------|
| 1 — Discovery | aws-cli/gcloud/az, dig, curl | ScoutSuite, Prowler, cloudfox, cloud_enum |
| 2 — IAM | aws-cli/gcloud/az, enumerate-iam | Pacu, ROADtools, gcpbucketbrute |
| 3 — Services | aws-cli/gcloud/az, nmap | s3scanner, CloudMapper, Cartography |
| 4 — Containers | kubectl, docker/crictl | kubeaudit, kube-hunter, trivy |
| 5 — Reporting | (writing phase) | — |

## Gate Enforcement (MANDATORY before `next`)

Before advancing any phase, run the gate checker:

```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/ctest/scripts"))
from gate_check import check_gate, print_gate_status

result = check_gate(".", phase=None)  # checks current phase from state.yaml
print_gate_status(result)
# Only advance if result["passed"] is True
```

If gate check fails, fix unmet items before advancing. Override only with explicit user justification.

## Script Invocation

Scripts are in `~/.hermes/skills/security/ctest/scripts/`. Invoke via `execute_code`.

**state_manager.py — engagement lifecycle:**
```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/ctest/scripts"))
import state_manager

workdir = "."
state_manager.init_state(workdir, "Target Cloud", provider="aws",
    scope_type="authenticated", access_level="compromised_user",
    target_assets=["arn:aws:iam::123456789012:role/dev-role"])

state_manager.status(workdir)
state_manager.advance_phase(workdir)
state_manager.add_finding(workdir, "CTEST-001", "Public S3 bucket", "High", "S3", "arn:aws:s3:::backup-prod")
state_manager.mark_na(workdir, 4, "No containers in scope")
state_manager.abandon(workdir, "Credentials rotated mid-test")
```

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

- **Authorization First** — cloud pentesting without explicit written authorization is illegal. Confirm scope covers specific accounts/projects.
- **Production Safety** — never modify production resources without explicit approval. Read-only enumeration by default. Document any write operations needed for PoC.
- **Credential Handling** — discovered credentials go in findings, not in your shell history. Use environment variables, clear after use.
- **Blast Radius** — before running automated tools (ScoutSuite, Pacu), confirm they won't trigger alerts or rate limits that disrupt production.
- **Region Awareness** — test ALL regions, not just the primary. Resources hidden in unused regions are a common finding.
- **No Persistence** — document persistence techniques but do NOT deploy backdoors without explicit authorization.
- **Evidence Preservation** — screenshot/log everything before remediation discussions. Cloud resources can be deleted quickly.
- **Alibaba Cloud metadata** — uses `100.100.100.200` (NOT 169.254.169.254). Requires no special headers (unlike GCP/Azure). RAM security credentials at `/latest/meta-data/ram/security-credentials/`.
- **Alibaba OSS buckets** — format `{name}.{region}.aliyuncs.com`. Common regions: oss-ap-southeast-1, oss-cn-hangzhou, oss-cn-shanghai. POST to OSS returns XML `MethodNotAllowed` with `webapp-origin.marmot-cloud.com` HostId (confirms static bucket). Always test via CNAME too — different ACLs possible.
- **Ant Group/Alipay infrastructure** — Spanner (internal LB), Tengine (CDN edge), ESA (edge security). `x-fc-request-id` = Function Compute, `x-oss-request-id` = OSS. See ptest `references/alibaba-cloud-infrastructure.md` for full fingerprinting guide.
- **Geo-blocking** — SEA companies (Grab, Gojek, Tokopedia, OVO) commonly geo-restrict API gateways. All endpoints return 502 from outside the region. If you hit consistent 502s across all API paths, test from a regional VPN before concluding the service is down. Static assets (CDN, S3 via CNAME) often remain accessible globally even when APIs are blocked.
- **Cost Awareness** — cloud pentesting can accidentally generate costs (ScoutSuite scanning all regions, large S3 sync, spinning up compute for PoC). If using client credentials, monitor billing. Prefer `--dry-run` flags and `--max-keys`/`--limit` on enumeration. Never run crypto mining PoCs on client accounts.
- **S3 ListBucket via CNAME** — some buckets allow ListBucket only through their CNAME (e.g., `subdomain.target.com` → bucket) but deny direct `bucket.s3.amazonaws.com` access. Always test both paths. A 200 on listing doesn't mean GetObject works — test read/write separately.
- **cloud_enum on macOS** — the pip-installed `cloud_enum` may fail with "Cannot access mutations file" because it looks for `fuzz.txt` relative to the binary, not the package. Fix: find the package dir (`pip3 show cloud_enum | grep Location`) and run from there, or symlink the enum_tools directory. If cloud_enum fails, use manual GCS bucket brute-force: `curl -sk "https://storage.googleapis.com/BUCKET" -o /dev/null -w "%{http_code}"` (404=doesn't exist, 403=exists+ACL'd, 401=exists+needs auth). Test keywords: {company}, {project}-prd/stg/dev, {product}-backup/logs/data.
- **macOS port 5000** — AirPlay Receiver occupies port 5000. Use 5001+ for Flask/web tools. Or disable AirPlay in System Settings > General > AirDrop & Handoff.
- **Firebase API key referer restriction** — Firebase Identity Toolkit returns 403 "Requests from referer <empty> are blocked" without Referer header. Always add `-H "Referer: https://target.domain/"` to all identitytoolkit.googleapis.com calls.
- **CDN path traversal → origin disclosure** — Fastly/Varnish/CloudFront may not normalize `%2e%2e` (URL-encoded `..`). When CDN can't resolve the traversed path, it often generates a 302 redirect to the internal origin hostname, leaking backend infrastructure. Test: `curl -D- "https://cdn-target.com/v1/any/%2e%2e/test"` — if Location header reveals a different domain (e.g., `api-origin.target.internal`), you've found the origin. Follow-up: DNS enumerate the leaked domain for admin panels, staging, internal services. Chain: if the redirect is to a domain you control or can influence → open redirect. This pattern is common on GCP (Google Frontend + Fastly) and AWS (CloudFront + ALB).

