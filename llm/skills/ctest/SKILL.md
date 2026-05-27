---
name: ctest
version: 1.0.0
description: "Cloud and container penetration testing framework with 5 gated phases covering AWS/GCP/Azure IAM, container escape, K8s exploitation, and serverless abuse."
tags: [cloud, aws, gcp, azure, kubernetes, container, iam, serverless, pentest]
trigger: "cloud pentest, aws pentest, gcp pentest, azure pentest, kubernetes pentest, container escape, iam escalation, cloud security"
argument-hint: "<command: start|status|resume|next|report>"
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
| `cleanup` | Archive engagement output, remove temporary files |

If no command is given, show current status and suggest next action.

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

## Phase 1: Scope & Discovery

### Gate: cloud provider confirmed, account/project enumerated, external attack surface mapped

**Prioritization by scope type:**
- **External:** Credential Discovery (#5) first → then Service Discovery (#3) → then External Attack Surface (#4). You need creds or public resources before anything else matters.
- **Authenticated:** Account/Project Enumeration (#2) first → then Service Discovery (#3). You already have access, map what's reachable.
- **Internal:** All techniques in parallel — you have visibility, be systematic.

**Techniques:**

1. **Provider Identification:**
   ```bash
   # DNS indicators
   dig +short CNAME target.com  # *.amazonaws.com, *.googleusercontent.com, *.azurewebsites.net
   # IP range lookup
   whois <IP> | grep -i "amazon\|google\|microsoft"
   # HTTP headers
   curl -sI https://target.com | grep -i "x-amz\|x-goog\|x-ms\|server"
   ```

2. **Account/Project Enumeration:**
   - AWS: account ID from S3 bucket policies, STS error messages, CloudFront distributions
   - GCP: project ID from APIs, Firebase configs, GCS bucket names
   - Azure: tenant ID from `.well-known/openid-configuration`, subscription from error messages

3. **Service Discovery:**
   ```bash
   # Multi-cloud resource enumeration (S3, Azure Blobs, GCS in one pass)
   # https://github.com/initstring/cloud_enum
   cloud_enum -k <keyword> -k <company> -k <product> --disable-gcp  # or --disable-aws, --disable-azure
   # Discovers: open buckets, Azure apps, GCP projects, storage containers

   # S3/GCS/Blob enumeration (manual)
   aws s3 ls s3://<bucket> --no-sign-request
   gsutil ls gs://<bucket>

   # PITFALL: Some buckets have different ACLs via CNAME vs direct S3 URL
   # e.g., assets.target.com (CNAME → bucket.s3.amazonaws.com) may allow ListBucket
   # but s3://bucket directly returns AccessDenied. Always test BOTH paths.
   curl -s 'https://assets.target.com/'  # via CNAME
   aws s3 ls s3://bucket-name --no-sign-request  # direct

   # Cloud metadata from SSRF (if web app in scope)
   curl http://169.254.169.254/latest/meta-data/
   curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
   curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
   ```

4. **External Attack Surface:**
   - Exposed storage buckets (public read/write)
   - Exposed databases (RDS/CloudSQL/CosmosDB with public endpoints)
   - Exposed management interfaces (console, API gateways)
   - Serverless function URLs (Lambda URLs, Cloud Functions, Azure Functions)
   - Container registries (ECR, GCR, ACR with public access)

5. **Credential Discovery:**
   - GitHub/GitLab code search for access keys
   - `.env` files, terraform state files, CI/CD configs
   - JS bundles with embedded cloud credentials
   - Docker images with baked-in secrets
   - **GitHub OSINT for leaked session tokens** (see `references/github-credential-osint.md`)

**Reference:** `references/aws-attack-paths.md`, `references/gcp-attack-paths.md`, `references/azure-attack-paths.md`

**Cross-reference:** ptest `references/cloud-infrastructure-enumeration.md` for passive enumeration techniques.

**Cross-skill triggers from ctest:**
- Web app found on cloud infra → invoke `ptest` for web pentest
- API gateway discovered → invoke `atest` for API-specific testing
- Container with mobile backend → invoke `mtest` if app in scope
- SSRF to internal services → feed endpoints back to `ptest`/`atest`
- Geo-blocked cloud services → see ptest `references/geo-restriction-bypass.md`

---

## Phase 2: IAM & Access Analysis

### Gate: identity enumeration complete, privilege level assessed, escalation paths identified

**Techniques:**

1. **Identity Enumeration:**
   ```bash
   # AWS — who am I?
   aws sts get-caller-identity
   aws iam list-users
   aws iam list-roles
   aws iam list-attached-user-policies --user-name <user>

   # GCP
   gcloud auth list
   gcloud projects get-iam-policy <project>
   gcloud iam service-accounts list

   # Azure
   az account show
   az ad user list
   az role assignment list
   ```

2. **Policy Analysis:**
   - Overly permissive policies (`*:*`, `s3:*`, `iam:PassRole`)
   - Cross-account trust relationships
   - Service-linked roles with excessive permissions
   - Conditional policies that can be bypassed

3. **Privilege Escalation Paths:**
   - AWS: `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, `iam:PassRole` + `lambda:CreateFunction`, `sts:AssumeRole` chains
   - GCP: `setIamPolicy`, `actAs` on service accounts, `deployments.create`
   - Azure: `Microsoft.Authorization/roleAssignments/write`, custom role abuse

4. **Federation & SSO:**
   - SAML provider misconfigurations
   - OIDC trust with overly broad conditions
   - Cross-account role assumption without external ID
   - Workload identity federation abuse

5. **Automated Enumeration:**
   ```bash
   # AWS
   enumerate-iam  # or pacu
   python3 pacu.py
   # GCP
   gcp_enum.sh  # custom or gcpbucketbrute
   # Azure
   azurehound  # or ROADtools
   roadrecon gather
   ```

**Prioritization by access level:**
- **Leaked keys (AKIA/ASIA):** Identity Enumeration (#1) → Policy Analysis (#2) → Escalation (#3). Determine what the key can do before trying to escalate.
- **Compromised user:** Federation & SSO (#4) first (can you pivot to other accounts?) → then Policy Analysis (#2) → Escalation (#3).
- **Service account:** Skip user enumeration. Go straight to Policy Analysis (#2) → check what services the SA can access → Escalation (#3).

**Reference:** `references/iam-escalation-patterns.md`

**Cross-reference:** ptest `references/cloud-privilege-escalation.md` for post-compromise escalation.

---

## Phase 3: Service Exploitation

### Gate: at least 3 service categories tested, storage/compute/network assessed

**Prioritization by what you have:**
- **Read-only access:** Storage first (S3/GCS/Blob enumeration, public snapshots) → Database (RDS snapshots, Firestore rules) → Secrets Manager/Parameter Store. You're looking for data exposure.
- **Limited write access:** Serverless first (Lambda env vars, event injection, layer poisoning) → Compute (user data scripts, instance profiles) → Network. You're looking for code execution.
- **Broad access:** Network first (VPC peering, security groups, private endpoints) → then sweep all categories. You're mapping blast radius.

**Techniques:**

1. **Storage Misconfigurations:**
   - Public buckets with sensitive data (PII, backups, logs, terraform state)
   - Bucket policy allowing `s3:PutObject` (write access)
   - Versioning enabled with deleted secrets recoverable
   - Cross-account access via bucket policies
   - Signed URL generation with long expiry
   ```bash
   # S3 policy and ACL check
   aws s3api get-bucket-policy --bucket <name> 2>/dev/null
   aws s3api get-bucket-acl --bucket <name>
   # List with no auth (public bucket)
   aws s3 ls s3://<name> --no-sign-request
   # Recover deleted secrets via versioning
   aws s3api list-object-versions --bucket <name> --prefix "secrets"
   ```

2. **Compute Exploitation:**
   - EC2/VM metadata SSRF (IMDSv1 vs v2)
   - Instance profile credential theft
   - User data scripts with secrets
   - SSM command execution on managed instances
   - Snapshot access (public AMIs/images with secrets)
   ```bash
   # Public snapshots with your account's data
   aws ec2 describe-snapshots --restorable-by-user-ids all --owner-ids <account_id>
   # User data (often contains bootstrap secrets)
   aws ec2 describe-instance-attribute --instance-id <id> --attribute userData | jq -r '.UserData.Value' | base64 -d
   # SSM command execution
   aws ssm send-command --instance-ids <id> --document-name "AWS-RunShellScript" --parameters 'commands=["id"]'
   ```

3. **Serverless Abuse:**
   - Lambda/Cloud Function environment variable extraction
   - Event injection (S3 trigger, SNS, API Gateway)
   - Layer poisoning
   - Timeout/memory abuse for crypto mining
   - Cold start credential caching
   ```bash
   # Lambda env vars (often contain DB creds, API keys)
   aws lambda get-function --function-name <name> | jq '.Configuration.Environment'
   aws lambda list-functions | jq '.Functions[].FunctionName'
   # GCP Cloud Function source
   gcloud functions describe <name> --format='value(sourceArchiveUrl)'
   ```

4. **Database & Secrets:**
   - RDS/CloudSQL public snapshots
   - Secrets Manager/Parameter Store enumeration
   - DynamoDB/Firestore without fine-grained access
   - Redis/Memcached exposed without auth
   ```bash
   # Secrets Manager enumeration
   aws secretsmanager list-secrets
   aws ssm describe-parameters
   aws ssm get-parameters-by-path --path "/" --recursive --with-decryption
   # RDS public access check
   aws rds describe-db-instances | jq '.DBInstances[] | select(.PubliclyAccessible==true) | .Endpoint'
   ```

5. **Network:**
   - VPC peering misconfigurations
   - Security group/NSG overly permissive rules
   - Transit gateway route leaks
   - Private link/endpoint exposure
   - DNS exfiltration via Route53/Cloud DNS

**Reference:** `references/serverless-abuse.md`, `references/cicd-pipeline-attacks.md`

---

## Phase 4: Container & Orchestration

### Gate: container runtime assessed, K8s API tested (if present), registry access checked

**Skip criteria:** If the target has no containers/K8s (pure serverless, VM-only, or PaaS-only), skip this phase entirely. Indicators that Phase 4 applies:
- EKS/GKE/AKS clusters found in Phase 1 or Phase 3
- Container registry (ECR/GCR/ACR) discovered
- Kubernetes-related subdomains or ports (6443, 10250, 2379)
- Docker/containerd references in instance metadata or user data
- Istio/Envoy headers in HTTP responses

**If skipping:** Move directly to Phase 5. Document "No container/orchestration infrastructure identified" in the report.

**Techniques:**

1. **Kubernetes API:**
   ```bash
   # Unauthenticated access
   curl -sk https://<k8s-api>:6443/api/v1/namespaces
   curl -sk https://<k8s-api>:6443/version
   # With token
   kubectl --token=$TOKEN --server=https://<api> get pods -A
   kubectl auth can-i --list
   ```

2. **Container Escape:**
   - Privileged containers (`--privileged`)
   - Host PID/network namespace
   - Mounted Docker socket (`/var/run/docker.sock`)
   - `SYS_ADMIN` capability + cgroup escape
   - Kernel exploits (CVE-2022-0185, CVE-2024-21626)

3. **Registry Access:**
   ```bash
   # ECR
   aws ecr get-login-password | docker login --username AWS --password-stdin <account>.dkr.ecr.<region>.amazonaws.com
   aws ecr describe-repositories
   # GCR
   gcloud container images list --repository=gcr.io/<project>
   # ACR
   az acr repository list --name <registry>
   ```

4. **Service Mesh & Network Policies:**
   - Istio AuthorizationPolicy gaps
   - Missing NetworkPolicies (pod-to-pod unrestricted)
   - Sidecar injection disabled on sensitive namespaces
   - mTLS in PERMISSIVE mode

5. **Secrets in Cluster:**
   ```bash
   kubectl get secrets -A -o json | jq '.items[].data | keys'
   # Mounted secrets in pods
   kubectl exec <pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
   # etcd direct access (if exposed)
   etcdctl get / --prefix --keys-only
   ```

6. **RBAC Escalation & Token Theft:**
   ```bash
   # Check what current SA can do
   kubectl auth can-i --list
   kubectl auth can-i create pods
   kubectl auth can-i create clusterrolebindings
   # Escalate via pod creation (mount privileged SA)
   kubectl run pwn --image=alpine --overrides='{"spec":{"serviceAccountName":"admin-sa","containers":[{"name":"pwn","image":"alpine","command":["sleep","3600"]}]}}'
   # EKS IRSA token theft (from inside pod)
   cat /var/run/secrets/eks.amazonaws.com/serviceaccount/token
   # GKE Workload Identity token
   curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
   # Azure Managed Identity
   curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
   ```

7. **Supply Chain:**
   - Image provenance (unsigned images, no admission controller)
   - Helm chart values with secrets
   - CI/CD pipeline credentials in cluster
   - Admission webhook bypass

**Reference:** `references/container-escape.md`, `references/k8s-cluster-attacks.md`

**Cross-reference:** ptest `references/kubernetes-container-attacks.md`, `references/kubernetes-management-tooling.md`

---

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

| Phase | % of Total Time | Rationale |
|-------|----------------|-----------|
| 1 Discovery | 15% | Scope mapping, not exploitation |
| 2 IAM & Access | 25% | Highest-value — IAM misconfig = game over |
| 3 Services | 25% | Broad surface, many quick wins |
| 4 Containers | 20% | Deep technical work |
| 5 Reporting | 15% | Write-up + remediation roadmap |

---

## Guardrails

- **Authorization First** — cloud pentesting without explicit written authorization is illegal. Confirm scope covers specific accounts/projects.
- **Production Safety** — never modify production resources without explicit approval. Read-only enumeration by default. Document any write operations needed for PoC.
- **Credential Handling** — discovered credentials go in findings, not in your shell history. Use environment variables, clear after use.
- **Blast Radius** — before running automated tools (ScoutSuite, Pacu), confirm they won't trigger alerts or rate limits that disrupt production.
- **Region Awareness** — test ALL regions, not just the primary. Resources hidden in unused regions are a common finding.
- **No Persistence** — document persistence techniques but do NOT deploy backdoors without explicit authorization.
- **Evidence Preservation** — screenshot/log everything before remediation discussions. Cloud resources can be deleted quickly.
- **Geo-blocking** — SEA companies (Grab, Gojek, Tokopedia, OVO) commonly geo-restrict API gateways. All endpoints return 502 from outside the region. If you hit consistent 502s across all API paths, test from a regional VPN before concluding the service is down. Static assets (CDN, S3 via CNAME) often remain accessible globally even when APIs are blocked.
- **Cost Awareness** — cloud pentesting can accidentally generate costs (ScoutSuite scanning all regions, large S3 sync, spinning up compute for PoC). If using client credentials, monitor billing. Prefer `--dry-run` flags and `--max-keys`/`--limit` on enumeration. Never run crypto mining PoCs on client accounts.
- **S3 ListBucket via CNAME** — some buckets allow ListBucket only through their CNAME (e.g., `subdomain.target.com` → bucket) but deny direct `bucket.s3.amazonaws.com` access. Always test both paths. A 200 on listing doesn't mean GetObject works — test read/write separately.
- **cloud_enum on macOS** — the pip-installed `cloud_enum` may fail with "Cannot access mutations file" because it looks for `fuzz.txt` relative to the binary, not the package. Fix: find the package dir (`pip3 show cloud_enum | grep Location`) and run from there, or symlink the enum_tools directory.
