# ctest References Index

## Phase References

| Phase | File | Purpose |
|-------|------|---------|
| 1 | `phase1-scope-discovery.md` | Cloud account enumeration, service mapping |
| 2 | `phase2-iam-access.md` | IAM policy review, privilege escalation |
| 3 | `phase3-service-exploitation.md` | Storage, compute, serverless abuse |
| 4 | `phase4-container-orchestration.md` | K8s RBAC, container escape, registry |

## Provider-Specific Attack Paths

| File | Provider | Coverage |
|------|----------|----------|
| `aws-attack-paths.md` | AWS | IAM escalation, S3, Lambda, EC2 |
| `gcp-attack-paths.md` | GCP | SA impersonation, GCS, Cloud Functions |
| `azure-attack-paths.md` | Azure | Managed Identity, Blob, App Service |
| `alibaba-cloud-attacks.md` | Alibaba | RAM, OSS, ECS, Function Compute, metadata |

## Technique References

| File | Topic |
|------|-------|
| `iam-escalation-patterns.md` | Cross-provider IAM privesc catalogue |
| `container-escape.md` | Docker/containerd breakout techniques |
| `k8s-cluster-attacks.md` | RBAC abuse, pod escape, etcd access |
| `serverless-abuse.md` | Lambda/CF/FC exploitation patterns |
| `cicd-pipeline-attacks.md` | GitHub Actions, GitLab CI, Jenkins |
| `firebase-auth-testing.md` | Firebase Identity Toolkit bypass |
| `github-credential-osint.md` | Leaked keys in commits/gists |
| `proven-patterns.md` | Battle-tested cloud attack chains |

## Scripts

| File | Purpose |
|------|---------|
| `scripts/iam_enum.py` | AWS IAM enumeration + escalation path check |
| `scripts/bucket_scan.py` | S3/GCS/Azure storage brute + ACL check |
| `scripts/metadata_probe.py` | Cloud metadata endpoint probing (direct + SSRF) |
