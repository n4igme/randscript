# Bug Bounty — Step 3t: Infrastructure-as-Code Vulnerabilities

Scan for security misconfigurations in Terraform, CloudFormation, Dockerfiles, Kubernetes manifests, CI/CD pipelines, and Helm charts.

## Input

- Read `./assessment/threat-model.md` for priority targets
- Read `./assessment/recon.md` for infrastructure components identified
- Focus on: `*.tf`, `*.yaml`, `*.yml`, `Dockerfile*`, `.github/workflows/`, `.gitlab-ci.yml`, `helm/`, `kustomize/`, `cloudformation/`

## Vulnerability Patterns

### Terraform / OpenTofu

**Overly Permissive IAM:**
```hcl
# VULNERABLE: wildcard permissions
resource "aws_iam_policy" "bad" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"          # ← Critical: full admin access
      Resource = "*"
    }]
  })
}

# VULNERABLE: public S3 bucket
resource "aws_s3_bucket_acl" "bad" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"      # ← High: data exposure
}

# VULNERABLE: unencrypted storage
resource "aws_db_instance" "bad" {
  storage_encrypted = false    # ← Medium: data at rest unencrypted
}

# VULNERABLE: security group open to world
resource "aws_security_group_rule" "bad" {
  type        = "ingress"
  from_port   = 0
  to_port     = 65535
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]  # ← Critical: all ports open to internet
}
```

**What to grep for:**
```bash
# Wildcard IAM
grep -rn '"*"' --include="*.tf" | grep -i "action\|resource"
grep -rn "Action.*\*" --include="*.tf"

# Public access
grep -rn "public-read\|public-read-write" --include="*.tf"
grep -rn "publicly_accessible.*true" --include="*.tf"
grep -rn "0\.0\.0\.0/0\|::/0" --include="*.tf"

# Missing encryption
grep -rn "storage_encrypted.*false\|encrypt.*false\|kms_key_id" --include="*.tf"
grep -rn "aws_db_instance\|aws_rds_cluster" --include="*.tf" -l | xargs grep -L "storage_encrypted"

# Hardcoded secrets
grep -rn "password\|secret\|api_key\|access_key" --include="*.tf" | grep -v "var\.\|data\.\|local\."

# Missing logging/monitoring
grep -rn "aws_cloudtrail\|aws_flow_log\|logging" --include="*.tf" -l
# If no results → logging may be missing entirely
```

**GCP-specific:**
```bash
# Public GCS bucket
grep -rn "allUsers\|allAuthenticatedUsers" --include="*.tf"

# Default service account usage
grep -rn "compute@developer.gserviceaccount.com" --include="*.tf"

# Missing VPC Service Controls
grep -rn "google_access_context_manager" --include="*.tf" -l

# Overly permissive firewall
grep -rn "0\.0\.0\.0/0" --include="*.tf" | grep -i "source_ranges\|allowed"
```

### CloudFormation

```bash
# Wildcard IAM
grep -rn "Action.*\*\|Resource.*\*" --include="*.yaml" --include="*.yml" --include="*.json" | grep -i "policy\|role\|statement"

# Public resources
grep -rn "PubliclyAccessible.*true\|PublicRead\|public-read" --include="*.yaml" --include="*.yml"

# Missing encryption
grep -rn "StorageEncrypted.*false\|Encrypted.*false" --include="*.yaml" --include="*.yml"

# Hardcoded secrets (should use Secrets Manager / SSM)
grep -rn "Password:\|SecretKey:\|ApiKey:" --include="*.yaml" --include="*.yml" | grep -v "!Ref\|!Sub\|Fn::\|AWS::SSM\|secretsmanager"
```

### Dockerfile Security

**Common vulnerabilities:**
```dockerfile
# VULNERABLE: running as root (default)
FROM node:18
COPY . /app
RUN npm install
CMD ["node", "server.js"]
# ← No USER directive = runs as root (Medium)

# VULNERABLE: secrets in build args/env
ARG DATABASE_PASSWORD=supersecret123    # ← High: visible in image layers
ENV API_KEY=sk_live_abc123              # ← High: visible in image inspect

# VULNERABLE: using latest tag (unpinned)
FROM python:latest                      # ← Low: non-reproducible builds

# VULNERABLE: installing unnecessary tools
RUN apt-get install -y curl wget netcat ssh  # ← Low: increased attack surface

# VULNERABLE: COPY entire context (may include .env, secrets)
COPY . /app                             # ← Medium: check .dockerignore exists

# VULNERABLE: running with --privileged or excessive capabilities
# (checked in docker-compose.yml or K8s manifests)
```

**What to grep for:**
```bash
# Missing USER directive
for f in $(find . -name "Dockerfile*"); do
    grep -L "^USER" "$f" && echo "  ↑ No USER directive (runs as root)"
done

# Secrets in Dockerfile
grep -rn "ARG.*PASSWORD\|ARG.*SECRET\|ARG.*KEY\|ARG.*TOKEN" --include="Dockerfile*"
grep -rn "ENV.*PASSWORD\|ENV.*SECRET\|ENV.*KEY\|ENV.*TOKEN" --include="Dockerfile*"

# Unpinned base images
grep -rn "^FROM.*:latest\|^FROM.*[^:]*$" --include="Dockerfile*"

# COPY without .dockerignore check
find . -name "Dockerfile*" -exec dirname {} \; | sort -u | while read dir; do
    [ ! -f "$dir/.dockerignore" ] && echo "Missing .dockerignore in $dir"
done

# Excessive packages
grep -rn "apt-get install\|apk add\|yum install" --include="Dockerfile*" | grep -i "ssh\|telnet\|netcat\|nmap\|curl\|wget"

# Multi-stage build check (secrets in early stages leak)
grep -c "^FROM" Dockerfile  # If >1, check that secrets only in final stage
```

### Kubernetes Manifests

**Critical misconfigurations:**
```yaml
# VULNERABLE: privileged container
securityContext:
  privileged: true              # ← Critical: container escape possible

# VULNERABLE: running as root
securityContext:
  runAsUser: 0                  # ← High: root in container

# VULNERABLE: hostPath mount
volumes:
  - name: host-root
    hostPath:
      path: /                   # ← Critical: full host filesystem access

# VULNERABLE: hostNetwork
spec:
  hostNetwork: true             # ← High: access to host network stack

# VULNERABLE: no resource limits (DoS)
containers:
  - name: app
    image: myapp:latest
    # No resources.limits → can consume all node resources (Medium)

# VULNERABLE: secrets in env vars (visible in pod spec)
env:
  - name: DB_PASSWORD
    value: "hardcoded123"       # ← High: use secretKeyRef instead

# VULNERABLE: no network policy (flat network)
# If no NetworkPolicy resources exist → all pods can talk to all pods (Medium)

# VULNERABLE: default service account with excessive RBAC
# If pods don't specify serviceAccountName → use default SA
```

**What to grep for:**
```bash
# Privileged containers
grep -rn "privileged: true" --include="*.yaml" --include="*.yml"

# Running as root
grep -rn "runAsUser: 0\|runAsNonRoot: false" --include="*.yaml" --include="*.yml"

# Host mounts
grep -rn "hostPath:\|hostNetwork: true\|hostPID: true\|hostIPC: true" --include="*.yaml" --include="*.yml"

# Missing resource limits
grep -rn "kind: Deployment\|kind: StatefulSet\|kind: DaemonSet" --include="*.yaml" --include="*.yml" -l | while read f; do
    grep -L "resources:" "$f" && echo "  ↑ Missing resource limits"
done

# Hardcoded secrets
grep -rn "value:.*password\|value:.*secret\|value:.*key" --include="*.yaml" --include="*.yml" -i | grep -v "valueFrom\|secretKeyRef\|configMapKeyRef"

# Missing security context
grep -rn "kind: Deployment" --include="*.yaml" --include="*.yml" -l | while read f; do
    grep -L "securityContext" "$f" && echo "  ↑ No securityContext in $f"
done

# No network policies
find . -name "*.yaml" -o -name "*.yml" | xargs grep -l "kind: NetworkPolicy" | wc -l
# If 0 → flat network (Medium)

# Capabilities
grep -rn "capabilities:" --include="*.yaml" --include="*.yml" -A5 | grep "add:"
# Look for: SYS_ADMIN, NET_ADMIN, SYS_PTRACE, ALL

# Latest tag in images
grep -rn "image:.*:latest\|image:.*[^:\"]*\"$" --include="*.yaml" --include="*.yml"
```

### CI/CD Pipeline Configs

**GitHub Actions:**
```bash
# Dangerous: pull_request_target with checkout of PR code
grep -rn "pull_request_target" --include="*.yml" --include="*.yaml" .github/
# If combined with actions/checkout of PR head → Critical (code injection)

# Secrets in logs (missing masking)
grep -rn "echo.*\${{.*secrets" --include="*.yml" .github/

# Overly permissive permissions
grep -rn "permissions:" --include="*.yml" .github/ -A5 | grep "write-all\|contents: write"

# Self-hosted runners without isolation
grep -rn "runs-on:.*self-hosted" --include="*.yml" .github/

# Third-party actions without pinning (supply chain risk)
grep -rn "uses:" --include="*.yml" .github/ | grep -v "@[a-f0-9]\{40\}\|@v[0-9]"
# Actions should be pinned to SHA, not just version tag

# Dangerous: script injection via github context
grep -rn "\${{.*github\.event\.\|title\|body\|head_ref" --include="*.yml" .github/ | grep "run:"
# User-controlled values in run: steps = command injection

# Missing environment protection
grep -rn "environment:" --include="*.yml" .github/ -l
# If no environment protection on deploy jobs → anyone can trigger deploy
```

**GitLab CI:**
```bash
# Variables without protection
grep -rn "variables:" .gitlab-ci.yml -A20 | grep -v "protected\|masked"

# Shared runners for sensitive jobs
grep -rn "tags:" .gitlab-ci.yml | grep -v "private\|secure\|dedicated"

# Artifacts with sensitive data
grep -rn "artifacts:" .gitlab-ci.yml -A10 | grep "paths:" -A5

# Missing branch protection on deploy
grep -rn "only:\|rules:" .gitlab-ci.yml -A5 | grep "deploy\|release"
```

**Docker Compose (dev/staging exposure):**
```bash
# Exposed ports
grep -rn "ports:" docker-compose*.yml -A5 | grep "0\.0\.0\.0\|:[0-9]"

# Privileged mode
grep -rn "privileged: true" docker-compose*.yml

# Hardcoded secrets
grep -rn "PASSWORD\|SECRET\|KEY\|TOKEN" docker-compose*.yml | grep -v "\${" | grep "="

# Volume mounts of sensitive paths
grep -rn "/var/run/docker.sock\|/etc/shadow\|/root" docker-compose*.yml
```

### Helm Charts

```bash
# Values with defaults that should be secrets
grep -rn "password:\|secret:\|apiKey:" --include="values.yaml" | grep -v '""'

# Templates without security context
find . -path "*/templates/*.yaml" | xargs grep -L "securityContext"

# Tiller (Helm 2) — if still present, Critical
grep -rn "tiller\|helm2" --include="*.yaml" --include="*.yml"

# Missing RBAC in chart
find . -path "*/templates/*" -name "*role*" | wc -l
# If 0 and chart deploys workloads → may use default SA (Medium)

# Ingress without TLS
grep -rn "kind: Ingress" --include="*.yaml" -l | while read f; do
    grep -L "tls:" "$f" && echo "  ↑ Ingress without TLS in $f"
done
```

## Automated Tools

```bash
# Checkov (multi-framework IaC scanner)
pip install checkov
checkov -d . --framework terraform --output json > assessment/checkov-terraform.json
checkov -d . --framework kubernetes --output json > assessment/checkov-k8s.json
checkov -d . --framework dockerfile --output json > assessment/checkov-docker.json

# tfsec (Terraform-specific)
brew install tfsec
tfsec . --format json > assessment/tfsec.json

# Trivy (config scanning)
brew install trivy
trivy config . --format json > assessment/trivy-config.json

# Hadolint (Dockerfile linter)
brew install hadolint
find . -name "Dockerfile*" -exec hadolint {} \;

# kube-score (K8s manifest scoring)
brew install kube-score
find . -name "*.yaml" | xargs kube-score score

# Kubesec (K8s security risk)
# https://kubesec.io/
find . -name "*.yaml" -exec grep -l "kind: Deployment\|kind: Pod" {} \; | while read f; do
    curl -sSX POST --data-binary @"$f" https://v2.kubesec.io/scan
done
```

## Process

1. **Identify IaC files** — find all Terraform, K8s, Docker, CI/CD configs
2. **Run automated tools** — checkov, tfsec, trivy config, hadolint
3. **Manual review** — check patterns above that tools may miss (logic issues, context-dependent)
4. **Cross-reference with recon** — do IaC configs match what's deployed? (drift = finding)
5. **Assess blast radius** — a misconfigured prod Terraform module > a dev docker-compose

## Severity Guide

| Finding | Severity | Context |
|---------|----------|---------|
| Wildcard IAM (`Action: *`) in prod | Critical | Full cloud account compromise |
| Privileged K8s container in prod | Critical | Container escape → node compromise |
| Security group 0.0.0.0/0 all ports | Critical | Full network exposure |
| Secrets hardcoded in Terraform/Docker | High | Credential exposure in VCS history |
| Public S3/GCS bucket with data | High | Data breach |
| Running as root (Docker/K8s) | Medium-High | Depends on what's in the container |
| pull_request_target + PR checkout | Critical | Arbitrary code execution with secrets |
| Missing encryption at rest | Medium | Compliance + data protection |
| No resource limits (K8s) | Medium | DoS potential |
| Unpinned base images/actions | Medium | Supply chain risk |
| Missing network policies | Medium | Lateral movement if pod compromised |
| No audit logging | Medium | Compliance + incident response gap |
| Latest tag on images | Low | Non-reproducible, potential drift |
| Missing .dockerignore | Low | Potential secret inclusion in image |

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Infrastructure-as-Code

**Date**: {date}
**Scanner**: vuln-infra

## Findings

### VULN-IAC-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Terraform / Dockerfile / Kubernetes / CI-CD / Helm}
**Location**: `{file}:{line}`
**CWE**: CWE-{number}

**Description**:
{What the misconfiguration is and why it's dangerous}

**Vulnerable Code**:
```{lang}
{snippet}
`` `

**Impact**:
{What attacker gains if this is exploited}

**Remediation**:
```{lang}
{fixed code}
`` `

---
```

## Rules

- **Context matters** — a privileged container in a dev docker-compose is Low; in a prod K8s manifest it's Critical.
- **Check if it's actually deployed** — IaC in a `deprecated/` or `examples/` folder is informational only.
- **Secrets in git history** — even if removed from current code, they're in VCS history. Still a finding.
- **Idempotent output** — if `vulnerabilities.md` already has `# Vulnerability Findings — Infrastructure-as-Code`, replace it entirely.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
