---
name: vuln-deployment-security
description: "Scan for deployment security gaps (Istio AuthorizationPolicy, mTLS, NetworkPolicy, Helm misconfig, service mesh bypass). Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Deployment Security

Scan for Kubernetes service mesh and deployment configuration weaknesses: missing AuthorizationPolicy, permissive mTLS, absent NetworkPolicy, and exposed internal services.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for infrastructure components
- If either is missing, tell the user which step to run first

## Applicability

```bash
find . -name "values*.yaml" -o -name "Chart.yaml" -o -name "*.helmfile*" -o -path "*/k8s/*" -o -path "*/deploy/*" -o -path "*/manifests/*" -o -name "istio*" | head -1
```
If no results → report "No deployment configs found — scanner not applicable" and skip.

## Vulnerability Patterns

### Missing Istio AuthorizationPolicy
- Services exposed without caller restrictions
- Any pod in the namespace can call any endpoint
- No service-to-service access control

**Grep patterns**: `AuthorizationPolicy`, `PeerAuthentication`, `RequestAuthentication`, `istio`

### Permissive mTLS
- `PERMISSIVE` mode allows plaintext fallback (attacker can downgrade)
- Missing `PeerAuthentication` defaults to permissive

**Grep patterns**: `PeerAuthentication`, `mtls`, `mode: STRICT`, `mode: PERMISSIVE`

### Missing NetworkPolicy
- Default K8s allows all pod-to-pod traffic within namespace
- No ingress/egress restrictions on sensitive pods

**Grep patterns**: `NetworkPolicy`, `ingress:`, `egress:`, `podSelector`

### External Service Exposure Without Auth
- Internal service exposed via Istio ingress without API gateway
- Missing JWT validation at mesh level (`RequestAuthentication`)
- Service reachable both internally and externally

**Grep patterns**: `istioIngress: enabled`, `VirtualService`, `Gateway`, `prefix.*rewrite`, `pathPrefix`

### Helm Values Misconfigurations
- Secrets in `values.yaml` (not sealed/external)
- Debug mode enabled in production
- Replicas set to 1 (no HA)

**Grep patterns**: `password:`, `secret:`, `token:`, `debug: true`, `replicas: 1`

## Process

1. **Find deployment configs** — Helm charts, K8s manifests, Istio resources
2. **Check AuthorizationPolicy** — are services protected with caller restrictions?
3. **Check mTLS mode** — is it STRICT or PERMISSIVE?
4. **Check NetworkPolicy** — are there pod-level network restrictions?
5. **Check external exposure** — which services are reachable outside the cluster?
6. **Assess impact** — lateral movement, unauthenticated access, traffic interception

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Deployment Security

**Date**: {date}
**Scanner**: vuln-deployment-security

## Findings

### VULN-DEPLOY-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {AuthorizationPolicy / mTLS / NetworkPolicy / External Exposure / Helm Config}
**Location**: `{file}:{line}`
**CWE**: CWE-{284|319|923|16}

**Description**:
{What the vulnerability is}

**Vulnerable Config**:
```yaml
{config snippet}
`` `

**Attack Scenario**:
1. {How attacker exploits — e.g., compromised pod → lateral movement}

**Impact**:
{Lateral movement, unauthenticated access, traffic interception}

**Remediation**:
```yaml
{fixed config}
`` `

---
```

## Positive Observations

While scanning, note strong patterns. Add to `# Positive Security Observations` at end of `vulnerabilities.md`:

```markdown
- vuln-deployment-security: {what the codebase does well}
```

## Rules

- **If AuthorizationPolicy exists and restricts callers** → downgrade access-control findings (defense-in-depth gap, not full exposure).
- **If no mesh security at all** → access-control findings remain at original severity.
- **If external ingress without auth** → upgrade to "externally exploitable".
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — Deployment Security` section, replace it entirely.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
