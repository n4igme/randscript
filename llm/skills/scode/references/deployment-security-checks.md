# Deployment Security Checks

When reviewing microservices deployed on Kubernetes with service mesh (Istio/Linkerd), check these beyond application code.

## Helm Values / K8s Manifests

Look for these files in the repo:
```bash
find . -name "values*.yaml" -o -name "Chart.yaml" -o -name "*.helmfile*" | head -20
find . -path "*/k8s/*" -o -path "*/deploy/*" -o -path "*/manifests/*" | head -20
```

### Istio Security Config (Critical)

| Resource | What to Check | Risk if Missing |
|----------|--------------|-----------------|
| `AuthorizationPolicy` | Which services can call which endpoints | Any pod = full access |
| `PeerAuthentication` | mTLS mode (STRICT vs PERMISSIVE) | Plaintext interception |
| `RequestAuthentication` | JWT validation at mesh level | No token verification |
| `NetworkPolicy` | Pod-to-pod communication restrictions | Lateral movement |

### Common Misconfigurations

1. **Istio ingress without auth gate**: Service exposed externally via `istioIngress: enabled: true` but no `AuthorizationPolicy` restricting callers
2. **PERMISSIVE mTLS**: Allows both plaintext and mTLS — attacker can downgrade
3. **No NetworkPolicy**: Default K8s allows all pod-to-pod traffic within namespace
4. **Service exposed on multiple paths**: Internal service also reachable via external ingress prefix

### What to Search For

```bash
# In Helm values
grep -ri "istio\|authorizationpolicy\|peerauthentication\|networkpolicy" .
grep -ri "ingress.*enabled\|istioIngress" .

# Check if service is externally exposed
grep -ri "prefix.*rewrite\|pathPrefix\|virtualservice" .
```

### Validation Questions

1. Is the service ONLY reachable via internal K8s DNS? Or also via external ingress?
2. If external: is there an API gateway with auth in front?
3. Are there Istio AuthorizationPolicies restricting which source services can call?
4. Is mTLS mode STRICT (not PERMISSIVE)?
5. Are there NetworkPolicies limiting ingress to the pod?

### Impact on Findings

- If AuthorizationPolicy exists restricting callers → DOWNGRADE access-control findings from Critical to Medium (defense-in-depth gap, not full exposure)
- If no mesh security at all → access-control findings remain Critical (any pod = full access)
- If external ingress without auth → UPGRADE to "externally exploitable" (not just cluster-internal)

## Integration with scode

Check deployment config during Step 1 (Recon) under "Authentication & Authorization". Note findings in recon.md. During Step 4 (Validation), use deployment config to confirm/downgrade access-control findings.
