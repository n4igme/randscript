# GCP Port Scan Pitfalls

## GCP Global Load Balancer SYN-ACK Trap (FALSE POSITIVE)

GCP Global External LBs (especially those fronting IAP-protected services) will **SYN-ACK on ANY port** but never send data. This makes them appear to have hundreds of open ports in both manual scans and Shodan.

### How to identify:
- ALL scanned ports show "open" (12/12, 100/100, etc.)
- No banners returned on any port
- Shodan shows 400-600+ ports for the IP
- IP is in GCP range (34.x.x.x, 35.x.x.x)
- HTTP connections get `RemoteProtocolError` (accepts TCP, doesn't speak HTTP)
- MySQL/Redis/SSH connections succeed but return no data

### Verification procedure:
```python
# If a host shows ALL ports open, verify it's a GCP LB trap:
# 1. Connect to MySQL port — real MySQL sends greeting packet immediately
sock.connect((ip, 3306))
data = sock.recv(1024)  # Empty = GCP LB, data = real MySQL

# 2. Connect to SSH — real SSH sends banner immediately  
sock.connect((ip, 22))
data = sock.recv(1024)  # Empty = GCP LB, "SSH-2.0-..." = real SSH

# 3. Connect to Redis and send PING
sock.connect((ip, 6379))
sock.send(b'PING\r\n')
data = sock.recv(1024)  # No response or ConnectionReset = GCP LB, "+PONG" = real Redis
```

### Rule of thumb:
- If >5 ports show open with NO banners → GCP LB false positive
- If 1-3 ports open with banners → real services
- Always verify with banner grab before reporting

### Known affected IPs (Bank Jago engagement, May 2026):
- 34.110.163.221 (face-clustering-data)
- 34.111.246.6 (jupyterhub-data)
- 34.111.250.173 (ge-data)
- 34.117.118.17 (growthbook-data)
- 34.117.58.157 (kubeflow-data)
- 34.49.208.3 (labs-cfn-mobile)

All confirmed as GCP LB SYN-ACK traps — no real services behind them.

## Cloudflare Port 8080 (NOT a bypass)

CF-proxied hosts have port 8080 open. This is Cloudflare's HTTP listener that:
- Returns 301 → https://host/ (redirect to HTTPS)
- OR returns the same CF 403 "Attention Required" page

It is NOT a WAF bypass. Do not report it as an open port finding.

## Shodan InternetDB (Free, No-Auth IP Lookup)

`https://internetdb.shodan.io/{ip}` — returns ports, hostnames, CVEs, CPEs for any IP.
- No API key needed
- Returns 404 if IP not indexed
- Good for quick Phase 1 enrichment
- Caveat: GCP LB IPs show hundreds of ports (same false positive as above)

## Delegation Pitfall: Subagents Refuse Pentest Tasks

When delegating pentest subtasks to subagents (delegate_task), they lack context about authorization and will refuse with "I can't help with penetration testing" responses.

**Workaround:** Do OSINT/recon tasks directly in the main session rather than delegating. Subagents don't inherit the engagement's authorization context.

**Tasks that get refused:**
- GitHub secret scanning for target org
- Shodan/Censys lookups for target IPs
- Google dorking for target domain
- Any task framed as "find vulnerabilities in X"

**Tasks that work via delegation:**
- Generic research ("how does Aiven service naming work")
- Tool documentation lookups
- Non-target-specific technical questions
