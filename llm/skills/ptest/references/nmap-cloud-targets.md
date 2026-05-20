# Nmap on Cloud-Hosted Targets (GCP/AWS/Azure)

Lessons from scanning GCP-hosted infrastructure during penetration testing.

## Key Observations

1. **Only 80/443 exposed** — cloud providers with proper firewall rules (GCP VPC firewall, AWS Security Groups) typically only expose web ports. Don't waste time on full 65535 scans against cloud LBs.

2. **"tcpwrapped" on port 80** — Google Cloud Load Balancer shows this in nmap. It means the port is open but the service didn't respond to nmap's probes (GCLB expects proper HTTP).

3. **Service detection is slow** — `-sV` against cloud LBs takes 10-15s per host because of timeout-based fingerprinting. For 150+ IPs, use a tiered approach.

## Recommended Scan Strategy

### Tier 1: Quick discovery (all IPs)
```bash
nmap -Pn --top-ports 100 -T4 --open -oG nmap-quick.gnmap <targets>
```
Fast, identifies which hosts have anything beyond 80/443.

### Tier 2: Service detection (high-value only)
```bash
nmap -Pn -sV -p 80,443 -T4 -oN nmap-svc-highvalue.txt <high-value-ips>
```
Only on interesting targets (admin panels, non-GCP hosts, auth endpoints).

### Tier 3: Non-web ports (non-GCP hosts only)
```bash
nmap -Pn -T4 --open -p 21,22,25,53,110,135,139,143,389,445,587,993,995,1433,3306,3389,5432,5900,6379,8080,8443,9090,9200,27017 <non-cloud-ips>
```
Only worth running against hosts NOT behind cloud load balancers.

## Pitfalls

- **Full port scans timeout** — `nmap -p- -sV` against 7 GCP IPs took 300s+ and got killed. Use tiered approach.
- **OS fingerprinting useless** — all behind LB/CDN, OS not detectable. Skip `-O` for cloud targets.
- **UDP scans very slow** — cloud firewalls drop UDP silently. Only scan UDP on non-cloud hosts if needed.
- **Timeout settings** — use `timeout=120` for nmap commands scanning 5-10 hosts, `timeout=180` for larger batches.

## What to Focus On Instead

Since cloud targets only expose HTTP/HTTPS, the real attack surface is the **application layer**:
- Directory/API enumeration (Phase 3)
- Authentication testing
- Business logic flaws
- The rare non-cloud host (different security posture, potentially more ports)
