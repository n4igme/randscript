# Phase 2: Active Reconnaissance

## Automated Setup

Run first when entering this phase:

```python
from hermes_tools import read_file
exec(read_file("~/.hermes/skills/security/ptest/scripts/phase2_active.py")["content"])
```

---

## When to Use
- After passive recon is complete (Gateway 1 PASSED).
- When you need to identify live hosts, open ports, and running services.

## Scope
This phase covers **network-layer discovery only**:
- Port scanning
- Service detection and banner grabbing
- OS fingerprinting
- Network topology mapping

Application-layer enumeration (directories, APIs, parameters) belongs in Phase 3 (Enumeration).

## Techniques & Tools

### 0. Active DNS Expansion (MANDATORY)

**Purpose:** Expand the subdomain list beyond what passive recon found. This is the #1 gap in most engagements — treating Phase 2 as "scan what we found" instead of "expand what we know."

#### 0a. Pattern-Based Permutation Brute-Force

**VPN/Internal K8s targets (MANDATORY — do NOT skip):** When the target is behind VPN with a private DNS resolver (e.g., 169.254.169.254), DNS brute-force IS possible — use `dig +short {sub}.target.domain` against the VPN resolver. The fact that public resolvers return NXDOMAIN does NOT mean brute-force is impossible. LoanPlatform (June 2026): initially skipped all DNS expansion as "not possible" for VPN-gated domain. User caught the gap — 100+ permutations were then tested via VPN DNS (all NXDOMAIN, but the technique was valid and necessary for completeness). Also test vhost enumeration with `--resolve` against the ingress IP.

After Phase 1 reveals naming patterns, build a custom wordlist and brute-force variations:

```bash
# Step 1: Extract patterns from Phase 1 discoveries
# If you found: dev-api, stg-api, pt-api → pattern is {env}-{service}
# If you found: airflow-data, argocd-data → pattern is {tool}-data

# Step 2: Build permutation wordlist
cat > /tmp/env-prefixes.txt << 'EOF'
dev
stg
staging
sit
uat
pt
prod
lab
test
sandbox
demo
internal
private
EOF

cat > /tmp/service-names.txt << 'EOF'
api
admin
auth
sso
keycloak
grafana
prometheus
alertmanager
kibana
elasticsearch
airflow
argocd
atlantis
vault
consul
sentry
jaeger
zipkin
jenkins
gitlab
harbor
nexus
sonar
n8n
metabase
superset
redash
datahub
dbt
mlflow
jupyter
notebook
workstation
vpn
bastion
jump
sftp
ftp
mail
smtp
noreply
monitoring
apm
dynatrace
datadog
newrelic
siem
soar
splunk
kafka
rabbitmq
redis
postgres
mysql
mongo
minio
s3
backup
dr
cdn
waf
gateway
ingress
proxy
lb
EOF

# Step 3: Generate permutations
while read prefix; do
  while read svc; do
    echo "${prefix}-${svc}"
    echo "${svc}-${prefix}"
    echo "${prefix}${svc}"
  done < /tmp/service-names.txt
done < /tmp/env-prefixes.txt > /tmp/permutation-wordlist.txt

# Step 4: Brute-force with ffuf
ffuf -u "https://FUZZ.target.com" \
  -w /tmp/permutation-wordlist.txt \
  -t 30 -timeout 5 \
  -mc 200,301,302,401,403,500 \
  -o ./ptest-output/recon-active/dns-permutation-results.json \
  -of json

# Alternative: DNS-only resolution check (faster, no HTTP overhead)
while read sub; do
  ip=$(dig +short "${sub}.target.com" 2>/dev/null | head -1)
  [ -n "$ip" ] && echo "${sub}.target.com|${ip}"
done < /tmp/permutation-wordlist.txt > ./ptest-output/recon-active/dns-expanded.txt
```

**Key insight:** Once you see a naming pattern in Phase 1 (e.g., `dev-*`, `*-data`, `lab-*`), you have enough signal to generate targeted permutations. Organizations typically have 3-5x more services than what's publicly indexed.

#### 0b. DNS-Level Subdomain Brute-Force (dnsx / puredns / massdns)

**Why this matters:** `ffuf` brute-force is HTTP-based — it only finds subdomains that respond to HTTP. Many internal services (SFTP, databases, message queues, internal APIs) resolve in DNS but don't serve HTTP. DNS-level tools catch ALL resolving subdomains regardless of protocol.

**Tool priority:**
1. `dnsx` (recommended) — fast, handles wildcards, ProjectDiscovery ecosystem
2. `puredns` — mass resolution with automatic wildcard filtering
3. `massdns` — raw speed for massive wordlists (100K+), needs post-processing
4. `dnsrecon` — all-in-one (brute-force, zone transfer, SRV, zone walking)
5. `dnsenum` — classic, includes Google scraping and reverse lookups

```bash
# === Option 1: dnsx (recommended) ===
# Install: go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Generate full wordlist (permutations + SecLists)
cat /tmp/permutation-wordlist.txt > /tmp/dns-bruteforce.txt
cat $SECLISTS_PATH/Discovery/DNS/subdomains-top1million-5000.txt >> /tmp/dns-bruteforce.txt
sort -u /tmp/dns-bruteforce.txt -o /tmp/dns-bruteforce.txt

# DNS resolution brute-force (finds ALL resolving subdomains, not just HTTP)
cat /tmp/dns-bruteforce.txt | dnsx -d target.com -silent -a -resp \
  -o ./ptest-output/recon-active/dnsx-bruteforce.txt

# Wildcard detection (important! avoids false positives)
cat /tmp/dns-bruteforce.txt | dnsx -d target.com -silent -a -resp \
  -wd target.com \
  -o ./ptest-output/recon-active/dnsx-no-wildcards.txt

# Also resolve all known subdomains for A, AAAA, CNAME, MX, TXT, NS
cat ./ptest-output/recon-passive/subdomains-all.txt | dnsx -silent \
  -a -aaaa -cname -mx -txt -ns -resp \
  -o ./ptest-output/recon-active/dnsx-full-records.txt

# === Option 2: puredns (mass resolution + wildcard filtering) ===
# Install: go install github.com/d3mondev/puredns/v2@latest
# Requires massdns: brew install massdns

puredns bruteforce /tmp/dns-bruteforce.txt target.com \
  --resolvers /tmp/resolvers.txt \
  --wildcard-batch 500 \
  -w ./ptest-output/recon-active/puredns-results.txt

# === Option 3: massdns (raw speed, needs post-processing) ===
# Install: brew install massdns

# Prepare input (FQDN format)
sed 's/$/.target.com/' /tmp/dns-bruteforce.txt > /tmp/massdns-input.txt

massdns -r /tmp/resolvers.txt -t A -o S \
  /tmp/massdns-input.txt > ./ptest-output/recon-active/massdns-raw.txt

# Filter to only resolved entries
grep -E "IN\s+A\s+" ./ptest-output/recon-active/massdns-raw.txt | \
  awk '{print $1}' | sed 's/\.$//' | sort -u > ./ptest-output/recon-active/massdns-resolved.txt

# === Option 4: dnsrecon (all-in-one) ===
# Install: pip3 install dnsrecon

# Brute-force + zone transfer + SRV enumeration
dnsrecon -d target.com -t brt -D /tmp/dns-bruteforce.txt \
  --xml ./ptest-output/recon-active/dnsrecon-brute.xml

# SRV record enumeration (finds internal services)
dnsrecon -d target.com -t srv \
  --xml ./ptest-output/recon-active/dnsrecon-srv.xml

# Zone walking (NSEC/NSEC3 — works on some DNSSEC-enabled domains)
dnsrecon -d target.com -t zonewalk \
  --xml ./ptest-output/recon-active/dnsrecon-zonewalk.xml

# === Option 5: dnsenum ===
# Install: brew install dnsenum (or apt install dnsenum)

dnsenum --enum -f /tmp/dns-bruteforce.txt \
  --threads 30 --noreverse \
  -o ./ptest-output/recon-active/dnsenum-results.xml \
  target.com
```

**Resolver list setup** (required for puredns/massdns):
```bash
# Create a reliable resolver list
cat > /tmp/resolvers.txt << 'EOF'
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
208.67.222.222
208.67.220.220
EOF
```

**When to use which tool:**

| Scenario | Best Tool | Why |
|----------|-----------|-----|
| Standard engagement (< 5K wordlist) | dnsx | Fast, wildcard-aware, clean output |
| Large wordlist (50K+) | puredns or massdns | Handles scale, auto-filters wildcards |
| Need SRV/SOA/zone walk | dnsrecon | Only tool that does SRV enumeration |
| Quick-and-dirty + Google scraping | dnsenum | All-in-one legacy tool |
| Already have subfinder output | dnsx (resolve mode) | Validates and enriches existing list |

**Critical: Wildcard detection**
Before trusting brute-force results, check for wildcard DNS:
```bash
# Test if wildcard exists
dig +short "randomnonexistent12345.target.com"
# If this returns an IP → wildcard is active → filter results against that IP
WILDCARD_IP=$(dig +short "randomnonexistent12345.target.com" | head -1)
if [ -n "$WILDCARD_IP" ]; then
  echo "[!] Wildcard DNS detected: *.target.com -> $WILDCARD_IP"
  echo "[!] Filter all results matching this IP"
  grep -v "$WILDCARD_IP" dnsx-bruteforce.txt > dnsx-filtered.txt
fi
```

#### 0c. Reverse DNS on Known IP Ranges

When Phase 1 reveals the target uses specific IP ranges (GCP, AWS, on-prem), scan adjacent IPs:

```bash
# Extract unique /24 ranges from Phase 1 resolved IPs
cat ./ptest-output/recon-passive/subdomains-resolved.txt | \
  grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | sort -u | \
  while read range; do
    echo "Scanning ${range}.0/24"
    # PTR lookup on the range
    for i in $(seq 1 254); do
      ptr=$(dig +short -x "${range}.${i}" 2>/dev/null)
      if echo "$ptr" | grep -qi "target.com"; then
        echo "[+] ${range}.${i} → ${ptr}"
      fi
    done
  done > ./ptest-output/recon-active/reverse-dns-results.txt

# For GCP specifically — check if IPs in 34.x/35.x resolve back to target
# GCP load balancers rarely have PTR records, but dedicated VMs sometimes do
```

**When to use:** Most effective on non-cloud infrastructure (Hetzner, DigitalOcean, on-prem) where PTR records are configured. GCP/AWS load balancer IPs rarely have useful PTR records.

#### 0d. Virtual Host Enumeration

For Cloudflare-proxied targets, brute-force `Host:` headers to discover hidden vhosts:

```bash
# Get the Cloudflare edge IP for the target
CF_IP=$(dig +short www.target.com | head -1)

# Brute-force Host headers against the CF edge
ffuf -u "https://${CF_IP}" \
  -H "Host: FUZZ.target.com" \
  -w /tmp/permutation-wordlist.txt \
  -t 20 -timeout 5 \
  -mc 200,301,302,401,403 \
  -fs 0 \
  -o ./ptest-output/recon-active/vhost-results.json \
  -of json

# For non-CF hosts (direct IP), vhost enum is more reliable
# Different response size = different vhost
ffuf -u "https://${DIRECT_IP}" \
  -H "Host: FUZZ.target.com" \
  -w /tmp/permutation-wordlist.txt \
  -t 20 -timeout 5 \
  -mc all \
  -fw 0 \
  -o ./ptest-output/recon-active/vhost-direct-results.json \
  -of json
```

**Limitations:** Cloudflare may return the same default page for all unknown Host headers. Filter by response size (`-fs`) to find unique responses. More effective against direct-IP hosts (non-proxied).

#### 0e. DNS Zone Transfer Attempt

Always attempt zone transfer — it rarely works but costs nothing:

```bash
# Get nameservers
dig +short NS target.com

# Attempt AXFR on each nameserver
for ns in $(dig +short NS target.com); do
  echo "Trying AXFR on ${ns}..."
  dig @${ns} target.com AXFR
done
```

#### 0f. Merge & Deduplicate

After all DNS expansion techniques, merge results with Phase 1:

```bash
# Combine all sources
cat ./ptest-output/recon-passive/subdomains-resolved.txt \
    ./ptest-output/recon-active/dns-expanded.txt \
    ./ptest-output/recon-active/dns-permutation-results.txt \
    ./ptest-output/recon-active/reverse-dns-results.txt \
    ./ptest-output/recon-active/vhost-results.txt \
    2>/dev/null | sort -u > ./ptest-output/recon-active/all-subdomains-expanded.txt

echo "[*] Total subdomains after expansion: $(wc -l < ./ptest-output/recon-active/all-subdomains-expanded.txt)"
echo "[*] New subdomains found in Phase 2: $(comm -13 \
  <(sort ./ptest-output/recon-passive/subdomains-resolved.txt) \
  <(sort ./ptest-output/recon-active/all-subdomains-expanded.txt) | wc -l)"
```

---

### 1. Port Scanning (MANDATORY: nmap)
Identify open ports and services on all in-scope hosts.
```bash
# Full TCP scan on primary targets
nmap -sV -sC -p- -oA ./ptest-output/recon-active/nmap-full-tcp target.com

# Fast initial scan (top ports)
nmap -sV --top-ports 1000 -T4 -oA ./ptest-output/recon-active/nmap-top1000 target.com

# UDP top 100
nmap -sU --top-ports 100 -oA ./ptest-output/recon-active/nmap-udp target.com

# Scan multiple IPs from passive recon
nmap -sV --top-ports 1000 -T4 -iL ./ptest-output/recon-passive/live-ips.txt -oA ./ptest-output/recon-active/nmap-all-hosts

# Masscan for speed on large ranges
masscan -p1-65535 --rate=1000 -oL ./ptest-output/recon-active/masscan.txt 10.0.0.0/24
```

**Requirements:**
- Scan ALL unique public IPs discovered in Phase 1 (not just the primary target)
- This includes NO_HTTP hosts (e.g., email infrastructure) — use -Pn if host seems down
- Document every open port with service version
- If nmap is unavailable, document the gap and use alternative (masscan + banner grab)

**WinTicket lesson (June 2026):** Phase 2 was marked PASSED without scanning the email host (137.22.240.193, SparkPost). User caught this gap at review. Even if a host is expected to be locked down, scan it and document the result (e.g., "all filtered" is still a valid documented outcome).

### 2. Service Detection & Banner Grabbing
Detailed version fingerprinting on discovered open ports.
```bash
# Intensive version detection
nmap -sV --version-intensity 9 -p <open-ports> target.com

# Manual banner grab
nc -nv target.com 22 <<< ""
curl -sI http://target.com:8080

# SMB enumeration (if port 445 open)
enum4linux -a target.com
smbclient -L //target.com -N

# SNMP (if port 161 open)
snmpwalk -v2c -c public target.com
```

### 3. OS Fingerprinting
```bash
# OS detection
nmap -O target.com

# TTL-based inference
ping -c 1 target.com | grep ttl
```

### 4. Network Topology Mapping
```bash
# Traceroute
traceroute target.com

# Identify shared hosting / CDN
# Compare IPs across subdomains to identify load balancers, CDNs, shared infrastructure
```

## Scope Type Adjustments

- **web/API:** Focus on HTTP/HTTPS ports (80, 443, 8080, 8443, 3000, 5000, 8000). Light UDP scan.
- **network:** Full TCP + UDP scan. All techniques apply.
- **cloud:** Focus on common cloud service ports. Check for metadata endpoints.
- **mobile:** Focus on API backend ports the app communicates with.

## Output

Document findings in `./ptest-output/recon-active/`:
- `summary.md` — consolidated scan results
- `ports-services.md` — open ports and services per host (table format)
- `nmap-*.xml/txt` — raw nmap output files
- `network-map.md` — topology and infrastructure notes

Write `./ptest-output/recon-active/checklist.md`:

```markdown
# Active Recon Checklist

| # | Technique | Status | Notes |
|---|-----------|--------|-------|
| 0a | Pattern-Based Permutation Brute-Force (MANDATORY) | PENDING | |
| 0b | DNS-Level Subdomain Brute-Force — dnsx/puredns/massdns (MANDATORY) | PENDING | |
| 0c | Reverse DNS on Known IP Ranges | PENDING | |
| 0d | Virtual Host Enumeration | PENDING | |
| 0e | DNS Zone Transfer Attempt | PENDING | |
| 0f | Merge & Deduplicate Expanded Subdomains | PENDING | |
| 1 | Port Scanning (nmap — MANDATORY) | PENDING | |
| 2 | Service Detection & Banner Grabbing | PENDING | |
| 3 | OS Fingerprinting | PENDING | |
| 4 | Network Topology Mapping | PENDING | |
| 5 | Subdomain Takeover Check (dangling CNAMEs) | PENDING | |
| 6 | WAF Fingerprinting (XSS/SQLi probes, header analysis) | PENDING | |
| 7 | HTTP Methods Enumeration (OPTIONS/PUT/DELETE/TRACE) | PENDING | |
| 8 | CORS Misconfiguration Check (Origin reflection + credentials) | PENDING | |
| 9 | Security Headers Audit (CSP, XFO, HSTS, X-Content-Type) | PENDING | |
| 10 | SSL/TLS SAN Analysis (discover new subdomains from certs) | PENDING | |
```

Mark each technique as `DONE`, `SKIPPED (reason)`, or `FAILED (reason)` after execution.

### 5. Subdomain Takeover Check
```bash
# Check all CNAMEs for dangling pointers
for sub in $(cat subdomains-all.txt); do
  cname=$(dig +short CNAME "$sub" 2>/dev/null)
  if [ -n "$cname" ]; then
    ip=$(dig +short "$sub" 2>/dev/null | grep -E "^[0-9]" | head -1)
    [ -z "$ip" ] && echo "⚠️ DANGLING: $sub → $cname"
  fi
done
```
Check CNAMEs pointing to: HubSpot, GitHub Pages, Heroku, AWS S3, Azure, Shopify, Fastly, etc.

### 6. WAF Fingerprinting
Send benign attack payloads to detect WAF presence and type:
```bash
# XSS probe
curl -sk "https://target/?q=<script>alert(1)</script>" -o /dev/null -w "%{http_code}"
# SQLi probe  
curl -sk "https://target/?id=1'%20OR%201=1--" -o /dev/null -w "%{http_code}"
# If 200/302 (not 403/406) → NO WAF
# Check response headers for WAF signatures (x-waf, x-sucuri, cf-ray, etc.)
```

### 7. HTTP Methods Enumeration
```bash
for method in OPTIONS PUT DELETE PATCH TRACE; do
  code=$(curl -sk -X $method -o /dev/null -w "%{http_code}" "https://target/")
  echo "$method → $code"
done
# PUT/DELETE returning 200 on API endpoints = potential write access
```

### 8. CORS Misconfiguration Check
```bash
# Test origin reflection
curl -sk -H "Origin: https://evil.com" "https://target/" -D - -o /dev/null | grep -i "access-control"
# CRITICAL: If access-control-allow-origin reflects + allow-credentials: true → exploitable
# Wildcard * without credentials = low impact (browsers block credentialed requests)
```

### 9. Security Headers Audit
```bash
curl -sk -I "https://target/" | grep -iE "^(x-frame|x-content|content-security|strict-transport|x-xss)"
# Missing all headers = no WAF/security middleware → payloads won't be blocked in Phase 5/6
```

### 10. SSL/TLS SAN Analysis
```bash
echo | openssl s_client -connect target:443 -servername target 2>/dev/null | \
  openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
# Look for *.subdomain.target.com wildcards and unknown hostnames
```

## Pitfall: Shell-based parallel DNS resolution fails on macOS

**Problem (Ant Group, June 2026):** `xargs -P 20` with `dig` inside `sh -c` silently fails (exit 1, no output) on macOS due to shell quoting and subshell issues with the dig pipeline.

**Fix:** Use Python `concurrent.futures.ThreadPoolExecutor` for DNS brute-force:
```python
import subprocess, concurrent.futures

def resolve(sub):
    try:
        r = subprocess.run(['dig', '+short', '+time=2', '+tries=1', f'{sub}.target.com'],
                          capture_output=True, text=True, timeout=5)
        ip = r.stdout.strip().split('\n')[0]
        if ip and ip[0].isdigit():
            return f'{sub}.target.com|{ip}'
    except:
        pass
    return None

with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
    results = [r for r in ex.map(resolve, subs) if r]
```
This is 3-5x faster than sequential and actually works cross-platform.

## Pitfall: VPN/Internal DNS — Never Skip DNS Expansion

**Problem (LoanPlatform, June 2026):** Phase 2 DNS expansion (0a, 0b, 0c) was marked SKIPPED with reasoning "Internal K8s single target, VPN DNS — no public DNS brute-force possible." User caught the gap at review.

**Why it's wrong:** VPN-gated targets with internal DNS resolvers (169.254.169.254 or custom) CAN be brute-forced — just use `dig +short {sub}.target.com` which goes through the VPN resolver. K8s ingress vhost enumeration via `--resolve` is also valid even when results are all 404 (documents strict routing rules).

**Fix:** Always execute DNS expansion techniques for internal targets:
```bash
# Works via VPN DNS resolver
for svc in api admin auth grafana prometheus loan scoring kyc; do
  ip=$(dig +short "stg-${svc}.target.io" 2>/dev/null | head -1)
  [ -n "$ip" ] && echo "[+] stg-${svc}.target.io -> $ip"
done

# VHost against K8s ingress (document even negative results)
curl -sk --resolve "stg-test.target.io:443:10.x.x.x" "https://stg-test.target.io/"
```

Mark DONE (no new hosts) rather than SKIPPED when techniques are executed but yield nothing.

## Pitfall: Incomplete live-hosts.txt

**Problem (Bank Jago, May 2026):** Phase 2 live-hosts.txt contained only 67 entries when the master subdomain list had 343. This caused Phase 3 to miss 184 subdomains entirely until the user caught it at sign-off.

**Root cause:** HTTP probing was done in batches but not all batches were consolidated into live-hosts.txt. Some subdomains were only in batch result files (http-probe-batch1.txt, http-probe-batch2.txt) but never merged.

**Prevention:** Before requesting Phase 2 sign-off, run:
```bash
# Verify all master subs were probed
diff <(sort -u subdomains-master.txt) <(sort -u live-hosts.txt) | grep "^<" | wc -l
# If > 0, there are unprobed subdomains — batch-probe them before advancing
```

## Exit Criteria
- [ ] Active DNS expansion performed (pattern permutation brute-force executed).
- [ ] Expanded subdomain list merged with Phase 1 results.
- [ ] All in-scope public IPs port-scanned (nmap executed).
- [ ] Open ports documented with service versions.
- [ ] Network topology understood (CDN, load balancers, shared infra).
- [ ] Checklist shows all applicable techniques executed.
- [ ] Mandatory tools (nmap, ffuf for DNS expansion) were run — or gap documented with justification.
