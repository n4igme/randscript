# Phase 1: Passive Recon

## Completion Criteria (ALL must be done on ALL accessible subdomains)

Before advancing to Phase 2, verify these are done for EVERY accessible target (not just the main domain):
- [ ] Subdomain enumeration (full list)
- [ ] Accessibility scan (HTTP status on ALL subdomains — not just a sample)
- [ ] Tech stack fingerprinting (headers on all accessible targets)
- [ ] JS bundle analysis (all SPA/React/Vue apps — extract API URLs, keys, Keycloak config)
- [ ] Security headers audit (all accessible targets)
- [ ] robots.txt + .well-known paths (all accessible targets)
- [ ] OSINT (Google dorks, GitHub code search, Wayback Machine)
- [ ] Certificate transparency analysis

**Common mistake:** Doing deep analysis on 5-10 targets and calling Phase 1 "done" while 20+ accessible targets remain unchecked. The user expects COMPLETE coverage before advancing. When asked "did we do all the activities to all subdomains?" — the answer must be yes.

**WinTicket lesson (June 2026):** Phase 1 was marked PASSED with TLS cert analysis, security headers audit, and robots.txt checks only done on the main site. User caught this at review — forced backtrack to complete ALL techniques on ALL 14 live hosts. Rule: every technique row in the checklist must be executed against EVERY live host, not just the primary target. If a technique is N/A for a host type (e.g., JS analysis on a GCS placeholder), mark it explicitly N/A with reason.

## Automated Setup

Run first when entering this phase:

```python
from hermes_tools import read_file
exec(read_file("~/.hermes/skills/security/ptest/scripts/phase1_passive.py")["content"])
```

---

## When to Use
- First phase of any engagement (Gateway 1 is OPEN).
- When you need to map the attack surface without alerting the target.

## Phase Boundary: Passive vs Active

**Phase 1 is STRICTLY passive** — no packets sent to the target. If it touches the target's infrastructure, it belongs in Phase 2.

| Passive (Phase 1) | Active (Phase 2) |
|---|---|
| DNS zone file analysis | HTTP probe (sending requests) |
| SPF/DMARC/TXT record reading | Technology fingerprinting (via response headers) |
| Shodan InternetDB lookup (third-party DB) | Port scanning (SYN packets) |
| GitHub/Google/Wayback search | TLS cert grabbing (connecting to :443) |
| CNAME resolution check (DNS only) | Directory/path discovery |
| Third-party service mapping (from DNS) | Banner grabbing |

**Why this matters:** The user corrected: "why did we do port scanning in phase 1? Phase 1 is just passive recon." Techniques 6b-6e in the checklist below (port scan, TLS analysis) are listed here for completeness of the Phase 1 output, but their EXECUTION happens in Phase 2. Phase 1 documents what needs scanning; Phase 2 does the scanning.

**Practical approach:** For internal engagements where stealth isn't a concern, it's acceptable to run HTTP probes and fingerprinting during Phase 1 setup — but classify them as Phase 2 work in the report and checklist.

## Techniques & Tools

### 0. Internal Engagement: Request Asset Inventory (MANDATORY for internal pentests)

When the operator is an internal pentester or has authorized internal access, **request these artifacts before brute-forcing**:

| Artifact | Source | Why |
|----------|--------|-----|
| DNS zone file export | Cloudflare / Route53 / Azure DNS dashboard | Complete subdomain list — eliminates blind brute-force |
| Asset inventory / CMDB | IT ops / infra team | Maps services to owners, environments, criticality |
| Network diagrams | Architecture team | Reveals internal segmentation, trust boundaries |
| CI/CD service list | DevOps / platform team | Reveals microservice names for pattern brute-force |
| Cloud project list | Cloud admin (GCP/AWS/Azure console) | Maps project IDs to teams and environments |

**Why this matters:** Passive recon tools (subfinder, crt.sh, amass) only find publicly-indexed subdomains. Internal services using wildcard SSL certs, Cloudflare universal SSL, or private DNS zones are invisible to external tools. A DNS zone file typically reveals 2-5x more subdomains than passive enumeration alone.

**Procedure:**
1. Ask the client/team: "Can you export the DNS zone file for {target domain}?"
2. If Cloudflare: Dashboard → DNS → Export (CSV/BIND format)
3. If Route53: `aws route53 list-resource-record-sets --hosted-zone-id {id}`
4. If Azure DNS: `az network dns record-set list -g {rg} -z {zone}`
5. Parse the zone file into `subdomains-from-zone.txt`
6. Merge with passive recon results: `sort -u subdomains.txt subdomains-from-zone.txt > all-subdomains.txt`
7. Note which subdomains are `cf-proxied:false` (direct-to-origin, no WAF) — these are priority targets

**If zone file is unavailable:** Document the gap and proceed with passive + brute-force. But always ASK first — it saves hours.

```bash
# Parse Cloudflare zone export (BIND format) to subdomain list
grep -E "^[a-zA-Z0-9]" zone-export.txt | awk '{print $1}' | sed 's/\.$//' | sort -u > subdomains-from-zone.txt

# Parse Cloudflare zone export (CSV format)
tail -n +2 zone-export.csv | cut -d',' -f1 | sort -u > subdomains-from-zone.txt

# Identify non-proxied (direct IP) hosts — priority targets
grep -i "proxied.*false\|proxy_status.*dns_only" zone-export.txt | awk '{print $1}' > direct-ip-hosts.txt
```

### 0b. Knowledge Base / Support Site Scraping

Before brute-forcing, scrape the target's public knowledge base or support site for service names and internal terminology:

```bash
# Yellow.ai / Next.js knowledge bases leak __NEXT_DATA__
curl -s "https://help.target.com" | grep -o '__NEXT_DATA__.*</script>' | python3 -c "
import sys, json
raw = sys.stdin.read().split('__NEXT_DATA__ = ',1)[1].rsplit('</script>',1)[0]
data = json.loads(raw)
print(json.dumps(data.get('props',{}).get('pageProps',{}), indent=2))
"

# Extract service/product names for wordlist generation
# Look for: product names, partner names, feature names, integration names
```

**What to extract:**
- Product/feature names → subdomain candidates (e.g., "Kantong" → `kantong.target.com`)
- Partner names → integration subdomains (e.g., "GoPay" → `gopay.target.com`)
- Service categories → environment patterns (e.g., "Loans" → `loan-*.target.com`)

---

### 1. OSINT Gathering
Search public sources for target information.

#### 1a. Domain Registration & History
```bash
# WHOIS lookup (registrant, dates, nameservers)
whois target.com

# Key things to note:
# - Creation date vs company founding date (acquired domain?)
# - Registrar (Namecheap, GoDaddy = less enterprise)
# - Nameservers (cloudflare = CF WAF likely, awsdns = Route53)
# - Expiry date (if soon, domain may lapse)
```

#### 1b. Shodan / Censys (Indexed Services)
```bash
# Shodan InternetDB (free, no API key needed)
# Query each known IP for indexed ports/vulns/hostnames
curl -s "https://internetdb.shodan.io/{IP}" | jq .

# Batch all resolved IPs
while IFS='|' read -r sub ip; do
  echo "=== ${sub} (${ip}) ==="
  curl -s "https://internetdb.shodan.io/${ip}" 2>/dev/null
  echo ""
done < ./ptest-output/recon-passive/resolving-subs.txt

# What to extract:
# - ports[] → confirms open ports without active scanning
# - hostnames[] → reveals reverse DNS, other domains on same IP
# - vulns[] → known CVEs indexed by Shodan
# - cpes[] → software versions (e.g., cpe:/a:openvpn:openvpn_access_server)
# - tags[] → cloud, starttls, etc.
```

#### 1c. App Association Files (MANDATORY for mobile-capable targets)
```bash
# Android Digital Asset Links (reveals package names, signing certs)
# Often accessible even when .well-known/ paths return WP 404
r = httpx.get("https://target.com/.well-known/assetlinks.json", verify=False)
# Also check root path (iOS prefers this):
r2 = httpx.get("https://target.com/apple-app-site-association", verify=False)

# What to extract:
# assetlinks.json: package_name (prod/stage/debug variants), sha256_cert_fingerprints
# apple-app-site-association: appIDs (TeamID.bundleID), components (deep link paths)
# Deep link paths reveal app-handled URL patterns: /line-auth/*, /invite/*, /meeting/*
# These paths may have server-side behavior or reveal internal service structure
```

**Why this matters (LINE WORKS, June 2026):** `assetlinks.json` revealed 12 Android packages including debug/staging variants. `apple-app-site-association` (at root, NOT .well-known) revealed 9 iOS bundle IDs and 20 deep link paths including `/line-auth/*` — exposing the auth flow structure. Always check BOTH files, and check both `/.well-known/` and root paths.

#### 1d. Wayback Machine (Historical URLs)
```bash
# Fetch all archived URLs for the domain
curl -s "https://web.archive.org/cdx/search/cdx?url=*.target.com&output=text&fl=original&collapse=urlkey&limit=200" > wayback-urls.txt

# Filter for interesting paths
grep -iE "\.(pdf|xlsx|csv|doc|conf|env|bak|sql|json|xml)" wayback-urls.txt
grep -iE "(admin|login|dashboard|internal|api|swagger|config)" wayback-urls.txt
grep -iE "(password|secret|token|key|credential)" wayback-urls.txt

# Check .well-known paths (often indexed historically)
curl -sk "https://www.target.com/.well-known/security.txt"
curl -sk "https://www.target.com/.well-known/openid-configuration"
curl -sk "https://www.target.com/robots.txt"
curl -sk "https://www.target.com/sitemap.xml"
```

#### 1d. GitHub / Code Repository Search
```bash
# Search for leaked credentials (MANUAL — requires browser)
# GitHub: https://github.com/search?q="target.com"+password+OR+secret+OR+token&type=code
# GitHub: https://github.com/search?q="company-name"&type=code
# GitLab: https://gitlab.com/search?search=target.com

# Automated tools (if available):
# trufflehog — scans repos for secrets
# gitleaks — finds secrets in git history
# gitrob — finds sensitive files in GitHub orgs

# Search patterns:
# "target.com" password OR secret OR token OR api_key
# "company-name" OR "parent-company" (e.g., "dkatalis" for Bank Jago)
# org:company-github-org (if known)
```

#### 1e. DNS Record Intelligence
```bash
# Full DNS record dump
dig target.com ANY
dig +short target.com MX
dig +short target.com TXT
dig +short target.com NS
dig +short _dmarc.target.com TXT

# SPF analysis — extract third-party email senders
dig +short target.com TXT | grep "v=spf1"
# Each "include:" reveals a service (google, sendinblue, sendgrid, etc.)

# DMARC analysis — check enforcement
dig +short _dmarc.target.com TXT
# p=none → email spoofing possible (FINDING!)
# p=quarantine → partial protection
# p=reject → properly enforced

# DKIM selectors (common ones)
for sel in google default mail s1 s2 k1 selector1 selector2; do
  dig +short ${sel}._domainkey.target.com TXT 2>/dev/null | grep -q "v=DKIM1" && echo "[+] DKIM selector: ${sel}"
done
```

#### 1f. Google Dorks
```bash
# File discovery
# site:target.com filetype:pdf
# site:target.com filetype:xlsx OR filetype:csv OR filetype:doc
# site:target.com filetype:conf OR filetype:env OR filetype:log

# Admin/login panels
# site:target.com inurl:admin OR inurl:login OR inurl:dashboard
# site:target.com intitle:"index of"

# Information disclosure
# site:target.com "internal" OR "confidential" OR "restricted"
# site:target.com "password" OR "username" OR "credential"
# "target.com" inurl:swagger OR inurl:api-docs

# Third-party leaks
# "target.com" site:pastebin.com OR site:paste.ee
# "target.com" site:trello.com
# "target.com" site:notion.so
```

#### 1g. Job Posting Intelligence
```bash
# Job postings reveal tech stack
# LinkedIn: search company jobs for engineering roles
# Look for: specific tool names (ArgoCD, Airflow, Terraform, Vault)
# Look for: cloud provider (GCP, AWS, Azure)
# Look for: languages/frameworks (Go, Java Spring Boot, Python)
# This confirms infrastructure without touching the target
```

### 2. Subdomain Enumeration
Discover subdomains from passive sources.
```bash
# subfinder
subfinder -d target.com -o subdomains.txt

# amass (passive only)
amass enum -passive -d target.com -o amass-subs.txt

# from certificate transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crt-subs.txt

# Wayback Machine URLs
waybackurls target.com | sort -u > wayback-urls.txt
```

### 3. Technology Fingerprinting
Identify tech stack from ALL live hosts (not just a sample).

**Fingerprint ALL live hosts in batch** — this is mandatory, not optional. A single httpx/curl pass collecting headers reveals infrastructure groupings that manual spot-checks miss.

```python
# Batch fingerprint all live hosts (Python httpx)
import httpx, json

with open('live-hosts.txt') as f:
    hosts = [h.strip() for h in f]

results = []
for host in hosts:
    try:
        r = httpx.get(f'https://{host}', verify=False, timeout=8,
                      headers={'User-Agent': 'Mozilla/5.0'})
        h = dict(r.headers)
        fp = {
            'host': host, 'status': r.status_code, 'size': len(r.content),
            'server': h.get('server', ''),
            'powered_by': h.get('x-powered-by', ''),
            'cdn_waf': 'Cloudflare' if 'cf-ray' in h else
                       'CloudFront' if 'x-amz-cf-id' in h else
                       'GCP' if 'x-goog-' in str(h).lower() else '',
            'technology': [],
        }
        # Detect from headers
        if 'x-envoy-upstream-service-time' in h: fp['technology'].append('Envoy/Istio')
        if 'x-kong-' in str(h).lower(): fp['technology'].append('Kong Gateway')
        if 'x-goog-iap-generated-response' in h: fp['technology'].append('Google IAP')
        if 'alt-svc' in h and 'h3' in h.get('alt-svc',''): fp['technology'].append('GCP LB')
        if 'x-cloud-trace-context' in h: fp['technology'].append('GCP Cloud Trace')
        # Detect from body (first 2000 chars)
        body = r.text[:2000].lower()
        if '__next' in body: fp['technology'].append('Next.js')
        if 'react' in body: fp['technology'].append('React')
        results.append(fp)
    except: pass

# Save and analyze
with open('phase1-fingerprints.json', 'w') as f:
    json.dump(results, f, indent=2)
```

**What to extract per host:**
- Server header (nginx, envoy, Lucy, OpenVPN-AS, cloudflare)
- X-Powered-By (Next.js, Express, Short.io/Edge)
- CDN/WAF (Cloudflare, CloudFront, GCP)
- Via header (1.1 google = GCP LB, kong/3.1.1 = Kong)
- IAP cookies (GCP_IAP_XSRF_NONCE = Google IAP protected)
- Technology from body (React, Vue, Angular, n8n, Dynatrace, Grafana)
- Security headers presence (HSTS, X-Frame-Options, CSP)

**Group results by infrastructure** to map the architecture:
- Same response size on 403 = same backend/WAF config
- Same `via` header = same load balancer cluster
- Same IAP client_id = same GCP project
- Same server header = same technology stack

```bash
# Quick CLI alternative (httpx with tech detection)
cat live-hosts.txt | httpx -status-code -title -web-server -tech-detect -content-length -o fingerprints.txt
```

### 4. Email & Username Discovery
Search for exposed emails and usernames.
```bash
# theHarvester
theHarvester -d target.com -b all -l 500

# hunter.io (requires API key)
curl -s "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=$HUNTER_API_KEY" | jq '.data.emails[].value'

# GitHub search for leaked credentials
# Search: "target.com" password OR secret OR token
```

### 5. Network Mapping
Identify IP ranges and ASN information.
```bash
# ASN lookup
whois -h whois.radb.net -- '-i origin AS12345'

# BGP data
curl -s "https://api.bgpview.io/search?query_term=target.com" | jq .

# Shodan (passive — queries indexed data)
shodan search hostname:target.com
shodan host 1.2.3.4
```

### 6. Asset Validation

**This step is MANDATORY before reporting any subdomain-related findings.**

After enumeration, validate every discovered subdomain for liveness. DNS existence alone is NOT evidence of exposure.

#### Pitfall: GCP Global Load Balancer False Positives

When port scanning GCP-hosted targets, some IPs will show ALL ports as "open" (SYN-ACK on every port). This is a GCP Global LB behavior — it accepts TCP connections on any port but sends no data (no banner, no HTTP response, connection resets on data send).

**How to identify:**
- All scanned ports return "open" with no banner
- IP is in GCP range (34.x.x.x, 35.x.x.x)
- Shodan shows 400+ ports for the IP
- Connecting to MySQL/Redis/SSH ports gives no greeting

**Verification:** Connect to a known-service port (3306, 6379, 22) and check for banner. Real services send greeting packets; GCP LBs give silence then RST.

**These are NOT real open services.** They're IAP-protected backends where the LB accepts TCP but requires Google OAuth before proxying. Mark as "GCP LB false positive" and move on.

#### Step 1: DNS Resolution Check
```bash
# Batch resolve all enumerated subdomains
while read sub; do
  ip=$(dig +short "$sub" | head -1)
  if [ -n "$ip" ]; then
    echo "RESOLVES|$sub|$ip"
  else
    echo "DEAD|$sub|"
  fi
done < subdomains.txt
```

Categorize results:
- **RESOLVES** — has a DNS A/AAAA record pointing to an IP
- **DEAD** — no DNS resolution (historical/decommissioned, exclude from findings)

#### Step 2: HTTP Probe (for resolving hosts)
```bash
# Probe each resolving subdomain for HTTP/HTTPS response
while read sub; do
  status=$(curl -sI --max-time 5 -o /dev/null -w "%{http_code}" "https://$sub" 2>/dev/null)
  if [ "$status" != "000" ]; then
    echo "LIVE|$sub|https|$status"
  else
    status=$(curl -sI --max-time 5 -o /dev/null -w "%{http_code}" "http://$sub" 2>/dev/null)
    if [ "$status" != "000" ]; then
      echo "LIVE|$sub|http|$status"
    else
      echo "NO_HTTP|$sub||"
    fi
  fi
done < resolving-subs.txt
```

Categorize results:
- **LIVE** — responds to HTTP/HTTPS (confirmed attack surface)
- **NO_HTTP** — resolves but no HTTP response (may have non-HTTP services; pass to active recon for port scanning)

#### Step 3: Classify
| Category | Meaning | Action |
|----------|---------|--------|
| LIVE | Resolves + HTTP response | Confirmed attack surface. Eligible for findings. |
| NO_HTTP | Resolves but no HTTP | Potential target. Pass to active recon for port scan. Do NOT report as finding. |
| DEAD | Does not resolve | Historical/inactive. Informational only. Not a finding. |

**Important:** When the subdomain list is very large (100+), batch the validation. Probe high-value targets first (admin panels, APIs, monitoring tools, databases), then sample the rest. Document the sampling methodology.

---

## Finding Standards

**These rules are mandatory for Phase 1 findings:**

1. **DNS existence is NOT a finding.** A subdomain appearing in CT logs or DNS is informational context for attack surface mapping — it is not a vulnerability.

2. **Only report a finding if ALL of the following are true:**
   - The host is **confirmed accessible** (LIVE status from validation)
   - The accessible service presents a **security concern** (e.g., unauthenticated panel, version disclosure, sensitive data exposure)
   - You have **direct evidence** (HTTP response, screenshot, or response body proving the concern)

3. **Severity guidance for passive recon findings:**
   - **Info:** Technology/version disclosure on confirmed-accessible hosts (e.g., `X-Powered-By` header)
   - **Low:** Confirmed information exposure with minor impact (e.g., directory listing with non-sensitive files)
   - **Medium:** Only if the service is confirmed accessible AND lacks authentication or exposes sensitive data (must be verified with evidence)
   - **High/Critical:** Extremely unlikely in passive recon. Requires confirmed unauthenticated access to sensitive systems with direct evidence.

4. **What to do with unverified potential issues:**
   - Document them in `domains-potential.md` as targets for active recon
   - Do NOT create findings for them
   - Note them in the phase summary as "requires active verification"

---

## Output

Document findings in `./ptest-output/recon-passive/`:
- `summary.md` — consolidated attack surface overview
- `domains-live.md` — confirmed accessible subdomains (resolved + HTTP response), with response codes
- `domains-potential.md` — resolved but not HTTP-accessible (for active recon to port scan)
- `domains-dead.md` — did not resolve (informational/historical only)
- `network.md` — IP ranges and ASNs
- `tech-stack.md` — technology stack per confirmed-live target
- `emails-usernames.md` — potential usernames/emails discovered

Write `./ptest-output/recon-passive/checklist.md`:

```markdown
# Passive Recon Checklist

| # | Technique | Status | Notes |
|---|-----------|--------|-------|
| 0 | Request Asset Inventory (internal engagements) | PENDING | |
| 0b | Knowledge Base / Support Site Scraping | PENDING | |
| 1 | OSINT Gathering (WHOIS, Wayback, GitHub, Google dorks, Shodan) | PENDING | |
| 2 | Subdomain Enumeration | PENDING | |
| 3 | Technology Fingerprinting (headers + body on ALL live hosts) | PENDING | |
| 4 | Email & Username Discovery | PENDING | |
| 5 | Network Mapping | PENDING | |
| 6 | Asset Validation (DNS + HTTP probe ALL hosts) | PENDING | |
| 6b | Port Scan (non-HTTP services: SFTP, VPN, SMTP, SSH) | PENDING | |
| 6c | Subdomain Takeover Check (all CNAME targets) | PENDING | |
| 6d | SPF/DMARC/Email Security Analysis | PENDING | |
| 6e | TLS Certificate Analysis (CN, SANs, issuer, expiry) | PENDING | |
| 6f | Third-Party Service Inventory (from DNS + headers) | PENDING | |
| 7 | Binary/Source Intelligence | PENDING | |
```

Mark each technique as `DONE`, `SKIPPED (reason)`, or `FAILED (reason)` after execution.

### 7. Binary/Source Intelligence

When the target has open-source components or exposed binaries, extract intelligence passively.

#### Open-Source Target Software Analysis
```bash
# Identify target software version (from headers, config endpoints, error pages)
# Check GitHub for the project
curl -s "https://api.github.com/repos/<org>/<project>/releases" | python3 -c "
import json,sys
for r in json.load(sys.stdin)[:10]:
    print(f'{r[\"tag_name\"]} - {r[\"published_at\"][:10]} - {r[\"name\"][:60]}')
"

# Check changelogs between target version and latest for security fixes
# Search issues for security-relevant keywords
curl -s "https://api.github.com/repos/<org>/<project>/issues?state=all&per_page=50" | \
  python3 -c "
import json,sys
keywords = ['auth','bypass','inject','xss','csrf','ssrf','priv','escal','vuln','secur','token','leak']
for i in json.load(sys.stdin):
    if any(k in i.get('title','').lower() for k in keywords):
        print(f'{i[\"number\"]} [{i[\"state\"]}] {i[\"title\"]}')
"
```

#### Exposed Binary Analysis
When binaries are downloadable (from open buckets, package repos, GitHub releases):
```bash
# Download and extract
dpkg-deb -x package.deb ./extracted/ 2>/dev/null || tar xf data.tar.* 2>/dev/null

# Identify binary type
file ./extracted/path/to/binary

# Extract URLs and endpoints
strings binary | grep -E "http(s)?://" | sort -u

# Extract internal paths and API routes
strings binary | grep -E "^/(api|v[0-9]|internal|metadata)" | sort -u

# Look for hardcoded secrets, tokens, keys
strings binary | grep -iE "(api[_-]?key|secret|token|password|credential)" | sort -u

# Check for metadata service interaction (cloud targets)
strings binary | grep -i "169.254.169.254"

# Verify if tool is internal (not publicly available)
curl -s "https://api.github.com/repos/<org>/<tool-name>" | grep -q "Not Found" && echo "INTERNAL TOOL"
```

**Key signals:**
- Internal endpoints reveal authenticated attack surface
- Metadata URLs confirm SSRF value (if you can reach the service)
- Internal-only tools (not on GitHub) are higher-value findings when exposed
- Version history in open repos enables targeted CVE research

## Env-Prefix Quick-Win Check (MANDATORY before Phase 2)

Before transitioning to Phase 2, scan ALL discovered subdomains for environment indicators and immediately generate prod equivalents. This is a 5-minute check that catches forgotten production assets.

**Process:**
1. Grep your merged subdomain list for env patterns: `grep -iE '\.(dev|staging|stg|sit|uat|mock|sandbox|test|qa|preprod|nonprod|demo|lab)\.' subdomains-merged.txt`
2. For EACH match, generate the bare-domain equivalent (strip the env segment)
3. Resolve the bare-domain equivalents with `dig +short`
4. If any resolve — add to master list, flag as **HIGH PRIORITY** targets (forgotten prod assets)

**Example (BFI, May 2026):**
```
Found in passive recon:  e-pmo2.dev.bfi.co.id → 172.22.32.94
Quick-win derivation:    e-pmo2.bfi.co.id     → 34.111.225.150 ← LIVE PROD!
Result:                  Forgotten PHP app with SQLi → 21 databases compromised
```

**Exit gate addition:** Document in Phase 1 output: "Env-prefix quick-win: X subdomains with env indicators found, Y bare-domain equivalents tested, Z new live hosts discovered."

---

## Exit Criteria

- [ ] Attack surface is mapped (domains, IPs, subdomains).
- [ ] Enumerated subdomains validated for liveness (DNS + HTTP probe ALL hosts).
- [ ] Technology fingerprinting completed on ALL live hosts (not a sample).
- [ ] Non-HTTP services port-scanned (SFTP, VPN, SMTP, SSH on relevant hosts).
- [ ] Subdomain takeover check completed (all CNAME targets verified for dangling).
- [ ] SPF/DMARC/email security analyzed (p=none is a finding for financial targets).
- [ ] TLS certificates analyzed (CN, SANs, issuer, expiry, mismatches).
- [ ] Third-party service inventory compiled (from DNS records + response headers).
- [ ] Only confirmed-accessible hosts reported as findings.
- [ ] Technology stack identified on live hosts.
- [ ] Potential entry points listed (verified).
- [ ] Open-source target software checked for security issues between versions.
- [ ] Exposed binaries analyzed for internal endpoints and secrets (if available).
- [ ] Env-prefix quick-win check completed.
- [ ] OSINT completed (GitHub, Shodan InternetDB, Google dorks).
- [ ] Checklist shows all applicable techniques executed.
