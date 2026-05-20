---
name: recon-passive
description: Passive reconnaissance — gather intelligence without touching the target directly.
version: 3.0.0
metadata:
  category: reconnaissance
  phase: 1
  scope_types: [web, network, cloud, mobile, mixed]
---

# Skill: Passive Reconnaissance

## When to Use
- First phase of any engagement (Gateway 1 is OPEN).
- When you need to map the attack surface without alerting the target.

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
```bash
# WHOIS lookup
whois target.com

# DNS records
dig target.com ANY
dig +short target.com MX
dig +short target.com TXT
host -t ns target.com

# Certificate transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq '.[].name_value' | sort -u

# Google dorks
# site:target.com filetype:pdf
# site:target.com inurl:admin
# site:target.com intitle:"index of"
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
Identify tech stack from public-facing assets.
```bash
# HTTP headers (passive — only reads response headers)
curl -sI https://target.com

# Wappalyzer CLI
wappalyzer https://target.com

# whatweb
whatweb -v https://target.com
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
| 1 | OSINT Gathering | PENDING | |
| 2 | Subdomain Enumeration | PENDING | |
| 3 | Technology Fingerprinting | PENDING | |
| 4 | Email & Username Discovery | PENDING | |
| 5 | Network Mapping | PENDING | |
| 6 | Asset Validation (DNS + HTTP probe) | PENDING | |
```

Mark each technique as `DONE`, `SKIPPED (reason)`, or `FAILED (reason)` after execution.

## Exit Criteria

> **Note:** The authoritative scope/technique matrix is in `SKILL.md` under "Scope-Aware Checklist Generation". The guidance below is supplementary.

- [ ] Attack surface is mapped (domains, IPs, subdomains).
- [ ] Enumerated subdomains validated for liveness (DNS + HTTP probe).
- [ ] Only confirmed-accessible hosts reported as findings.
- [ ] Technology stack identified on live hosts.
- [ ] Potential entry points listed (verified).
- [ ] Checklist shows all applicable techniques executed.
