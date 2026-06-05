# Domain Reconnaissance — Deep Methodology

## Phase Flow

```
Domain seed → DNS records → ASN/CIDR → Subdomain enum → Cloud assets → HTTP probing → Tech fingerprint
```

## 1. DNS Record Extraction

```bash
# Full record pull
dig +noall +answer {domain} ANY
dig +short {domain} A AAAA MX TXT NS SOA CNAME
dig +short _dmarc.{domain} TXT

# Zone transfer attempt (rare but free wins)
dig axfr {domain} @{ns_server}

# Reverse DNS on discovered IPs
for ip in $(dig +short {domain} A); do dig +short -x $ip; done
```

**What to extract:**
- MX → email provider (Google Workspace, O365, custom = interesting)
- TXT → SPF senders (reveals third-party services), DKIM selectors, verification records (google-site-verification → GCP project, MS= → Azure tenant)
- NS → hosting provider, potential for NS takeover if delegated to deprecated service
- SOA → admin email (often real address, not role-based)

## 2. ASN & CIDR Mapping

```bash
# Find ASN for domain's IP
whois -h whois.cymru.com " -v $(dig +short {domain} A | head -1)"

# Get all prefixes announced by that ASN
whois -h whois.radb.net -- '-i origin AS{number}' | grep route:

# BGP toolkit (richer data)
curl -s "https://api.bgpview.io/asn/{asn}/prefixes" | jq '.data.ipv4_prefixes[].prefix'
```

**Why this matters:** Companies own entire CIDR blocks. Everything in that range is attack surface even if no DNS points to it. Reverse-scan the ranges for web services.

## 3. Subdomain Enumeration

### Passive (no target contact)
```bash
# Certificate Transparency — most reliable passive source
curl -s "https://crt.sh/?q=%25.{domain}&output=json" | \
  jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

# Subfinder (aggregates 20+ sources)
subfinder -d {domain} -silent -all

# Amass passive
amass enum -passive -d {domain} -o amass_passive.txt

# SecurityTrails API (if available)
curl -s "https://api.securitytrails.com/v1/domain/{domain}/subdomains" \
  -H "APIKEY: {key}" | jq -r '.subdomains[]' | sed "s/$/.{domain}/"

# Common Crawl index
curl -s "https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{domain}&output=json" | \
  jq -r '.url' | unfurl -u domains | sort -u
```

### Active (touches target)
```bash
# DNS bruteforce with permutations
gobuster dns -d {domain} -w /opt/wordlists/subdomains-top1m.txt -t 50

# Pattern-based (if you found staging.example.com, try dev.example.com, test.example.com)
# Generate permutations from discovered subs
cat known_subs.txt | dnsgen - | massdns -r resolvers.txt -t A -o S

# Recursive enumeration (find sub.sub.domain)
for sub in $(cat found_subs.txt); do
  subfinder -d $sub -silent >> recursive_subs.txt
done
```

### VHOST discovery (same IP, different hostname)
```bash
# Brute virtual hosts on known IPs
ffuf -u http://{ip} -H "Host: FUZZ.{domain}" -w /opt/wordlists/subdomains.txt \
  -fs {baseline_size} -mc all
```

## 4. Cloud Asset Discovery

```bash
# S3 bucket enumeration (company name + common suffixes)
for suffix in "" "-dev" "-staging" "-prod" "-backup" "-assets" "-uploads" "-logs" "-data"; do
  aws s3 ls s3://{company}${suffix} 2>/dev/null && echo "OPEN: {company}${suffix}"
done

# GCP bucket check
for b in {company} {company}-prod {company}-dev; do
  curl -s "https://storage.googleapis.com/$b" | grep -q "NoSuchBucket" || echo "EXISTS: $b"
done

# Azure blob check
for b in {company} {company}prod {company}dev; do
  curl -s "https://${b}.blob.core.windows.net/?comp=list" | grep -q "AuthenticationFailed" && echo "EXISTS: $b"
done
```

## 5. HTTP Probing & Tech Fingerprint

```bash
# Probe all discovered subdomains
cat all_subs.txt | httpx -silent -status-code -title -tech-detect -follow-redirects -o alive.txt

# Screenshot live hosts (visual triage)
cat alive.txt | aquatone -ports 80,443,8080,8443

# Extract tech stack indicators
cat alive.txt | httpx -silent -H "Accept: text/html" -response-time -web-server -cdn
```

## 6. Historical Data

```bash
# Wayback Machine — find deleted pages, old endpoints, exposed files
curl -s "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&limit=5000" | \
  jq -r '.[]|.[2]' | sort -u | grep -E '\.(js|json|xml|config|env|bak|sql)$'

# Google cache (for recently changed pages)
site:{domain} cache:

# DNSdumpster historical records
# Passive Total / RiskIQ for historical DNS
```

## 7. Correlation Triggers

| Discovery | Next Action |
|-----------|-------------|
| SPF includes third-party sender | Check that service for account takeover |
| Azure tenant ID in TXT record | Feed to ctest for Azure enumeration |
| Wildcard DNS (*.domain → same IP) | VHOST brute required, subdomain takeover unlikely |
| Dangling CNAME (NXDOMAIN target) | Subdomain takeover candidate |
| S3 bucket with ListBucket | Check for sensitive files, feed to ptest |
| MX points to custom server | Potential for mail server exploitation |
| Exposed git repo (/.git/HEAD responds) | Feed to scode for source code review |

## Output Format

```markdown
## Domain: {domain}

### DNS Records
| Type | Value | Notes |

### Infrastructure
- ASN: AS{number} ({owner})
- CIDRs: {list}
- Cloud: {providers detected}

### Subdomains ({count} total)
| Subdomain | IP | Status | Tech | Notes |

### Cloud Assets
| Asset | Type | Access | Contents |

### Takeover Candidates
| Subdomain | CNAME Target | Status | Takeover Type |
```
