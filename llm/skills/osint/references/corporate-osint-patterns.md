# Corporate OSINT Patterns

Techniques for enumerating organizations, employees, and infrastructure when targeting companies (bug bounty recon, internal pentest prep).

## Employee Enumeration

### LinkedIn (via Google dorks — no login required)
```
site:linkedin.com/in/ "{company}" "{role}"
site:linkedin.com/in/ "{company}" "security"
site:linkedin.com/in/ "{company}" "engineer"
site:linkedin.com/in/ "{company}" "devops"
```

### GitHub Organization Discovery
```bash
# Find org repos
curl -s "https://api.github.com/orgs/{org}/repos?per_page=100&type=public" | python3 -c "
import json,sys
for r in json.load(sys.stdin):
    print(f\"{r['name']} ({r['language']}) - {r['description'] or 'no desc'}\")"

# Find employees via org members (if public)
curl -s "https://api.github.com/orgs/{org}/members?per_page=100"

# Find via commit emails across org repos
curl -s "https://api.github.com/orgs/{org}/repos?per_page=100" | python3 -c "
import json,sys
for r in json.load(sys.stdin): print(r['full_name'])" | while read repo; do
  curl -s "https://api.github.com/repos/$repo/commits?per_page=30" 2>/dev/null | \
    python3 -c "
import json,sys
try:
    for c in json.load(sys.stdin):
        e = c.get('commit',{}).get('author',{}).get('email','')
        n = c.get('commit',{}).get('author',{}).get('name','')
        if e and 'noreply' not in e: print(f'{n} <{e}>')
except: pass" 2>/dev/null
done | sort -u
```

### Email Pattern Discovery
1. Find one confirmed email (LinkedIn, GitHub commit, WHOIS)
2. Derive pattern: `{first}.{last}@`, `{f}{last}@`, `{first}@`
3. Validate: MX + SMTP VRFY/RCPT TO (if not rate-limited)
4. Hunter.io / phonebook.cz for bulk pattern confirmation

## Infrastructure Recon

### ASN & IP Range
```bash
# Find ASN by company name
curl -s "https://api.bgpview.io/search?query_term={company}" | python3 -c "
import json,sys
data = json.load(sys.stdin)
for asn in data.get('data',{}).get('asns',[]):
    print(f\"AS{asn['asn']} - {asn['name']} ({asn['country_code']})\")"

# Get prefixes for ASN
curl -s "https://api.bgpview.io/asn/{asn}/prefixes" | python3 -c "
import json,sys
data = json.load(sys.stdin)
for p in data.get('data',{}).get('ipv4_prefixes',[]):
    print(p['prefix'])"
```

### Cloud Asset Discovery
```bash
# S3 bucket permutations
for prefix in {company} {company}-prod {company}-dev {company}-staging {company}-backup {company}-assets {company}-data; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://$prefix.s3.amazonaws.com/")
  echo "$prefix.s3.amazonaws.com → $status"
done

# GCS equivalent
for prefix in {company} {company}-prod {company}-backup; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/$prefix/")
  echo "gs://$prefix → $status"
done
```

### Acquisition & Subsidiary Discovery
- Crunchbase: acquisitions timeline
- Wikipedia: company article → subsidiaries section
- SEC EDGAR (US): 10-K filings list subsidiaries
- Google: `"{company}" acquired OR acquisition site:techcrunch.com`

## Technology Stack Fingerprinting

### Job Postings (reveal internal tech)
```
site:linkedin.com/jobs "{company}" "kubernetes"
site:greenhouse.io "{company}"
site:lever.co "{company}"
"{company}" careers "terraform" OR "aws" OR "gcp"
```

### Conference Talks & Blog Posts
```
site:youtube.com "{company}" "infrastructure" OR "architecture"
site:medium.com "{company}" "microservices" OR "kubernetes"
site:slideshare.net "{company}" "devops"
```

## Supply Chain Mapping

### Package Registry Presence
```bash
# npm packages by org
curl -s "https://registry.npmjs.org/-/v1/search?text=scope:@{company}&size=50"

# PyPI packages
web_search "{company} site:pypi.org"

# Docker Hub
curl -s "https://hub.docker.com/v2/repositories/{company}/?page_size=100"
```

### DNS Infrastructure Patterns
```bash
# SPF reveals email infra
dig +short {domain} TXT | grep spf

# DMARC reveals reporting
dig +short _dmarc.{domain} TXT

# MX reveals email provider
dig +short {domain} MX
```

## Pitfalls

- LinkedIn scraping triggers account locks — use Google dorks only
- GitHub rate limit: 60 req/hr unauthenticated, 5000 with token
- Cloud bucket enumeration: 403 = exists but private (different from 404 = doesn't exist)
- Job postings may be stale (tech stack already migrated)
- Acquisitions: acquired company's infra often remains on old domain for months/years
