---
name: recon-passive
description: Passive reconnaissance — gather intelligence without touching the target directly.
version: 2.1.0
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

## Output

Document findings in `./ptest-output/recon-passive/`:
- `summary.md` — consolidated attack surface overview
- `domains.md` — target domains and subdomains
- `network.md` — IP ranges and ASNs
- `tech-stack.md` — technology stack per target
- `emails-usernames.md` — potential usernames/emails discovered
- `exposed-services.md` — publicly exposed services or data

Write `./ptest-output/recon-passive/checklist.md`:

```markdown
# Passive Recon Checklist

| # | Technique | Status | Notes |
|---|-----------|--------|-------|
| 1 | OSINT Gathering | PENDING | |
| 2 | Subdomain Enumeration | PENDING | |
| 3 | Technology Fingerprinting | PENDING | |
| 4 | Email & Username Discovery | PENDING | |
| 5 | Network Mapping | PENDING | |
```

Mark each technique as `DONE` or `SKIPPED (reason)` after execution.

## Exit Criteria
- [ ] Attack surface is mapped (domains, IPs, subdomains).
- [ ] Technology stack identified.
- [ ] Potential entry points listed.
- [ ] No direct contact with target systems was made.
- [ ] Checklist shows all applicable techniques executed.
