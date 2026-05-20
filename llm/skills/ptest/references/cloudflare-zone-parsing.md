# Cloudflare Zone File Parsing

When an internal engagement provides a Cloudflare DNS zone export, use this workflow to extract actionable intelligence.

## Zone File Format (BIND export)

Cloudflare exports in BIND format with inline comments containing CF-specific metadata:
```
subdomain.domain.com.	1	IN	A	1.2.3.4 ; comment text cf_tags=cf-proxied:true
```

Key metadata in comments:
- `cf-proxied:true` — traffic goes through Cloudflare (WAF protected)
- `cf-proxied:false` — DNS-only, direct to origin IP (NO WAF — priority target)
- `cf_tags=partner` — partner integration endpoint
- `cf_tags=iap` — Google IAP protected
- `cf_tags=brevo` — Brevo/Sendinblue mail relay
- Free-text comments often contain Jira ticket links, purpose descriptions, creation dates

## Parsing Script (Python)

```python
import re

with open("zone-export.txt", "r") as f:
    lines = f.readlines()

a_records = []
for line in lines:
    match = re.match(r'^(\S+?)\s+\d+\s+IN\s+A\s+(\S+)\s*;?\s*(.*)', line)
    if match:
        fqdn = match.group(1).rstrip('.')
        ip = match.group(2)
        comment = match.group(3).strip()
        proxied = 'true' if 'cf-proxied:true' in comment else 'false'
        comment_clean = re.sub(r'\s*cf_tags=\S*', '', comment).strip('; ').strip()
        a_records.append({
            'fqdn': fqdn,
            'ip': ip,
            'proxied': proxied,
            'comment': comment_clean
        })

# Priority targets: non-proxied (direct IP, no WAF)
direct_ip = [r for r in a_records if r['proxied'] == 'false']

# Group by IP to identify shared infrastructure
ip_groups = {}
for r in a_records:
    ip_groups.setdefault(r['ip'], []).append(r['fqdn'])
```

## Quick Shell Commands

```bash
# Extract all non-proxied hosts (priority targets)
grep -i "proxied.*false\|proxy_status.*dns_only" zone-export.txt | awk '{print $1}' | sed 's/\.$//' > direct-ip-hosts.txt

# Extract all A record subdomains
grep -E "^\S+\s+\d+\s+IN\s+A\s+" zone-export.txt | awk '{print $1}' | sed 's/\.$//' | sort -u > all-subdomains-from-zone.txt

# Extract IPs grouped (find shared infra)
grep -E "^\S+\s+\d+\s+IN\s+A\s+" zone-export.txt | awk '{print $4}' | sort | uniq -c | sort -rn | head -20

# Find IAP-tagged hosts
grep -i "iap" zone-export.txt | awk '{print $1, $4}' | sed 's/\.$//'

# Find partner-tagged hosts
grep -i "partner" zone-export.txt | awk '{print $1, $4}' | sed 's/\.$//'
```

## Intelligence Extraction

From a zone file you can derive:
1. **Complete subdomain inventory** — 100% coverage vs passive recon's ~30-50%
2. **Direct-IP targets** (cf-proxied:false) — no WAF, higher attack surface
3. **Infrastructure mapping** — shared IPs reveal load balancers, clusters
4. **Environment classification** — dev/stg/prod patterns from naming
5. **Partner integrations** — partner tags reveal B2B API endpoints
6. **GCP project structure** — IAP-tagged hosts share project IDs
7. **Third-party services** — CNAME targets reveal SaaS integrations (Brevo, SendGrid, Zendesk, Aiven, AWS Transfer)
8. **Internal comments** — Jira tickets, creation dates, purpose descriptions
9. **Decommissioned services** — DNS records that no longer respond

## Comparison with Phase 1 Results

Always compare zone file against passive recon to quantify the gap:
```bash
# Subdomains found by passive recon
cat resolving-subs.txt | cut -d'|' -f1 | sort > passive-found.txt

# Subdomains from zone file
cat all-subdomains-from-zone.txt | sort > zone-all.txt

# Gap analysis
comm -13 passive-found.txt zone-all.txt > missed-by-passive.txt
echo "Passive recon missed $(wc -l < missed-by-passive.txt) subdomains"
```

## Lesson from Bank Jago Engagement (2026-05)

- Passive recon found 138 subdomains
- Zone file revealed 221 unique hosts
- **143 subdomains (65%) were invisible to passive tools**
- Root cause: Cloudflare universal SSL (no individual CT log entries), internal naming conventions not in any wordlist
- The zone file request took 5 minutes; brute-forcing would never have found names like `ailligence`, `benbot-dev`, `conv-banking`, `face-clustering-data`
