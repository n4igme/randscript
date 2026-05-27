# Intigriti Platform Recon Notes

## Accessing Program Data Without Login

Intigriti's web app is heavily JS-rendered and triggers reCAPTCHA/bot detection on automated login attempts. Workaround:

```bash
# Structured JSON of all Intigriti programs (scope, bounties, targets)
curl -s "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json" -o /tmp/intigriti.json
```

This gives: program name, handle, company_handle, URL, status, min/max bounty, in_scope targets (type + endpoint + description), out_of_scope targets.

## Parsing Program Data

```python
import json
with open('/tmp/intigriti.json') as f:
    data = json.load(f)

# Filter by bounty amount
for p in data:
    max_b = p.get('max_bounty', {}).get('value', 0)
    targets = p.get('targets', {}).get('in_scope', [])
    oos = p.get('targets', {}).get('out_of_scope') or []
```

## Key Fields
- `company_handle` + `handle` → unique program identifier
- `targets.in_scope[].type`: url, wildcard, iprange, ios, android, other, None (for GitHub repos)
- `targets.in_scope[].endpoint`: the actual target
- `targets.in_scope[].description`: scope notes, testing guidelines
- `targets.out_of_scope`: same structure, critical to check before testing

## Intigriti Rules (from memory)
- Use @intigriti.me email for account creation on targets
- UA: "Intigriti - <username> - <original_ua>"
- X-Intigriti-Username header on requests
- Max 5 req/sec rate limit
- Login: sinaubib@gmail.com

## Phase 1 Recon Checklist for Intigriti Wildcard Programs
1. Pull scope from bounty-targets-data JSON
2. Filter OOS subdomains/wildcards before enumeration
3. subfinder for subdomain discovery
4. ~/go/bin/httpx (NOT system httpx) for live host detection with tech fingerprinting
5. Categorize by: status code, technology stack, interesting names (staging, test, internal, api, admin)
6. Probe CSP headers on main app for internal domain leakage
7. Check for open S3/Spaces bucket listings on repo/cdn subdomains
8. Look for exposed API docs (OpenAPI/Swagger) on app platform instances
