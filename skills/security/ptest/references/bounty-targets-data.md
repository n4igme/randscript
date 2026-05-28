# Bounty Targets Data - Structured Scope for Bug Bounty Platforms

## Source
GitHub: https://github.com/arkadiyt/bounty-targets-data
Updated automatically. Contains structured JSON for all major platforms.

## Available Files

```bash
BASE="https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"

# Platform-specific program data
curl -s "$BASE/intigriti_data.json" -o /tmp/intigriti.json
curl -s "$BASE/hackerone_data.json" -o /tmp/hackerone.json
curl -s "$BASE/bugcrowd_data.json" -o /tmp/bugcrowd.json
curl -s "$BASE/yeswehack_data.json" -o /tmp/yeswehack.json
curl -s "$BASE/federacy_data.json" -o /tmp/federacy.json

# Pre-extracted scope lists (domains/wildcards only)
curl -s "$BASE/domains.txt" -o /tmp/all_domains.txt
curl -s "$BASE/wildcards.txt" -o /tmp/all_wildcards.txt
```

## Use Cases
- Bypass platform login/CAPTCHA for scope enumeration
- Compare programs across platforms (same company, different scopes)
- Bulk filter by bounty amount, target type, program status
- Feed wildcards directly into subfinder/amass for mass recon
- Validate scope before testing (check OOS lists)

## Schema (Intigriti example)
```json
{
  "id": "...",
  "name": "Program Name",
  "company_handle": "company",
  "handle": "program",
  "url": "https://www.intigriti.com/programs/company/program/detail",
  "status": "open",
  "confidentiality_level": "public",
  "min_bounty": {"value": 50},
  "max_bounty": {"value": 10000},
  "targets": {
    "in_scope": [
      {"type": "wildcard|url|iprange|ios|android|other", "endpoint": "*.example.com", "description": "..."}
    ],
    "out_of_scope": [...]
  }
}
```

## HackerOne schema differs slightly
- Uses `targets.in_scope[].asset_identifier` instead of `endpoint`
- Uses `targets.in_scope[].asset_type` instead of `type`
- Has `targets.in_scope[].eligible_for_bounty` boolean
