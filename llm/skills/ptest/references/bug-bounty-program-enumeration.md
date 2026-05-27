# Bug Bounty Program Enumeration

## Data Sources for Program Discovery

### arkadiyt/bounty-targets-data (GitHub)
Primary source for structured program data across platforms:
```bash
# Intigriti programs (JSON with full scope, bounty ranges, targets)
curl -s "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json" -o /tmp/intigriti.json

# Parse and filter
python3 -c "
import json
with open('/tmp/intigriti.json') as f:
    data = json.load(f)
# Sort by max bounty
programs = sorted(data, key=lambda p: p.get('max_bounty',{}).get('value',0), reverse=True)
for p in programs[:20]:
    print(f\"{p['name']} | Max: \${p.get('max_bounty',{}).get('value',0)} | Targets: {len(p.get('targets',{}).get('in_scope',[]))} | {p['url']}\")
"
```

### Key fields in intigriti_data.json
- `id`, `name`, `company_handle`, `handle`, `url`
- `status` (open/closed)
- `confidentiality_level` (public/private)
- `tacRequired`, `twoFactorRequired`
- `min_bounty.value`, `max_bounty.value`
- `targets.in_scope[]` — each has `type` (url/wildcard/ios/android/iprange/other), `endpoint`, `description`
- `targets.out_of_scope[]` — same structure

### Target Selection Criteria
Prioritize programs with:
1. Wide wildcard scope (*.domain.com) — more attack surface
2. High max bounty ($10K+)
3. API endpoints explicitly in scope
4. Fewer reports (less competition)
5. Recently updated scope (fresh targets)
6. No 2FA requirement to join (lower friction)

### Platform-Specific Notes
- **Intigriti**: Login at login.intigriti.com, researcher programs at app.intigriti.com/researcher/programs
- **Intigriti rules**: Some programs require @intigriti.me email, custom UA, X-Intigriti-Username header, rate limits
- **Browser login**: Intigriti has aggressive bot detection (reCAPTCHA triggers on automated login)
