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

### Algolia Direct Query (Intigriti — bypasses pagination and bot detection)

Intigriti's public program page (intigriti.com/researchers/bug-bounty-programs) uses Algolia InstantSearch with client-side credentials embedded in JS bundles. This bypasses the 24-per-page pagination and login requirement:

**Step 1: Extract credentials from JS bundles (browser console)**
```javascript
// Find the chunk containing searchClient export
const chunks = performance.getEntriesByType('resource')
  .filter(e => e.name.includes('/_next/static/chunks/') && e.name.endsWith('.js'))
  .map(e => e.name);
for (const url of chunks) {
  const resp = await fetch(url);
  const text = await resp.text();
  if (text.includes('AAZUKSYAR4') && text.includes('searchClient')) {
    // Look near the searchClient export for the 32-char hex API key
    const idx = text.indexOf('AAZUKSYAR4');
    console.log(text.substring(Math.max(0, idx - 200), idx + 300));
    break;
  }
}
```

**Step 2: Query all programs (curl, no auth needed)**
```bash
# As of June 2026: appId=AAZUKSYAR4, apiKey=70d8a3400477311f27ce002ec953aeb0
curl -s "https://aazuksyar4-dsn.algolia.net/1/indexes/programs_prod?hitsPerPage=200" \
  -H "X-Algolia-Application-Id: AAZUKSYAR4" \
  -H "X-Algolia-API-Key: 70d8a3400477311f27ce002ec953aeb0" | python3 -c "
import sys, json
data = json.load(sys.stdin)
programs = [(h.get('name',''), h.get('programType',''), h.get('industryName',''), h.get('handle',''), h.get('companyHandle','')) for h in data['hits']]
print(f'Total: {len(programs)}')
for i, (name, ptype, industry, slug, company) in enumerate(programs, 1):
    print(f'{i}. {name} | {ptype} | {industry} | {company}/{slug}')
"
```

**Key fields in Algolia hits:**
- `name`, `handle` (slug), `companyHandle`
- `programType` (Bug bounty program / Responsible disclosure)
- `industryName`, `minBounty`, `maxBounty`
- Program URL: `https://app.intigriti.com/programs/{companyHandle}/{handle}`

**General technique for any Next.js + Algolia site:**
1. Load the page, check `window[Symbol.for("InstantSearchInitialResults")]` for index name and hit count
2. Find Algolia appId/apiKey in JS chunks (search for `-dsn.algolia.net` or the appId pattern `[A-Z0-9]{10}`)
3. Query the index directly with `hitsPerPage=200` (Algolia search-only keys allow reads up to 1000)
4. The `/browse` endpoint is usually blocked by search-only keys, but `/indexes/{name}?hitsPerPage=N` works

**Note:** Algolia search-only API keys are intentionally public (designed for frontend use). This is not credential theft — it's using the same key the browser uses.

### Platform-Specific Notes
- **Intigriti**: Login at login.intigriti.com, researcher programs at app.intigriti.com/researcher/programs
- **Intigriti rules**: Some programs require @intigriti.me email, custom UA, X-Intigriti-Username header, rate limits
- **Browser login**: Intigriti has aggressive bot detection (reCAPTCHA triggers on automated login)
- **Intigriti Algolia index**: `programs_prod` (161 programs as of June 2026), also has `policies` index for program policies

### IssueHunt (Japan-focused)
- **URL pattern**: `https://issuehunt.io/programs/{uuid}` (programs use UUIDs, not slugs)
- **Public programs list**: `https://issuehunt.io/programs` (SPA — requires browser rendering, curl gets empty shell)
- **API**: No documented public API for program listing; the site is a React SPA that fetches data client-side
- **Program page structure**: Overview tab has Introduction, Rewards (by severity), In Scope (targets + vuln categories), Guideline (rules in English/Japanese toggle)
- **Scope format**: Lists specific domains + vulnerability categories with reward ranges per category
- **Key programs**: bitbank (crypto exchange), other Japanese fintech companies
- **Report format**: Submit via platform after sign-in
- **Scraping**: `document.body.innerText.substring(start, end)` via browser_console to extract full page content (snapshot truncates)
- **Discovery tip**: If you know the company name but not UUID, check their website footer/security page for the direct IssueHunt link, or find the program via the "Public Programs" navigation link on issuehunt.io
