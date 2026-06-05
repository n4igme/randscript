# Intigriti Engagement Notes

## Immunefi Self-Bounty (Cross-Platform Reference)

Immunefi's own program is a good web target:
- **Web Assets:** immunefi.com, bugs.immunefi.com, shieldmybags.immunefi.com + Primacy of Impact
- **Web Rewards:** Critical $5K-$10K, High $2K-$5K, Medium $2K, Low $1K
- **Critical impacts:** RCE, sensitive data, app takedown, state-modifying actions on behalf of users, wallet manipulation, subdomain takeover w/ wallet, direct fund theft
- **High impacts:** Persistent HTML injection, changing sensitive user details (≤1 click), PII disclosure, subdomain takeover w/o wallet
- **Requirements:** PoC required, KYC required, triaged (9hr median resolution)
- **Vault:** ~$4.6K (small — SC bounty capped at $50K)
- **Best vectors:** IDOR on reports/profiles, auth bypass on bugs.immunefi.com, CSRF on wallet connection, SSRF via URL inputs, broken access control between researcher/project roles

## Account
- Login: sinaubib@gmail.com
- Platform rules: @intigriti.me email, UA "Intigriti - <user> - <ua>", X-Intigriti-Username header, 5 req/sec max

## Active Programs

### Dropbox Bug Bounty — $15K max, 27 targets
- URL: https://www.intigriti.com/programs/dropbox/dropbox/detail
- Status: Recon done, unauth findings all OOS (user enum, leaked tokens, info disc explicitly excluded)
- Next: Auth testing (IDOR, privilege escalation, business logic)
- Paid: dropbox/dropbox/detail

### Capital.com — $15K max, 12 targets (NEXT TARGET)
- URL: https://www.intigriti.com/programs/capitalcom/capitalcom/detail
- Scope: payment.backend-capital.com, *.backend-capital.com, capital.com/*, *.capital.com, *.itcapital.io, open-api.capital.com, aff.capital.com, go.capital.com
- Mobile: iOS (com.capital.trading), Android (com.capital.trading)
- Why: Fintech/trading = business logic bugs, IDOR on trading/payment flows, API auth issues. Wide wildcard scope.
- No 2FA required, no TAC

## Programmatic Target Discovery (Bot Detection Workaround)

Intigriti login triggers reCAPTCHA for automated browsers. Use this fallback:

```bash
# Download full Intigriti program data (updated regularly)
curl -s "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json" -o /tmp/intigriti.json

# Parse and rank programs
python3 -c "
import json
with open('/tmp/intigriti.json') as f:
    data = json.load(f)
# Sort by max bounty
programs = sorted(data, key=lambda p: p.get('max_bounty', {}).get('value', 0), reverse=True)
for p in programs[:20]:
    print(f\"{p['name']} | Max: \${p.get('max_bounty', {}).get('value', 0)} | Targets: {len(p.get('targets', {}).get('in_scope', []))} | {p['url']}\")
"
```

Data includes: id, name, company_handle, handle, url, status, confidentiality_level, tacRequired, twoFactorRequired, min_bounty, max_bounty, targets (in_scope with type/endpoint).

## Top Programs by Bounty (as of 2026-05-27)

| Program | Max Bounty | Targets | Notes |
|---------|-----------|---------|-------|
| Intel | $100K | 5 | Hardware-focused, not ideal |
| Arm | $20K | 2 | Firmware, niche |
| Trusted Firmware | $20K | 4 | Firmware, niche |
| BMW Group Automotive | $15K | 4 | Automotive IoT |
| Capital.com | $15K | 12 | Fintech, wide API scope ★ |
| Delen Private Bank | $15K | 19 | Banking, EU |
| Dropbox | $15K | 27 | Already hunting |
| Yahoo | $15K | 37 | Massive scope, heavily hunted |
| Intigriti (self) | $13.3K | 4 | Meta-hunting |
| Monzo | $12.5K | 6 | Banking, UK |
| DigitalOcean | $10K | 19 | Cloud, SSRF in scope (169.254.169.254) |
| AS Watson group | $8.5K | 55-122 | Retail e-commerce (Kruidvat, Watsons, etc.) |
| Visma | $7.5K | 20 | B2B SaaS, staging URLs in scope |
| SBB (Swiss Railways) | $6.6K | 10 | Transport, wide scope |

## Target Selection Strategy for Intigriti

Priority factors:
1. **Fintech/payment** — business logic bugs pay well, less competition than pure web
2. **Wide wildcard scope** — more attack surface to discover
3. **API-heavy** — your strongest skill area
4. **Min bounty > $0** — guarantees payout for valid Low findings
5. **No 2FA/TAC required** — lower friction to start

Avoid:
- Hardware/firmware (Intel, Arm) — not your skillset
- VDP programs ($0 bounty) — waste of time
- Heavily hunted (Yahoo) — unless you have a specific angle

## Intigriti Public Programs (No Login Required) — 2026-05-27

Paid bug bounty programs visible on public page:
- **Coveo Public Bug Bounty** — $100–$5,500. AI search platform, crawlers, Python execution, GenAI. 2FA required.
- **Randstad.be** — €25–€5,000. New W-One deployment, recently migrated. Application required.
- **Nutaku / Pornhub / Brazzers / TrafficJunky / Probiller** — MindGeek family, adult platforms.

VDPs (no bounty): Grafana Labs, Wärtsilä, University of Basel, Atolls, Anaconda, Storebrand, DIGI, Voi, Toast.

Monthly CTF: Challenge 0526 (live).

## intigriti.me Domain (Recon 2026-05-27)

- `intigriti.me` → 307 redirect to `www.intigriti.com`
- NS: Route53 (AWS), MX: SES, SPF: amazonses.com -all
- 1Password site verification present
- 5 subdomains (subfinder) — all dead (no A/CNAME records)
- No live HTTP services on any subdomain
- Mail-only domain with redirect — no web apps to test

## Directory Structure
```
~/PenTest/Hunting/Intigriti/
├── Dropbox/          (auth testing pending)
├── Capital.com/      (next target)
├── intigriti-me/     (closed — no attack surface)
└── ...
```
