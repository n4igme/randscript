# LINE Works / LY Corporation Program Intel

## HackerOne Program
- **Program URL:** https://hackerone.com/line (LY Corporation)
- **Status:** SUSPENDED since December 3, 2025
- **No new submissions accepted, no bounties paid**
- **Email reporting:** ml-bug-report@lycorp.co.jp (no reward)

## Scope Details (as of suspension)
- 31 assets total, 20 "In Scope"
- Closed Scope program (only listed assets qualify)
- **line-works.com is NOT explicitly listed** — falls under "Other Assets" (bounty ineligible, case-by-case triage)
- Tier A assets: LINE Messenger (iOS/Android/Desktop), LINE VOOM, LINE Pay, LINE STORE
- "Other Assets" category: in-scope but bounty-ineligible; third-party vendor domains may be rejected entirely

## Program Slug Discovery
- `hackerone.com/line_works` → 404
- `hackerone.com/lineworks` → 404
- `hackerone.com/line` → LY Corporation program (correct)

## Key Exclusions
- Automated scanner output without analysis
- Theoretical vulns without PoC
- Brute force for passwords/tokens
- DoS / Cache-poisoned DoS
- Missing security headers
- Login/logout CSRF
- Self-XSS / scripts not affecting users
- Unsafe SSL/TLS ciphers
- Profile photo accessibility via URL

## Bounty Ranges
- Minimum: $100
- Average: $397–$500
- Top: $1,500–$12,500
- Total paid: $382,512 (672 reports resolved, 388 hackers thanked)

## Decision Points
If targeting line-works.com:
1. Program suspended — no H1 payout regardless
2. Not in explicit scope — "Other Assets" only
3. Options: (a) proceed for practice/portfolio, (b) submit critical findings via email, (c) abort for active program
4. LINE Works is a separate product from LINE Messenger (enterprise collaboration tool by Works Mobile Corp, subsidiary of LY Corp)
