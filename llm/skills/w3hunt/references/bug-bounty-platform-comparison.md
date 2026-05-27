# Bug Bounty Platform Comparison (for n4igme, Indonesia-based)

## Platform Rankings (by money potential)

### 1. Immunefi (Web3) — Highest payouts
- Payouts: $500–$100K+ for smart contract, $2K–$25K for web
- Limit: 1 report/day for new accounts
- Strength: Web+contract hybrid programs, less competition on web layer
- Active: StakeWise (3 reports), Beefy (submitted)

### 2. YesWeHack — Best for APAC
- Payouts: €500–€15K for Critical
- Programs: GoPay, Gojek (*.gojekapi.com), CoinDCX
- Strength: SEA companies, less competition than HackerOne
- Also has Dojo CTF challenges (reputation, no payout)

### 3. HackerOne — Volume + private invites (DEPRIORITIZED 2026-05-27)
- Payouts: $200–$100K+
- Key programs: Grab ($200–$10K, massive scope), TikTok, LINE
- Strength: Largest pool, private invite pipeline
- Strategy: Build rep on public programs → get invited to high-paying privates
- Grab scope: 9 wildcards (*.grab.com, *.ovo.id, *.grabpay.com, etc.)
- **TRUST ISSUE (2026-05-27):** WalletOnTelegram finding marked as duplicate with suspicious timing — possible triager front-running. TikTok TIKTOK-001 (passport/email/bind auth bypass, High) submitted but awaiting verdict. Decision: postpone H1 activity until TIKTOK-001 verdict. If also duped with suspicious timing, abandon H1 entirely.
- **Known H1 problems:** Triagers accused of stealing/front-running bugs, opaque duplicate rulings, reputation score damage from dupes, time wasted on reports that get closed without transparency

### 4. Bugcrowd — Complementary
- Payouts: $50–$75K (Okta top)
- Key programs: Okta ($75K), Zendesk ($50K), eToro ($15K), Chime ($20K)
- Strength: Different program pool from HackerOne
- Caveat: Chime is geo-blocked (US-only), Okta needs credentials from program

### 5. Intigriti — Active
- Payouts: $50–$100K (Intel top), $15K for fintech (Capital.com, Dropbox, Yahoo)
- 128 public programs, many with wildcard scope
- Active: Dropbox (auth testing pending), Capital.com (next target)
- Strength: Fintech programs (Capital.com, Delen Private Bank, Monzo), less competition than HackerOne
- Caveat: Login triggers reCAPTCHA for bots — use arkadiyt/bounty-targets-data repo for programmatic discovery
- Spring Heist events are EU/UK residents only (skip events, hunt programs directly)
- See: references/intigriti-engagement.md

### 6. HackenProof — Parked
- Web3-focused, decent payouts
- Blocked: requires $5 credit to submit (unknown top-up mechanism)
- Active finding: Hacken SSRF (CVSS 8.6) ready but can't submit

## Geo-Restriction Issues (Indonesia)

### Blocked:
- **Chime** (Bugcrowd) — all endpoints return 403 from non-US IPs (Cloudflare geo-block)
- **Intigriti Spring Heist** — EU/UK residents only
- **Any US-only fintech** requiring SSN/US phone for testing

### Accessible:
- **Grab** (HackerOne) — SEA company, no geo-block, OVO is Indonesian
- **eToro** (Bugcrowd) — global trading platform
- **Fireblocks** (Bugcrowd) — web3 infra, global
- **Blockchain.com** (Bugcrowd) — global crypto
- **Rapyd** (Bugcrowd) — global payment APIs
- **TikTok** (HackerOne) — global
- **All Immunefi programs** — web3 is borderless

## Strategy

### Immediate (reports ready):
1. Immunefi: StakeWise (validate CORS impact first, then upload/signature)
2. YesWeHack: GoPay reports (need login)
3. YesWeHack: Dojo #51 (get flag, reply with corrected payload)

### Active hunting:
1. HackerOne/Grab — massive scope, OVO is home turf
2. Immunefi — new DeFi target with web frontend
3. Bugcrowd — eToro or Fireblocks as backup

### Long-term:
1. HackerOne private invites (build rep first)
2. Standalone VDPs (Google, Meta, Adobe) if opportunity arises

## Directory Structure
```
~/PenTest/Hunting/
├── Bugcrowd/       (Chime, Okta)
├── Hackerone/      (Grab)
├── Hackenproof/    (Hacken)
├── Immunefi/       (StakeWise, Beefy)
├── YesWeHack/      (GoPay, Gojek, Dojo, CoinDCX)
├── Google/         (standalone VDP)
├── Meta/           (standalone VDP)
└── Adobe/          (standalone VDP)
```
