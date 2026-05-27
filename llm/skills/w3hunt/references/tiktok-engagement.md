# TikTok Engagement — HackerOne (2026-05-26)

## Target
- Program: TikTok (HackerOne)
- Directory: ~/PenTest/Hunting/Hackerone/TikTok/
- Session user: toxicnolep (uid 7157352216311284737, UK +44)

## Findings

### TIKTOK-001: Missing Authentication on /passport/email/bind/ (HIGH)
**Title:** Missing Authentication on `/passport/email/bind/` Leads to Potential Account Takeover
**Asset:** www.tiktok.com
**Weakness:** CWE-306: Missing Authentication for Critical Function
**Severity:** High (CVSS 8.1 — AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)
**Status:** Submitted 2026-05-27. WalletOnTelegram finding (separate H1 program) marked as duplicate — suspected triager theft. ALL H1 activity postponed indefinitely due to platform distrust (duplicate abuse pattern). Awaiting TIKTOK-001 verdict before deciding whether to return to H1.

**Chain (3 bugs combined):**
1. `/passport/email/bind/` processes requests without authentication (error_code:1703 = code validation, not session check)
2. No rate limiting on code attempts (50+ requests confirmed, 2.2+ req/s)
3. `/passport/email/send_code/` sends verification codes to arbitrary emails without auth

**Key insight:** error_code 1703 ("Verification code is expired or incorrect") proves the server skipped auth and went straight to code validation. Compare: `/passport/email/verify/` returns error_code 1 ("Session expired") — correct behavior.

**Attack chain:**
1. POST /passport/email/send_code/ (victim's email) → code sent
2. POST /passport/email/bind/ (brute-force 000000-999999) → no auth, no rate limit
3. On correct code → email bound → password reset → ATO

**Feasibility:** 1M combinations, 100 threads ≈ 1.2 hours

**Scope:** Systemic across 8 domains sharing TikTok Passport service:
- www.tiktok.com, ads.tiktok.com, business.tiktok.com, shop.tiktok.com
- live-backstage.tiktok.com, effecthouse.tiktok.com
- seller-id.tokopedia.com, www.soundonw.us

**What's NOT confirmed:** Whether successful code actually completes bind without session cookie. Hence AC:H (not AC:L) and High (not Critical).

**Reporting decisions:**
- Submitted as ONE report on www.tiktok.com (highest-value asset), all 8 domains listed in body
- CWE-306 as primary weakness (root cause), CWE-307 mentioned in body
- HackerOne format: Summary, Steps To Reproduce, Supporting Material/References

**Files:**
- `ptest-output/findings/FINAL-hackerone-passport-bind.md` — report
- `ptest-output/findings/poc-passport-bind.py` — PoC script

### Other findings (not submitted)
- **Logout CSRF** — confirmed but Low severity, not worth submitting
- **Seller IDOR** — needs seller account, seller-us geo-blocked, try seller-uk.tiktok.com
- **OAuth redirect_uri** — tested, NOT vulnerable (server rejects at auth step)

## Technical Notes

### TikTok Passport error codes
- error_code 1 = "Session expired. Log in to continue." (auth enforced)
- error_code 1703 = "Verification code is expired or incorrect." (auth NOT enforced, processing request)

### MSSDK/Argus
- Blocks curl-based API testing on most authenticated endpoints
- Workaround: use Burp browser for authenticated testing
- Unauthenticated passport endpoints work fine with curl

### Reporting strategy for shared infrastructure
- TikTok Passport is shared across all properties
- ONE report targeting highest-value asset (www.tiktok.com)
- List all affected domains in report body as table
- Exception: if Tokopedia has separate asset owner, split into max 2

## Lessons
- Subtle auth bypass: server saying "wrong code" instead of "who are you?" is the vulnerability
- Always compare sibling endpoints (verify/ vs bind/) to spot inconsistencies
- For chained bugs on H1: pick root cause CWE for weakness field, mention others in body
- Shared infra = one report, not N reports per domain
