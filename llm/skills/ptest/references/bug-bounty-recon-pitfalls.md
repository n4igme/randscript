# Bug Bounty Recon Pitfalls & Tricks

## Geo-Blocking Detection (MUST CHECK BEFORE COMMITTING TO TARGET)

US fintech programs (Chime, etc.) geo-block ALL endpoints from non-US IPs at Cloudflare level. This includes QA/staging environments.

**Detection:**
```bash
curl -sk -I https://target.com | grep -i 'server\|cf-ray'
# If: server: cloudflare + cf-ray: xxx-SIN (or SGP/HKG) + HTTP 403 + 16-byte body
# → Target is geo-blocked from your location. Skip it.
```

**Lesson (Chime, 2026-05-25):** All 21 probed endpoints returned 403/16 bytes from Indonesia. Even `member-qa.chime.com` (their QA env for non-US researchers) was blocked. Wasted 30 min on subdomain enum before discovering this. Always probe 2-3 endpoints FIRST.

## macOS Tool Gotchas

- **`httpx` on macOS (Homebrew) is Python httpx CLI** — NOT ProjectDiscovery's httpx. It has different flags (`--json`, `--no-verify`, `--verbose` only). Use `curl` for HTTP probing or install PD httpx via `go install github.com/projectdiscovery/httpx/cmd/httpx@latest`.
- **`grep -P` (PCRE) doesn't work on macOS** — use `grep -E` (extended regex) instead.
- **`subfinder` on large domains (grab.com = 13K+ subs) can take 60-120s** — set appropriate timeouts.

## HackerOne GraphQL API (No Auth Required)

Query any program's scope without logging in:

```bash
curl -sk "https://hackerone.com/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"query { team(handle: \"TARGET\") { name, offers_bounties, structured_scopes(first: 50, archived: false) { edges { node { asset_identifier, asset_type, eligible_for_bounty, max_severity } } } } }"}'
```

**Fields returned per scope item:**
- `asset_identifier` — domain, app ID, or wildcard
- `asset_type` — WILDCARD, URL, GOOGLE_PLAY_APP_ID, APPLE_STORE_APP_ID, OTHER
- `eligible_for_bounty` — true/false
- `max_severity` — critical/high/medium/low/none

**Use case:** Quickly assess a program's attack surface before signing up. Grab had 34 scope items including 9 wildcards — visible without any account.

## Bugcrowd Program Listing

- Table view (`tab "Table"`) shows bounty ranges inline
- Filter by "Bug Bounty" tab (not VDP or Pen Tests)
- Programs with "Application Required" need approval before testing
- "2FA Required" programs need Bugcrowd 2FA enabled

## Subdomain Enumeration Strategy for Large Scopes

When a program has 5+ wildcard domains:

```bash
# Run subfinder on each domain, save separately
for d in grab.com grabpay.com ovo.id ovofinansial.com; do
  subfinder -d $d -silent 2>/dev/null | sort -u > subs-${d//./_}.txt
done

# Merge and dedup
cat subs-*.txt | sort -u > all-subs-merged.txt

# Remove OOS
grep -v 'qms.grab.com' all-subs-merged.txt > in-scope-subs.txt

# Find high-value targets
grep -iE '(api|auth|admin|internal|gateway|graphql|pay|transfer|staging|dev|qa)' in-scope-subs.txt
```

**Priority order for probing:**
1. Auth/login endpoints (staging > prod)
2. API gateways
3. Internal tools (jira, wiki, gitlab, grafana)
4. Dev/staging environments
5. Payment/financial endpoints

## Probe Without httpx (macOS workaround)

```bash
# Batch probe with curl
while read url; do
  status=$(curl -sk -o /dev/null -w '%{http_code} %{size_download} %{redirect_url}' \
    --connect-timeout 5 --max-time 10 "https://$url" 2>/dev/null)
  echo "$url → $status"
done < targets.txt | grep -v '→ 000'
```

## Response Size Fingerprinting

| Size | Likely meaning |
|------|---------------|
| 0 bytes | Connection refused or timeout |
| 16 bytes | Cloudflare geo-block/WAF block |
| 919 bytes | Cloudflare generic 403 page |
| 1741 bytes | Application-level 403 (IP restriction, not geo-block) |
| 4000+ bytes | Real application response |

## SPA False Positive Detection (CRITICAL for Modern Targets)

Modern SPAs (React/Vue/Angular/Goofy/Garfish) return HTTP 200 for ALL paths via client-side routing. This causes massive false positives when scanning for `.git/HEAD`, `/actuator/*`, `/swagger`, `/admin`, etc.

**Detection method:** Compare response SIZE against a baseline non-existent path:

```bash
baseline=$(curl -sk "https://target.com/nonexistent-xyz-baseline" | wc -c)
for path in /actuator /actuator/health /swagger /.git/HEAD /admin /console /debug /metrics; do
  size=$(curl -sk "https://target.com${path}" | wc -c)
  if [ "$size" != "$baseline" ] && [ "$size" -gt 5 ]; then
    echo "[REAL] $path -> $size bytes (vs baseline $baseline)"
  fi
done
```

**Real endpoint indicators (different from SPA shell):**
- Different response size from baseline
- JSON error response (e.g., `{"code":10000}`, `{"message":"error"}`)
- Different Content-Type (application/json vs text/html)
- 403 with 0 bytes (server blocked but endpoint exists)
- "Not Found" in small response (server-side 404, not SPA shell)

**Confirmed SPA patterns (TikTok, 2026-05-26):**
- scm-us.tiktok.com: 89,145 bytes for ANY path (Garfish micro-frontend)
- notes.tiktok.com: 35,588 bytes for ANY path (Goofy Deploy)
- safety-enforcement.tiktok.com: 57,359 bytes (Goofy Deploy)
- seller-us.tiktok.com: returns 404 (162 bytes) for unknown paths — proper server-side routing, NOT SPA catch-all

## MSSDK/Anti-Bot Protected APIs

ByteDance/TikTok platforms use client-side request signing (MSSDK/Argus/webmssdk.js) that blocks API testing via curl. Symptoms:
- Empty responses or `{"status_code":0,"status_msg":"url doesn't match"}`
- Endpoints work in browser but not via curl even with valid cookies
- All `/api/*` paths on www.tiktok.com require signatures

**Endpoints that DON'T need MSSDK (test these first):**
- `/passport/web/*` (auth flows — send_code, account/info, unbind, logout)
- Seller platform APIs (`/api/v1/*` on seller-*.tiktok.com)
- SSO/OAuth endpoints (`/v2/auth/authorize/`, `/passport/sso/login`)

**Workaround:** Test via Burp browser (JS generates signatures automatically), then replay/modify in Repeater.

## OAuth redirect_uri Validation Testing

Many OAuth implementations show the consent page regardless of redirect_uri validity, then validate server-side at the authorization step. This is standard behavior, NOT a vulnerability.

**Correct testing flow:**
1. Request `/authorize?redirect_uri=https://evil.com` → consent page renders? This alone is NOT a finding
2. Complete the flow (click Authorize with valid session)
3. Check final redirect destination:
   - Error "redirect_uri invalid" → properly secured
   - Auth code lands on evil.com → CONFIRMED VULN (Critical)

**TikTok (2026-05-26):** Shows consent page ("Authorize with TikTok") for any redirect_uri including evil.com. But clicking Authorize returns error: "redirect_uri — Something went wrong." Server-side validation works. NOT exploitable.

## Regional Seller Platform Restrictions

TikTok Shop seller centers are region-locked to the account's registration country:
- Account registered in Indonesia → redirected to seller-id.tokopedia.com (Tokopedia merger)
- Account registered in UK (+44) → can access seller-uk.tiktok.com
- US seller center requires US-based account

**Impact on testing:** Need accounts in the correct region to test seller APIs. Cross-region session reuse doesn't work (separate auth domains).

## Vanilla Forums Community Platforms (Dropbox, others)

Vanilla Forums (now Higher Logic) exposes REST API without authentication by default. Many companies use it for community forums.

**Unauthenticated endpoints:**
- `GET /api/v2/users?limit=100&page=N` — full user listing with pagination
- `GET /api/v2/users?roleID=X` — filter by role (enumerate employees)
- `GET /api/v2/config` — platform config (cookie names, site ID, plugins)
- `GET /api/v2/roles` — role listing with IDs
- `GET /api/v2/categories` — category listing
- `GET /api/v2/search?query=TERM` — full-text search
- `GET /api/v2/comments` — comment listing

**Pagination headers reveal total count:**
```
x-app-page-result-count: 10000
x-app-page-last-url: .../users?page=10000&limit=1
```

**Employee identification:** Look for `label` field (e.g., "Dropboxer") or filter by `roleID`. The `dateLastActive` field reveals online presence.

**Severity:** Medium at best — it's a public forum, no emails exposed. Best angle is employee enumeration enabling social engineering. Likely Tier 2-3 bounty.

**Dev instances:** Check for `community-dev.` or `community-staging.` subdomains — often have same issues plus PHP error disclosure.

## Custom CAPTCHA Systems

Some targets use proprietary CAPTCHA (e.g., Dropbox uses `dropboxcaptcha.com`). These block:
- Automated account creation via headless browsers
- Playwright/Puppeteer signup flows

**Detection:** Check for iframes with custom captcha domains in signup forms:
```javascript
document.querySelectorAll('iframe').forEach(f => console.log(f.src))
```

**Workaround:** Manual account creation required. Don't waste time trying to bypass — move on to unauthenticated testing.

## Mature Target Decision Framework

When testing well-funded targets (Dropbox, Google, Microsoft, etc.) with heavy CDN/WAF:

**Stop unauthenticated phase early if after 1 hour you have:**
- All APIs return 401/403 without auth
- No CORS reflection, no open redirects
- S3 buckets exist but locked (403)
- No subdomain takeover candidates
- Nuclei/automated scanners blocked by WAF
- Only Low/Info findings (user enum on community forums, health endpoints)

**Pivot to authenticated testing** — these targets are hardened at the perimeter. The real bugs are in:
- Business logic (IDOR on shared resources, privilege escalation in teams)
- State-changing actions (CSRF on sensitive operations)
- File handling (SSRF via URL import, path traversal in zip extraction)
- API authorization (horizontal/vertical access control)

**Don't waste time on:** broad nuclei scans, directory brute-forcing marketing sites, testing Webflow/WordPress marketing pages that aren't the core product.

## Intigriti Scope Extraction

Unlike HackerOne (GraphQL API), Intigriti requires login to view full scope. The public program page shows:
- Bounty tiers and ranges
- Rules of engagement
- Out-of-scope items
- But NOT the full domain/asset list (hidden behind "Log in or sign up")

**Workaround:** Check the program's "Out of scope" section (visible without login) to infer what IS in scope. Also check for program-specific documentation links in the rules.

## Bug Bounty Platform Bot Detection

Intigriti and HackerOne detect headless browsers on login:
- Error: "Bot-like behavior detected, please try again"
- Sign-in button becomes disabled after failed attempt

**Workaround:** Log in manually in a real browser. Don't attempt platform logins via automation.

## Nuclei on CDN-Heavy Targets

Nuclei hangs indefinitely on targets behind Cloudflare/Akamai CDN. The scanner gets rate-limited or connection-pooled to death.

**Symptoms:** No output, no progress, process runs forever with 0 lines logged.

**Alternatives that work:**
- `ffuf` — works fine for directory brute-forcing behind CDN (~50 req/sec)
- `dalfox` — works for XSS testing (but may find nothing on hardened targets)
- Manual curl with specific payloads — targeted testing over broad scanning

**Rule:** On CDN-fronted targets, prefer targeted tool usage over broad nuclei scans. Use ffuf for discovery, manual testing for exploitation.

## Chromium Cookie Extraction (Burp Pre-Wired Browser)

When Burp MCP isn't working, extract session cookies directly from Burp's Chromium profile:

```python
import subprocess, sqlite3, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Get encryption key from macOS Keychain
result = subprocess.run(['security', 'find-generic-password', '-s', 'Chromium Safe Storage', '-w'], capture_output=True, text=True)
key = hashlib.pbkdf2_hmac('sha1', result.stdout.strip().encode(), b'saltysalt', 1003, dklen=16)

# Read cookies
db = sqlite3.connect("~/.BurpSuite/pre-wired-browser/Default/Cookies")
# v10 prefix = AES-128-CBC, IV = 16 spaces, first block decrypts to garbage
# Real value starts after first non-printable prefix (strip ">S" or similar 2-char garbage)
```

**Pitfall:** First AES block decrypts to garbage (CBC IV issue). Cookie values have a 2-char non-printable prefix — strip it. E.g., `>S841cb56e8bf09521c47313fbc6cf5591` → actual sessionid is `841cb56e8bf09521c47313fbc6cf5591`.
