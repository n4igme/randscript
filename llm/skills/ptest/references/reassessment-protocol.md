# Re-assessment Protocol (Reopening Completed Engagements)

## When to Use
When the user says "re-open all phases" or "option 2: resume for additional testing" on a PASSED engagement. This is NOT a new engagement — it's a systematic sweep to find what the original run missed.

## Critical Lesson (BlueSpider, June 2026)
Re-assessment phases 1-6 were marked PASSED rapidly by carrying over old data and skipping mandatory techniques. The user caught this by asking "have we done all activities in phase X properly?" for each phase. Every phase had 3-7 missed techniques.

## Common Gaps in Re-assessment (ranked by frequency)

### Phase 1 Gaps
- Wayback Machine: marked "carried from v1" without re-querying
- GitHub/Google dorks: marked SKIPPED "internal engagement" — ptest rules say ALWAYS execute web_search
- Shodan InternetDB: only checked original IPs, not the 10+ new IPs discovered
- JS bundle analysis: only checked 1 host when 5+ new SPAs found

### Phase 2 Gaps
- Pattern permutation brute-force: NEVER done (most commonly skipped)
- DNS-level brute-force: NEVER done
- Reverse DNS: NEVER done
- VHost enumeration: NEVER done
- HTTP Methods: NEVER done
- Security Headers audit: not systematic on new hosts
- Zone transfer: NEVER attempted

### Phase 3 Gaps
- Directory brute-force (MANDATORY): NEVER run
- JS Bundle Diff between environments: NEVER compared dev vs prod
- Param brute-force: only tested known values, not systematic
- Bulk actuator scan: NEVER done on new hosts
- WebSocket/GraphQL discovery: NEVER checked
- ALL-hosts coverage: only deeply enumerated 2/8 new hosts

### Phase 4 Gaps
- Entry point map: never formally documented
- Attack surface scoring matrix: missing
- Cross-environment correlation: never mapped
- Dismissed assets: not formally verified

### Phase 5 Gaps
- Nuclei scan (MANDATORY): never run
- CVE mapping: informal, never documented
- SSL/TLS assessment: never done
- Formal attack trees: missing for new targets
- Prioritized vector list: not created

### Phase 6 Gaps
- Credential inventory (MANDATORY): never created
- Injection testing: never done on new endpoints
- Write method testing on unauth endpoints: not tested
- Credential chaining cross-environment: not attempted
- Per-host coverage table: missing

## Mandatory Re-assessment Procedure

When reopening phases, for EACH phase:

1. **Load the phase reference file** — don't rely on memory of what's required
2. **Read the existing checklist** — understand what was done before
3. **Diff against reference checklist** — identify missing techniques
4. **Execute ALL missing techniques** — don't skip because "it's just a re-assessment"
5. **Update the checklist with evidence** — every row needs a file path or N/A

## Indonesian ISP Pitfalls (BlueSpider-specific, generalizable)

### Transparent Proxy/NAT (all ports "open")
Indonesian hosting providers (iForte, Quantum.net.id) run transparent proxies that accept TCP SYN on ALL ports but send no data. nmap shows 100% ports open with no banners.

**Detection:** If top-100 scan shows ALL ports open with no service versions → transparent proxy.
**Verification:** `nc -w 3 <ip> 3306` → no banner = fake. Real MySQL sends greeting.
**Workaround:** Use Shodan InternetDB (`curl -s https://internetdb.shodan.io/<ip>`) for real port data. Only HTTP probing is reliable for service discovery.

### Nuclei Timeout
Targets behind these ISPs respond slowly (2-3s per request). nuclei with default threads/rate will timeout.
**Workaround:** Use `-rate-limit 3 -c 2 -timeout 5 -no-interactsh`. If still times out, document gap and do manual targeted checks instead.

## VHost Enumeration on Shared Hosting
When a single IP hosts 12+ vhosts (common with Indonesian shared hosting), the server often has a catch-all that reflects the Host header into the login form. All responses will be ~same size with tiny variations (host name length). This is NOT hidden vhosts — it's a catch-all. Verify by checking if response size variance equals hostname length variance.
