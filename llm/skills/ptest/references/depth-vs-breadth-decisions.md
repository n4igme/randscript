# Depth vs Breadth Decision Framework

Quick decision criteria for penetration testing: when to dig deeper, when to move on, and how to recognize dead ends early.

## When to STOP Digging (Move to Next Target)

| Signal | Example | Action |
|--------|---------|--------|
| All hosts behind WAF/CDN with IP allowlisting | Partner gateway: 17 hosts all CF IP-allowlisted | Abandon — no direct access possible |
| Auth is federated-only (SAML/OIDC) with no local bypass | Dynatrace SAML-only, no local login | Abandon unless IdP is in scope |
| Service is broken/non-functional | n8n with broken DB | Note finding, move on — limited exploit value |
| Default creds already changed + no known CVEs | Patched admin panel | Move on after 15min |
| Rate limiting + account lockout active | Login brute-force blocked after 5 attempts | Switch to other vectors |
| Target returns identical responses regardless of input AND path | WAF normalizing all requests, confirmed on 3+ distinct path prefixes with gobuster | Abandon fuzzing (but ONLY after directory fuzzing proves no unique paths exist) |
| mTLS or client cert required | API gateway requiring mutual TLS | Abandon unless you have valid cert |

## When to Go DEEPER

| Signal | Example | Action |
|--------|---------|--------|
| Verbose error messages leaking internals | Stack traces, DB names, internal IPs | Fuzz harder, map internal architecture |
| Default/weak credentials found | admin:admin on one service | Check credential reuse across all targets |
| Unpatched software with public exploits | Old Tomcat, known CVE | Exploit immediately, pivot |
| Internal hostnames/IPs disclosed | Via headers, error pages, JS files | Add to scope, resolve and scan |
| API responds differently to auth variations | 403 vs 401 vs 200 on different endpoints | Map full API, test IDOR/authz bypass |
| Debug/dev endpoints exposed | /debug, /actuator, /graphql playground | Enumerate everything available |
| File upload with minimal validation | Accepts unusual extensions | Test for RCE chains |

## Diminishing Returns Indicators

Stop investing time when you observe:

- **3+ failed bypass attempts** on same control (WAF, auth, rate limit)
- **No new information** after 20 minutes of active testing on a target
- **All interesting ports filtered** and no alternative entry points found
- **Scan results identical** to what Shodan/Censys already showed (nothing hidden)
- **Every subdomain resolves to same IP/CDN** — likely wildcard or catch-all

## Dead-End Recognition Patterns

### Pattern: CDN/WAF Wall (Bank Jago: Partner Gateway)
- Discovery: 17 subdomains enumerated
- Reality: All resolve to Cloudflare, origin IP-allowlisted
- Time wasted if ignored: hours of WAF bypass attempts
- **Rule: If >80% of hosts in a subdomain group share same CDN IP, treat group as single target. Test one, skip rest.**

### Pattern: Federated Auth Only (Bank Jago: Dynatrace)
- Discovery: Login page found
- Reality: SAML redirect only, no local auth endpoint
- Time wasted if ignored: hours hunting for auth bypass
- **Rule: If /login immediately redirects to external IdP with no local form, move on in <5 minutes.**

### Pattern: Broken Service (Bank Jago: n8n)
- Discovery: Service accessible
- Reality: DB connection broken, workflows non-functional
- Time wasted if ignored: 30+ min trying to exploit non-working features
- **Rule: If core functionality is broken (DB errors, service unavailable), document and move on. Broken services rarely yield useful access.**

## PITFALL: "Third-Party" Dismissal Without Verification (LINE WORKS, June 2026)

**What happened:** `mkt.line-works.com` and `mkt.tw.line-works.com` were dismissed as "Pardot/Salesforce = third-party, skip." Reality: they 302 redirect to `line-works.com` (the main target), meaning they're controlled by the target org. Had they hosted content, it would be in-scope.

**Rule:** A subdomain pointing to a third-party CNAME (Pardot, Marketo, HubSpot, etc.) still needs a single HTTP request to verify behavior. If it redirects back to an in-scope domain or serves custom content, it's testable. Only dismiss if it serves purely the third-party platform's default content with no target branding/config.

## PITFALL: Gobuster Without Manual Follow-Up (LINE WORKS, June 2026)

**What happened:** `lp.line-works.com` was gobuster'd (file exists in enumeration/) but never manually investigated. The gobuster output was "done" but nobody checked what it found or probed the WP-specific attack surface.

**Rule:** Gobuster is DISCOVERY, not ASSESSMENT. After every gobuster run, the results MUST be triaged:
1. Read the output file
2. Identify unique responses (non-404, non-catch-all)
3. Manually probe each unique path
4. For WordPress hosts: run the full WP checklist (plugins, xmlrpc, REST API, user enum, admin-ajax)

## PITFALL: Catch-All Response ≠ Empty Target (LINE WORKS, June 2026)

**What happened:** `cxtalk-service.line-works.com` returned a generic "Invalid Path" (12 bytes) on root and a catch-all error page (14975 bytes) on random paths. Initial probe concluded "nothing here" and skipped fuzzing. Reality: under the `/jp1/` prefix, the service exposed:
- Full AngularJS app with internal infrastructure URLs (21 alpha/dev endpoints)
- Unauthenticated GraphQL endpoint with introspection (43 types, write operations)
- NELO logging injection (arbitrary log writes to internal Naver systems)
- Chat history API, customer service endpoints, bot APIs

**Root cause:** Checked only the root path and one random path. Never ran directory fuzzing (gobuster/ffuf) against the host.

**Rule: EVERY in-scope subdomain that returns ANY HTTP response (even 400/403/catch-all) MUST receive at least ONE gobuster run with raft-medium-directories.txt BEFORE being dismissed.** Filter out the catch-all response size and look for size/status deviations.

**Mandatory pre-dismissal checks for hosts with catch-all responses:**
1. ✅ Gobuster with `--exclude-length <catch-all-size>` on root path
2. ✅ Test common prefixes: `/api/`, `/v1/`, `/v2/`, `/internal/`, `/admin/`, `/p/`, region codes (`/jp1/`, `/kr1/`, `/sg1/`)
3. ✅ Test with POST method (catch-alls are often GET-only)
4. ✅ Check if different Content-Type headers produce different responses

**Time cost:** 5 minutes per host with gobuster. Skipping this "saved" 5 minutes but missed 3 reportable findings.

## DNS Expansion Stop Criteria

Stop expanding DNS/subdomain enumeration when:

1. **Wildcard detected** — resolve random string first; if it resolves, wildcard is active
2. **New subdomains all resolve to known CDN/parking IPs** — no new origin servers
3. **Diminishing unique IPs** — last 50 subdomains found yielded <3 new unique IPs
4. **Scope boundary hit** — subdomains point to third-party SaaS (not in scope)
5. **Time box exceeded** — 30 min max for passive enum, 15 min for active brute

## Quick Decision Flowchart

```
[New Target Found]
       |
       v
[Can you reach it directly?] --NO--> [Behind CDN/WAF?]
       |                                      |
      YES                              YES: Try origin IP lookup (5 min max)
       |                                      |
       v                               Found origin? --NO--> ABANDON
[Auth required?]                              |
       |                                     YES --> Continue below
      YES
       |
       v
[Local auth available?] --NO (SAML/SSO only)--> ABANDON
       |
      YES
       |
       v
[Default creds / known CVE?] --YES--> GO DEEP
       |
       NO
       |
       v
[Verbose errors / info leak?] --YES--> GO DEEP (map internals)
       |
       NO
       |
       v
[Spent >20 min with no progress?] --YES--> MOVE ON
       |
       NO
       |
       v
[Continue testing, re-evaluate in 15 min]
```

## Time Boxing Rules

| Target Type | Max Initial Assessment | Max Deep Dive |
|-------------|----------------------|---------------|
| Web app with auth | 15 min | 2 hours |
| API endpoint | 10 min | 1 hour |
| Infrastructure service | 10 min | 45 min |
| CDN-fronted target | 5 min (origin hunt) | Abandon if no origin |
| SSO-only service | 5 min | Abandon |

---

*Framework derived from Bank Jago engagement patterns. Update with new dead-end patterns as encountered.*
