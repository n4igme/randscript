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
| Target returns identical responses regardless of input | WAF normalizing all requests | Abandon fuzzing |
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
