## Phase Completion Criteria (Large Scope)

When scope has 100+ subdomains, define "phase complete" explicitly:

**Phase 1 (Recon) is complete when:**
- ALL subdomains resolved and accessibility-checked (not just a sample)
- ALL accessible targets have: tech stack identified, JS bundles analyzed, security headers checked, robots.txt/.well-known checked
- Google dorking, Wayback Machine, GitHub code search done for the domain
- Pattern-based subdomain brute-force done (e.g., if `e-doc` exists, try `e-pmo`, `e-line`, `e-*`)
- Recon summary written with prioritized Phase 2 targets

**Phase 2 (Enumeration) is complete when:**
- ALL accessible non-static targets have: path fuzzing, login form identification, credential testing
- ALL API endpoints discovered from JS bundles tested for auth status
- Service discovery exhaustive on API gateways (try 50+ common prefixes)
- CORS, verb tampering, header injection tested on all non-CDN targets
- Credential wordlist built and tested against all login endpoints

**Phase 3 (Vuln Scanning) is complete when:**
- Nuclei run against all accessible targets (critical+high+medium)
- Manual CVE checks for identified tech (Pimcore, Keycloak, Spring Boot versions)
- JWT attacks, SSRF, path traversal, CRLF tested on relevant endpoints
- Actuator/debug endpoint bypass attempts exhausted

---

# ═══════════════════════════════════════════════════════════════
# SETUP — Tool preparation, engagement initialization, resumption
# ═══════════════════════════════════════════════════════════════


---

## Scope Viability Assessment (Phase 1 Exit)

At Phase 1 exit, classify the engagement's expected yield:

| Yield | Signals | Recommendation |
|-------|---------|----------------|
| **HIGH** | Real application in scope, multiple APIs/services, auth flows, user-generated content, complex business logic | Full 8-phase engagement, allocate maximum Phase 6 time |
| **MEDIUM** | Mix of marketing + app surface, some APIs behind auth, limited input points | Standard engagement, focus Phase 6 on authenticated surface |
| **LOW** | Marketing-only site (WP/Marketo), real app on different domain, all REST locked behind auth, no registration, static content | Flag to user: "Expected yield is low. Real app appears to be on [other domain]. Recommend: (a) fast-track Phases 3-5, (b) pivot to mobile app analysis for API discovery, or (c) confirm with user before investing full effort." |

**LINE WORKS lesson (June 2026):** Phase 1 revealed the real product lives on worksmobile.com (not in scope). line-works.com is a marketing WordPress site. This should have been flagged at Phase 1 exit — instead, full effort was spent on a hardened marketing site yielding only 3 low-medium findings.

**Rules:**
- LOW yield does NOT mean skip phases — it means inform the user and let them decide
- If user says "continue anyway" — execute all phases normally
- Document the assessment in `scope.md` under "Viability Assessment"
