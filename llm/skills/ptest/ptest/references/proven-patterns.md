# Proven Pentest Patterns

High-hit-rate findings from Bank Jago, bug bounties, and CTFs. Check these first in Phase 5/6.

## Pattern 1: Spring Boot Actuator Exposure

**Check:** Probe /actuator, /actuator/env, /actuator/heapdump, /actuator/configprops
**Impact:** High-Critical — credential leak, heap dump with secrets
**Phase:** 3 (enumeration) or 5 (vuln assessment)

## Pattern 2: CORS Misconfiguration on Auth Endpoints

**Check:** `curl -H "Origin: https://evil.com" -I https://target/api/auth/...`
**Trigger:** Origin reflected + Access-Control-Allow-Credentials: true
**Impact:** High — session/token theft via cross-origin request
**Phase:** 5

## Pattern 3: OAuth redirect_uri Bypass

**Check:** Append path, use subdomain, try open redirect chain
**Variants:** `/callback/../attacker`, `//evil.com`, `@evil.com`, `.evil.com`
**Impact:** High-Critical — authorization code theft
**Phase:** 6

## Pattern 4: IDOR on First Endpoint with User ID

**Check:** Find any endpoint with user/account ID → swap with another user's ID
**Pattern:** `/api/users/{id}`, `/api/accounts/{id}/transactions`
**Impact:** High — data access, account takeover chain
**Phase:** 6

## Pattern 5: Subdomain Takeover via Dangling CNAME

**Check:** crt.sh + DNS resolution → NXDOMAIN on CNAME target = takeover candidate
**Platforms:** AWS S3, Azure, Heroku, GitHub Pages, Shopify
**Impact:** High — phishing on legitimate subdomain, cookie theft if parent domain
**Phase:** 1 (discovery) → 6 (exploitation)

## Pattern 6: Source Map / JS Bundle Secret Leak

**Check:** `curl https://target/static/js/main.*.js.map` → grep for API keys, internal URLs
**Impact:** Medium-High — depends on what's leaked
**Phase:** 3

## Pattern 7: GraphQL Introspection + Unauth Mutations

**Check:** `{"query":"{ __schema { mutationType { fields { name } } } }"}`
**Impact:** High-Critical if write mutations lack auth
**Phase:** 3 → 6

## Pattern 8: Path Traversal on Actuator Behind Reverse Proxy

**Check:** `/..;/actuator/env`, `/%2e%2e/actuator/heapdump`, `/actuator;.js/env`
**Impact:** High — bypasses path-based access control
**Phase:** 6

## Pattern 9: Insecure Direct Object Reference via Predictable IDs

**Check:** Sequential numeric IDs, UUIDs leaked in responses, enumerable ranges
**Impact:** High — mass data access
**Phase:** 6

## Pattern 10: n8n Workflow Automation RCE

**Check:** `/rest/settings` (unauthenticated config), webhook enumeration, CVE-2026-42231
**Impact:** Critical — remote code execution
**Phase:** 5 → 6

---

## When to Add New Patterns

Add after engagement when:
- Pattern produced a confirmed High+ finding
- Applies to multiple targets (not target-specific)
- Can be checked in <10 minutes
