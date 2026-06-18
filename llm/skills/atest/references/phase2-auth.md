## Phase 2: Authentication & Authorization

### Gate: auth bypass tested, BOLA/IDOR tested on all object-referencing endpoints, privilege escalation attempted

**First: run proven patterns (10 min) — see `references/proven-patterns.md`**
7 high-hit-rate checks before systematic testing. If any hits → validate and document immediately.

**If CDN-fronted and automated scanning fails in Phase 1:** see ptest `vuln-assessment.md` Section 0 (CDN/WAF-Aware Pre-Check) for manual alternatives.

**Techniques:**

1. **Authentication Bypass:**
   ```bash
   # Remove auth header entirely
   curl -sk "$ENDPOINT"
   # Empty Bearer token
   curl -sk -H "Authorization: Bearer " "$ENDPOINT"
   # JWT none algorithm
   # JWT expired token reuse
   # JWT signature stripping
   ```

2. **JWT Attacks (if JWT):**
   - Algorithm confusion (RS256 → HS256 with public key as secret)
   - `alg: none` bypass
   - Key ID (`kid`) injection (path traversal, SQLi)
   - `jku`/`jwk` header injection
   - Weak secret brute-force: `hashcat -m 16500 jwt.txt wordlist.txt`
   - Expired token acceptance
   - Cross-tenant token reuse

3. **BOLA/IDOR:**
   ```bash
   # For every endpoint with an object reference:
   # Test horizontal access (user A's token → user B's resource)
   curl -sk -H "Authorization: Bearer $TOKEN_A" "$BASE_URL/api/users/$USER_B_ID"
   # Test with different ID formats: numeric, UUID, encoded
   # Test collection endpoints: /api/users (returns all?)
   ```

4. **Privilege Escalation:**
   - Vertical: regular user → admin endpoints
   - Role parameter injection: `{"role": "admin"}` in registration/update
   - Function-level: access admin functions with user token
   - Tenant isolation: cross-tenant data access

5. **OAuth Flows (if OAuth):**
   - `redirect_uri` manipulation
   - Authorization code reuse
   - PKCE bypass (downgrade to no PKCE)
   - Token exchange abuse
   - Client credential theft

6. **Response Diffing (systematic BOLA/data exposure detection):**
   For every endpoint with object references, compare responses across roles:
   ```bash
   # Capture responses for same resource with different auth levels
   curl -sk -H "Authorization: Bearer $ADMIN_TOKEN" "$BASE_URL/api/users/123" > /tmp/resp_admin.json
   curl -sk -H "Authorization: Bearer $USER_TOKEN" "$BASE_URL/api/users/123" > /tmp/resp_user.json
   curl -sk "$BASE_URL/api/users/123" > /tmp/resp_unauth.json

   # Diff field count (data exposure = admin sees more fields)
   echo "Admin fields: $(jq 'keys | length' /tmp/resp_admin.json)"
   echo "User fields:  $(jq 'keys | length' /tmp/resp_user.json)"
   echo "Unauth fields: $(jq 'keys | length' /tmp/resp_unauth.json)"

   # Diff content (BOLA = user A can read user B's data)
   curl -sk -H "Authorization: Bearer $USER_A_TOKEN" "$BASE_URL/api/users/$USER_B_ID" > /tmp/resp_cross.json
   [ "$(jq -r '.id' /tmp/resp_cross.json)" = "$USER_B_ID" ] && echo "BOLA CONFIRMED"
   ```
   **Pattern:** Run this on every object-referencing endpoint. Fastest way to find BOLA at scale.

7. **Rate Limiting:**
   ```bash
   # Test rate limit enforcement
   for i in $(seq 1 100); do
     curl -sk -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $TOKEN" "$ENDPOINT"
   done | sort | uniq -c
   # Bypass attempts: IP rotation headers, different auth tokens, path case variation
   ```

8. **OTP/Verification Code Oracle:**
   When endpoints validate OTP/verification codes, test authenticated vs unauthenticated contexts for differential responses. A different error code for correct vs wrong code = oracle = brute-force viable. Always compare with sibling endpoints (e.g. `/bind/` has no rate limit vs `/verify/` does).
   **Reference:** `references/otp-oracle-bruteforce.md`

**Reference:** `references/api-auth-bypass.md`

**Cross-reference:** ptest `references/jwt-attack-techniques.md`, `references/oauth-sso-attack-chains.md`

**Cross-skill triggers from atest:**
- SSRF found → invoke `ctest` Phase 3 (cloud metadata, internal services)
- Cloud storage URLs in responses → invoke `ctest` Phase 3 (S3/GCS/Blob misconfig)
- API serves mobile app → invoke `mtest` if app not yet tested
- Smart contract interaction via API → invoke `w3hunt`
- Source code leaked via error/debug → invoke `scode`
- Geo-blocked endpoints → see ptest `references/geo-restriction-bypass.md`

**OpenAPI/Swagger discovery (MANDATORY in Phase 1):**
- Check standard paths: `/docs`, `/swagger`, `/openapi.json`, `/api-docs`, `/swagger.json`
- **JS bundle extraction:** Modern SPAs often embed the full OpenAPI spec in JS bundles. Search for `openapi` in JS filenames: `curl -s https://target/ | grep -oE '/static/js/openapi[^"]+\.js'` — then extract all `url:"..."` patterns. This revealed 494 endpoints on Wallet on Telegram in seconds.
- Telegram Mini Apps: see ptest `references/telegram-webapp-auth.md` for auth patterns

**CORS Testing (MANDATORY):**
```bash
# Origin reflection test
curl -sk -H "Origin: https://evil.com" -I "$BASE_URL/api/users" | grep -i "access-control"
# Null origin bypass
curl -sk -H "Origin: null" -I "$BASE_URL/api/users" | grep -i "access-control"
# Subdomain wildcard
curl -sk -H "Origin: https://attacker.target.com" -I "$BASE_URL/api/users" | grep -i "access-control"
```
If `Access-Control-Allow-Origin` reflects attacker origin + `Access-Control-Allow-Credentials: true` → High (credential theft via CORS). If reflects but no credentials → Medium (data leakage only).

**Also check `Access-Control-Expose-Headers`:** This header controls which response headers are readable by cross-origin JavaScript. If it leaks auth token header names (e.g., `CST, X-SECURITY-TOKEN`, `Authorization`, `Set-Cookie`) on ANY endpoint (including public ones), it enables a separate finding — cross-origin session token exposure — even when `Access-Control-Allow-Credentials` is not set. The exposed headers become readable by any `fetch()` call from an allowed origin, and if `Allow-Origin: *` is set, from any origin at all. This is a Medium severity finding on its own (information disclosure of auth header names + readable by any site).
