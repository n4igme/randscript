# Stuck Playbook — When Standard Checks Find Nothing

Load this when you're at 40-50% time budget with zero findings.
Don't abandon yet — try these non-obvious techniques first.

---

## Tier 1: Quick Wins You Probably Missed (5 min each)

1. **Content-Type confusion**
   - Send JSON body with `Content-Type: application/xml`
   - Send URL-encoded body to JSON endpoint
   - Send multipart/form-data to API endpoints
   - Some parsers accept both and behave differently

2. **HTTP method override**
   ```bash
   # Try method override headers on restricted endpoints
   curl -X POST -H "X-HTTP-Method-Override: PUT" "$URL"
   curl -X POST -H "X-Method-Override: DELETE" "$URL"
   curl -X GET -H "X-HTTP-Method: POST" "$URL"
   ```

3. **Path normalization tricks**
   ```bash
   # Bypass path-based auth
   /api/admin/../admin/users
   /api/admin/./users
   /api/ADMIN/users       # case sensitivity
   /api/admin%2fusers     # URL encoding
   /api/admin/users/..;/admin/settings  # Tomcat/Spring
   //api/admin/users      # double slash
   ```

4. **Verb tampering**
   - 403 on GET? Try HEAD, OPTIONS, PATCH, TRACE
   - Some WAFs only check GET/POST
   - TRACE may reflect internal headers

5. **Accept header manipulation**
   ```bash
   curl -H "Accept: application/xml" "$URL"     # Different serializer?
   curl -H "Accept: text/csv" "$URL"            # Export functionality?
   curl -H "Accept: application/pdf" "$URL"     # Report generation?
   ```

---

## Tier 2: Protocol-Level (10 min each)

6. **HTTP Request Smuggling (CL.TE / TE.CL)**
   - Only if target has reverse proxy + backend (look for Server headers)
   - Test with `Transfer-Encoding: chunked` + `Content-Length` conflict

7. **HTTP/2 specific**
   - Header name with uppercase (H2 allows, some backends choke)
   - Pseudo-header injection (`:authority` override)
   - CRLF in H2 header value → response splitting on downgrade

8. **WebSocket upgrade on non-WS endpoints**
   ```bash
   curl -H "Upgrade: websocket" -H "Connection: Upgrade" \
        -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
        -H "Sec-WebSocket-Version: 13" "$URL"
   ```
   Some endpoints expose different behavior on upgrade attempt.

9. **Cache poisoning probes**
   ```bash
   # Unkeyed headers that affect response
   curl -H "X-Forwarded-Scheme: http" "$URL"   # Force redirect?
   curl -H "X-Forwarded-Port: 1234" "$URL"     # Reflected in links?
   curl -H "X-Original-URL: /admin" "$URL"     # Path override?
   ```

---

## Tier 3: Logic & Timing (15 min each)

10. **Race condition on state changes**
    - Parallel requests on anything that changes state once
    - Use: `seq 1 20 | xargs -P20 -I{} curl ...`

11. **Timing-based enumeration**
    - Valid vs invalid username → measure response time difference
    - Valid vs invalid token → timing oracle

12. **Second-order injection**
    - Inject payload in field A, trigger from field B
    - Profile name → PDF export (XSS in PDF)
    - Username → admin panel view (stored XSS)
    - Address → shipping label API (SSTI)

13. **Integer handling**
    - Negative amounts in financial operations
    - Integer overflow: 2147483647 + 1
    - Float precision: 0.1 + 0.2 != 0.3 in financial calcs

---

## Decision Point

After Tier 1-3 (roughly 60-90 min additional):
- Found something? → Exploit and report
- Still nothing? → Target is genuinely hardened. Write "hardened" report.

Do NOT keep testing past 75% time budget with zero findings.
