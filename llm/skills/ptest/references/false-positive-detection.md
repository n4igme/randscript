# False Positive Detection Patterns

Common false positives encountered during black-box penetration testing, and how to distinguish them from real findings.

## 1. SPA Catch-All (200 for any path)

**Pattern:** Single Page Applications serve the same `index.html` for all routes, returning 200 regardless of path.

**Detection:**
```bash
# Compare byte counts across 3+ paths
size1=$(curl -s "${TARGET}/app/" | wc -c)
size2=$(curl -s "${TARGET}/app/doesnotexist123" | wc -c)
size3=$(curl -s "${TARGET}/app/admin/users/delete" | wc -c)

# If all identical → SPA catch-all
if [ "$size1" = "$size2" ] && [ "$size2" = "$size3" ]; then
  echo "SPA catch-all detected (${size1} bytes for all paths)"
fi
```

**Key indicators:**
- Same byte count for any path under a prefix
- Content-Type: text/html (not application/json)
- Response contains React/Vue/Angular bootstrap code
- No server-side rendering of the requested path

**Affected frameworks:** Keycloak Account Console, React Router, Vue Router, Angular, Next.js (client-only routes)

**Rule:** Never report "admin endpoint accessible" based solely on HTTP 200 from a SPA. Verify the response contains actual data (JSON with records, not HTML shell).

---

## 2. CORS Crash Masking Real Endpoints (all 500s)

**Pattern:** A misconfigured CORS filter crashes before request routing, making ALL paths under a prefix return 500 with the same error.

**Detection:**
```bash
# Test a known-fake path
real=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/api/v1/known-endpoint")
fake=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/api/v1/thispathdoesnotexist12345")

# If both return 500 with same error message → CORS crash
if [ "$real" = "500" ] && [ "$fake" = "500" ]; then
  msg_real=$(curl -s "${TARGET}/api/v1/known-endpoint" | python3 -c "import sys,json; print(json.load(sys.stdin).get('message','')[:50])")
  msg_fake=$(curl -s "${TARGET}/api/v1/thispathdoesnotexist12345" | python3 -c "import sys,json; print(json.load(sys.stdin).get('message','')[:50])")
  if [ "$msg_real" = "$msg_fake" ]; then
    echo "CORS crash detected — cannot enumerate endpoints via status codes"
  fi
fi
```

**Common error:** `"Duplicate key Vary (attempted merging values Origin and Origin)"`

**Implications:**
- Cannot use response codes to discover real endpoints
- All POST/PUT requests fail (write operations broken)
- SSRF via POST body is impossible
- The CORS bug itself is a finding (accidental DoS on write operations)

**Rule:** When all paths under a prefix return 500 with identical error, do NOT report each path as a "discovered endpoint." Report the CORS misconfiguration as a single finding.

---

## 3. 302 to Login ≠ Access

**Pattern:** Protected endpoints return 302 redirect to login page. This confirms the endpoint EXISTS but does NOT mean it's accessible.

**Detection:**
```bash
resp=$(curl -s -D- "${TARGET}/admin/dashboard" --max-time 10)
if echo "$resp" | grep -q "302"; then
  location=$(echo "$resp" | grep -i "location:" | head -1)
  if echo "$location" | grep -qi "login\|auth\|signin\|sso"; then
    echo "Redirect to login — endpoint exists but requires auth (NOT a finding)"
  fi
fi
```

**Rule:** 302 → login is informational at best. Only report if:
- The redirect itself leaks information (internal hostnames, parameters)
- The login page has vulnerabilities (default creds, XSS)
- The endpoint shouldn't exist at all (e.g., admin panel on public-facing server)

---

## 4. WAF/CDN Generic Error Pages

**Pattern:** Cloudflare, AWS WAF, or GCP Cloud Armor return their own error pages that look like application responses.

**Detection:**
| Response | Source |
|----------|--------|
| `cf-ray` header present | Cloudflare |
| `server: cloudflare` | Cloudflare |
| HTML with "Attention Required" | Cloudflare challenge |
| `x-amzn-requestid` header | AWS |
| `via: 1.1 google` | GCP load balancer |
| Generic 403 with no app-specific content | WAF block |

**Rule:** Distinguish between "WAF blocked my request" (not a finding about the app) vs "application returned 403" (the app's own access control). Check response headers to identify the source.

---

## 5. Actuator Exists but Blocked (403 ≠ exploitable)

**Pattern:** Spring Boot Actuator endpoints return 403, confirming they exist but are access-controlled.

**Detection:**
```bash
# 403 = exists but blocked, 404 = doesn't exist
for endpoint in env health beans mappings; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/actuator/${endpoint}")
  case $code in
    404) echo "${endpoint}: not exposed" ;;
    403) echo "${endpoint}: exists, blocked (informational)" ;;
    401) echo "${endpoint}: exists, requires auth (informational)" ;;
    200) echo "${endpoint}: ACCESSIBLE (finding!)" ;;
  esac
done
```

**Rule:** Report actuator 403 as informational only ("actuator endpoints exist but are access-controlled"). It becomes a finding only if:
- You can bypass the 403 (path traversal, header injection)
- The endpoint returns actual data (200 with JSON content)
- Combined with another finding that could lead to bypass

---

## 6. DNS Resolution ≠ Live Service

**Pattern:** A subdomain resolves in DNS but the service is not actually running or accessible.

**Detection:**
```bash
# DNS resolves but no HTTP response
ip=$(dig +short subdomain.target.com)
if [ -n "$ip" ]; then
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://subdomain.target.com" --max-time 5)
  if [ "$code" = "000" ]; then
    echo "DNS resolves to ${ip} but no HTTP service (stale DNS record)"
  fi
fi
```

**Rule:** Never report "subdomain discovered" as a finding unless the service is actually running and has a security issue. Stale DNS records are informational at best.

---

## 7. Internal IP in DNS ≠ Reachable

**Pattern:** DNS returns a private/internal IP (172.x, 10.x, 192.168.x) — this leaks network info but the host is NOT reachable from outside.

**Rule:** Report as "information disclosure (internal IP leaked via DNS)" — Low severity. Do NOT claim the internal service is "accessible" or "exposed."

---

## 8. Version Number ≠ Vulnerable

**Pattern:** A service banner reveals a version number that has known CVEs, but the specific vulnerable feature may be disabled or patched.

**Rule:** Version-based findings should be marked as "Unverified" until you can demonstrate the specific vulnerable behavior. "Running Apache 2.4.49" is informational; "path traversal via CVE-2021-41773 returns /etc/passwd" is a confirmed finding.

---

## Quick Decision Matrix

| Signal | Real Finding? | Action |
|--------|--------------|--------|
| 200 + JSON with real data | ✅ Yes | Document with evidence |
| 200 + same HTML for all paths | ❌ No | SPA catch-all |
| 500 + same error for all paths | ❌ No (but CORS bug is) | Report CORS misconfiguration only |
| 302 → login page | ❌ No | Informational |
| 403 on sensitive endpoint | ⚠️ Maybe | Try bypass techniques, report as info if blocked |
| DNS resolves, no HTTP | ❌ No | Skip |
| Internal IP in DNS | ⚠️ Low | Report as info disclosure |
| Version with known CVE | ⚠️ Unverified | Must demonstrate exploitability |
| Header leaks internal info | ⚠️ Low-Medium | Report with context |
