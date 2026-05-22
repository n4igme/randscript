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
|| Header leaks internal info | ⚠️ Low-Medium | Report with context |

---

## Statistical Validation Rules

Before logging ANY finding that relies on behavioral differences (timing, response size, status code), apply these validation rules to prevent false positives.

### Rule 1: Body-Diff Rule

**A status code change alone is NOT proof of a bypass or vulnerability.**

You MUST compare response BODIES, not just status codes:

```bash
# WRONG: "I got 200 instead of 403, therefore bypass!"
curl -sk -o /dev/null -w "%{http_code}" "https://target/admin" -H "X-Forwarded-For: 127.0.0.1"
# 200 ← this alone proves nothing

# RIGHT: Compare response bodies
BASELINE=$(curl -sk "https://target/admin" | md5)
TEST=$(curl -sk "https://target/admin" -H "X-Forwarded-For: 127.0.0.1" | md5)
if [ "$BASELINE" != "$TEST" ]; then
  # Different body — investigate further
  diff <(curl -sk "https://target/admin") <(curl -sk "https://target/admin" -H "X-Forwarded-For: 127.0.0.1")
fi
```

**Common false positives caught by this rule:**
- SPA catch-all returns 200 for everything (same React app body)
- WAF returns 200 with block page (not the actual admin page)
- Load balancer returns 200 with maintenance page
- 302 redirect to login (not a bypass, just a redirect)

**Validation requirement:** The response body must contain DIFFERENT content that demonstrates actual access to the protected resource (admin panel HTML, user data, API response with records).

### Rule 2: Statistical-Sample Rule (Timing-Based Claims)

**For ANY timing-based finding (blind SQLi, blind SSRF, race condition), you need statistical evidence.**

Minimum requirements:
- **n ≥ 10 trials** (interleaved: 5 baseline + 5 test, alternating)
- **Non-overlapping confidence intervals** between baseline and test
- **Consistent reproduction** (at least 4/5 test trials show the effect)

```bash
# WRONG: "sleep(5) made it take 5 seconds, therefore SQLi!"
curl -sk -w "%{time_total}" "https://target/api?id=1' AND SLEEP(5)--"
# 5.2s ← single trial proves nothing (could be network latency, server load)

# RIGHT: Statistical validation
echo "=== Baseline (no injection) ==="
for i in $(seq 1 5); do
  curl -sk -o /dev/null -w "%{time_total}\n" "https://target/api?id=1"
  sleep 1
done

echo "=== Test (with injection) ==="
for i in $(seq 1 5); do
  curl -sk -o /dev/null -w "%{time_total}\n" "https://target/api?id=1'+AND+SLEEP(5)--"
  sleep 1
done

# Baseline: 0.15s, 0.18s, 0.14s, 0.16s, 0.15s (mean: 0.156s)
# Test:     5.14s, 5.18s, 5.15s, 5.16s, 5.14s (mean: 5.154s)
# Gap: 4.998s ± 0.02s — non-overlapping → CONFIRMED
```

**Rejection criteria:**
- If ANY baseline trial overlaps with test range → NOT confirmed
- If test results vary by more than 2x the injection delay → likely network noise
- If only 2/5 test trials show the effect → NOT confirmed (intermittent)

### Rule 3: Marker Discipline

**Use unique, random markers for injection testing — never generic words.**

```bash
# WRONG: Testing XSS reflection
curl "https://target/search?q=test"
# Response contains "test" ← proves nothing, "test" appears naturally

# RIGHT: Use a unique marker
MARKER="xss$(openssl rand -hex 4)probe"  # e.g., "xss8a3f1b2cprobe"
curl "https://target/search?q=$MARKER"
# Response contains "xss8a3f1b2cprobe" ← confirms reflection (this string can't appear naturally)
```

**Marker rules:**
- Must be random/unique per test (not reused across targets)
- Must not be a word that could appear naturally in the response
- Must be verifiable in the response body (grep for exact match)
- For blind testing: use Collaborator/interactsh with unique subdomain per test

### Rule 4: Shell-Loop Ban

**If you need more than 5 iterations of a test, use Python (not bash loops).**

Bash loops with curl are:
- Sequential (slow)
- Hard to collect/analyze results
- Prone to timing artifacts from shell overhead
- Difficult to implement proper interleaving

```python
# For statistical validation, use Python with proper timing
import requests
import time
import statistics

baseline_times = []
test_times = []

for i in range(10):  # Interleaved trials
    # Baseline
    start = time.time()
    requests.get("https://target/api?id=1", verify=False)
    baseline_times.append(time.time() - start)
    
    time.sleep(0.5)
    
    # Test
    start = time.time()
    requests.get("https://target/api?id=1'+AND+SLEEP(5)--", verify=False)
    test_times.append(time.time() - start)
    
    time.sleep(0.5)

print(f"Baseline: mean={statistics.mean(baseline_times):.3f}s, stdev={statistics.stdev(baseline_times):.3f}s")
print(f"Test:     mean={statistics.mean(test_times):.3f}s, stdev={statistics.stdev(test_times):.3f}s")
print(f"Gap:      {statistics.mean(test_times) - statistics.mean(baseline_times):.3f}s")

# Confirm non-overlapping
baseline_max = max(baseline_times)
test_min = min(test_times)
if test_min > baseline_max:
    print("CONFIRMED: Non-overlapping ranges")
else:
    print("NOT CONFIRMED: Ranges overlap")
```

### Rule 5: Reproduction Before Reporting

**Every finding must be reproducible at least 3 times before logging.**

One-time observations are NOT findings:
- Network glitch caused a timeout (looks like blind injection)
- Server restart caused a 500 (looks like crash-based detection)
- CDN cache served stale content (looks like access bypass)
- Rate limiter kicked in (looks like different behavior)

**Procedure:**
1. Observe the behavior once
2. Wait 30 seconds
3. Reproduce with identical request
4. Wait 30 seconds
5. Reproduce again
6. If 3/3 consistent → log as finding
7. If 2/3 or less → investigate further or discard

### Integration with ptest Phases

| Phase | Apply These Rules |
|---|---|
| Phase 5 (Vuln Assessment) | Body-Diff on all scanner results, Statistical-Sample on timing findings |
| Phase 6 (Exploitation) | All rules — especially Marker Discipline for injection testing |
| Phase 7 (Post-Exploitation) | Reproduction rule for access validation |
