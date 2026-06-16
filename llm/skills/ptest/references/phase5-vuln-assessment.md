# Phase 5: Threat Modeling & Vulnerability Assessment

## Automated Setup

Run first when entering this phase:

```python
from hermes_tools import read_file
exec(read_file("~/.hermes/skills/security/ptest/scripts/phase5_vuln_assess.py")["content"])
```

---

## When to Use
- After attack surface mapping is complete (Gateway 4 PASSED).
- When you need to identify and prioritize vulnerabilities before exploitation.

## Purpose

This phase has two sub-phases:
- **5A: Threat Modeling** — map attack paths from the attacker's perspective
- **5B: Vulnerability Assessment** — run targeted scanning and manual verification

The output is a prioritized list of exploitation vectors that feeds directly into Phase 6.

---

## 5A: Threat Modeling (Attack-Tree Approach)

### Methodology

For each high-priority asset (from Phase 4 asset inventory), build an attack tree:

```
[Goal: What the attacker wants to achieve]
├── [Path 1: Entry point → Technique → Impact]
│   ├── Prerequisite: ...
│   ├── Likelihood: High/Medium/Low
│   └── Impact: Critical/High/Medium/Low
├── [Path 2: ...]
└── [Path 3: ...]
```

### Steps

1. **Identify attacker goals** per asset:
   - Unauthorized access to admin panels
   - Data exfiltration (customer data, credentials)
   - Service disruption
   - Lateral movement to internal systems
   - Privilege escalation

2. **Map attack paths** from discovered entry points:
   - What entry points exist? (from Phase 4 entry-points.md)
   - What techniques could exploit each entry point?
   - What's the path of least resistance?
   - What's the maximum impact achievable?

3. **Assess likelihood × impact** for each path:
   - **Likelihood:** Based on exposure, complexity, and required prerequisites
   - **Impact:** Based on data sensitivity, business criticality, and blast radius

4. **Prioritize vectors** — rank by: `likelihood × impact`

### Output Format

```markdown
# Attack Tree: [Asset Name]

## Goal: [Attacker objective]

### Path 1: [Short description]
- **Entry Point:** [URL/endpoint]
- **Technique:** [Attack type — SQLi, auth bypass, SSRF, etc.]
- **Prerequisites:** [What's needed — valid account, specific parameter, etc.]
- **Likelihood:** High / Medium / Low
- **Impact:** Critical / High / Medium / Low
- **Priority Score:** [L×I — e.g., High×Critical = P1]

### Path 2: ...
```

---

## 5B: Vulnerability Assessment

### 0. CDN/WAF-Aware Pre-Check (MANDATORY before scanning)

Before running automated scanners, determine if targets are behind CDN/WAF:
```bash
# Check for CDN indicators
curl -sI https://target.com | grep -i "server\|cf-ray\|x-cache\|x-amz-cf\|cloudfront\|akamai"
```

**If behind Cloudflare/CloudFront/Akamai:**
- Skip nuclei/nikto (they'll timeout or get blocked)
- Use **manual targeted checks** instead (see below)
- Focus on: CSP analysis, bucket misconfigs, config endpoints, header intelligence
- Look for non-CDN subdomains (staging, internal, dev) that bypass WAF

**CDN-Fronted Manual Checks (replace automated scanning):**
```bash
# 1. CSP header analysis → extract third-party keys
curl -sI https://target.com | grep -i "content-security-policy" | tr ';' '\n'
# Look for: Sentry DSN, analytics endpoints, internal domains, staging URLs

# 2. Third-party key abuse (Sentry DSN example)
# Extract from CSP: https://<key>@<org>.ingest.<region>.sentry.io/<project>
# Test write access with event injection

# 3. Config/settings endpoints (common patterns)
for path in /api/config /api/settings /api/v0/config/settings /config.json /.well-known/; do
  curl -s "https://target.com$path" -w "\n%{http_code}" | tail -5
done

# 4. Cloud storage enumeration
# Check for S3/Spaces bucket listing on discovered subdomains
curl -s "https://subdomain.target.com" | grep -i "ListBucket\|AccessDenied\|NoSuchBucket"

# 5. Token format oracle on unauthenticated endpoints
# See references/token-format-oracle.md for full technique
# Test token-based endpoints (email confirm, withdrawal approve, password reset)
# with varying lengths to identify format validation oracles
```

### 1. Automated Vulnerability Scanning (nuclei — skip if CDN-blocked)

Run nuclei against ALL confirmed-live web targets. **Skip if targets are CDN-fronted and scans timeout.**
```bash
# Full scan against all live hosts
nuclei -l ./ptest-output/recon-passive/live-urls.txt -o ./ptest-output/vuln-assessment/nuclei-full.txt -severity info,low,medium,high,critical

# Targeted scan against priority targets
nuclei -u https://priority-target.com -t cves/ -t vulnerabilities/ -t misconfiguration/ -o ./ptest-output/vuln-assessment/nuclei-priority.txt

# Technology-specific templates
nuclei -u https://target.com -t technologies/ -t exposures/ -o ./ptest-output/vuln-assessment/nuclei-tech.txt
```

**Requirements:**
- Nuclei MUST be run against all live web hosts
- Results must be manually verified (eliminate false positives)
- If nuclei is unavailable, document the gap

**Timeout mitigation (Bank Jago, June 2026):** Full template scans (10K+ templates) timeout on rate-limited hosts even at `-rate-limit 5 -c 2`. Use tag-specific scans instead:
```bash
# Tag-specific scans (fast, targeted)
nuclei -u https://target.com -tags n8n,workflow -rate-limit 3 -c 1 -no-interactsh -timeout 5
nuclei -u https://target.com -tags openvpn -rate-limit 3 -c 1 -no-interactsh -timeout 5
nuclei -u https://target.com -tags tyk -rate-limit 3 -c 1 -no-interactsh -timeout 5

# If full scan needed, split by severity
nuclei -l targets.txt -severity critical,high -rate-limit 3 -c 2 -no-interactsh -timeout 5
nuclei -l targets.txt -severity medium -rate-limit 3 -c 2 -no-interactsh -timeout 5
```
Never mark nuclei "DONE" with 0 results from a timeout — that's a gap requiring manual supplementation.

### 2. Web Server Scanning (Recommended: nikto)
```bash
# Nikto scan
nikto -h https://target.com -o ./ptest-output/vuln-assessment/nikto.txt -Format txt

# Multiple hosts
nikto -h ./ptest-output/recon-passive/live-urls.txt -o ./ptest-output/vuln-assessment/nikto-all.txt
```

### 3. SSL/TLS Assessment (Recommended: testssl.sh)
```bash
# Full SSL/TLS analysis
testssl.sh --html --csvfile ./ptest-output/vuln-assessment/testssl.csv https://target.com

# Quick check
testssl.sh --fast https://target.com
```

### 4. CVE Mapping
Match discovered service versions against known vulnerabilities.
```bash
# Search for CVEs based on identified versions
searchsploit "pimcore"
searchsploit "php 8.1"
searchsploit "keycloak"
searchsploit "nginx"

# Check NVD/CVE databases
# Cross-reference: service version from Phase 2 → known CVEs → exploitability
```

### CORS Severity Quick-Reference

Before reporting CORS findings, assess actual impact:

| Configuration | Severity | Rationale |
|--------------|----------|-----------|
| `ACAO: *` (no credentials) | **Low/Info** | Only leaks data accessible without cookies. Most programs won't pay for this. |
| `ACAO: *` + debug traces/errors | **Low-Medium** | Leaks internal architecture cross-origin, but no user data |
| `ACAO: attacker.com` + `ACAC: true` | **High** | Reads authenticated responses cross-origin — real ATO vector |
| `ACAO: null` + `ACAC: true` | **High** | Exploitable via sandboxed iframe |
| `ACAO: *.same-domain.com` (subdomain only) | **Medium** | Requires XSS on a subdomain to exploit |

**Key rule:** `Access-Control-Allow-Origin: *` WITHOUT `Access-Control-Allow-Credentials: true` = **Low at best**. Browsers won't send cookies with `*`, so the attacker only reads public data. Many programs explicitly exclude this. Check program policy before investing time.

**When CORS `*` IS reportable:**
- Combined with debug mode (leaks internal paths/schema cross-origin)
- On an endpoint that returns different data based on IP/geo (not cookie-based auth)
- When the response contains sensitive data that's "public" but shouldn't be cross-origin readable (e.g., internal error messages)

**When to skip CORS `*`:**
- All responses are the same regardless of auth state
- Data is truly public (marketing content, public API)
- Program explicitly excludes "CORS misconfiguration without demonstrated impact"

### CORS Origin Reflection Testing (MANDATORY)

Test ALL endpoints that return sensitive data or perform state-changing actions.
### CORS Origin Reflection Testing (MANDATORY)
### CORS Origin Reflection Testing (MANDATORY — including ALL API backends)

**AntGroup lesson (June 2026):** Critical CORS (arbitrary origin + credentials) was found on `ilmprodmerchant.alipayplus.com` only during Phase 6 by accident. Phase 5 CORS checks only tested frontend hosts. **Always test CORS on every discovered API backend**, not just SPA frontends. API backends often have permissive CORS because developers assume "only our SPA calls this."

Test ALL endpoints that return sensitive data or perform state-changing actions, **especially**:
- Real API backends discovered via SPA backend discovery (JS extraction, browser network)
- Internal service endpoints (actuator, /api/v1/*, etc.)
- Endpoints behind auth that return `AUTH_FAILED` (CORS headers still reflect before auth check)

Test ALL endpoints that return sensitive data or perform state-changing actions:

```bash
# Test 1: Arbitrary origin reflection
curl -sk -H "Origin: https://evil.com" "$ENDPOINT" -D- | grep -i "access-control"
# VULN if: Access-Control-Allow-Origin: https://evil.com + Allow-Credentials: true

# Test 2: Null origin
curl -sk -H "Origin: null" "$ENDPOINT" -D- | grep -i "access-control"
# VULN if: Access-Control-Allow-Origin: null

# Test 3: Subdomain reflection (check if *.target.com is trusted)
curl -sk -H "Origin: https://evil.target.com" "$ENDPOINT" -D- | grep -i "access-control"
# VULN if: reflects any subdomain (attacker can use XSS on any subdomain to steal data)

# Test 4: Prefix/suffix bypass
curl -sk -H "Origin: https://target.com.evil.com" "$ENDPOINT" -D- | grep -i "access-control"
curl -sk -H "Origin: https://eviltarget.com" "$ENDPOINT" -D- | grep -i "access-control"
```

**CRITICAL (AntGroup lesson, June 2026):** CORS testing MUST be repeated in Phase 6 on any newly-discovered API backends. The ilmprodmerchant.alipayplus.com backend was only discovered during Phase 5 bot.alipayplus.com testing — its CORS reflection (arbitrary origin + credentials: true) was the highest-severity finding on that asset. Phase 5 nuclei scans missed it entirely because the backend was behind an SPA. Always re-test CORS on:
- API backends discovered via JS bundle analysis
- Endpoints found through browser network interception
- Any host not in the original Phase 2 live-hosts list

**Impact assessment:**
- Reflected origin + `Access-Control-Allow-Credentials: true` + endpoint returns sensitive data = **High** (cross-origin data theft)
- Reflected origin without credentials = **Low** (limited to non-credentialed requests)
- Wildcard `*` without credentials = **Info** (by design for public APIs)

### 5b. Firebase Auth Provider Enumeration (MANDATORY when Firebase detected)

When Firebase Auth is in use, test ALL sign-in providers — apps often enable password auth but only use email-link in the UI:

```bash
# 1. Test password signup (most common misconfiguration)
curl -sk -H "Referer: https://TARGET/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=FIREBASE_API_KEY" \
  -X POST -H "Content-Type: application/json" \
  -d '{"email":"test@attacker.com","password":"Test123456!","returnSecureToken":true}'
# VULN if: returns idToken with sign_in_provider: "password" when app only uses emailLink

# 2. Test anonymous signup
curl -sk -H "Referer: https://TARGET/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=FIREBASE_API_KEY" \
  -X POST -H "Content-Type: application/json" \
  -d '{"returnSecureToken":true}'
# VULN if: returns idToken (anonymous auth enabled)

# 3. Test signInWithPassword on existing accounts
curl -sk -H "Referer: https://TARGET/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=FIREBASE_API_KEY" \
  -X POST -H "Content-Type: application/json" \
  -d '{"email":"victim@target.com","password":"common_pass","returnSecureToken":true}'

# 4. Check createAuthUri (email enumeration)
curl -sk -H "Referer: https://TARGET/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=FIREBASE_API_KEY" \
  -X POST -H "Content-Type: application/json" \
  -d '{"identifier":"test@target.com","continueUri":"https://TARGET/login"}'
# Returns registered: true/false

# 5. Decode JWT claims to verify bypass
echo "$ID_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
# Check: firebase.sign_in_provider, email_verified, auth_time
```

**Impact assessment:**
- Password auth enabled on passwordless-only app = **Medium-High** (auth flow bypass, account squatting, KYC bypass on regulated platforms)
- Anonymous auth enabled = **Medium** (unlimited account creation)
- Email enumeration via createAuthUri = **Low** (often excluded by programs)

**Key insight:** Firebase API keys are referer-restricted, NOT secret. Always add `-H "Referer: https://TARGET/"` to bypass the restriction. The API key + referer = full access to Identity Toolkit.

### 6. OAuth/OIDC redirect_uri Validation (MANDATORY)

Test the authorization endpoint's redirect_uri parameter for open redirect and token theft:

```bash
# Find the authorize endpoint (common patterns)
# /oauth/authorize, /auth/realms/{realm}/protocol/openid-connect/auth, /authorize

# Test 1: Open redirect to attacker domain
curl -sk "$AUTH_URL?client_id=$CID&redirect_uri=https://evil.com/callback&response_type=code" -D- | grep -i "location"

# Test 2: Path traversal
curl -sk "$AUTH_URL?client_id=$CID&redirect_uri=https://target.com/callback/../../../evil" -D-

# Test 3: Subdomain substitution
curl -sk "$AUTH_URL?client_id=$CID&redirect_uri=https://evil.target.com/callback" -D-

# Test 4: Parameter pollution
curl -sk "$AUTH_URL?client_id=$CID&redirect_uri=https://target.com/callback%23@evil.com" -D-

# Test 5: Scheme downgrade
curl -sk "$AUTH_URL?client_id=$CID&redirect_uri=http://target.com/callback" -D-
```

**Impact:** If redirect_uri validation is weak, attacker can steal OAuth authorization codes or tokens by redirecting the user to an attacker-controlled URL after authentication.

### 7. Manual Verification

**Every scanner finding must be manually verified before being added to the findings log.**

For each scanner result:
1. Reproduce the finding manually (curl, browser, or tool)
2. Confirm it's a true positive (not a false positive)
3. Assess actual exploitability in this specific context
4. Assign severity using CVSS 3.1

**False positives** → document in `./ptest-output/vuln-assessment/false-positives.md`
**Confirmed findings** → add to `./ptest-output/findings-log.md`

### 6. Prioritized Vector List

Combine threat model paths with confirmed vulnerabilities into a final prioritized exploitation list:

```markdown
# Prioritized Exploitation Vectors

| Priority | Target | Vector | Technique | Likelihood | Impact | Status |
|----------|--------|--------|-----------|-----------|--------|--------|
| P1 | target.com/admin | Auth bypass | Credential brute-force | High | Critical | Ready |
| P2 | api.target.com | Injection | SQLi in search param | Medium | High | Ready |
| P3 | ... | ... | ... | ... | ... | ... |
```

This list becomes the input for Phase 6 (Exploitation).

---

## Scope Type Adjustments

- **web/API:** Focus on OWASP Top 10, API-specific vulns (BOLA, mass assignment, rate limiting).
- **network:** Focus on CVE mapping for service versions, default credentials, misconfigurations.
- **cloud:** Focus on IAM misconfigurations, storage permissions, metadata exposure, SSRF to cloud endpoints.
- **mobile:** Focus on API-level vulnerabilities, certificate pinning bypass, insecure data storage.

## Output

Document in `./ptest-output/vuln-assessment/`:
- `attack-trees.md` — attack trees per high-priority asset
- `nuclei-*.txt` — raw nuclei output
- `nikto-*.txt` — raw nikto output (if run)
- `testssl-*.csv` — SSL/TLS results (if run)
- `cve-mapping.md` — service versions mapped to known CVEs
- `false-positives.md` — scanner results dismissed as false positives
- `vectors-prioritized.md` — final ranked exploitation vector list

Write `./ptest-output/vuln-assessment/checklist.md`:

```markdown
# Vulnerability Assessment Checklist

| # | Technique | Status | Notes |
|---|-----------|--------|-------|
| 1 | Threat Modeling (attack trees) | PENDING | |
| 2 | Nuclei Scan (MANDATORY) | PENDING | |
| 3 | Nikto Scan | PENDING | |
| 4 | SSL/TLS Assessment | PENDING | |
| 5 | CVE Mapping | PENDING | |
| 6 | Manual Verification of Findings | PENDING | |
| 7 | Prioritized Vector List | PENDING | |
```

Mark each technique as `DONE`, `SKIPPED (reason)`, or `FAILED (reason)` after execution.

## Exit Criteria
- [ ] Attack trees documented for all high-priority assets.
- [ ] Nuclei scan completed on all live web hosts.
- [ ] All scanner findings manually verified (no unverified findings in final list).
- [ ] CVEs mapped to discovered service versions.
- [ ] Exploitation vectors prioritized by likelihood × impact.
- [ ] Mandatory tool (nuclei) was run — or gap documented.
- [ ] Checklist shows all applicable techniques executed.
