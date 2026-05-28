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

### 5. CORS Origin Reflection Testing (MANDATORY)

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

**Impact assessment:**
- Reflected origin + `Access-Control-Allow-Credentials: true` + endpoint returns sensitive data = **High** (cross-origin data theft)
- Reflected origin without credentials = **Low** (limited to non-credentialed requests)
- Wildcard `*` without credentials = **Info** (by design for public APIs)

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
