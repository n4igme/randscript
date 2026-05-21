# Signal Hunting Table: A→B→C Reference

## Concept: Signal-Based Vulnerability Hunting

Signal hunting is the practice of using one confirmed finding (Signal A) to systematically predict and discover related vulnerabilities (Finding B) nearby, because they share a common root cause. When a developer makes a security mistake in one place, the same mistake—or a closely related one—almost certainly exists elsewhere in the same codebase, module, or feature set.

**The core principle:** Vulnerabilities are not random. They cluster around:
- The same developer's code
- The same module or feature
- The same time period of development
- The same architectural pattern
- The same misunderstanding of a security concept

When you find X, you don't celebrate and move on. You systematically hunt for Y nearby because the conditions that created X almost certainly created Y.

**A→B→C Chain:**
- **A (Signal):** The initial finding that tells you something is wrong
- **B (Hunt):** What you should immediately test based on that signal
- **C (Escalation):** The high-impact chain you can build when B confirms

---

## Signal Lookup Table

### IDOR Signals

| Finding A (Signal) | Hunt for B | Why (Shared Root Cause) | Escalation to C |
|---|---|---|---|
| IDOR on GET /api/users/{id} | Check PUT, DELETE, PATCH on same resource | Dev checked auth on read but forgot write operations | Full account takeover via IDOR write |
| IDOR on one API version (v1) | Check same endpoint on v2, v3, legacy paths | Newer versions often miss auth checks from older code | Access via unprotected API version |
| IDOR on user profile endpoint | Check all endpoints accepting user ID parameter | Authorization logic is per-endpoint, not middleware | Mass data exfiltration across all user resources |
| Numeric sequential IDs exposed | Enumerate all resources via ID iteration | No randomization means no obscurity layer | Full database enumeration |
| IDOR in export/download function | Check import/upload with same ID pattern | Export and import share resource lookup logic | Overwrite other users' data via import |

### Auth Bypass Signals

| Finding A (Signal) | Hunt for B | Why (Shared Root Cause) | Escalation to C |
|---|---|---|---|
| Missing auth on one admin endpoint | Check all sibling admin endpoints | Auth was applied per-route, not per-prefix | Full admin panel access |
| Auth bypass via HTTP method change (GET→POST) | Try all HTTP methods on all protected endpoints | Method-based routing bypasses middleware | Write access to read-only resources |
| JWT signature not validated | Check all services consuming the same JWT | Shared auth library misconfigured | Forge tokens for any user/role |
| Session doesn't invalidate on password change | Check session handling on email change, role change | Session lifecycle not tied to credential state | Persistent access after account recovery |
| Auth cookie missing Secure flag | Check all cookies for HttpOnly, SameSite, path | Cookie security is configured globally or not at all | Session hijack via XSS or MITM |
| Rate limiting absent on login | Check OTP, password reset, API key endpoints | Rate limiting not applied as middleware | Brute force any credential mechanism |

### Information Disclosure Signals

| Finding A (Signal) | Hunt for B | Why (Shared Root Cause) | Escalation to C |
|---|---|---|---|
| /debug/pprof accessible | Check /debug/vars, /metrics, /healthz, /env | Debug endpoints enabled as a group | Leak secrets from environment variables |
| Stack trace in error response | Trigger errors on all endpoints, check verbose mode | Global error handler exposes internals | Map internal architecture, find injection points |
| .git directory exposed | Check .env, .svn, backup files, docker-compose.yml | Deployment copies source tree without exclusions | Clone full source, extract secrets |
| Version header in response (X-Powered-By) | Check all default/sample pages for framework | Default config shipped to production | Exploit known CVEs for exact version |
| GraphQL introspection enabled | Check for query batching, field suggestions, debug mode | Dev-friendly features left on in prod | Map entire API schema, find hidden mutations |

### Injection Signals

| Finding A (Signal) | Hunt for B | Why (Shared Root Cause) | Escalation to C |
|---|---|---|---|
| SQLi in one parameter | Test all parameters on same endpoint and siblings | No parameterized queries in this module | Database dump, auth bypass, RCE via stacked queries |
| SQLi in search function | Check filter, sort, export functions | Dynamic query building pattern reused | Extract entire database via UNION-based injection |
| XSS in one input field | Test all input fields in same feature | No output encoding in this template/component | Session hijack, admin impersonation |
| Template injection (SSTI) in one field | Check all user-controlled strings rendered server-side | Template engine used unsafely throughout | Remote code execution |
| Command injection in filename | Check all file-processing parameters (path, extension, size) | Shell exec used for file operations | Full server compromise |
| LDAP injection in login | Check all directory-query functions (search, group lookup) | LDAP queries built via string concatenation | Bypass auth, enumerate directory |

### Configuration Signals

| Finding A (Signal) | Hunt for B | Why (Shared Root Cause) | Escalation to C |
|---|---|---|---|
| /actuator/health exposed | Check /actuator/env, /actuator/heapdump, /actuator/mappings | Actuator exposed without endpoint filtering | Dump heap for secrets, map all routes |
| Exposed Kubernetes dashboard | Check /api, /apis, etcd, kubelet ports | Cluster deployed without network policies | Full cluster compromise |
| Default credentials on one service | Check all services for default creds | Deployment automation skipped credential rotation | Lateral movement across infrastructure |
| .env file accessible via web | Check for .env.backup, .env.production, .env.local | Multiple env files in deployment directory | Harvest all environment secrets |
| Open S3 bucket (one) | Check all buckets for same account/naming pattern | IAM policy is permissive at account level | Access all cloud storage |

### CORS Signals

| Finding A (Signal) | Hunt for B | Why (Shared Root Cause) | Escalation to C |
|---|---|---|---|
| Access-Control-Allow-Origin: * | Check if credentials: true also set | Permissive CORS without understanding implications | Steal auth tokens cross-origin |
| Origin reflection (echoes attacker origin) | Check if cookies/auth headers sent with CORS requests | Dynamic CORS without whitelist validation | Cross-origin account takeover |
| CORS allows null origin | Test via sandboxed iframe (data: URI) | Null origin whitelisted for "flexibility" | Bypass CORS from any context |

### SSRF Signals

| Finding A (Signal) | Hunt for B | Why (Shared Root Cause) | Escalation to C |
|---|---|---|---|
| SSRF in URL parameter (webhooks, imports) | Hit cloud metadata (169.254.169.254) | No URL validation or allowlist | AWS/GCP/Azure credential theft |
| SSRF in PDF generator | Check all document generation features (export, report) | Same library used without URL restrictions | Internal network scanning, credential theft |
| SSRF with DNS rebinding possible | Check for time-of-check/time-of-use on URL validation | Validation happens before fetch | Bypass allowlist, hit internal services |
| Partial SSRF (can hit internal hosts) | Scan internal network (ports 80, 443, 8080, 6379, 5432) | Internal network has no auth between services | Pivot to databases, caches, admin panels |

### File Upload Signals

| Finding A (Signal) | Hunt for B | Why (Shared Root Cause) | Escalation to C |
|---|---|---|---|
| File upload accepts any extension | Upload .php, .jsp, .aspx webshell | No server-side extension validation | Remote code execution |
| Upload path disclosed in response | Try path traversal in filename (../../etc/cron.d/shell) | Filename used directly in storage path | Arbitrary file write, cron-based RCE |
| File download by filename parameter | Try path traversal in download (../../etc/passwd) | Same path handling flaw in both directions | Arbitrary file read, source code disclosure |
| Image upload with no processing | Upload SVG with XSS, polyglot files | File content not validated or sanitized | Stored XSS, bypass CSP via uploaded content |
| Upload size limit not enforced | Check for zip bomb, decompression bomb handling | Resource limits not enforced server-side | Denial of service, disk exhaustion |

---

## The Sibling Rule

### Formalization

**If N endpoints in a group have a security control, and N is large, the probability that at least one sibling endpoint is missing that control approaches 1.**

More concretely:

> If 9 out of 10 endpoints in a module enforce authorization, the 10th almost certainly does not.

### Why This Works

1. **Manual application:** When auth is applied per-route rather than via middleware, human error guarantees gaps as the number of routes grows.

2. **Copy-paste drift:** Developers copy endpoint handlers and modify business logic but forget to copy the auth decorator/middleware attachment.

3. **Late additions:** Endpoints added after the initial security review often skip the auth pattern established earlier.

4. **Refactoring casualties:** When code is restructured, auth checks that lived in now-deleted wrapper functions silently disappear.

5. **Test coverage gaps:** If auth isn't tested per-endpoint, missing checks are invisible until exploited.

### How to Apply

1. Identify a group of related endpoints (same controller, same prefix, same feature)
2. Confirm that most have a specific security control (auth, rate limiting, input validation)
3. Systematically test each sibling for the absence of that control
4. Pay special attention to:
   - The newest endpoint (added last, reviewed least)
   - The least-used endpoint (edge case, forgotten)
   - Endpoints with different HTTP methods on the same path
   - Batch/bulk variants of single-resource endpoints
   - Export/download variants of view endpoints

### Mathematical Intuition

If each endpoint has a 5% chance of missing auth independently:
- 1 endpoint: 5% chance of finding a gap
- 10 endpoints: 40% chance at least one is missing auth
- 20 endpoints: 64% chance at least one is missing auth
- 50 endpoints: 92% chance at least one is missing auth

The more endpoints in a group, the more certain you should be that a gap exists.

---

## Protocol: Systematic Signal Hunting (Phase 6)

### Step 1: Catalog Initial Findings

After completing initial testing phases, list every confirmed finding with:
- Vulnerability class
- Affected endpoint/parameter
- Root cause (why it exists)

### Step 2: Generate Hunt List

For each finding, consult the signal table above:
- Map Finding A → all possible B targets
- Prioritize by impact (what escalation C is possible)
- Group hunts by target area to avoid redundant testing

### Step 3: Execute Sibling Sweeps

For each finding category:

```
1. Identify the "family" (same controller, same dev, same module)
2. List all siblings (endpoints, parameters, methods)
3. Test each sibling for the same flaw
4. Test each sibling for the RELATED flaw (A→B from table)
5. Document: confirmed, likely, or ruled out
```

### Step 4: Chain Building

When B confirms:
- Immediately test for escalation C
- Check if C enables access to new attack surface
- Recurse: treat C as a new Signal A and re-enter the table

### Step 5: Lateral Signal Propagation

Signals propagate across boundaries:
- **Same developer:** If dev X made mistake in module A, check all of dev X's code (git blame)
- **Same library:** If library Y is misconfigured here, check all uses of library Y
- **Same deployment:** If service A is misconfigured, check sibling services in same cluster
- **Same time period:** If code from sprint N has bugs, check all code from sprint N

### Step 6: Document Signal Chains

Record the full chain for reporting:
```
Signal: IDOR on GET /api/v2/orders/{id}
Hunt: Checked PUT /api/v2/orders/{id}, DELETE /api/v2/orders/{id}
Result: PUT also vulnerable (no auth check)
Escalation: Can modify any user's order → price manipulation → financial impact
Chain: Read IDOR → Write IDOR → Business logic abuse
```

### Completion Criteria

Signal hunting is complete when:
- Every finding has been used as a signal at least once
- All sibling endpoints for each finding have been tested
- All escalation paths have been attempted
- No new signals are being generated from hunt results
