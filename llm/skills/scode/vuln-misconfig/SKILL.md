---
name: vuln-misconfig
description: "Step 3f of bug bounty workflow. Scan for security misconfigurations (CORS, CSP, debug mode, default creds). Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Step 3f: Security Misconfiguration

Scan for CORS issues, missing security headers, debug mode, default credentials, and exposed admin interfaces.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for configuration and deployment details
- If either is missing, tell the user which step to run first

## Vulnerability Patterns

### CORS Misconfiguration
- `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`
- Origin reflected from request without validation
- Null origin allowed
- Regex bypass in origin validation (e.g., `evil.example.com` matching `example.com`)

**Grep patterns**: `cors`, `Access-Control`, `origin`, `credentials: true`

### Missing Security Headers
- No Content-Security-Policy
- No X-Frame-Options (clickjacking)
- No X-Content-Type-Options
- No Strict-Transport-Security
- Permissive CSP (`unsafe-inline`, `unsafe-eval`, wildcard sources)

### Debug Mode in Production
- `DEBUG = True` / `debug: true` in production configs
- Stack traces enabled
- Verbose logging in production
- Development endpoints exposed (e.g., `/debug`, `/phpinfo`, `/__debug__`)

**Grep patterns**: `DEBUG`, `debug`, `NODE_ENV`, `FLASK_ENV`, `verbose`, `stackTrace`

### Default Credentials
- Unchanged default passwords in config files
- Hardcoded admin accounts
- Default database credentials
- Test accounts left in production config

### Exposed Admin/Internal Interfaces
- Admin panels without additional auth
- Health check endpoints leaking internal info
- Swagger/API docs exposed in production
- Database admin tools (phpMyAdmin, Adminer) accessible

**Grep patterns**: `/admin`, `/swagger`, `/api-docs`, `/health`, `/metrics`, `/debug`

## Process

1. **Check CORS configuration** — find where CORS is set up and validate the origin policy
2. **Review security headers** — check middleware/response configuration
3. **Find environment configs** — check for debug flags in production configs
4. **Search for default creds** — grep config files for common defaults
5. **Map internal endpoints** — find admin/debug routes and check their protection

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Misconfiguration

**Date**: {date}
**Scanner**: vuln-misconfig

## Findings

### VULN-MC-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {CORS / Missing Headers / Debug Mode / Default Creds / Exposed Interface}
**Location**: `{file}:{line}`
**CWE**: CWE-{942|693|489|1188|16}

**Description**:
{What is misconfigured and why it matters}

**Evidence**:
```{lang}
{configuration showing the issue}
`` `

**Attack Scenario**:
{How an attacker exploits this misconfiguration}

**Impact**:
{Cross-origin data theft, clickjacking, information disclosure, unauthorized access}

**Remediation**:
{Correct configuration with code example}

---
```


## Positive Observations

While scanning, note any strong security patterns relevant to this scanner's domain. Add them to the `# Positive Security Observations` section at the end of `vulnerabilities.md`:

```markdown
- {scanner-name}: {what the codebase does well in this area}
```
## Rules

- **Distinguish dev vs prod configs** — debug mode in dev-only config is informational, not a finding.
- **CORS with credentials is the key** — wildcard without credentials is usually acceptable.
- **Check if headers are set at infrastructure level** — they may not be in app code.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — Misconfiguration` section, replace it entirely. See `sc3-vuln-scan` idempotency rule.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
