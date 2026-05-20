---
name: vuln-ssrf
description: "Step 3d of bug bounty workflow. Scan for SSRF vulnerabilities (user-controlled URLs, internal service access). Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Step 3d: SSRF Vulnerabilities

Scan for Server-Side Request Forgery where user input controls outbound HTTP requests.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points making outbound requests
- If either is missing, tell the user which step to run first

## Applicability

Skip if the codebase makes no outbound HTTP/network requests based on user input — no URL fetching, webhook delivery, or proxy functionality. Report "Not applicable" and skip.

## Vulnerability Patterns

### Direct SSRF
- User-supplied URL passed to HTTP client (fetch, axios, requests, HttpClient)
- Webhook URLs stored and later fetched by the server
- URL preview/unfurling features
- File download from user-provided URL
- Image/avatar fetching from URL

**Grep patterns**: `fetch(`, `axios(`, `requests.get(`, `http.get(`, `urllib`, `HttpClient`, `curl`, `webhook`, `url` in request params

### Indirect SSRF
- User controls part of a URL (path, query param, host)
- Redirect following that can be pointed to internal services
- SVG/XML processing that fetches external resources
- PDF generation with user-controlled HTML (wkhtmltopdf, puppeteer)

### Cloud Metadata Access
- Can the SSRF reach `169.254.169.254` (AWS metadata)?
- Can it reach `metadata.google.internal` (GCP)?
- Internal service discovery endpoints

### Bypass Patterns to Check
- Is there URL validation? Can it be bypassed with:
  - DNS rebinding
  - URL encoding
  - IPv6 addresses
  - Redirects (302 to internal)
  - Alternative IP representations (decimal, octal)

## Process

1. **Find all outbound HTTP calls** in the codebase
2. **Trace URL source** — is any part of the URL user-controlled?
3. **Check validation** — is there an allowlist? Blocklist? DNS resolution check?
4. **Assess internal access** — what internal services could be reached?
5. **Check redirect handling** — does the HTTP client follow redirects?

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — SSRF

**Date**: {date}
**Scanner**: vuln-ssrf

## Findings

### VULN-SSRF-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Direct SSRF / Indirect SSRF / Partial SSRF}
**Location**: `{file}:{line}`
**CWE**: CWE-918

**Description**:
{How user input reaches an outbound request}

**Vulnerable Code**:
```{lang}
{code showing user input → HTTP request}
`` `

**Attack Scenario**:
{Request to trigger SSRF, target internal service or metadata}

**Impact**:
{Internal network scanning, metadata access, internal service abuse}

**Remediation**:
{URL allowlist, disable redirects, block private IP ranges}

---
```

## Rules

- **Check every outbound HTTP call** — even indirect ones (PDF generators, email senders).
- **Verify URL validation is robust** — blocklists are often bypassable.
- **Note cloud environment** — metadata endpoint access elevates severity to Critical.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — SSRF` section, replace it entirely. See `sc3-vuln-scan` idempotency rule.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
