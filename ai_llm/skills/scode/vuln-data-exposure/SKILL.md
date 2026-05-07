---
name: vuln-data-exposure
description: "Step 3c of bug bounty workflow. Scan for sensitive data exposure (secrets, verbose errors, logging PII, missing encryption). Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Step 3c: Sensitive Data Exposure

Scan for hardcoded secrets, information leakage, PII exposure in logs, and missing encryption.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for data flow context
- If either is missing, tell the user which step to run first

## Vulnerability Patterns

### Hardcoded Secrets
- API keys, tokens, passwords in source code
- Private keys committed to repo
- Connection strings with credentials
- JWT signing secrets in code

**Grep patterns**: `password`, `secret`, `api_key`, `apikey`, `token`, `private_key`, `AWS_SECRET`, `AKIA`, `-----BEGIN`, `jdbc:`, `mongodb://.*:.*@`

### Verbose Error Responses
- Stack traces returned to users in production
- Database error messages exposed (table names, query structure)
- Internal file paths leaked in error responses
- Debug information in API responses

**What to check**: Error handlers, catch blocks, and what they return to the client.

### Sensitive Data in Logs
- Passwords logged during auth flows
- Tokens/session IDs in log statements
- PII (email, SSN, credit card) written to logs
- Request bodies logged without redaction

**Grep patterns**: `console.log`, `logger.`, `log.`, `print(` near sensitive variable names

### Missing Encryption
- Sensitive data stored in plaintext (passwords not hashed)
- HTTP used instead of HTTPS for sensitive operations
- Cookies without Secure/HttpOnly flags
- Sensitive data in localStorage/sessionStorage

### Over-exposed API Responses
- Full database objects returned without field filtering
- Internal IDs, timestamps, or metadata leaked
- Other users' data included in responses

## Process

1. **Grep for secret patterns** across the entire codebase
2. **Review error handlers** — what gets returned to the client on failure?
3. **Check logging statements** — are sensitive values being logged?
4. **Review API responses** — are full objects returned or properly filtered?
5. **Check storage** — are passwords hashed? Are sensitive fields encrypted?

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Data Exposure

**Date**: {date}
**Scanner**: vuln-data-exposure

## Findings

### VULN-DE-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Category**: {Hardcoded Secret / Verbose Error / PII in Logs / Missing Encryption / Over-exposed Response}
**Location**: `{file}:{line}`
**CWE**: CWE-{798|209|532|311|200}

**Description**:
{What is exposed and how}

**Evidence**:
```{lang}
{code showing the exposure}
`` `

**Impact**:
{What attacker gains from this exposure}

**Remediation**:
{How to fix — env vars, error sanitization, log redaction, field filtering}

---
```

## Rules

- **Do NOT include actual secret values in the report** — redact them, show only the pattern.
- **Distinguish dev vs prod** — a secret in a test file is lower severity than in production config.
- **Check .gitignore** — are sensitive files properly excluded?
- **Append to `./assessment/vulnerabilities.md`** and confirm.
