---
name: vuln-client-side
description: "Step 3k of bug bounty workflow. Scan for client-side vulnerabilities (open redirect, clickjacking, prototype pollution, DOM-based attacks). Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Step 3k: Client-Side Vulnerabilities

Scan for client-side security issues beyond basic XSS — open redirects, clickjacking, prototype pollution, and DOM-based attacks.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Vulnerability Patterns

### Open Redirect
- User-controlled URL in redirect responses (`302`, `301`)
- `Location` header set from query params or POST body
- Client-side redirects via `window.location` from URL params
- Insufficient URL validation (protocol-relative `//evil.com`, backslash `\/\/evil.com`)

**Grep patterns**: `redirect(`, `res.redirect`, `Location`, `window.location`, `document.location`, `returnUrl`, `next=`, `url=`, `redirect_to`, `return_to`, `continue=`

### Clickjacking
- Missing `X-Frame-Options` header
- Missing or weak `Content-Security-Policy frame-ancestors`
- Sensitive actions (password change, transfers) without frame protection
- Missing anti-CSRF + framing = full clickjack exploitation

**Grep patterns**: `X-Frame-Options`, `frame-ancestors`, `helmet`, `frameguard`, `CSP`, `Content-Security-Policy`

### Prototype Pollution
- Deep merge/extend with user-controlled input
- `Object.assign()` or spread with unsanitized keys
- Lodash `_.merge`, `_.set`, `_.defaultsDeep` with user input
- JSON parsing into object without key filtering (`__proto__`, `constructor`, `prototype`)

**Grep patterns**: `merge(`, `extend(`, `deepMerge`, `_.merge`, `_.set`, `_.defaultsDeep`, `Object.assign`, `__proto__`, `constructor.prototype`, `JSON.parse`

### DOM-Based Attacks
- DOM clobbering via user-controlled HTML attributes
- `postMessage` without origin validation
- Client-side URL parsing with user input (`location.hash`, `location.search`)
- Unsafe use of `eval()`, `Function()`, `setTimeout(string)` with DOM data

**Grep patterns**: `postMessage`, `addEventListener.*message`, `origin`, `location.hash`, `location.search`, `eval(`, `Function(`, `setTimeout(`, `setInterval(`, `document.getElementById`

### Client-Side Storage Abuse
- Sensitive data in `localStorage`/`sessionStorage` accessible to XSS
- Overly broad `document.cookie` scope
- Service worker cache poisoning vectors

**Grep patterns**: `localStorage.setItem`, `sessionStorage.setItem`, `document.cookie`, `serviceWorker`, `caches.open`

## Process

For each priority target from threat-model.md:

1. **Find redirect points** — identify all server and client-side redirects using user input
2. **Check framing protections** — verify X-Frame-Options/CSP frame-ancestors on sensitive pages
3. **Trace object merges** — find deep merge operations that accept user-controlled keys
4. **Audit postMessage** — check for missing origin validation on message handlers
5. **Assess impact** — phishing via redirect, action hijack via clickjack, RCE via prototype pollution

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Client-Side

**Date**: {date}
**Scanner**: vuln-client-side

## Findings

### VULN-CLIENT-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Category**: {Open Redirect / Clickjacking / Prototype Pollution / DOM-Based / Storage Abuse}
**Location**: `{file}:{line}`
**CWE**: CWE-{601|1021|1321|79}

**Description**:
{What the vulnerability is}

**Vulnerable Code**:
```{lang}
{code snippet}
`` `

**Attack Scenario**:
1. {Step-by-step exploitation}

**Proof of Concept**:
{Malicious URL/payload}

**Impact**:
{Phishing, session theft, RCE via gadgets}

**Remediation**:
```{lang}
{fixed code}
`` `

---
```

## Rules

- **Only report exploitable client-side flaws** — missing headers alone are informational unless a sensitive action is frameable.
- **For prototype pollution, identify a gadget** — pollution without a usable gadget is low severity.
- **For open redirect, confirm the bypass** — show the exact URL that evades validation.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
