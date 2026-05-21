# Bug Bounty — Step 3a: Injection Vulnerabilities

Scan for all injection flaws where user input reaches a dangerous interpreter without proper sanitization.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Vulnerability Patterns

### SQL Injection
- String concatenation/interpolation in SQL queries
- Dynamic query building with user input
- Raw queries bypassing ORM parameterization
- Stored procedures called with unsanitized input

**Grep patterns**: `query(`, `execute(`, `raw(`, `${}` near SQL keywords, `+ "SELECT`, `+ 'SELECT`, `f"SELECT`, `format(` near SQL

### Command Injection
- User input passed to `exec`, `system`, `spawn`, `popen`, `child_process`
- Shell command construction with string interpolation
- Unsanitized input in `subprocess.call` with `shell=True`

**Grep patterns**: `exec(`, `system(`, `spawn(`, `popen(`, `child_process`, `subprocess`, `shell=True`

### Server-Side Template Injection (SSTI)
- User input rendered directly in template engines
- Dynamic template compilation with user data
- `render_template_string()` or equivalent with user input

**Grep patterns**: `render_template_string`, `Template(`, `eval(`, `compile(`, `Jinja2`, `{{`

### Cross-Site Scripting (XSS)
- User input reflected in HTML without encoding
- `innerHTML`, `dangerouslySetInnerHTML`, `v-html` with user data
- Missing output encoding in server-rendered pages
- DOM-based XSS via `document.location`, `document.URL`

**Grep patterns**: `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `document.write`, `\.html(`, `res.send(` with user input

### NoSQL Injection
- User input as MongoDB query operators (`$gt`, `$ne`, `$regex`)
- Unsanitized objects passed to `find()`, `findOne()`, `aggregate()`
- Missing type validation on query parameters

**Grep patterns**: `find(`, `findOne(`, `aggregate(`, `$where`, `$regex`

## Process

For each priority target from threat-model.md:

1. **Identify sinks** — find all dangerous function calls (query executors, command runners, template renderers, HTML output points)
2. **Trace back to source** — for each sink, trace backwards to find if user input can reach it
3. **Check sanitization** — is there parameterization, escaping, or validation between source and sink?
4. **Check framework-level protections** — many frameworks auto-escape by default:
   - **React/JSX**: Text interpolation `{value}` auto-escapes HTML. Only `dangerouslySetInnerHTML` and `href`/`src` attributes are XSS sinks. Do NOT report XSS for values rendered via normal JSX text nodes.
   - **Vue**: `{{ value }}` auto-escapes. Only `v-html` is a sink.
   - **Angular**: Interpolation `{{ value }}` auto-escapes. Only `[innerHTML]` with `bypassSecurityTrustHtml()` is a sink.
   - **Supabase/PostgREST**: The JS client's `.eq()`, `.ilike()`, `.in()` methods parameterize values — they are NOT vulnerable to SQL injection. Only raw `.rpc()` with string interpolation or unescaped LIKE wildcards (%, _) are concerns.
   - **Next.js**: Server components auto-escape. Only `dangerouslySetInnerHTML` in client/server components is a sink.
5. **Confirm exploitability** — can a crafted input actually trigger the injection given framework protections?
6. **Assess impact** — what can the attacker achieve? (RCE, data exfil, XSS session hijack)

## Output

Save to `./assessment/vulnerabilities.md` (create if doesn't exist, append if it does):

```markdown
# Vulnerability Findings — Injection

**Date**: {date}
**Scanner**: vuln-injection

## Findings

### VULN-INJ-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {SQL Injection / Command Injection / SSTI / XSS / NoSQL Injection}
**Location**: `{file}:{line}`
**CWE**: CWE-{89|78|1336|79|943}

**Description**:
{What the vulnerability is}

**Vulnerable Code**:
```{lang}
{code snippet}
`` `

**Data Flow**:
1. Input enters at: {source}
2. Passes through: {processing}
3. Reaches sink at: {dangerous call}

**Proof of Concept**:
{Exploit payload/request}

**Impact**:
{What attacker gains}

**Remediation**:
```{lang}
{fixed code}
`` `

---
```

## Rules

- **Only report confirmed injection paths** — sink must be reachable from user-controlled source.
- **Check framework protections** — ORMs, auto-escaping templates, CSP may neutralize the issue.
- **Include the exact payload** that would trigger the injection.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — Injection` section, replace it entirely. See `sc3-vuln-scan` idempotency rule.
- **Save to `./assessment/vulnerabilities.md`** and confirm.