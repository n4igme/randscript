---
name: vuln-dos
description: "Scan for denial of service vulnerabilities (ReDoS, algorithmic complexity, resource exhaustion, zip/XML bombs). Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Step 3o: Denial of Service Vulnerabilities

Scan for application-level DoS vectors that allow an attacker to exhaust resources or degrade availability.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Applicability

Skip if the target is a purely static site with no server-side processing, no user input handling, and no backend logic. Report "Not applicable" and skip.

## Vulnerability Patterns

### Regular Expression DoS (ReDoS)
- Nested quantifiers (`(a+)+`, `(a|a)*`)
- Overlapping alternations with repetition
- User input matched against complex regex without timeout
- Regex in input validation, search, or routing

**Grep patterns**: `new RegExp(`, `RegExp(`, `.match(`, `.test(`, `.replace(`, `.search(`, `re.compile`, `re.match`, `re.search`, `Pattern.compile`

### Algorithmic Complexity
- Hash collision attacks (user-controlled keys in hash maps)
- Quadratic string operations (nested loops on user input)
- Sorting user-controlled data with worst-case O(n²)
- Recursive parsing without depth limits (JSON, XML, YAML)

**Grep patterns**: `JSON.parse`, `xml.parse`, `yaml.load`, `sort(`, `forEach` nested, `while.*while`, `for.*for`

### Resource Exhaustion
- Unbounded memory allocation from user input (large arrays, strings)
- No request body size limit
- Unlimited concurrent connections/requests per user
- Thread/connection pool starvation via slow requests (Slowloris)
- Disk exhaustion via logging or temp files from user actions

**Grep patterns**: `bodyParser`, `body-parser`, `limit`, `maxBodyLength`, `maxContentLength`, `Buffer.alloc`, `new Array(`, `malloc`, `pool`, `maxConnections`

### Zip/Compression Bombs
- Archive extraction without size validation
- Decompression of user-uploaded files without ratio checks
- Nested archives (zip within zip)
- Gzip bomb via `Accept-Encoding` manipulation

**Grep patterns**: `unzip`, `gunzip`, `inflate`, `decompress`, `extract(`, `tar`, `zlib`, `archiver`, `createGunzip`

### XML Bombs (Billion Laughs)
- XML parsing with entity expansion enabled
- No limit on entity recursion depth
- DTD processing enabled on user-supplied XML
- SVG/XHTML parsing with embedded entities

**Grep patterns**: `xml2js`, `DOMParser`, `SAXParser`, `parseString`, `etree`, `lxml`, `DOCTYPE`, `ENTITY`, `libxml`, `expat`

### Event Loop / Thread Blocking
- Synchronous operations on user-controlled data size
- CPU-intensive operations without worker threads (crypto, image processing)
- Blocking I/O in async context
- `JSON.stringify` on circular or massive objects

**Grep patterns**: `Sync(`, `readFileSync`, `writeFileSync`, `crypto.pbkdf2Sync`, `bcrypt.hashSync`, `sharp(`, `jimp`, `canvas`, `worker_threads`

### Connection/Pool Starvation
- Database connections not released on error paths
- HTTP keep-alive without timeout
- WebSocket connections without limits per user
- File descriptor leaks on error

**Grep patterns**: `pool`, `connection`, `release(`, `destroy(`, `close(`, `timeout`, `keepAlive`, `maxSockets`, `WebSocket`

## Process

For each priority target from threat-model.md:

1. **Find regex patterns** — identify all regex applied to user input, test for catastrophic backtracking
2. **Check size limits** — are request bodies, uploads, arrays, and strings bounded?
3. **Identify expensive operations** — find CPU/memory-intensive code reachable from user input
4. **Check resource cleanup** — are connections/handles released on all code paths (including errors)?
5. **Assess amplification** — what's the ratio of attacker effort to server resource consumption?

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Denial of Service

**Date**: {date}
**Scanner**: vuln-dos

## Findings

### VULN-DOS-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {ReDoS / Algorithmic Complexity / Resource Exhaustion / Compression Bomb / XML Bomb / Event Loop Blocking / Pool Starvation}
**Location**: `{file}:{line}`
**CWE**: CWE-{1333|400|405|776|834}

**Description**:
{What the vulnerability is}

**Vulnerable Code**:
```{lang}
{code snippet}
`` `

**Attack Scenario**:
1. {Step-by-step exploitation}

**Proof of Concept**:
{Malicious input that triggers resource exhaustion}

**Amplification Factor**:
{e.g., "10KB input causes 30s CPU hang" or "1 request holds DB connection indefinitely"}

**Impact**:
{Service unavailability, degraded performance, cascading failure}

**Remediation**:
```{lang}
{fixed code}
`` `

---
```


## Positive Observations

While scanning, note any strong security patterns relevant to this scanner's domain. Add them to the `# Positive Security Observations` section at the end of `vulnerabilities.md`:

```markdown
- {scanner-name}: {what the codebase does well in this area}
```
## Rules

- **Only report DoS with significant amplification** — a slow endpoint is not a vuln unless attacker effort is disproportionately small.
- **Test regex patterns** — use backtracking analysis to confirm ReDoS, don't just flag complex regex.
- **Consider existing protections** — reverse proxy timeouts, WAF rate limits, container restart policies.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — Denial of Service` section, replace it entirely. See `sc3-vuln-scan` idempotency rule.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
