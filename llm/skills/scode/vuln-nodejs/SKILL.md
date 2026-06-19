---
name: vuln-nodejs
description: "Scan for Node.js library-level vulnerabilities (path.join traversal, Zip Slip, dynamic require RCE, prototype pollution, vm escape, ReDoS). Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Node.js Library-Level Vulnerabilities

Scan for Node.js-specific vulnerability patterns that standard injection/file-path scanners miss.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Applicability

```bash
find . -name "package.json" -not -path "*/node_modules/*" | head -1
```
If no results → report "No Node.js code found — scanner not applicable" and skip.

## Vulnerability Patterns

### path.join() / path.resolve() Traversal
- User input flows into path functions without post-validation
- `path.resolve()` with user input as second arg (absolute path overrides base)

**Grep patterns**: `path.join(`, `path.resolve(`, `req.params`, `req.query`, `req.body` near path operations

### Zip Slip (Archive Path Traversal)
- Zip/tar extraction without entry name validation
- Vulnerable libraries: yauzl, adm-zip, unzipper, decompress, tar (npm)

**Grep patterns**: `yauzl`, `adm-zip`, `unzipper`, `decompress`, `archiver`, `tar.extract`, `.extractAll`

### Dynamic require() as RCE
- `require()` with user-influenced path → arbitrary code execution
- Plugin loaders scanning directories without validation

**Grep patterns**: `require(` (dynamic, not static string), `module.createRequire`, `import(`

### Prototype Pollution
- Deep merge/clone/set operations with user-controlled keys
- Missing `__proto__` / `constructor` / `prototype` key filter
- Gadgets: EJS compile, child_process options, ORM query builders

**Grep patterns**: `merge`, `defaultsDeep`, `assign`, `extend`, `[key] =`, `[prop] =`

### vm / vm2 Sandbox Escape
- Using `vm` module as security boundary (it's not one)
- vm2 < 3.9.19 has multiple CVEs for sandbox escape

**Grep patterns**: `require('vm')`, `vm.run`, `vm.createContext`, `vm2`, `NodeVM`, `VMScript`

### Unsafe Deserialization
- `node-serialize` unserialize with user data → RCE via IIFE
- `serialize-javascript` with `unsafe: true`

**Grep patterns**: `serialize`, `unserialize`, `node-serialize`, `$$ND_FUNC$$`

### ReDoS
- Regex with nested quantifiers processing user input
- User-supplied regex patterns via `new RegExp(userInput)`

**Grep patterns**: `new RegExp(req`, `new RegExp(params`, `new RegExp(body`

### HTTP Parameter Pollution (Express)
- Express parses duplicate query params as arrays, breaking type assumptions
- Array value flows into MongoDB → operator injection

**Grep patterns**: `req.query` with `===` comparison (assumes string, could be array)

### Event Loop Blocking
- Synchronous file/crypto operations on request handler path
- User-controlled input size to sync operations

**Grep patterns**: `readFileSync`, `writeFileSync`, `execSync`, `pbkdf2Sync`, `scryptSync`

## Process

1. **Check package.json** — identify Node.js frameworks, vulnerable dependencies
2. **Find path operations** — trace user input into path.join/resolve
3. **Find archive handling** — check extraction without path validation
4. **Find dynamic requires** — can user influence require paths?
5. **Find merge/set operations** — check for prototype pollution sinks + gadgets
6. **Find regex patterns** — test for catastrophic backtracking on user input
7. **Assess impact** — RCE, file read/write, DoS

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Node.js

**Date**: {date}
**Scanner**: vuln-nodejs

## Findings

### VULN-NODE-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Path Traversal / Zip Slip / Dynamic Require / Prototype Pollution / Sandbox Escape / Deserialization / ReDoS / HPP / Event Loop}
**Location**: `{file}:{line}`
**CWE**: CWE-{22|94|1321|502|1333|400}

**Description**:
{What the vulnerability is}

**Vulnerable Code**:
```javascript
{code snippet}
`` `

**Data Flow**:
1. Input enters at: {source}
2. Reaches sink at: {dangerous call}

**Proof of Concept**:
{Exploit payload}

**Impact**:
{RCE, file read, DoS, etc.}

**Remediation**:
```javascript
{fixed code}
`` `

---
```

## Positive Observations

While scanning, note strong patterns. Add to `# Positive Security Observations` at end of `vulnerabilities.md`:

```markdown
- vuln-nodejs: {what the codebase does well}
```

## Rules

- **Check for existing mitigations** — startsWith() checks after path.join, key filters on merge.
- **Prototype pollution needs a gadget** — pollution alone is Medium, + RCE gadget = Critical.
- **vm module is NEVER a security boundary** — but only report if untrusted code is being sandboxed.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — Node.js` section, replace it entirely.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
