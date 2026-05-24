# Node.js Library-Level Vulnerability Scanner

Scanner ID: **3w — nodejs**

## Skip Condition

```bash
# Skip if no Node.js/JavaScript in project
find . -name "package.json" -not -path "*/node_modules/*" | head -1
# If empty → SKIP this scanner
```

---

## Focus Areas

### 1. Path Traversal via path.join() / path.resolve()

**Pattern:** User input flows into `path.join()` or `path.resolve()` without post-validation.

```javascript
// VULNERABLE
const filepath = path.join(baseDir, req.params.filename);
fs.readFileSync(filepath);

// VULNERABLE — path.resolve with absolute input ignores base
const filepath = path.resolve(baseDir, req.body.path);
// If req.body.path = "/etc/passwd" → returns "/etc/passwd"
```

**Grep patterns:**
```bash
grep -rn "path\.join\|path\.resolve" --include="*.js" --include="*.ts" | grep -v node_modules | grep -v test
```

**What to check:**
- Does user input (req.params, req.query, req.body) flow into the path function?
- Is there a prefix check AFTER the join/resolve? (`if (!result.startsWith(baseDir))`)
- Does `path.resolve()` receive user input as second arg? (absolute path overrides base)

---

### 2. Zip Slip (Archive Path Traversal)

**Pattern:** Zip/tar extraction without entry name validation.

**Vulnerable libraries:**
| Library | Vulnerable? | Notes |
|---------|------------|-------|
| `yauzl` (strictFileNames: true) | YES — `../` not blocked | Only blocks absolute + backslash |
| `yauzl` (strictFileNames: false/default) | YES | No validation at all |
| `adm-zip` | YES | No path validation |
| `unzipper` | YES | No built-in validation |
| `tar` (npm) | Partial | `strip` option helps but doesn't fully prevent |
| `decompress` | YES | No validation |

**Grep patterns:**
```bash
grep -rn "yauzl\|adm-zip\|unzipper\|decompress\|archiver\|tar\.extract\|\.extractAll" --include="*.js" --include="*.ts" | grep -v node_modules
```

**What to check:**
- After getting entry filename, is there a `path.resolve()` + `startsWith()` check?
- Is `strictFileNames` set? (insufficient alone — still allows `../`)
- Does the extracted path get used in `require()` or served via HTTP?

---

### 3. require() / import() as Code Execution

**Pattern:** Dynamic `require()` with user-influenced path → arbitrary code execution.

```javascript
// VULNERABLE — plugin loader
const files = fs.readdirSync(pluginDir);
files.forEach(f => require(path.join(pluginDir, f)));

// VULNERABLE — dynamic require from user input
const module = require(`./modules/${req.params.name}`);
```

**Grep patterns:**
```bash
grep -rn "require\s*(" --include="*.js" --include="*.ts" | grep -v node_modules | grep -v "require('\\|require(\"" | head -30
# Finds dynamic requires (not static string requires)

grep -rn "module\.createRequire\|import\s*(" --include="*.js" --include="*.ts" | grep -v node_modules
```

**What to check:**
- Can attacker write a file to the directory being `require()`'d? (via upload, zip extraction, etc.)
- Is the require path constructed from user input?
- What interface must the loaded module export? (validation gates like `typeof plugin.get === 'function'`)

---

### 4. Prototype Pollution

**Pattern:** Deep merge/clone/set operations with user-controlled keys.

**Vulnerable functions:**
```bash
grep -rn "merge\|defaultsDeep\|assign\|extend\|set\s*(" --include="*.js" --include="*.ts" | grep -v node_modules | grep -v test
grep -rn "\[key\]\s*=\|\[prop\]\s*=\|\[field\]\s*=" --include="*.js" --include="*.ts" | grep -v node_modules
```

**What to check:**
- Does user JSON input flow into a recursive merge/set function?
- Is there a `__proto__` / `constructor` / `prototype` key filter?
- What gadgets exist downstream? (child_process options, template engine options, ORM query builders)

**Gadget detection:**
```bash
# EJS gadget
grep -rn "ejs\|render\|compile" --include="*.js" --include="*.ts" | grep -v node_modules
# child_process gadget
grep -rn "spawn\|exec\|fork\|execFile" --include="*.js" --include="*.ts" | grep -v node_modules
```

---

### 5. vm / vm2 Sandbox Escapes

**Pattern:** Using `vm` module as security boundary (it's not one).

```bash
grep -rn "require.*vm\|vm\.run\|vm\.createContext\|vm2\|VM2\|NodeVM\|VMScript" --include="*.js" --include="*.ts" | grep -v node_modules
```

**What to check:**
- Is `vm` used to sandbox untrusted code? (always escapable)
- Is `vm2` used? Check version — multiple CVEs for sandbox escape (< 3.9.19)
- Is there a `new Function()` or `eval()` with user input?

---

### 6. Unsafe Deserialization

**Pattern:** `node-serialize`, `serialize-javascript` (with eval), or custom unserialize.

```bash
grep -rn "serialize\|unserialize\|node-serialize\|funcster" --include="*.js" --include="*.ts" | grep -v node_modules
grep -rn "\\$\\$ND_FUNC\\$\\$" --include="*.js" --include="*.ts"  # node-serialize RCE marker
```

**What to check:**
- Does `unserialize()` process user-controlled data?
- Is `serialize-javascript` used with `unsafe: true`?
- Are there custom deserializers that call `eval()` or `new Function()`?

---

### 7. ReDoS (Regular Expression Denial of Service)

**Pattern:** Regex with nested quantifiers processing user input.

```bash
# Find regex definitions
grep -rn "new RegExp\|/.*[+*].*[+*]/" --include="*.js" --include="*.ts" | grep -v node_modules | grep -v test
# Find user-controlled regex
grep -rn "new RegExp(req\|new RegExp(params\|new RegExp(body\|new RegExp(query" --include="*.js" --include="*.ts" | grep -v node_modules
```

**Vulnerable patterns:**
```
/^(a+)+$/           — nested quantifiers
/(a|a)+$/           — alternation with quantifier
/([a-zA-Z]+)*$/     — group with quantifier, outer quantifier
/(.*a){x}/          — greedy .* with repetition
```

**What to check:**
- Does user input reach a regex with nested quantifiers?
- Can user supply their own regex pattern? (`new RegExp(userInput)`)
- Is there a timeout/limit on regex execution?

---

### 8. HTTP Parameter Pollution (Express-specific)

**Pattern:** Express parses duplicate query params as arrays, breaking type assumptions.

```bash
grep -rn "req\.query\|req\.params\|req\.body" --include="*.js" --include="*.ts" | grep -v node_modules | grep "===\|!==\|typeof"
```

**What to check:**
- Does code assume `req.query.param` is always a string? (could be array)
- Is there type validation before comparison? (`typeof x === 'string'`)
- Does the value flow into a database query? (array → MongoDB operator injection)

---

### 9. Event Loop Blocking / Sync Operations

**Pattern:** Synchronous file/crypto operations on request path → DoS.

```bash
grep -rn "readFileSync\|writeFileSync\|execSync\|pbkdf2Sync\|scryptSync\|randomBytes.*Sync" --include="*.js" --include="*.ts" | grep -v node_modules | grep -v test | grep -v config
```

**What to check:**
- Is the sync operation on a request handler path? (blocks all other requests)
- Can user control the input size? (large file read, expensive crypto)
- Is there a worker thread or cluster to mitigate?

---

### 10. Insecure Dependencies (Quick Check)

```bash
# Check for known vulnerable patterns in package.json
cat package.json | grep -E "\"(node-serialize|serialize-javascript|merge-deep|mixin-deep|defaults-deep|set-value|lodash)\"" 
# Check npm audit
npm audit --json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'Critical:{d.get(\"metadata\",{}).get(\"vulnerabilities\",{}).get(\"critical\",0)} High:{d.get(\"metadata\",{}).get(\"vulnerabilities\",{}).get(\"high\",0)}')"
```

---

## Finding Severity Guide

| Pattern | Typical Severity | Condition for Upgrade |
|---------|-----------------|---------------------|
| path.join traversal → file read | Medium-High | + sensitive file readable (secrets, source) |
| Zip Slip → file write | High | + write to execution path (plugins, web root) = Critical |
| Dynamic require with user path | Critical | Direct RCE |
| Prototype pollution | Medium | + RCE gadget (EJS, child_process) = Critical |
| vm sandbox escape | High-Critical | Depends on what's accessible outside sandbox |
| node-serialize unserialize | Critical | Direct RCE via IIFE |
| ReDoS | Medium (DoS) | + single request blocks event loop = High |
| HPP type confusion | Low-Medium | + leads to auth bypass or injection = High |

---

## Cross-Reference

- **ptest skill**: `references/nodejs-library-attacks.md` — exploitation perspective (payloads, PoCs)
- **This scanner**: detection perspective (grep patterns, what to check in code)
- **vuln-file-path.md**: general file/path traversal (language-agnostic)
- **vuln-injection.md**: command injection via child_process
- **vuln-dos.md**: ReDoS (language-agnostic patterns)
