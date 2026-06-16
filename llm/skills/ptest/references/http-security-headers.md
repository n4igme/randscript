# HTTP Security Headers Checklist

Quick-reference for testing HTTP response security headers (Phase 5).

## Header Checklist

| Header | Expected Value | Impact if Missing |
|--------|---------------|-------------------|
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | Clickjacking |
| `Content-Security-Policy` | Restrictive policy | XSS, data injection |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | SSL stripping |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing attacks |
| `X-XSS-Protection` | `0` (deprecated) or absent | N/A (legacy) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Referer leakage |
| `Permissions-Policy` | Feature restrictions | Unwanted API access |
| `Cache-Control` | `no-store` (for sensitive pages) | Cached credentials |
| `Cross-Origin-Opener-Policy` | `same-origin` | Cross-origin attacks |
| `Cross-Origin-Resource-Policy` | `same-origin` | Spectre-style leaks |

## Quick Test

```bash
# Get all response headers
curl -sk -I "https://target.com/" 2>&1 | grep -iE "^(x-frame|content-security|strict-transport|x-content-type|referrer-policy|permissions-policy|cache-control|cross-origin|x-xss|server|x-powered)"

# One-liner gap analysis
curl -sk -I "https://target.com/" 2>&1 | python3 -c "
import sys
headers = {l.split(':')[0].lower().strip() for l in sys.stdin if ':' in l}
expected = ['x-frame-options','content-security-policy','strict-transport-security',
            'x-content-type-options','referrer-policy','permissions-policy']
missing = [h for h in expected if h not in headers]
print('Missing headers:')
for h in missing: print(f'  - {h}')
if not missing: print('  (none - all present)')
"
```

## Header Details

### X-Frame-Options (Clickjacking)
```
X-Frame-Options: DENY              # Never allow framing
X-Frame-Options: SAMEORIGIN        # Only same-origin framing
```
**Superseded by:** `Content-Security-Policy: frame-ancestors 'self'`
**Finding if missing:** Clickjacking (CWE-1021)

### Content-Security-Policy
```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'self'
```
**Dangerous values:** `unsafe-inline`, `unsafe-eval`, `*`, `data:` in script-src
**Finding if missing:** XSS impact amplified (CWE-693)

### Strict-Transport-Security (HSTS)
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```
**Check:** `max-age` should be ≥31536000 (1 year)
**Finding if missing:** SSL stripping via MITM (CWE-319)

### X-Content-Type-Options
```
X-Content-Type-Options: nosniff
```
**Finding if missing:** MIME type confusion attacks (CWE-16)

### Referrer-Policy
```
Referrer-Policy: strict-origin-when-cross-origin
```
**Dangerous:** `unsafe-url` or absent (full URL leaked in Referer)
**Finding if missing:** Token/path leakage via Referer (CWE-200)

### Cache-Control (Sensitive Pages)
```
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
```
**Required on:** Login pages, profile pages, API responses with PII
**Finding if missing on sensitive page:** Cached credentials (CWE-524)

## Server Information Disclosure

| Header | Issue |
|--------|-------|
| `Server: Apache/2.4.52 (Ubuntu)` | Version disclosed |
| `X-Powered-By: PHP/8.1.2` | Technology + version |
| `X-AspNet-Version: 4.0.30319` | .NET version |
| `X-Debug-Token: abc123` | Debug mode exposed |

**Remediation:** Remove or genericize (e.g., `Server: webserver`)

## Severity Guide

| Finding | Typical Severity |
|---------|-----------------|
| Missing CSP + XSS present | Medium (enables exploitation) |
| Missing X-Frame-Options (standalone) | Low |
| Missing HSTS | Low-Medium (depends on sensitivity) |
| Missing X-Content-Type-Options | Low |
| Server version disclosure | Informational |
| Missing Cache-Control on login | Low |
| CSP with unsafe-inline + unsafe-eval | Low-Medium |

## Reporting Template

```markdown
## Missing Security Header: [HEADER_NAME]

**Severity:** Low
**CWE:** CWE-[NUMBER]
**Asset:** target.com

### Evidence
Response headers from: GET https://target.com/

[paste relevant headers]

Missing: [HEADER_NAME]

### Impact
[Specific attack enabled]

### Remediation
Add the following header to server configuration:
[header: value]

Apache: Header always set [HEADER] "[VALUE]"
Nginx:  add_header [HEADER] "[VALUE]" always;
```
