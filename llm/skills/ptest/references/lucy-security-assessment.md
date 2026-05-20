# Lucy Security Platform Assessment

## Overview

Lucy Security is a phishing simulation / security awareness training platform. Common in enterprise environments (often on separate infrastructure like Hetzner/DigitalOcean). Runs on PHP (Yii framework) with Apache/nginx.

## Identification

- `Server: Lucy` header
- PHP sessions (`PHPSESSID`)
- Login page title contains organization name + "Login"
- `/loginforms` endpoint returns JSON with CSRF token and login form templates
- JS/CSS files tagged with `?v=X.Y.Z` (version disclosure)
- Default error page mentions "PLEASE EDIT ME IN THE UI UNDER SETTINGS/WHITELABEL"

## Assessment Checklist

### 1. Version Discovery
- Check CSS/JS version tags: `/public/assets/all.css?v=4.9.2`
- Check `/loginforms` response for version indicators

### 2. Port Enumeration
- Port 443: User-facing phishing pages + admin login
- Port 8443: Dedicated admin interface (common Lucy config)
- Port 25: SMTP relay for phishing campaigns (Postfix)
- Port 80: HTTP redirect

### 3. API Discovery
Lucy has a REST API that accepts JWT tokens:
```bash
# Check if API exists
curl -sk "https://target:8443/api/version"
# Expected: {"error":"No token header."}

# Determine JWT algorithm
# Send Bearer token with different alg headers:
# "Algorithm not supported" = not accepted
# "Algorithm not allowed" = recognized but blocked
# "Signature verification failed" = THIS IS THE ACCEPTED ALGORITHM

# Known valid endpoints:
/api/version    # Version info
/api/campaigns  # Campaign data (employee emails, results)
/api/domains    # Domain configuration
```

### 4. JWT Algorithm Enumeration
```bash
for alg in HS256 HS384 HS512 RS256 RS384 RS512 ES256 PS256; do
  # Build JWT with each alg, send to /api/version
  # Look for "Signature verification failed" (= accepted alg)
done
```
In Bank Jago engagement: HS512 was the accepted algorithm.

### 5. Sensitive File Probing
Lucy (Yii framework) has predictable file paths:
```
/.env                          # Environment config (JWT secret, DB creds, SMTP creds)
/.git/HEAD                     # Source code repository
/protected/config/main.php     # Yii main config
/protected/config/db.php       # Database credentials
/protected/runtime/application.log  # Application logs
/server-status                 # Apache mod_status
/robots.txt                    # Usually "Disallow: /"
```
All typically return 403 (Apache blocks). Bypass attempts:
- Path traversal via `/public/..%2f.git/HEAD`
- Case variation `/.GIT/HEAD`
- Null byte `/.git/HEAD%00.html`
- Query string `/.git/HEAD?`
- Semicolon `/.git;/HEAD`

In Bank Jago engagement: All bypasses failed — Apache blocks at pattern level.

### 6. CORS Testing
Lucy often has wildcard CORS (misconfiguration):
```bash
curl -sk -X OPTIONS "https://target:8443/admin/login" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST"
# Look for: Access-Control-Allow-Origin: *
```
If wildcard: cross-origin session theft is possible when admin is logged in.

### 7. SMTP Relay Testing
```bash
# Banner grab
nc target 25
# Check for open relay
EHLO test.com
MAIL FROM:<test@test.com>
RCPT TO:<external@gmail.com>
# 554 = relay denied (good)
# 250 = OPEN RELAY (critical finding)

# VRFY enumeration
VRFY postmaster  # 252 = exists
VRFY admin       # 554 = doesn't exist or relay denied
```

### 8. Authentication Testing
- Login form at `/admin` or `/admin/login`
- CSRF protected (YII_CSRF_TOKEN)
- Must get fresh session + CSRF before each login attempt
- Default creds: `admin@admin.com / admin` (rarely works on deployed instances)
- No password reset endpoint (typically disabled)
- No registration endpoint

### 9. Unauthenticated Endpoints
```
/loginforms     # Returns CSRF + all login form HTML templates (always accessible)
/user           # User-facing phishing landing (302 → /user)
/public/*       # Static assets (301)
```

## Key Findings Pattern

| Finding | Severity | Likelihood |
|---------|----------|-----------|
| CORS wildcard on admin | Medium | High (common misconfiguration) |
| API with JWT auth exposed | Medium | High (always present) |
| .env/.git on disk (403) | Low-Medium | High (common in deployments) |
| SMTP VRFY enabled | Low | Medium |
| SMTP open relay | Critical | Low (usually configured correctly) |
| Default credentials | Critical | Low (usually changed) |
| JWT weak secret | High | Low-Medium (depends on deployment) |

## Pitfalls

- **Rate limiting**: Hetzner-hosted Lucy instances aggressively rate-limit. Don't use large wordlists for directory brute-force. Use targeted lists (50-100 paths max).
- **CSRF on login**: Must maintain session cookies and extract fresh CSRF token for each login attempt. Stateless brute-force won't work.
- **403 vs 404 distinction**: Lucy returns custom 404 pages (1078 bytes, pink background "This page does not exist!"). Real 403s are Apache-level (275 bytes). Use size to distinguish.
- **Port 8443 vs 443**: Admin interface may only be on 8443. Always check both ports — they may have different vhost configs.
