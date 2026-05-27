# GitHub OSINT for Leaked Credentials

Technique for discovering leaked API tokens, session IDs, and credentials in public GitHub repositories. Particularly effective for bug bounty targets where developers or third-party integrators accidentally commit secrets.

## When to Use

- Target has a mobile app (session tokens often hardcoded in wrapper scripts)
- Target has third-party integrations (SDK wrappers, automation tools)
- Target uses JWT-based auth (long-lived tokens get committed)
- You need authenticated access but don't have an account

## Search Techniques

### Using `gh` CLI (preferred — returns code results)

```bash
# Search for session headers/tokens
gh search code 'X-mts-ssid' --limit 20
gh search code 'Authorization Bearer <target-domain>' --limit 20

# Search for API keys by header name
gh search code '<custom-auth-header> <target>' --limit 20

# Search for hardcoded tokens in SDK wrappers
gh search code '<target> token secret' --limit 20
gh search code '<target> api_key' --limit 20
```

### Using GitHub API (limited without auth for code search)

```bash
# Repository search (always works)
curl -s 'https://api.github.com/search/repositories?q=<target>+api' | jq '.items[].full_name'

# Code search (requires auth token for results)
curl -s -H "Authorization: token $GH_TOKEN" \
  'https://api.github.com/search/code?q=<auth-header>+<target>&per_page=10'
```

### Common Search Patterns

| Target Type | Search Query |
|---|---|
| Mobile app API | `<app-name> authorization bearer` |
| Custom auth header | `<header-name> <domain>` |
| JWT tokens | `eyJ <domain>` (base64 JWT prefix) |
| API wrappers | `<company> api client secret` |
| Config files | `<domain> token password` |
| SDK repos | `gh search repos '<company> api' --language python` |

## Validating Found Tokens

### JWT Tokens

```python
import json, base64, datetime

token = "eyJ..."
# Decode payload (second segment)
payload_b64 = token.split('.')[1]
payload_b64 += '=' * (4 - len(payload_b64) % 4)
payload = json.loads(base64.urlsafe_b64decode(payload_b64))

# Check expiry
exp = datetime.datetime.fromtimestamp(payload['exp'])
print(f"Expires: {exp}")
print(f"Still valid: {datetime.datetime.now() < exp}")
print(f"Audience: {payload.get('aud')}")
print(f"Subject: {payload.get('sub')}")
```

### Testing Token Validity

```bash
# Test against target API
curl -s -w '\n%{http_code}' 'https://target-api.com/profile' \
  -H 'Authorization: Bearer <token>'

# Check for different responses:
# 200 = valid, authenticated
# 401 = expired or revoked
# 403 = valid but insufficient permissions
# 502 = geo-blocked (try VPN to target region)
```

## Real-World Example: Grab (2026)

Found a merchant JWT in `thgiang/omnichannel-now-grab-baemin` repo:
- Token audience: `MEXUSERS` (merchant)
- Issued: 2021-06-08
- Expires: 2038-07-19 (17-year lifetime!)
- The token was valid but `p.grabtaxi.com` returned 502 from outside Southeast Asia (geo-blocked)

**Lesson:** Even valid tokens may be unusable without a VPN to the target's region.

## Pitfalls

1. **Geo-blocking**: Many APIs (especially SEA companies like Grab, Gojek, Tokopedia) geo-restrict their API gateways. A valid token + 502 response = need regional VPN.
2. **Token rotation**: Some tokens found on GitHub are already rotated. Always validate before building an attack chain.
3. **Scope**: Using leaked tokens from GitHub is generally acceptable in bug bounty IF you only access your own data or prove the concept without accessing others' data. Check program rules.
4. **Rate limits**: GitHub code search has aggressive rate limits without auth. Use `gh` CLI with authenticated session.
5. **False positives**: Many repos contain redacted tokens (`REDACTED`, `xxx`, placeholder values). Check the actual value before celebrating.

## Tools

- `gh` CLI (GitHub CLI) — best for code search
- `trufflehog` — automated secret scanning in repos
- `gitleaks` — detect secrets in git history
- `gitdorker` — GitHub dork automation
