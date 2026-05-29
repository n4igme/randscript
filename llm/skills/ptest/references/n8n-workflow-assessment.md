# n8n Workflow Automation Assessment

## Overview

n8n is a self-hosted workflow automation tool (similar to Zapier). When exposed, it can reveal sensitive configuration, allow workflow execution, or provide access to connected services (databases, APIs, email).

## Discovery Signals

- Server responds with n8n HTML page (14-15KB, contains "n8n" in body)
- `via: 1.1 google` header (often deployed on GCP)
- Path `/healthz` returns `{"status":"ok"}`

## Unauthenticated Endpoints

### /rest/settings (CRITICAL — often unauthenticated)

Returns instance configuration without auth:

```json
{
  "data": {
    "versionCli": "1.121.3",
    "instanceId": "336c90574c...",
    "userManagement": {
      "authenticationMethod": "email",
      "smtpSetup": true
    },
    "sso": {
      "saml": {"loginEnabled": false},
      "ldap": {"loginEnabled": false},
      "oidc": {"loginEnabled": false, "loginUrl": "...", "callbackUrl": "..."}
    },
    "mfa": {"enabled": true, "enforced": false},
    "oauthCallbackUrls": {
      "oauth1": "https://host/rest/oauth1-credential/callback",
      "oauth2": "https://host/rest/oauth2-credential/callback"
    },
    "telemetry": {
      "config": {"key": "...", "url": "https://telemetry.n8n.io"}
    }
  }
}
```

**What this reveals:**
- Exact version (check for CVEs)
- Auth method (email, SAML, LDAP, OIDC)
- Whether MFA is enforced (if not → password spray viable)
- OAuth callback URLs (potential for OAuth redirect attacks)
- SMTP configured (can send emails → phishing from internal tool)
- Telemetry key (minor info leak)
- Instance ID (fingerprinting)

### /healthz

Returns `{"status":"ok"}` — confirms n8n is running.

### /.well-known/oauth-authorization-server (MCP OAuth metadata)

Returns OAuth server metadata including registration endpoint:
```json
{
  "issuer": "https://host",
  "registration_endpoint": "https://host/mcp-oauth/register",
  "authorization_endpoint": "https://host/mcp-oauth/authorize",
  "token_endpoint": "https://host/mcp-oauth/token",
  "scopes_supported": ["tool:listWorkflows", "tool:getWorkflowDetails"]
}
```

If this returns 200 → **CVE-2026-42236 exploitable**. See `references/n8n-mcp-oauth-exploitation.md`.

### /mcp-oauth/register (Unauthenticated client registration)

POST with JSON body registers an OAuth client. No auth required. Returns 201 with client_id + client_secret. Rate limited after ~15 requests but no auth gate.

## Authenticated Endpoints (require session or API key)

| Endpoint | Auth | Method | Info |
|----------|------|--------|------|
| `/rest/workflows` | Session | GET | List all workflows |
| `/rest/executions` | Session | GET | Execution history |
| `/rest/credentials` | Session | GET | Stored credentials |
| `/rest/users` | Session | GET | User list |
| `/rest/login` | None | POST | Login endpoint |
| `/api/v1/workflows` | X-N8N-API-KEY | GET | API access to workflows |
| `/api/v1/executions` | X-N8N-API-KEY | GET | API access to executions |
| `/api/v1/credentials` | X-N8N-API-KEY | GET (405) | Credentials via API |
| `/webhook/` | Varies | * | Webhook triggers (may be unauthenticated) |
| `/webhook-test/` | Varies | * | Test webhook triggers |

## Attack Vectors

1. **MCP OAuth Client Registration (UNAUTH → workflow theft)** — see `references/n8n-mcp-oauth-exploitation.md` for full chain. Check `/.well-known/oauth-authorization-server` for registration endpoint. If returns 200 with `registration_endpoint` → register rogue client → phish user → read workflows.
2. **Version-based CVEs** — check version against known n8n vulnerabilities
3. **Credential brute-force** — if MFA not enforced and auth is email-based
4. **Webhook abuse** — `/webhook/*` paths may trigger workflows without auth (RCE via CVE-2026-42231)
5. **OAuth callback manipulation** — if OIDC is configured
6. **SSRF via workflows** — if you gain access, workflows can make arbitrary HTTP requests
7. **Telemetry data injection** — write key allows polluting analytics pipeline

## Severity Assessment

| Finding | Severity |
|---------|----------|
| /rest/settings unauthenticated (version + config) | Low-Medium |
| /rest/settings + version has unpatched Critical CVEs | Medium (escalates the info disclosure) |
| Telemetry write key valid (data injection) | Low |
| Workflow list accessible without auth | High |
| Credentials accessible without auth | Critical |
| Webhook triggers without auth (depends on workflow) | Medium-High |
| Webhook + CVE-2026-42231 (XML prototype pollution RCE) | Critical |
| Version disclosure only | Info |

## Telemetry Key Exploitation

The `telemetry.config.key` is a **RudderStack write key**. Test it:

```bash
# Verify write access
curl -X POST https://telemetry.n8n.io/v1/track \
  -u "TELEMETRY_KEY:" \
  -H "Content-Type: application/json" \
  -d '{"userId":"probe","event":"test"}'
# Returns "ok" if valid

# Other writable endpoints (all return 200 "ok" with valid key):
# POST /v1/identify, /v1/batch, /v1/alias, /v1/group, /v1/page
```

**Impact:** Can inject fake telemetry events (data pollution). Write-only — cannot read existing analytics. Low severity alone but documents the exposure.

**RudderStack health check (no auth):**
```
GET https://telemetry.n8n.io/health
→ {"appType":"GATEWAY","server":"UP","db":"UP","acceptingEvents":true}
```

## CVE Assessment (version-based)

n8n versions < 1.123.x have multiple unpatched CVEs. After confirming version via `/rest/settings`, check:

**Unauthenticated (exploitable without login):**
- **CVE-2026-42231** (Critical): Prototype Pollution in XML Webhook Body → RCE. Requires knowing a valid webhook path.
- **CVE-2026-42236** (High): Unauthenticated Denial of Service.
- **CVE-2026-42228** (Medium): Hijacking of Unauthenticated Channel.

**Authenticated (post-login, useful if creds obtained):**
- **CVE-2026-44791** (Critical): XML Node Prototype Pollution → RCE
- **CVE-2026-44790** (Critical): Arbitrary File Read via Git Node
- **CVE-2026-44789** (Critical): HTTP Request Pagination Prototype Pollution → RCE
- **CVE-2026-44792** (High): Source Control Pull SQL Injection
- **CVE-2026-42234** (High): Python Task Runner Sandbox Escape

**Check latest advisories:** `gh api /advisories?ecosystem=npm&affects=n8n`

## Webhook Brute Force

Webhooks are the key to unauthenticated RCE (CVE-2026-42231). n8n webhooks use either custom names or UUIDs:

```
/webhook/{name-or-uuid}      # Production webhooks
/webhook-test/{name-or-uuid}  # Test webhooks (active during editing)
```

404 response = webhook doesn't exist. Any other response = active webhook found.
Try: common names (slack, alert, notify, deploy, github, jira, payment, callback), then UUID patterns if needed.

## Auth Endpoint Behavior

- `/rest/forgot-password` — always returns 200 regardless of email validity (no user enumeration). Rate limited after ~2 requests.
- `/rest/login` — returns 400 with validation error if format wrong. Rate limited.
- OAuth flow initiation (`/rest/oauth2-credential/auth`) — requires session (401).
- OAuth callbacks render HTML page but need valid state to process.

## Bank Jago Example (May 2026)

- Host: `n8n.jago.com`
- Version: 1.121.3 (vulnerable to 4 Critical + 7 High CVEs)
- Auth: email-based, MFA enabled but NOT enforced
- OIDC configured but disabled (license required)
- `/rest/settings` fully accessible without auth
- Telemetry key valid for RudderStack writes (confirmed)
- All other endpoints properly require auth (401)
- API requires `X-N8N-API-KEY` header
- No active webhooks found (common names tested)
- Forgot-password rate limited after 2 requests
