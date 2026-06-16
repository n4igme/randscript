# Laravel Default Password ATO Chain

## Trigger Conditions
- Laravel app with `/api/get-params/{type}` endpoint
- Multi-tenant contact center / CRM pattern (BlueSpider, Saji, etc.)
- Multiple dev/staging/prod hosts sharing codebase

## Attack Chain

```
1. GET /api/get-params/passDefault → default password (unauth)
2. GET /api/load-user → full user list with emails (unauth)
3. POST /login with email + default password → session
4. Access dashboard → customer PII, SIP creds, internal data
```

## Key Observations (BlueSpider, June 2026)

### Endpoint Discovery
- `/api/load-user` may exist on prod but NOT in dev JS bundle
- Always diff JS bundles between environments
- `/api/user-combo-username` returns usernames only (NOT emails)
- Login requires EMAIL format — usernames alone are useless for brute-force

### passDefault Enumeration
- Test on ALL subdomains — auth requirements differ per host
- Dev hosts often expose it unauthenticated while prod may gate it
- In this case, PROD also exposed it unauthenticated
- Different environments have different default passwords:
  - Dev: `12345678`
  - Prod (Bank Jago): `JAGO1234!`
  - Client-specific (Bina): `Bscrm123!`

### Login Behavior
- HTTP 204 = successful login (Laravel Sanctum)
- HTTP 422 = wrong credentials
- HTTP 429 = rate limited (IP-based, ~5 attempts/60s)
- Rate limit is global per IP, not per user
- New session per attempt does NOT bypass rate limit

### Post-Auth Data
- Inertia `data-page` attribute contains full user props
- `checkToken.token` = session validation token (NOT API token)
- `auth.sip[].dnPassword` = SIP/VoIP credentials
- `auth.sip[].websocket_server_url` = PBX WebSocket
- `/dashboardStatus/*` routes use session auth (not token)
- `/api/*` routes use separate token auth system

## Param Types to Enumerate
When `/api/get-params/{type}` is found, try:
- passDefault, PASSWORD, DEFAULT_PASSWORD
- VERIFIKASI, CATEGORY, STATUS, DEPARTMENT
- CHANNEL, SLA, PRIORITY, ROLE
- API_KEY, SECRET, CONFIG

## Results (BlueSpider, June 2026)
- 69/90 active PRODUCTION accounts compromised
- Including: 1 SUPER ADMIN, 5 MANAGER, 1 SPV, 61 AGENT
- Customer PII accessed (names, campaign data)
- SIP infrastructure credentials obtained
