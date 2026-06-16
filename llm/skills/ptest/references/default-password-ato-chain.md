# Default Password ATO Chain

## Origin: BlueSpider Contact Center (Bank Jago), June 2026

## Pattern
Many SaaS/contact center platforms store system configuration (including default passwords) in a parameters table accessible via API. When these parameter endpoints lack authentication, the default password is publicly exposed.

## Attack Chain
1. **Discover param endpoint**: `/api/get-params/{type}` found in JS bundle
2. **Enumerate param types**: Test `passDefault`, `password`, `defaultPassword`, `config`, `secret`
3. **Extract default password**: Response contains `param_value` with cleartext password
4. **Get user emails**: Find endpoint returning full user objects with email field (`/api/load-user`, `/api/users`, `/api/get-all-users`)
5. **Mass login spray**: Combine all emails + default password
6. **Result**: Any user who hasn't changed from default is compromised

## Indicators This Pattern Exists
- Laravel/PHP application with Sanctum auth
- `/api/get-params/{type}` style wildcard routes
- `/api/reset-default-password` endpoint visible in JS (confirms a default password mechanism)
- User management is admin-only (no self-registration)

## Key Findings (BlueSpider)
- Dev environments: `12345678` (generic)
- Production (Bank Jago): `JAGO1234!`
- Another client (Bina Persada): `Bscrm123!`
- 69/90 active production accounts still using default password
- Including SUPER ADMIN service account

## Enumeration Wordlist for Param Types
```
passDefault
password
defaultPassword
defaultPass
CONFIG
SECRET
API_KEY
SLA
CATEGORY
STATUS
DEPARTMENT
CHANNEL
VERIFIKASI
EMAIL
SMS
TEMPLATE
```

## Why Users Don't Change Default Passwords
- Contact center agents are provisioned in bulk
- No forced password change on first login
- Agents use the system via supervised workstations (perceived low risk)
- Service accounts (`svc.*`) are set-and-forget

## Severity
- Critical when: default password exposed unauth + user list with emails exposed unauth + active accounts still use default
- High when: default password exposed but no user email list found (need to guess email format)
- Medium when: default password exposed but auth required to trigger password reset
