# Supabase Backend Testing Methodology

## Overview

Supabase is a Firebase alternative used by many modern web apps. When detected, follow this systematic approach to test for misconfigurations.

## Detection Signals

- CNAME to `*.supabase.co` on auth/API subdomains
- `createBrowserClient()` or `createClient()` in JS bundles
- `sb-project-ref` header in responses
- `supabase-js-*` version strings in JS
- JWT tokens with `iss: "supabase"` and `ref: "<project-ref>"`

## Finding the Anon Key

The anon key is required for all Supabase API calls. Search for it in:

1. **JS chunks** — grep for `eyJ` (JWT prefix) or `sb_publishable_` (newer format)
2. **RSC stream** — `curl -sk <url> -H "RSC: 1"` and grep
3. **`__NEXT_DATA__`** — inline JSON in page source
4. **Network requests** — `apikey` header in authenticated requests
5. **Build manifest** — `/_next/static/<buildId>/_buildManifest.js`

Note: Newer Supabase uses `sb_publishable_*` format instead of JWT `eyJ*` format.

## Testing Checklist (with anon key)

```bash
SUPABASE_URL="https://<project-ref>.supabase.co"
ANON_KEY="<key>"

# 1. Auth settings (reveals enabled providers, signup policy)
curl -sk "${SUPABASE_URL}/auth/v1/settings" -H "apikey: ${ANON_KEY}"
# Key fields: disable_signup, mailer_autoconfirm, external.github/gitlab/etc

# 2. List accessible tables via REST
curl -sk "${SUPABASE_URL}/rest/v1/" -H "apikey: ${ANON_KEY}" -H "Authorization: Bearer ${ANON_KEY}"
# 401 with "Secret API key required" = schema listing blocked (good)
# 200 with table list = schema exposed (finding)

# 3. Query known tables (from JS/app analysis)
curl -sk "${SUPABASE_URL}/rest/v1/<table>?select=*&limit=10" \
  -H "apikey: ${ANON_KEY}" -H "Authorization: Bearer ${ANON_KEY}"
# 200 with data = RLS not enforced or SELECT allowed for anon (finding)
# 200 with [] = RLS filtering (no data visible to anon)
# 401/403 = table not accessible

# 4. Test INSERT (RLS bypass)
curl -sk -X POST "${SUPABASE_URL}/rest/v1/<table>" \
  -H "apikey: ${ANON_KEY}" -H "Authorization: Bearer ${ANON_KEY}" \
  -H "Content-Type: application/json" -H "Prefer: return=representation" \
  -d '{"name":"pentest-probe"}'
# 201 = RLS bypass on INSERT (HIGH finding)
# 401 with "violates row-level security policy" = RLS enforced (good)
# 400 with column error = reveals schema (info disclosure)

# 5. Enumerate RPC functions
curl -sk -X POST "${SUPABASE_URL}/rest/v1/rpc/nonexistent" \
  -H "apikey: ${ANON_KEY}" -H "Authorization: Bearer ${ANON_KEY}" \
  -H "Content-Type: application/json" -d '{}'
# Error "hint" field may reveal actual function names (info disclosure)

# 6. Storage buckets
curl -sk "${SUPABASE_URL}/storage/v1/bucket" \
  -H "apikey: ${ANON_KEY}" -H "Authorization: Bearer ${ANON_KEY}"
# 200 with bucket list = storage enumerable
# Then try: /storage/v1/object/list/<bucket-name>

# 7. GraphQL (if pg_graphql extension enabled)
curl -sk -X POST "${SUPABASE_URL}/graphql/v1" \
  -H "apikey: ${ANON_KEY}" -H "Authorization: Bearer ${ANON_KEY}" \
  -H "Content-Type: application/json" -d '{"query":"{ __typename }"}'

# 8. Realtime (WebSocket subscriptions)
# Can subscribe to table changes if RLS allows

# 9. OAuth signup (if providers enabled + signup not disabled)
curl -sk "${SUPABASE_URL}/auth/v1/authorize?provider=github"
# Returns redirect URL with client_id (info disclosure)

# 10. Email signup (if mailer_autoconfirm=true + email enabled)
curl -sk -X POST "${SUPABASE_URL}/auth/v1/signup" \
  -H "apikey: ${ANON_KEY}" -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Test123!"}'
# If autoconfirm=true, account is immediately active (no email verification)
```

## Schema Enumeration via Errors

Even when tables return empty results, you can probe column existence:

```bash
# Column exists → 200 (empty or filtered)
curl -sk "${SUPABASE_URL}/rest/v1/<table>?id=eq.1" -H "apikey: ${ANON_KEY}" -H "Authorization: Bearer ${ANON_KEY}"

# Column doesn't exist → 400 with error message
curl -sk "${SUPABASE_URL}/rest/v1/<table>?nonexistent_col=eq.1" -H "apikey: ${ANON_KEY}" -H "Authorization: Bearer ${ANON_KEY}"
# {"code":"42703","message":"column <table>.nonexistent_col does not exist"}
```

## Severity Assessment

| Finding | Severity | Rationale |
|---------|----------|-----------|
| Anon key in client JS | Info (by design) | Supabase expects this — security relies on RLS |
| RLS bypass (read other users' data) | High | Unauthorized data access |
| RLS bypass (write/modify) | Critical | Unauthorized data modification |
| Auth settings exposure | Low | Reveals attack surface but no direct impact |
| Schema enumeration via errors | Low | Info disclosure, aids further attacks |
| Storage bucket listing | Medium | Depends on bucket contents |
| Signup without email verification | Medium | Account creation abuse, depends on app |
| RPC function name leak | Low | Info disclosure via error hints |
| OAuth client_id exposure | Info | Public by design in OAuth flows |

## Common Misconfigurations

1. **RLS not enabled on tables** — devs forget to enable RLS, making all data public to anon key holders
2. **Overly permissive RLS policies** — `USING (true)` on SELECT = anyone can read everything
3. **mailer_autoconfirm + email signup** — instant account creation without verification
4. **Storage buckets without RLS** — uploaded files accessible to anyone with anon key
5. **RPC functions without security definer** — execute with caller's permissions (anon)

## Hacken Engagement Example (2026-05-25)

- Project: znksrgcjncicswolrntc.supabase.co
- Key format: `sb_publishable_*` (non-JWT, newer Supabase)
- Tables found: repositories, organizations, github_installations, gitlab_groups, bitbucket_workspaces
- RLS enforced on writes (organizations INSERT blocked)
- Auth: GitHub/GitLab/Bitbucket OAuth enabled, email disabled
- RPC leak: `get_trace_events_ordered` revealed via error hint
- OAuth client_id: Ov23liAsUz6KT94gieHZ
