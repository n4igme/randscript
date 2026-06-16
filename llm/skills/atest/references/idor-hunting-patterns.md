# IDOR Hunting Patterns

Systematic IDOR/BOLA testing beyond basic ID swapping.

## Setup

1. Create 2+ accounts per role (attacker + victim)
2. Map all endpoints with object references
3. Intercept traffic, swap IDs, observe response differences

## Where to Find IDORs

### Common Parameter Names
```
id, user_id, account_id, file, doc, document, record, item, order,
profile, edit, view, filename, object, num, key, userid, uuid, group, role
```

Also check: JWT claims (`sub`, `org_id`), signed cookies, WebSocket room IDs.

### High-Impact Targets
```
/settings/profile          /api/users/{id}/backup-codes
/user/settings             /api/users/{id}/totp-secret
/api/users/{id}/sessions   /api/users/{id}/disable-2fa
/api/notifications/{id}    /api/webhooks/{id}/config
/api/rooms/{id}/join       /api/live-sessions/{id}
/oauth/authorize (state)   /api/collaborative-docs/{id}
```

---

## Parameter Manipulation Techniques

| Technique | Example |
|-----------|---------|
| Direct swap | `id=1` → `id=2` |
| Add missing ID | `GET /api/messages` → `GET /api/messages?user_id=victim` |
| UUID replacement | Swap one user's GUID with another's |
| Base64 decode+modify | `/api/doc/MjQ2` (246) → `/api/doc/MjQ3` (247) |
| Array wrapping | `{"id":19}` → `{"id":[19]}` |
| JSON object wrap | `{"id":111}` → `{"id":{"id":111}}` |
| Wildcard | `GET /api/users/*` |
| Numeric for UUID | `account_id=UUID` → `account_id=123` |
| Param name swap | `album_id` → `account_id` |
| File type append | `/resource/123` → `/resource/123.json` |
| Case variants | `userId` / `user_id` / `UserId` / `USER_ID` |
| Nested object | `{"profile":{"owner_id":"attacker","target_id":"victim"}}` |

### Multiple Values (HPP)
```
id=123&id=456
user_id=attacker[]&user_id=victim[]
{"user_id":"attacker","user_id":"victim"}  (JSON duplicate keys)
```

---

## Bypass Techniques

### Access Control Bypass
```
# HTTP method switch
GET /api/users/123 → POST /api/users/123

# Content-Type manipulation
Content-Type: application/json → Content-Type: application/xml

# Path traversal
POST /users/delete/MY_ID/../VICTIM_ID

# Old API version
GET /v3/users/123 → 403
GET /v1/users/123 → 200

# Mixed case / path normalization
GET /admin/profile → GET /ADMIN/profile
```

### ID Obfuscation Bypass
- Hashed IDs: collect legitimate hashes, map to users
- Encoded IDs: decode base64/hex, modify, re-encode
- Encrypted IDs: test related IDs, look for patterns

### Mass Assignment
```json
{"name":"John", "role":"admin", "user_id":"victim", "is_admin":true}
```

---

## Blind IDOR Detection

1. Compare response size/time between valid vs invalid IDs
2. Inject Collaborator/webhook URLs in modifiable params — monitor callbacks
3. Side-channel: timing differences, error message variations
4. Cache probing: ETag/If-None-Match to infer object existence

---

## Platform-Specific Patterns

### GraphQL
```graphql
query { user(id: "victim_id") { email password_hash } }
mutation { changePassword(userId: "victim_id", new: "pwned") }
```
Test aliasing, fragments, batched queries. Enforce per-field auth.

### gRPC
- IDs in binary protobuf messages — test with `grpcurl`
- If server reflection enabled, fetch `.proto` definitions

### Presigned URLs (S3/GCS/Azure)
- Tweak object path in presigned URL
- Test cross-tenant reuse
- Modify `X-Amz-Security-Token` or credentials

### WebSocket
- Room IDs as direct object references
- Manipulate subscription channel identifiers

---

## Chaining

- **IDOR + Info Disclosure**: leak UUIDs from one endpoint → exploit IDOR on another
- **IDOR + Stored XSS**: modify another user's profile field → inject XSS
- **IDOR + Feature Abuse**: add items to victim's cart, trigger actions on their behalf
- **IDOR + 2FA Bypass**: access backup codes → disable victim's MFA
- **IDOR + OAuth**: manipulate state/code params → session hijack

### Response-Leaked ID Chaining (SecOps Exam, June 2026)

Some IDOR vulnerabilities require **multi-step chaining** where one request leaks data needed for the next:

**Pattern:** Endpoint returns YOUR data in `RESULT` but leaks ANOTHER user's identifier in a metadata field (e.g., `MESSAGE`, `next_token`, `cursor`).

**Real example (`/api_key` endpoint):**
1. POST with `enc_id=<your_enc_id>&new_user_id=<any_number>`
2. Response: `{"STATUS":1, "MESSAGE":"<OTHER_USER_ENC_ID>", "RESULT":"<YOUR_API_KEY>"}`
3. The `MESSAGE` field leaks another user's encrypted ID
4. Use that leaked enc_id as `enc_id` in next request → get THEIR API key

**Testing methodology:**
1. Make a normal request, note ALL fields in response (not just the obvious data field)
2. Try using response metadata values (MESSAGE, token, cursor, next) as INPUT parameters
3. Vary secondary parameters (user_id, page, offset) — observe which response fields change
4. Chain: response field from request N becomes input for request N+1

**Indicators this pattern exists:**
- Response contains fields you didn't ask for (extra IDs, encoded strings)
- Different `new_user_id`/`offset` values return different metadata but same primary data
- Metadata field looks like an encoded/encrypted identifier (base64, hex, UUID)

---

## Tools

- **Authorize** (Burp): compare responses between user roles
- **AuthMatrix** (Burp): matrix-based access control testing
- **Auto Repeater** (Burp): replay with ID modifications
- **Arjun**: discover hidden parameters
- **RESTler**: stateful REST API fuzzing (auto-generates BOLA cases)
- **Kiterunner**: API endpoint discovery
