## Phase 1: Scope & Recon

### Gate: endpoints mapped, auth flow documented, API surface understood, at least one valid token obtained (or documented as unobtainable). OR: `mtest-output/phase8-api/phase8-handoff.md` exists from a prior mtest engagement (skip discovery, use provided artifacts).

**mtest handoff fast-path:** If starting atest after mtest Phase 8, check for `phase8-handoff.md` in the mtest output. If it exists, load it — it contains: auth script path, required headers, host mapping, device context, endpoint list, and constraints. Skip endpoint discovery and token acquisition. Go directly to Phase 2.

**Token acquisition is a Phase 1 exit criterion.** You cannot test BOLA/IDOR without a token. Before advancing to Phase 2, you must have:
- ✅ At least one valid authenticated token, OR
- ✅ Documented proof that no token is obtainable (no self-registration, no default creds, no provided creds) — Phase 2 then runs unauthenticated-only testing

**Token Acquisition Attempts (do this BEFORE advancing):**

**Mobile app with device attestation (Eversafe, SafetyNet, etc.):**
When transitioning from mtest Phase 8 → atest, check if attestation tokens are forgeable before assuming you need the real app. Eversafe TLV tokens can be forged (see mtest `references/eversafe-attestation.md`). Pattern: forge attestation → enroll device via API → register your own RSA key → sign logins independently. If attestation is NOT forgeable, use HTTP Toolkit to capture Bearer JWTs from the app and use those directly (5min window per token).

```bash
# Default credentials
for creds in admin:admin admin:password root:root test:test admin:changeme; do
  user=$(echo $creds | cut -d: -f1); pass=$(echo $creds | cut -d: -f2)
  curl -s "$BASE_URL/api/auth/login" -X POST -H "Content-Type: application/json" \
    -d "{\"username\":\"$user\",\"password\":\"$pass\"}"
done

# Empty/null password (if MinPasswordLength:0 found in config)
curl -s "$BASE_URL/api/auth/login" -X POST -H "Content-Type: application/json" \
  -d '{"username":"admin","password":""}'

# Registration endpoint (self-signup)
for path in /api/auth/register /api/register /api/signup /api/users/create; do
  curl -s "$BASE_URL$path" -X POST -H "Content-Type: application/json" \
    -d '{"username":"pentest@test.com","password":"Test1234!","email":"pentest@test.com"}' \
    -w "\n%{http_code}"
done

# OAuth/OIDC public client flows
# Check /.well-known/openid-configuration for token_endpoint
```

**With docs vs without docs:**
- **With OpenAPI/Swagger/introspection:** Phase 1 takes ~10% of time. Parse the spec, map all endpoints, move quickly to Phase 2. Your job is validation, not discovery.
- **Without docs (blind):** Phase 1 expands to ~25-30% of time. You need: JS bundle extraction, path fuzzing, error-based parameter discovery, response analysis to infer data models. Invest here — you can't test what you haven't found.

**Techniques:**

1. **Documentation Discovery:**
   ```bash
   # OpenAPI/Swagger
   for path in /swagger.json /openapi.json /api-docs /swagger-ui.html /v2/api-docs /v3/api-docs; do
     curl -sk -o /dev/null -w "%{http_code} $path\n" "$BASE_URL$path"
   done

   # GraphQL introspection
   curl -s "$BASE_URL/graphql" -H "Content-Type: application/json" \
     -d '{"query":"{ __schema { queryType { fields { name } } mutationType { fields { name args { name type { name kind ofType { name } } } } } } }"}'

   # gRPC reflection
   grpcurl -plaintext $HOST:$PORT list
   grpcurl -plaintext $HOST:$PORT describe <service>
   ```

2. **Endpoint Enumeration:**
   - Parse OpenAPI spec for all paths + methods
   - Extract from JS bundles if frontend exists
   - Fuzz common API paths: `/api/v1/users`, `/api/v1/admin`, `/internal/`
   - Check for versioning: `/v1/`, `/v2/`, `/v3/` (older versions may lack auth)

3. **Authentication Flow:**
   - Document token lifecycle (obtain → refresh → expire)
   - Identify token type and claims (JWT decode)
   - Map which endpoints require auth vs public
   - Check for API key in headers vs query params

4. **Response Analysis:**
   - Identify data models from responses
   - Note sequential/predictable IDs (IDOR candidates)
   - Check error verbosity (stack traces, internal paths)
   - Document rate limit headers (`X-RateLimit-*`, `Retry-After`)

5. **Error Intelligence:**
   Extract library/framework info from deliberate malformed requests:
   ```bash
   # Type confusion — send wrong types to reveal Go/Java/Python struct info
   curl -s "$BASE_URL/api/login" -X POST -H "Content-Type: application/json" \
     -d '{"username":"admin","password":true}'
   # Look for: "cannot unmarshal bool into Go struct field .password of type string"
   #           "JsonWebTokenError: jwt malformed"
   #           "TypeError: expected string, got int"

   # Missing fields — reveals required parameters
   curl -s "$BASE_URL/api/login" -X POST -H "Content-Type: application/json" -d '{}'

   # Overflow/boundary — reveals validation logic
   curl -s "$BASE_URL/api/login" -X POST -H "Content-Type: application/json" \
     -d '{"username":"'$(python3 -c "print('A'*10000)")'"}'
   ```
   **What to extract:** JWT library name, language/framework, struct field names, internal error codes, validation rules.

6. **Config/Settings Discovery:**
   Many API frameworks expose unauthenticated config endpoints:
   ```bash
   for path in /api/config /api/v0/config/settings /api/settings /config.json \
     /actuator/env /actuator/configprops /.well-known/openid-configuration \
     /api/v1/config /settings /api/info /api/version; do
     resp=$(curl -s -w "|%{http_code}" "$BASE_URL$path" --max-time 5)
     code=$(echo "$resp" | rev | cut -d'|' -f1 | rev)
     [ "$code" != "404" ] && [ "$code" != "000" ] && echo "  $path -> $code"
   done
   ```
   **What to extract:** Auth mechanisms enabled, password policies (MinPasswordLength), feature flags (SelfProvisioning, LoginFormVisible), available backends, version info.

**Reference:** `references/rest-api-patterns.md`, `references/graphql-testing.md`, `references/grpc-testing.md`, `references/mobile-api-auth-patterns.md`

---