# Write Access Response Protocol

When write access (POST/PUT/PATCH/DELETE) succeeds on an unauthenticated endpoint, follow this decision tree:

```
Write Access Confirmed
├── Is this PRODUCTION?
│   ├── YES → Minimize impact. ONE record is sufficient proof.
│   │   ├── Use obviously-fake data: {"name":"PENTEST-PROBE-DELETE","code":"PT-DELETE"}
│   │   ├── Do NOT test PATCH/PUT on existing records (risk of corrupting real data)
│   │   ├── Prove PATCH exists without corrupting: test on the record YOU just created
│   │   └── Document record ID immediately for client cleanup
│   └── NO (nonprod) → More latitude, but still document for cleanup
│
├── Can you DELETE the test record?
│   ├── YES → Delete immediately, screenshot before/after as evidence
│   └── NO (no DELETE endpoint or DELETE returns 405/403)
│       ├── Can you PATCH it to a flagged state?
│       │   ├── YES → PATCH name to "PENTEST-DELETE-ME-{date}" so client can find it
│       │   └── NO → Leave as-is, document in cleanup appendix
│       └── Add to "Test Records Created" cleanup table
│
├── Is the write DESTRUCTIVE? (overwrites/deletes existing data)
│   ├── YES → DO NOT EXECUTE on real records
│   │   ├── Prove the method is accepted: send request with empty/malformed body
│   │   ├── Document: "PUT /resource/1 returns 400 (bad body) not 401/405 — write method accepted"
│   │   ├── Or: test on YOUR created record only
│   │   └── This is sufficient evidence without corrupting production data
│   └── NO (creates new record) → Safe to execute once as proof
│
└── Documentation requirements:
    ├── Screenshot/save the response showing successful write
    ├── Record the exact ID/key of created records
    ├── Add to report "Appendix: Test Records (Client Cleanup Required)"
    ├── Format: | Environment | Endpoint | Record ID | Data Written | Action Needed |
    └── Notify client in debrief that cleanup is needed
```

## Test Payload Conventions

- Always use obviously-fake data that's easy to find and delete
- Include "PENTEST" or "DELETE-ME" in the name/description field
- Use code/identifier like "PT-{date}" (e.g., "PT-20260521")
- Never use real-looking data that could be confused with legitimate records
- Never write offensive/inappropriate content (it's production)

## Proving Write Without Writing (when risk is too high)

```bash
# Method 1: OPTIONS check
curl -sk -X OPTIONS "$ENDPOINT" -D- | grep "Allow:"
# If Allow: GET, POST, PUT, DELETE → methods accepted

# Method 2: Empty body (triggers 400, not 401/405)
curl -sk -X POST "$ENDPOINT" -H "Content-Type: application/json" -d '{}' -w "[%{http_code}]"
# 400 = endpoint accepts POST but body is invalid (PROVES write access exists)
# 401/403 = auth required (safe)
# 405 = method not allowed (safe)

# Method 3: Invalid content-type (triggers 415, not 401)
curl -sk -X POST "$ENDPOINT" -H "Content-Type: text/plain" -d 'test' -w "[%{http_code}]"
# 415 = Unsupported Media Type (PROVES endpoint processes POST requests)
```

## Cleanup Appendix Format (add to report)

```markdown
## Appendix: Test Records Created (Client Cleanup Required)

| # | Environment | Endpoint | Record ID | Data Written | Date | Action |
|---|-------------|----------|-----------|-------------|------|--------|
| 1 | PROD | /master/v1/general | 5668 | {"name":"PENTEST-PROBE","code":"PT"} | 2026-05-21 | DELETE |
| 2 | SIT | /master/v1/general | 8078 | {"name":"PENTEST-PROBE","code":"PT"} | 2026-05-21 | DELETE |
```
