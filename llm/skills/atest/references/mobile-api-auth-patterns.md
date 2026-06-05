# Mobile API Auth Patterns & Testing Notes

## Common Mobile API Auth Flows

### Two-Step Token Acquisition
Many mobile banking APIs don't return a JWT directly from login. Instead:
1. `POST /login` → returns `tokenId` (opaque session reference)
2. `POST /access-token` with `{"tokenId":"..."}` → returns `accessToken` + `refreshToken`

Always test both steps. The tokenId may be brute-forceable if short/predictable.

### Device Attestation Bypass (Eversafe, SafetyNet, etc.)
- Eversafe TLV tokens (version 0x02) can sometimes be forged without crypto
- Key fields: TOTP (unix_time // 30), device ID, package name, root status
- Generate FRESH token per request — they expire within the TOTP window (30s)
- If attestation is forgeable → full device enrollment without physical device

### RSA Device Binding
Pattern: enroll device with RSA public key → sign `deviceId:timestamp_ms` for login
- Allows passwordless login after initial enrollment
- If attacker registers their own key pair, they get permanent access
- Test: can you re-enroll a new key without re-authenticating?

## GCS/Cloud Signed URL Patterns

When APIs return signed cloud storage URLs:
- Check expiry duration (259200s = 72h is excessive for sensitive docs)
- Note the service account and bucket (infrastructure disclosure)
- Test if URL path contains predictable user identifiers (IDOR potential)
- Verify the URL is actually scoped to the authenticated user's data

## Multi-Step Business Flow Testing (e.g., Loan Applications)

Typical pattern:
1. Check eligibility / get offers
2. Simulate terms (interest, schedule)
3. Fraud detection check
4. Compliance check → generates legal document (PDF)
5. Consent recording → user "approves" the document

**Test vectors:**
- Skip steps: can you submit consent without viewing the document?
- Replay: can you re-submit the same consent multiple times?
- Parameter manipulation: change amounts between simulation and submission
- IDOR: does compliance-check use JWT subject or a client-supplied ID?
- Timing: is there a window between PDF generation and consent where terms could change?

## Burp History Parsing (for mobile API reconnaissance)

Burp MCP returns giant single-line JSON. Reliable parsing approach:

```python
# Write to /tmp/parse_burp.py — NEVER use heredoc for this
import json, re

with open("/path/to/tooluse_XXX.txt") as f:
    raw = f.read()

inner = json.loads(raw)["result"]

# Extract endpoints
endpoints = set()
for m in re.finditer(r"(GET|POST|PUT|DELETE|PATCH) (/[^ ]+) HTTP", inner):
    method = m.group(1)
    path = m.group(2).split("?")[0]
    endpoints.add(f"{method} {path}")

for ep in sorted(endpoints):
    print(ep)
```

Tips:
- Fetch in batches of 50 (offset 0, 50, 100...) until no new endpoints appear
- Filter with regex in the Burp MCP call to reduce noise
- Parse all batches together for the complete endpoint map
