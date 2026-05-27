# Telegram WebApp (Mini App) Authentication

When a target is a Telegram Mini App (bot with WebApp), authentication uses Telegram's `initData` mechanism. This is increasingly common for crypto wallets, P2P trading, and payment bots.

## How It Works

1. User opens the bot's WebApp inside Telegram
2. Telegram injects `window.Telegram.WebApp.initData` — a URL-encoded string containing user info
3. The app sends this to its backend for verification
4. Backend validates the HMAC-SHA256 signature using the bot token as secret

## initData Structure

```
query_id=AAHdF6IQAAAAAN0XohDhrOrc
&user=%7B%22id%22%3A123456789%2C%22first_name%22%3A%22John%22%2C%22last_name%22%3A%22Doe%22%2C%22username%22%3A%22johndoe%22%2C%22language_code%22%3A%22en%22%7D
&auth_date=1716731082
&hash=abc123def456...
```

Decoded fields:
- `query_id` — unique query identifier
- `user` — JSON with `id`, `first_name`, `last_name`, `username`, `language_code`
- `auth_date` — Unix timestamp when auth was granted
- `hash` — HMAC-SHA256 signature of all other fields

## Signature Verification (Server-Side)

```python
import hmac, hashlib

# Bot token is the secret
secret_key = hmac.new("WebAppData".encode(), bot_token.encode(), hashlib.sha256).digest()

# Sort all fields except hash, join with \n
data_check_string = "\n".join(sorted([f"{k}={v}" for k,v in params.items() if k != "hash"]))

# Verify
computed_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
assert computed_hash == params["hash"]
```

## Attack Vectors

### 1. Hash Validation Bypass
- **Empty hash:** Send `hash=""` — some implementations skip validation
- **None/null:** Send `hash=null` or omit the field entirely
- **auth_date manipulation:** Set to far future — some apps only check hash, not expiry
- **Partial fields:** Omit `query_id` or `user` — may break signature but pass validation

### 2. User ID Manipulation (IDOR)
- After getting a valid session, change `user.id` in subsequent requests
- The session token may not be bound to the user ID in all endpoints
- Test: authenticate as user A, then call `/user-statistics/get/by-user-id` with user B's ID

### 3. Bot Token Leakage
- If the bot token is leaked (GitHub, JS bundle, error messages), you can forge any initData
- Search: `gh search code "BOT_TOKEN" "telegram" target-name`
- Check JS bundles for hardcoded tokens

### 4. Session Token Analysis
- After successful auth, the backend typically returns a JWT or session token
- Decode it — check if it contains user ID, expiry, permissions
- Test: can you modify the JWT payload? (none algorithm, key confusion)

### 5. Race Conditions in Auth
- Multiple simultaneous auth requests with same initData
- Can you create multiple sessions? Does it invalidate previous ones?

## Extracting initData (For Authenticated Testing)

### Method 1: Telegram Desktop + DevTools
```
1. Open Telegram Desktop
2. Open the bot's WebApp
3. Right-click → Inspect Element (or Ctrl+Shift+I)
4. Console: window.Telegram.WebApp.initData
5. Copy the full string
```

### Method 2: Intercept via Proxy
```
1. Configure Burp/mitmproxy
2. Open WebApp in Telegram (mobile with proxy configured)
3. Look for the first POST request to the backend — it contains initData
4. The response typically contains the session token
```

### Method 3: Telegram Bot API (if you control a bot)
```python
# If you have a bot token, you can generate valid initData for testing
# But this only works for YOUR bot, not the target's bot
```

## Common Endpoints Pattern (Wallet on Telegram)

```
POST /api/v1/users/authorize_by_telegram/
Body: {"hash": "<hmac>", "id": <telegram_user_id>, "first_name": "...", "auth_date": 1716731082}
Response: {"token": "eyJ...", "user": {...}}
```

The returned token is then used as `Authorization: Bearer <token>` for all subsequent API calls.

## Pitfalls

- **initData expires** — `auth_date` is checked; tokens older than 24h may be rejected
- **One session per user** — new auth may invalidate old tokens
- **Rate limiting on auth** — don't brute-force the hash
- **Bot token ≠ API key** — the bot token is used for HMAC verification, not as an API key
- **WebApp vs Bot API** — the WebApp auth is separate from the Bot API token; they serve different purposes

## Real-World Example (Wallet on Telegram, May 2026)

- Auth endpoint: `POST /api/v1/users/authorize_by_telegram/`
- Required: `hash` + `id` (minimum)
- Error on invalid hash: `{"code":"signature_not_correct","detail":"Signature is not correct"}`
- Error on missing fields: 422 with `{"detail":[{"type":"missing","loc":["body","hash"],...}]}`
- Backend: Python/FastAPI (inferred from error format)
- 494 endpoints discovered via OpenAPI JS bundle
