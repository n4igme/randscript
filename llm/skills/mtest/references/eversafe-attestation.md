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

## Token Replay for API Testing (Confirmed Technique)

1. Capture `x-eversafe-verification-token` from Burp proxy (visible in intercepted traffic)
2. Token is NOT per-request — generated once at app startup, reused across all API calls
3. Replay window: ~15-30 minutes from generation (server validates embedded timestamp)
4. Within the window, curl replay works — server returns JWT errors (not Eversafe errors)
5. After expiry: `{"error":{"message":"eversafe token verification failed","code":"TOKEN_VERIFICATION_FAILED"}}`

**Practical workflow:**
- Keep app active with proxy (generates fresh tokens every ~15 min)
- Grab fresh Eversafe token + JWT from Burp
- Replay within 5 min (JWT TTL is the real limiter, not Eversafe)
- Test IDOR, parameter tampering, etc. directly with curl

## Staging vs Production Behavior

- **Staging builds:** Often have relaxed detection — app stays alive on rooted devices with Frida attached. Attestation in "report-only mode" (server accepts tokens reporting proxy/root/pin failure).
- **Production builds:** Likely enforce attestation (reject tokens with failure flags) and kill app on root detection.

**Testing strategy:** Always test staging builds first before investing in bypass work.

**Detecting enforcement mode:**
- Send a token with known proxy/pin failure flags
- If server returns JWT errors (not Eversafe errors) → attestation not enforced
- If server returns `TOKEN_VERIFICATION_FAILED` → attestation enforced

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
