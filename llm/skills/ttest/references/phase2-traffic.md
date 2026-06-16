# Phase 2: Traffic Analysis

## Gate: All protocols intercepted, API surface mapped, auth flow documented

## Steps

### 2.1 HTTP/HTTPS Traffic Capture
- Configure proxy (see Phase 1)
- Exercise all app features while capturing
- Map: endpoints, auth mechanism, data formats
- Note: client-side headers (custom User-Agent, API keys, device IDs)

### 2.2 Non-HTTP Protocol Analysis
```bash
# Wireshark capture during all operations
# Export: File → Export Packet Dissections → As JSON

# Custom TCP binary protocol:
# 1. Identify framing (length-prefix, delimiter, fixed-size)
# 2. Find magic bytes / protocol version
# 3. Map message types by replaying actions
# 4. Look for auth tokens in binary stream

# gRPC (HTTP/2 + protobuf):
# Burp with HTTP/2 enabled captures gRPC
# Decode: protoc --decode_raw < message.bin
# Or: grpcurl -plaintext localhost:50051 list
```

### 2.3 Certificate Pinning Bypass (Desktop)

**.NET:** Find `ServerCertificateValidationCallback` or `HttpClientHandler.ServerCertificateCustomValidationCallback` in decompiled source. Patch to `return true`.

**Java:** Find custom `TrustManager` or `HostnameVerifier`. Patch or use JVM flag: `-Dcom.sun.net.ssl.checkRevocation=false`

**Electron:** Launch with `--ignore-certificate-errors`

**Native:** Use Proxifier + Burp invisible proxy mode, or patch certificate validation function (find via xrefs to OpenSSL/WinCrypt).

### 2.4 Authentication Flow Mapping
Document:
1. How does the app authenticate? (OAuth, custom token, NTLM, certificate)
2. Where is the token stored locally?
3. Token refresh mechanism?
4. Can the token be replayed from another machine?
5. Is auth validated per-request or only at session start?

### 2.5 Key Questions
- Does the client send credentials in plaintext?
- Are API keys embedded in the binary?
- Does the server trust client-side assertions (role, user ID)?
- Can you downgrade from HTTPS to HTTP?
- Are there undocumented/debug endpoints?

## Handoff
If HTTP API surface is significant (10+ endpoints), invoke atest Phase 2 with captured endpoints + tokens.
