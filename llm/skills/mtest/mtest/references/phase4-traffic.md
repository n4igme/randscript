# Phase 4: Traffic Analysis

### Gate: proxy intercepting traffic, API endpoints mapped, auth flow documented, at least one full user journey captured, `endpoints.md` written (OR documented N/A with justification if app has no network communication)

**Required output: `mtest-output/phase4-traffic/endpoints.md`**
Format:
```markdown
| Method | Path | Host | Auth Required | Notes |
|--------|------|------|---------------|-------|
| POST | /auth/mobile/v1/login | stg-mobile.jago.com | No (Tyk+Eversafe) | RSA signed |
| GET | /account/accounts | stg-api.jago.com | Bearer | List accounts |
```
This file is consumed by Phase 8 handoff and atest Phase 1. Write it during step 4 below.

**Steps:**

1. Install proxy CA certificate:
   ```bash
   # Android (system-level, requires root)
   openssl x509 -inform DER -in cacert.der -out cacert.pem
   HASH=$(openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1)
   cp cacert.pem ${HASH}.0
   adb root && adb remount
   adb push ${HASH}.0 /system/etc/security/cacerts/
   adb shell "chmod 644 /system/etc/security/cacerts/${HASH}.0"
   adb reboot

   # iOS
   # Settings > General > Profile > Install Burp CA
   # Settings > About > Certificate Trust Settings > Enable Full Trust
   ```

2. Configure proxy:
   ```bash
   # Android
   adb shell settings put global http_proxy <host_ip>:8080

   # Invisible proxy (apps ignoring system proxy)
   adb shell iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to <host_ip>:8080
   adb shell iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to <host_ip>:8080
   ```

3. Capture baseline traffic:
   - Launch app, complete registration/login flow
   - Navigate all major features
   - Trigger push notifications, background sync
   - Export all requests from proxy

4. Map API surface:
   - Base URLs and versioning
   - Authentication mechanism (JWT, OAuth, session, API key)
   - Request/response patterns
   - File upload/download endpoints
   - WebSocket connections

5. Document auth flow:
   - Login sequence (OTP, biometric, PIN)
   - Token lifecycle (access token, refresh token, expiry)
   - Session management
   - Multi-factor authentication steps

6. Identify interesting patterns:
   - Sequential/predictable IDs (IDOR candidates)
   - Sensitive data in responses (PII, financial data)
   - Missing security headers
   - Verbose error messages
   - Rate limiting (or lack thereof)
   - Certificate pinning coverage gaps

**Diagnostic: SSL Bypass Hooks Firing But No Burp Traffic**

When redsocks shows "accepted" (no errors), packets route (iptables counters climb), but Burp HTTP History is empty — isolate the failure layer:

1. **Verify hooks fire:** Add `send("[VERIFY-CALLED]")` to `onEnter` of each SSL bypass hook. Re-spawn app and watch Frida console. If verify calls appear → hooks work, problem is Burp-side.
2. **Burp-side checklist:**
   - Intercept must be OFF (CONNECT requests get stuck in intercept queue)
   - "Support invisible proxying" must be OFF (redsocks sends explicit CONNECT)
   - "Force use of TLS" must be OFF (CONNECT is plain HTTP)
   - Check Dashboard → Event Log for TLS handshake failures
   - Try fresh listener on a different port
3. **If hooks DON'T fire:** Pattern mismatch — app uses different BoringSSL build. Try alternate patterns (see `references/flutter-ssl-bypass.md`) or Ghidra RE approach.

Key insight: hooks firing + no Burp traffic = Burp config issue, never the app or bypass.

**Reference:** `traffic-analysis.md`, `burp-mcp-integration.md`, `passive-traffic-analyzer.md`

**CRITICAL: Flutter + Burp Proxy Chain Failure Mode (CONNECT-by-IP)**

When using redsocks → Burp for Flutter apps, a common failure is:
- redsocks accepts connections (log shows `accepted`)
- ESTABLISHED connections visible on Burp port (`lsof -i :PORT | grep -c ESTABLISHED` shows 20+)
- SSL bypass verify hooks fire (confirmed with onEnter logging)
- BUT Burp HTTP History shows NOTHING

**Root cause:** redsocks sends `CONNECT <IP>:443` to Burp (not `CONNECT hostname:443`).
Burp cannot extract the hostname from an IP-based CONNECT, so it can't:
1. Generate a proper per-host certificate
2. Route upstream correctly
3. Log the request in HTTP history

**Why invisible proxy also fails:** Direct DNAT to Burp with `support_invisible_proxying=true`
still doesn't work because Flutter's BoringSSL connects to the resolved IP, and the TLS
ClientHello SNI may be empty or IP-based when the DNS resolution happened in Dart.

**Proven diagnostic sequence:**
1. `curl -sk --proxy http://127.0.0.1:PORT https://target.com/` → confirms Burp works from Mac (hostname in CONNECT)
2. Hook `getaddrinfo` + `connect()` in libc.so to map DNS → IP for all endpoints
3. Check redsocks log for `accepted` lines (traffic IS flowing)
4. `lsof -i :PORT | grep ESTABLISHED` to confirm connections reach Burp
5. If all above pass but no history → it's the CONNECT-by-IP problem

**Solutions (in order of preference):**
1. **Passive analyzer (BEST for Flutter):** Keep Burp as terminal proxy, use Jython extension
   to POST req/resp to Flask analyzer at localhost:5557. See `references/passive-traffic-analyzer.md`
2. **HTTP Toolkit:** Handles Flutter H2 natively with transparent mode
3. **Frida HTTP dumper:** Hook at Dart HttpClient layer to dump all requests/responses
   directly (bypasses proxy chain entirely). Script captures traffic to file for analysis.
4. **mitmproxy upstream mode:** `mitmdump --mode upstream:http://127.0.0.1:8081@PORT`
   handles CONNECT-by-IP better than Burp

**What does NOT fix this (confirmed failures):**
- Disabling HTTP/2 on Burp listener
- Setting `ssl_pass_through.apply_to_out_of_scope_items: false`
- Adding `hostname_resolution` entries in project options
- Adding scope includes for *.jago.com
- Switching between `certificate_mode: per_host` variants

**Passive Analyzer Setup (PREFERRED for Flutter apps):**
Do NOT try to place Flask inline (upstream proxy) — Flutter apps use redsocks which sends CONNECT with IPs, not hostnames. Instead:
1. Keep Burp as terminal proxy (redsocks → Burp → real API)
2. Load Jython Burp extension that POSTs every req/resp to Flask analyzer
3. Flask at localhost:5557 auto-parses tokens, IDOR, sensitive data
4. See `references/passive-traffic-analyzer.md` for full architecture

**Reusable Traffic Parsing Proxy:**

For apps where you need automated session/token extraction from live traffic, deploy a Flask proxy (port 5556) as Burp upstream that:
1. Forwards all requests to real API (transparent)
2. Parses auth responses (login/refresh) → extracts access/refresh tokens
3. Detects IDOR candidates (path params matching account/payment/user ID patterns)
4. Flags sensitive data in responses (cvv, pin, password, privateKey)
5. Exposes admin endpoints: /proxy-admin/{sessions,tokens,log,idor,sensitive,export}

Setup: Burp upstream proxy destination=`*` (wildcard), proxy=127.0.0.1:5556.
Must use wildcard because redsocks sends CONNECT with IP, not hostname.

See `scripts/traffic_parsing_proxy_template.py` for base implementation.
