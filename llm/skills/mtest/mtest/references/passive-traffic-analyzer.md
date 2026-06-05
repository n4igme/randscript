# Passive Traffic Analyzer Pattern (Flask + Burp)

## Architecture

```
Mobile → redsocks → Burp → Real API (UNCHANGED)
                      ↓
              Burp Extension (Jython)
                      ↓ HTTP POST
              Flask Analyzer (localhost:5557)
                      ↓
              Auto-parse: tokens, IDOR, sensitive data, errors
```

**Key principle:** Flask is a PASSIVE OBSERVER. It does NOT sit inline in the traffic path. The app talks to the real API through Burp unchanged. A Burp extension pushes every completed request/response pair to Flask for analysis.

## Why NOT Inline

- Flask cannot handle HTTP CONNECT (which redsocks/proxies send for HTTPS)
- Inline proxy adds latency and breaks SSL negotiation
- Upstream proxy in Burp matches hostnames, but redsocks sends IPs → match fails
- The app's Eversafe/anti-tamper may detect proxy chain differences

## Components

### 1. Flask Analyzer (localhost:5557)
- `/feed` — POST JSON request/response pairs
- `/feed/burp-xml` — POST Burp XML export
- `/dashboard` — overview stats
- `/dashboard/sessions` — captured auth sessions
- `/dashboard/tokens` — captured Bearer + refresh tokens
- `/dashboard/idor` — IDOR candidates (account numbers, IDs in paths)
- `/dashboard/sensitive` — PII/secrets in responses
- `/dashboard/errors` — error responses with info leaks
- `/dashboard/export` — dump everything

### 2. Burp Extension (Jython)
Registers as IHttpListener, on every response:
- Extracts method, path, host, status, headers, bodies
- POSTs JSON to Flask analyzer async (daemon thread)
- No blocking — fire and forget

### 3. Auto-Analysis Rules
- Auth responses → extract accessToken, refreshToken, sessionId
- Path params matching `/accounts/\d+`, `/participants/UUID` → flag IDOR
- Response containing cvv, pin, nik, phoneNumber → flag sensitive
- 4xx/5xx with stack_trace, exception, sql → flag error leak
- OTP endpoints → track rate limiting behavior

## Alternative Feed Methods (no Jython)

If Jython unavailable:
1. **Burp XML export:** Select items → Save → `curl -X POST http://localhost:5557/feed/burp-xml --data-binary @export.xml`
2. **Manual JSON feed:** `curl -X POST http://localhost:5557/feed -H "Content-Type: application/json" -d '[{...}]'`
3. **Burp Logger++ extension** with CSV export → parse with script

## Pitfall: Burp Upstream Proxy + Redsocks

redsocks sends HTTP CONNECT with **IP addresses** (e.g., `CONNECT 172.64.148.24:443`), not hostnames. Burp upstream proxy rules match by **destination host** string. Setting it to `api.jago.com` won't match — traffic arrives with IP only.

Setting to `*` (wildcard) also fails because Flask can't handle CONNECT.

**Solution:** Don't use upstream proxy. Keep Burp as the terminal proxy. Use the Burp extension to push data to Flask.
