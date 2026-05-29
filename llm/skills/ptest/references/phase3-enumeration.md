# Phase 3: Enumeration

## Automated Setup

Run first when entering this phase:

```python
from hermes_tools import read_file
exec(read_file("~/.hermes/skills/security/ptest/scripts/phase3_enumerate.py")["content"])
```

---

## When to Use
- After active recon is complete (Gateway 2 PASSED).
- When you need to discover application-layer content: directories, files, API endpoints, parameters, and hidden functionality.

## Scope
This phase covers **application-layer discovery**:
- Directory and file brute-forcing
- API endpoint discovery and mapping
- Parameter discovery
- Virtual host enumeration
- CMS-specific enumeration
- JavaScript analysis and source map extraction
- Authentication endpoint mapping

Network-layer discovery (port scanning, service detection) belongs in Phase 2 (Active Recon).

## Techniques & Tools

### 1. Directory & File Brute-Force (MANDATORY: gobuster or feroxbuster)
Discover hidden paths, files, and directories on web targets.
```bash
# gobuster — directory mode
gobuster dir -u https://target.com -w $SECLISTS_PATH/Discovery/Web-Content/raft-medium-directories.txt -o ./ptest-output/enumeration/gobuster-dirs.txt -t 50

# gobuster — file mode (common extensions)
gobuster dir -u https://target.com -w $SECLISTS_PATH/Discovery/Web-Content/raft-medium-files.txt -x php,html,js,json,xml,txt,bak,env,conf -o ./ptest-output/enumeration/gobuster-files.txt

# feroxbuster — recursive
feroxbuster -u https://target.com -w $SECLISTS_PATH/Discovery/Web-Content/raft-medium-directories.txt -o ./ptest-output/enumeration/ferox.txt --depth 3

# Targeted wordlists for specific tech stacks
# Pimcore: /admin, /bundles, /var, /bin
# WordPress: /wp-content, /wp-includes, /wp-json
# Laravel: /api, /storage, /vendor
```

**Requirements:**
- Run against ALL confirmed-live web hosts (from Phase 1 domains-live.md)
- Use appropriate wordlists for the identified technology stack
- If gobuster/feroxbuster unavailable, document gap and use alternative (dirsearch, dirb)

**Pitfalls:**
- SPA catch-all: Many modern apps (Flutter, React, Angular) return 200 for ALL paths. Use `--exclude-length <spa-size>` to filter. First check a random UUID path to determine the catch-all response size.
- gobuster `-s` and `-b` conflict: Don't use `-s` (status codes) without clearing `-b` (blacklist) first. Use `-b ""` to clear the default 404 blacklist when specifying `-s`.
- Rate-limited targets: gobuster/feroxbuster may timeout. Fall back to `xargs -P` with curl for parallel path discovery on slow targets.

### 2. API Endpoint Discovery (MANDATORY: ffuf)
Map API endpoints, methods, and response patterns.
```bash
# ffuf — API endpoint fuzzing
ffuf -u https://target.com/api/FUZZ -w $SECLISTS_PATH/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,301,302,401,403,405 -o ./ptest-output/enumeration/ffuf-api.json

# ffuf — versioned API paths
ffuf -u https://target.com/api/v1/FUZZ -w $SECLISTS_PATH/Discovery/Web-Content/api/api-endpoints.txt -mc all -fc 404

# Check common API documentation endpoints
for path in /swagger /swagger-ui /api-docs /openapi.json /swagger.json /docs /redoc; do
  curl -s --max-time 5 -o /dev/null -w "%{http_code} $path\n" "https://target.com$path"
done

# GraphQL introspection
curl -s -X POST https://target.com/graphql -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}'
```

### 3. Parameter Discovery
Identify hidden parameters on discovered endpoints.
```bash
# arjun — parameter discovery
arjun -u https://target.com/endpoint -o ./ptest-output/enumeration/arjun-params.json

# Manual parameter fuzzing
ffuf -u "https://target.com/page?FUZZ=test" -w $SECLISTS_PATH/Discovery/Web-Content/burp-parameter-names.txt -mc all -fc 404 -fs <baseline-size>
```

### 4. Virtual Host Enumeration
Discover additional virtual hosts on the same IP.
```bash
# gobuster vhost mode
gobuster vhost -u https://target.com -w $SECLISTS_PATH/Discovery/DNS/subdomains-top1million-5000.txt --append-domain

# ffuf vhost fuzzing
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w $SECLISTS_PATH/Discovery/DNS/subdomains-top1million-5000.txt -mc all -fc 404 -fs <baseline-size>
```

### 5. CMS-Specific Enumeration
Run targeted enumeration based on identified CMS/framework.
```bash
# WordPress
wpscan --url https://target.com --enumerate ap,at,u -o ./ptest-output/enumeration/wpscan.txt

# Pimcore
# Check: /admin/login, /bundles/, /js/routing, /_profiler, /_wdt
# Enumerate admin routes via FOS routing bundle if exposed

# Drupal
droopescan scan drupal -u https://target.com

# Joomla
joomscan -u https://target.com
```

### 6. JavaScript Analysis
Extract endpoints, secrets, and functionality from client-side code.

**Flutter Web Apps:** If target serves `main.dart.js` + `flutter.js`, see `references/flutter-web-app-analysis.md` for specialized extraction (JWT decode, auth headers, partner IDs, internal domains from 4-10MB Dart-compiled JS).
```bash
# linkfinder — extract endpoints from JS files
linkfinder -i https://target.com -o ./ptest-output/enumeration/linkfinder.txt

# Download and analyze JS bundles
curl -s https://target.com/static/js/main.*.js | grep -ioE '(https?://[^\s"]+|/api/[^\s"]+|/v[0-9]/[^\s"]+)' | sort -u

# Check for source maps
curl -sI https://target.com/static/js/main.*.js | grep -i sourcemap
curl -s https://target.com/static/js/main.*.js.map | head -100

# Extract hardcoded secrets/tokens from JS
curl -s https://target.com/static/js/main.*.js | grep -ioE '(api[_-]?key|token|secret|password|auth)["\s]*[:=]["\s]*[^\s",}]+' | sort -u
```

### 7. Authentication Endpoint Mapping
Document all authentication mechanisms and entry points.
```bash
# Identify login pages
for path in /login /signin /auth /admin/login /api/auth /oauth /sso; do
  code=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" "https://target.com$path")
  if [ "$code" != "404" ] && [ "$code" != "000" ]; then
    echo "HTTP $code $path"
  fi
done

# Check auth mechanisms
curl -sI https://target.com/api/protected 2>/dev/null | grep -iE "www-authenticate|x-auth|authorization"

# OAuth/OIDC discovery
curl -s https://target.com/.well-known/openid-configuration | python3 -m json.tool
curl -s https://target.com/.well-known/oauth-authorization-server | python3 -m json.tool
```

### 8. Framework Detection & Targeted Enumeration

Identify the web framework, then load the appropriate attack playbook.

```bash
# Detect framework from response headers/body
# Next.js: __NEXT_DATA__ in source, /_next/ paths
# Laravel: laravel_session cookie, /telescope, /horizon
# Django: csrftoken cookie, /admin/
# WordPress: /wp-content/, /wp-json/
# Rails: _session_id cookie, X-Request-Id header
# Spring Boot: /actuator, x-envoy-* headers
# GraphQL: /graphql, /graphiql, /playground
# Tyk Gateway: /hello returns JSON with "Tyk GW", 403 "Requested endpoint is forbidden"
# n8n: /rest/settings returns config JSON, /healthz returns {"status":"ok"}
# Flutter Web: main.dart.js + flutter.js in page source

# Quick framework fingerprint
curl -sk "https://target.com" -D - -o /tmp/fw-detect.html 2>/dev/null
grep -qi "__NEXT_DATA__" /tmp/fw-detect.html && echo "[+] Next.js detected"
grep -qi "laravel_session" /tmp/fw-detect.html && echo "[+] Laravel detected"
grep -qi "csrftoken" /tmp/fw-detect.html && echo "[+] Django detected"
grep -qi "wp-content" /tmp/fw-detect.html && echo "[+] WordPress detected"
```

**When framework is identified:** Load `references/framework-specific-attacks.md` for targeted enumeration paths specific to that framework.

### 9. GraphQL Endpoint Discovery & Introspection

```bash
# Find GraphQL endpoints
for path in /graphql /graphiql /playground /api/graphql /v1/graphql /query /gql; do
  code=$(curl -sk -X POST "https://target.com${path}" -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}' -o /dev/null -w "%{http_code}")
  [ "$code" != "404" ] && [ "$code" != "000" ] && echo "[+] GraphQL at ${path} -> ${code}"
done

# Full introspection (if enabled)
curl -sk "https://target.com/graphql" -X POST -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}' | python3 -m json.tool | head -50
```

**Deep dive:** See `references/framework-specific-attacks.md` §6 and `references/web-vuln-bypass-tables.md` (GraphQL section).

### 10. WebSocket Endpoint Discovery

```bash
# Search for WebSocket URLs in page source and JS files
curl -sk "https://target.com" | grep -ioE "wss?://[^\"' ]+"

# Check common WebSocket paths
for path in /ws /websocket /socket /socket.io /hub /signalr /cable /live; do
  code=$(curl -sk -H "Upgrade: websocket" -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    "https://target.com${path}" -o /dev/null -w "%{http_code}")
  [ "$code" = "101" ] && echo "[+] WebSocket upgrade at ${path}"
  [ "$code" = "400" ] && echo "[?] Possible WS at ${path} (400 = bad handshake)"
done
```

**Deep dive:** See `references/advanced-web-attacks.md` §1 for WebSocket security testing.

### 11. Deserialization Sink Identification

Look for serialized data in cookies, headers, and request bodies.

```bash
# Check cookies for serialized data
curl -skI "https://target.com" | grep -i "set-cookie" | grep -iE "base64|eyJ|rO0AB|AAEAAAD|O:[0-9]"

# Java serialization magic bytes (base64 of AC ED 00 05 = rO0AB)
# PHP serialization (O:4:"User":...)
# .NET BinaryFormatter (AAEAAAD...)
# Python pickle (base64 blob in cookie/session)

# Check ViewState (.NET)
curl -sk "https://target.com" | grep -oE '__VIEWSTATE[^"]*"[^"]*"' | head -3
```

**Deep dive:** See `references/insecure-deserialization.md` for full exploitation methodology.

### 12. Bulk Actuator/Admin Scan (MANDATORY)

```bash
# Run against ALL live hosts, not just priority targets
# See references/bulk-actuator-scanning.md for the full script
bash scripts/bulk-actuator-scan.sh ./ptest-output/recon-passive/resolving-subs.txt

# Quick manual check
while read sub; do
  for path in /actuator /actuator/health /actuator/env /swagger-ui.html /api-docs /admin /console; do
    code=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" "https://${sub}${path}")
    [ "$code" != "000" ] && [ "$code" != "404" ] && echo "${sub}${path} -> ${code}"
  done
done < live-subs.txt
```

**Deep dive:** See `references/bulk-actuator-scanning.md` and `references/framework-specific-attacks.md` §7.

## Scope Type Adjustments

- **web/API:** All techniques apply. Focus on techniques 1, 2, 3, 6, 7.
- **network:** Skip web-specific techniques. Focus on service-specific enumeration (SMB shares, SNMP walks, NFS exports).
- **cloud:** Focus on storage bucket enumeration, API gateway discovery, serverless function endpoints.
- **mobile:** Focus on API endpoints the app communicates with (extract from APK/IPA), certificate pinning checks.

## Output

Document findings in `./ptest-output/enumeration/`:
- `summary.md` — consolidated enumeration results
- `directories.md` — discovered paths per host
- `api-endpoints.md` — API endpoints with methods and auth requirements
- `parameters.md` — discovered parameters per endpoint
- `auth-mechanisms.md` — authentication mechanisms per application
- `js-analysis.md` — findings from JavaScript analysis
- `gobuster-*.txt` — raw tool output
- `ffuf-*.json` — raw tool output

Write `./ptest-output/enumeration/checklist.md`:

```markdown
# Enumeration Checklist

| # | Technique | Status | Notes |
|---|-----------|--------|-------|
| 1 | Directory & File Brute-Force (MANDATORY) | PENDING | |
| 2 | API Endpoint Discovery (MANDATORY) | PENDING | |
| 3 | Parameter Discovery | PENDING | |
| 4 | Virtual Host Enumeration | PENDING | |
| 5 | CMS-Specific Enumeration | PENDING | |
| 6 | JavaScript Analysis | PENDING | |
| 7 | Authentication Endpoint Mapping | PENDING | |
| 8 | Framework Detection & Targeted Enumeration | PENDING | |
| 9 | GraphQL Endpoint Discovery | PENDING | |
| 10 | WebSocket Endpoint Discovery | PENDING | |
| 11 | Deserialization Sink Identification | PENDING | |
| 12 | Bulk Actuator/Admin Scan (MANDATORY) | PENDING | |
```

Mark each technique as `DONE`, `SKIPPED (reason)`, or `FAILED (reason)` after execution.

## 13. Cloud Misconfiguration Checks

Systematic checks for cloud-specific misconfigurations on all discovered subdomains.

### Storage Bucket Enumeration
```bash
# Check all subdomains for open S3/Spaces bucket listing
for url in $(cat live-urls.txt); do
  resp=$(curl -s "$url" | head -5)
  if echo "$resp" | grep -qi "ListBucket\|<Key>\|<Contents>"; then
    echo "OPEN BUCKET: $url"
    # Check write access
    curl -s -X PUT "$url/test-write-check" -d "test" -w "%{http_code}"
  fi
done

# Check for non-package files in open buckets (internal tools, scripts, keys)
# Look for: install scripts, GPG keys, config files, internal binaries NOT on GitHub
```

### Exposed Monitoring/Observability
```bash
# Sentry DSN extraction from CSP headers
curl -sI https://target.com | grep -i "content-security-policy" | grep -oP 'https://[a-f0-9]+@[^/]+\.sentry\.io/\d+'

# Prometheus metrics endpoints
for path in /metrics /api/v1/metrics /actuator/prometheus; do
  curl -s "https://target.com$path" -w "\n%{http_code}" | tail -3
done

# Health/readiness endpoints (may leak versions, dependencies)
for path in /health /healthz /readyz /status /api/health; do
  curl -s "https://target.com$path" -w "\n%{http_code}" | tail -3
done
```

### Exposed API Documentation
```bash
# OpenAPI/Swagger specs
for path in /openapi.json /swagger.json /api-docs /docs /api/docs /swagger-ui /redoc; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
  [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$path -> $code"
done
```

### Container Registry Exposure
```bash
# Docker Registry V2 API
curl -s "https://registry.target.com/v2/" -w "\n%{http_code}"
curl -s "https://registry.target.com/v2/_catalog" -w "\n%{http_code}"
# Check www-authenticate header for auth realm
curl -sI "https://registry.target.com/v2/" | grep -i "www-authenticate"
```

## Exit Criteria
- [ ] All live web applications have directory/file enumeration completed.
- [ ] API endpoints mapped with methods and parameters.
- [ ] Authentication mechanisms identified per application.
- [ ] Hidden content and functionality discovered.
- [ ] Cloud misconfiguration checks completed (buckets, monitoring, API docs, registries).
- [ ] Mandatory tools (gobuster/feroxbuster, ffuf) executed — or gap documented.
- [ ] Checklist shows all applicable techniques executed.
