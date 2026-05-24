# Spring Boot Security Scanner

Focused vulnerability scanner for Spring Boot applications. Covers actuator exposure, security annotation gaps, SpEL injection, unsafe deserialization, configuration secrets, OAuth/Keycloak integration flaws, and more.

## Scope

Spring Boot specific vulnerabilities in microservice architectures. Primary context: Indonesian financial services (Bank Jago, BFI Finance) running Spring Boot on GKE/Kubernetes with Keycloak SSO.

## Grep Patterns Quick Reference

```bash
# Run these first to identify high-priority files
grep -rn "management.endpoints.web.exposure" --include="*.yml" --include="*.properties" .
grep -rn "@PreAuthorize\|@Secured\|@RolesAllowed" --include="*.java" .
grep -rn "SpelExpressionParser\|parseExpression" --include="*.java" .
grep -rn "enableDefaultTyping\|activateDefaultTyping\|@JsonTypeInfo" --include="*.java" .
grep -rn "ObjectInputStream\|readObject\|XMLDecoder" --include="*.java" .
grep -rn "password\|secret\|token\|apikey" --include="*.yml" --include="*.properties" .
grep -rn "@CrossOrigin\|CorsConfiguration\|addAllowedOrigin" --include="*.java" .
grep -rn "createNativeQuery\|@Query.*\\+" --include="*.java" .
grep -rn "RestTemplate\|WebClient" --include="*.java" .
grep -rn "dangerouslySetInnerHTML\|v-html\|th:utext" --include="*.java" --include="*.html" .
```

---

## 1. Actuator Exposure

**Severity:** Critical (if heapdump/env exposed) / High (if mappings/beans exposed)
**CWE:** CWE-200, CWE-215

### Patterns to Find

```bash
# Configuration
grep -rn "management.endpoints.web.exposure.include" --include="*.yml" --include="*.properties" .
grep -rn "management.server.port" --include="*.yml" --include="*.properties" .
grep -rn "management.endpoint.health.show-details" --include="*.yml" .

# Security exclusions
grep -rn "actuator\|management" --include="*.java" . | grep -i "permit\|ignore\|exclude"

# Custom endpoints
grep -rn "@Endpoint\|@ReadOperation\|@WriteOperation" --include="*.java" .
```

### Vulnerable Code

```yaml
# application.yml — exposes ALL actuator endpoints
management:
  endpoints:
    web:
      exposure:
        include: "*"
  endpoint:
    health:
      show-details: always
```

```java
// SecurityConfig.java — actuator excluded from auth
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/actuator/**").permitAll()  // VULNERABLE
        .anyRequest().authenticated()
    );
    return http.build();
}
```

### Fixed Code

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info,prometheus  # Only safe endpoints
  endpoint:
    health:
      show-details: when-authorized
  server:
    port: 9090  # Separate port (not exposed via gateway)
```

```java
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/actuator/health", "/actuator/info").permitAll()
    .requestMatchers("/actuator/**").hasRole("ADMIN")
    .anyRequest().authenticated()
);
```

### Financial Services Context

Actuator `/env` and `/heapdump` on financial services expose: database credentials, Keycloak client secrets, encryption keys, service account tokens. A single exposed heapdump = full infrastructure compromise (proven at BFI Finance, May 2026).

---

## 2. Security Annotation Gaps

**Severity:** High (missing auth on sensitive endpoint) / Medium (inconsistent auth)
**CWE:** CWE-862, CWE-306

### Patterns to Find

```bash
# Controllers without class-level auth
grep -rln "@RestController\|@Controller" --include="*.java" . | while read f; do
  grep -L "@PreAuthorize\|@Secured\|@RolesAllowed" "$f"
done

# Methods with mapping but no auth annotation
grep -rn "@GetMapping\|@PostMapping\|@PutMapping\|@DeleteMapping\|@PatchMapping" --include="*.java" .

# Overly broad permitAll
grep -rn "permitAll" --include="*.java" .

# SecurityFilterChain configuration
grep -rn "SecurityFilterChain\|WebSecurityConfigurerAdapter" --include="*.java" .
```

### Vulnerable Code

```java
@RestController
@RequestMapping("/api/v1/users")
// NO class-level @PreAuthorize — each method must have its own
public class UserController {

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('USER')")  // Protected
    public User getUser(@PathVariable Long id) { ... }

    @DeleteMapping("/{id}")
    // MISSING @PreAuthorize — anyone can delete!
    public void deleteUser(@PathVariable Long id) { ... }

    @GetMapping("/export")
    // MISSING — bulk data export without auth check
    public List<User> exportAll() { ... }
}
```

### Fixed Code

```java
@RestController
@RequestMapping("/api/v1/users")
@PreAuthorize("hasRole('USER')")  // Class-level default
public class UserController {

    @GetMapping("/{id}")
    public User getUser(@PathVariable Long id) { ... }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")  // Explicit elevation
    public void deleteUser(@PathVariable Long id) { ... }

    @GetMapping("/export")
    @PreAuthorize("hasRole('ADMIN')")
    public List<User> exportAll() { ... }
}
```

### Key Check: SecurityFilterChain Order

```java
// VULNERABLE — order matters! First match wins
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/**").permitAll()      // This catches everything!
    .requestMatchers("/api/admin/**").hasRole("ADMIN")  // Never reached
);

// FIXED — specific rules first
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/admin/**").hasRole("ADMIN")  // Specific first
    .requestMatchers("/api/public/**").permitAll()       // Only public paths
    .anyRequest().authenticated()                        // Default deny
);
```

---

## 3. SpEL Injection

**Severity:** Critical (RCE)
**CWE:** CWE-917

### Patterns to Find

```bash
grep -rn "SpelExpressionParser\|parseExpression\|ExpressionParser" --include="*.java" .
grep -rn "@Value.*#\{" --include="*.java" .
grep -rn "@PreAuthorize.*#" --include="*.java" .  # SpEL in security annotations
grep -rn "StandardEvaluationContext" --include="*.java" .
```

### Vulnerable Code

```java
// User input reaches SpEL parser
@PostMapping("/search")
public List<Object> search(@RequestParam String filter) {
    ExpressionParser parser = new SpelExpressionParser();
    Expression exp = parser.parseExpression(filter);  // VULNERABLE — RCE
    return (List<Object>) exp.getValue();
}

// Spring Cloud Function pattern (CVE-2022-22963)
// Header: spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec('id')
```

### Fixed Code

```java
// Use SimpleEvaluationContext (no type references, no method calls)
@PostMapping("/search")
public List<Object> search(@RequestParam String filter) {
    ExpressionParser parser = new SpelExpressionParser();
    SimpleEvaluationContext context = SimpleEvaluationContext
        .forReadOnlyDataBinding()
        .build();
    Expression exp = parser.parseExpression(filter);
    return (List<Object>) exp.getValue(context);  // Safe — restricted context
}

// Better: don't use SpEL with user input at all
// Use a predefined filter enum or Criteria API
```

---

## 4. Mass Assignment / Binding

**Severity:** High (role escalation) / Medium (data tampering)
**CWE:** CWE-915

### Patterns to Find

```bash
# Direct entity binding (no DTO)
grep -rn "@RequestBody.*Entity\|@ModelAttribute" --include="*.java" .

# Check for missing @JsonIgnore on sensitive fields
grep -rn "role\|isAdmin\|balance\|creditLimit\|permissions" --include="*.java" . | grep -i "private\|protected"

# ObjectMapper configuration
grep -rn "FAIL_ON_UNKNOWN_PROPERTIES\|DeserializationFeature" --include="*.java" .
```

### Vulnerable Code

```java
// Entity with sensitive fields — bound directly from request
@Entity
public class User {
    private Long id;
    private String name;
    private String email;
    private String role;          // SENSITIVE — should not be user-writable
    private Boolean isAdmin;      // SENSITIVE
    private BigDecimal creditLimit; // SENSITIVE — financial impact
}

@PutMapping("/{id}")
public User updateUser(@PathVariable Long id, @RequestBody User user) {
    // VULNERABLE — attacker can send {"role":"ADMIN","isAdmin":true,"creditLimit":999999}
    return userRepository.save(user);
}
```

### Fixed Code

```java
// Use a DTO that only contains writable fields
public class UserUpdateDTO {
    private String name;
    private String email;
    // role, isAdmin, creditLimit NOT here
}

@PutMapping("/{id}")
public User updateUser(@PathVariable Long id, @RequestBody UserUpdateDTO dto) {
    User user = userRepository.findById(id).orElseThrow();
    user.setName(dto.getName());
    user.setEmail(dto.getEmail());
    // Sensitive fields never touched
    return userRepository.save(user);
}

// Alternative: @JsonIgnore on entity
@Entity
public class User {
    // ...
    @JsonIgnore private String role;
    @JsonIgnore private Boolean isAdmin;
}
```

---

## 5. Unsafe Deserialization

**Severity:** Critical (RCE via gadget chains)
**CWE:** CWE-502

### Patterns to Find

```bash
grep -rn "ObjectInputStream\|readObject\|readUnshared" --include="*.java" .
grep -rn "enableDefaultTyping\|activateDefaultTyping" --include="*.java" .
grep -rn "@JsonTypeInfo.*Id.CLASS\|@JsonTypeInfo.*Id.MINIMAL_CLASS" --include="*.java" .
grep -rn "XMLDecoder\|XStream" --include="*.java" .
grep -rn "new Yaml()\|Yaml()" --include="*.java" . | grep -v "SafeConstructor"
grep -rn "SerializationUtils\|SerializableUtils" --include="*.java" .
```

### Vulnerable Code

```java
// Jackson polymorphic deserialization — RCE
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();  // CRITICAL — allows arbitrary class instantiation

// SnakeYAML without SafeConstructor — RCE
Yaml yaml = new Yaml();  // VULNERABLE — default constructor allows !!python/object
Object data = yaml.load(userInput);

// Redis message deserialization
@Bean
public RedisTemplate<String, Object> redisTemplate() {
    RedisTemplate<String, Object> template = new RedisTemplate<>();
    template.setValueSerializer(new JdkSerializationRedisSerializer());  // VULNERABLE
    return template;
}
```

### Fixed Code

```java
// Jackson — use name-based typing with closed set
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME)
@JsonSubTypes({
    @JsonSubTypes.Type(value = Dog.class, name = "dog"),
    @JsonSubTypes.Type(value = Cat.class, name = "cat")
})
public abstract class Animal { }

// SnakeYAML — use SafeConstructor
Yaml yaml = new Yaml(new SafeConstructor());

// Redis — use JSON serializer instead
template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
```

---

## 6. Configuration Secrets

**Severity:** High (exposed credentials) / Medium (weak encryption)
**CWE:** CWE-798, CWE-312

### Patterns to Find

```bash
# Hardcoded secrets in config
grep -rn "password:\|secret:\|token:\|api-key:\|client-secret:" --include="*.yml" --include="*.properties" . | grep -v "\${" | grep -v "changeme\|placeholder"

# Secrets not using environment variables
grep -rn "spring.datasource.password\|keycloak.credentials.secret" --include="*.yml" . | grep -v "\${"

# Jasypt with hardcoded password
grep -rn "jasypt.encryptor.password" --include="*.yml" --include="*.properties" .

# Git history check
git log --all -p -- "*.yml" "*.properties" | grep -i "password\|secret\|token" | head -20
```

### Vulnerable Code

```yaml
# application.yml — hardcoded secrets
spring:
  datasource:
    password: Pr0duction_P@ss!  # VULNERABLE — in git history forever
keycloak:
  credentials:
    secret: 7a8b9c0d-1234-5678-abcd-ef0123456789  # VULNERABLE
```

### Fixed Code

```yaml
# Use environment variables
spring:
  datasource:
    password: ${DB_PASSWORD}
keycloak:
  credentials:
    secret: ${KEYCLOAK_CLIENT_SECRET}

# Or Spring Cloud Vault
spring:
  cloud:
    vault:
      uri: https://vault.internal:8200
      authentication: KUBERNETES
```

---

## 7. OAuth/Keycloak Integration Flaws

**Severity:** High-Critical
**CWE:** CWE-287, CWE-346

### Patterns to Find

```bash
grep -rn "public-client\|bearer-only\|ssl-required\|verify-token-audience" --include="*.yml" --include="*.properties" --include="*.json" .
grep -rn "keycloak" --include="*.yml" --include="*.properties" .
grep -rn "@AuthenticationPrincipal\|SecurityContext\|JwtDecoder" --include="*.java" .
grep -rn "redirect-uri\|valid-redirect" --include="*.yml" --include="*.json" .
```

### Vulnerable Code

```yaml
# application.yml — insecure Keycloak config
keycloak:
  realm: production
  resource: my-app
  public-client: true           # No client secret — code theft via redirect
  ssl-required: none            # VULNERABLE — allows HTTP
  verify-token-audience: false  # VULNERABLE — accepts tokens for other clients
  credentials:
    secret: ""                  # Empty secret
```

```java
// Not validating token claims
@GetMapping("/api/data")
public Data getData(@AuthenticationPrincipal Jwt jwt) {
    // VULNERABLE — not checking audience, issuer, or required claims
    String userId = jwt.getSubject();
    return dataService.getByUser(userId);
}
```

### Fixed Code

```yaml
keycloak:
  realm: production
  resource: my-app
  bearer-only: true             # API-only, no redirect
  ssl-required: external        # Require HTTPS
  verify-token-audience: true   # Reject tokens for other clients
```

```java
// Validate token claims properly
@GetMapping("/api/data")
public Data getData(@AuthenticationPrincipal Jwt jwt) {
    // Verify audience
    if (!jwt.getAudience().contains("my-app")) {
        throw new AccessDeniedException("Invalid audience");
    }
    // Verify issuer
    if (!jwt.getIssuer().toString().contains("/realms/production")) {
        throw new AccessDeniedException("Invalid issuer");
    }
    String userId = jwt.getSubject();
    return dataService.getByUser(userId);
}
```

---

## 8. CORS Misconfiguration

**Severity:** Critical (with credentials) / Low (without)
**CWE:** CWE-346, CWE-942

### Patterns to Find

```bash
grep -rn "@CrossOrigin" --include="*.java" .
grep -rn "CorsConfiguration\|CorsRegistry\|addCorsMappings" --include="*.java" .
grep -rn "allowedOrigins\|addAllowedOrigin\|allowCredentials" --include="*.java" .
grep -rn "Access-Control-Allow-Origin" --include="*.java" .
```

### Vulnerable Code

```java
// Reflects origin from request — Critical
@Bean
public CorsFilter corsFilter() {
    CorsConfiguration config = new CorsConfiguration();
    config.addAllowedOriginPattern("*");  // VULNERABLE with credentials
    config.setAllowCredentials(true);      // Enables cookie/auth theft
    config.addAllowedHeader("*");
    config.addAllowedMethod("*");
    // ...
}

// Dynamic origin reflection
@Override
public void addCorsMappings(CorsRegistry registry) {
    registry.addMapping("/api/**")
        .allowedOrigins(request.getHeader("Origin"))  // VULNERABLE — reflects any origin
        .allowCredentials(true);
}
```

### Fixed Code

```java
@Bean
public CorsFilter corsFilter() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(List.of(
        "https://app.bankjago.com",
        "https://admin.bankjago.com"
    ));
    config.setAllowCredentials(true);
    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
    config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
    // ...
}
```

---

## 9. SQL/JPA Injection

**Severity:** Critical (data breach, RCE via stacked queries)
**CWE:** CWE-89

### Patterns to Find

```bash
# String concatenation in queries
grep -rn "@Query" --include="*.java" . | grep "\\+"
grep -rn "createNativeQuery\|createQuery" --include="*.java" . | grep "\\+"
grep -rn "JdbcTemplate" --include="*.java" . | grep "\\+"

# Sort/order injection
grep -rn "Sort.by\|OrderBy\|order by" --include="*.java" . | grep -i "param\|request\|input"
```

### Vulnerable Code

```java
// String concatenation in @Query — SQLi
@Query("SELECT u FROM User u WHERE u.name = '" + name + "'")  // VULNERABLE
List<User> findByName(String name);

// Native query with concatenation
public List<User> search(String term) {
    String sql = "SELECT * FROM users WHERE name LIKE '%" + term + "%'";  // VULNERABLE
    return entityManager.createNativeQuery(sql, User.class).getResultList();
}

// Sort injection
@GetMapping("/users")
public List<User> getUsers(@RequestParam String sortBy) {
    String sql = "SELECT * FROM users ORDER BY " + sortBy;  // VULNERABLE
    return jdbcTemplate.query(sql, userRowMapper);
}
```

### Fixed Code

```java
// Parameterized @Query
@Query("SELECT u FROM User u WHERE u.name = :name")
List<User> findByName(@Param("name") String name);

// Parameterized native query
public List<User> search(String term) {
    String sql = "SELECT * FROM users WHERE name LIKE :term";
    return entityManager.createNativeQuery(sql, User.class)
        .setParameter("term", "%" + term + "%")
        .getResultList();
}

// Sort with allowlist
private static final Set<String> ALLOWED_SORTS = Set.of("name", "email", "createdAt");

@GetMapping("/users")
public List<User> getUsers(@RequestParam String sortBy) {
    if (!ALLOWED_SORTS.contains(sortBy)) {
        throw new BadRequestException("Invalid sort field");
    }
    return userRepository.findAll(Sort.by(sortBy));
}
```

---

## 10. SSRF via RestTemplate/WebClient

**Severity:** High-Critical
**CWE:** CWE-918

### Patterns to Find

```bash
grep -rn "RestTemplate\|WebClient\|HttpClient\|URL(" --include="*.java" . | grep -i "param\|request\|input\|variable"
grep -rn "getForObject\|getForEntity\|exchange\|retrieve" --include="*.java" .
grep -rn "URI.create\|new URL\|UriComponentsBuilder" --include="*.java" .
```

### Vulnerable Code

```java
// Full URL from user input — Critical SSRF
@GetMapping("/proxy")
public String proxy(@RequestParam String url) {
    return restTemplate.getForObject(url, String.class);  // VULNERABLE
}

// Partial URL control — still exploitable
@GetMapping("/fetch")
public String fetch(@RequestParam String host) {
    String url = "https://" + host + "/api/data";  // VULNERABLE — host=169.254.169.254
    return restTemplate.getForObject(url, String.class);
}
```

### Fixed Code

```java
// URL allowlist validation
private static final Set<String> ALLOWED_HOSTS = Set.of(
    "api.partner.com", "data.provider.com"
);

@GetMapping("/fetch")
public String fetch(@RequestParam String host) {
    if (!ALLOWED_HOSTS.contains(host)) {
        throw new BadRequestException("Host not allowed");
    }
    String url = "https://" + host + "/api/data";
    return restTemplate.getForObject(url, String.class);
}

// Better: use an enum/ID to select predefined URLs
@GetMapping("/fetch/{provider}")
public String fetch(@PathVariable String provider) {
    String url = providerUrlMap.get(provider);  // Predefined mapping
    if (url == null) throw new NotFoundException();
    return restTemplate.getForObject(url, String.class);
}
```

---

## 11. Async/Event Security Context Loss

**Severity:** Medium-High
**CWE:** CWE-862

### Patterns to Find

```bash
grep -rn "@Async" --include="*.java" .
grep -rn "@EventListener\|ApplicationEventPublisher" --include="*.java" .
grep -rn "CompletableFuture\|@Scheduled" --include="*.java" .
grep -rn "SecurityContextHolder.getContext" --include="*.java" .
```

### Vulnerable Code

```java
// @Async loses security context — runs as anonymous
@Async
public void processOrder(Long orderId) {
    // SecurityContextHolder.getContext().getAuthentication() == null here!
    // Any @PreAuthorize checks in called methods will FAIL or be bypassed
    orderService.approve(orderId);  // May run without auth checks
}
```

### Fixed Code

```java
// Propagate security context to async threads
@Configuration
@EnableAsync
public class AsyncConfig implements AsyncConfigurer {
    @Override
    public Executor getAsyncExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.initialize();
        return new DelegatingSecurityContextExecutor(executor);
    }
}

// Or explicitly pass the context
@Async
public void processOrder(Long orderId, Authentication auth) {
    SecurityContextHolder.getContext().setAuthentication(auth);
    orderService.approve(orderId);
}
```

---

## 12. Logging Sensitive Data

**Severity:** Medium (PII in logs) / Low (verbose errors)
**CWE:** CWE-532, CWE-209

### Patterns to Find

```bash
grep -rn "log\.\(info\|debug\|warn\|error\)" --include="*.java" . | grep -i "password\|token\|secret\|credit\|ssn\|ktp"
grep -rn "include-stacktrace\|include-message" --include="*.yml" --include="*.properties" .
grep -rn "printStackTrace\|e.getMessage" --include="*.java" . | grep -i "response\|return"
```

### Vulnerable Code

```java
// Logging sensitive data
log.info("User login: username={}, password={}", username, password);  // VULNERABLE
log.debug("Token issued: {}", jwtToken);  // VULNERABLE
log.error("Payment failed for card: {}", cardNumber);  // VULNERABLE — PII

// Stack trace to client
@ExceptionHandler(Exception.class)
public ResponseEntity<String> handleError(Exception e) {
    return ResponseEntity.status(500).body(e.getMessage() + "\n" + Arrays.toString(e.getStackTrace()));
}
```

### Fixed Code

```java
log.info("User login: username={}", username);  // No password
log.debug("Token issued for user: {}", userId);  // No token value
log.error("Payment failed for card ending: {}", cardNumber.substring(cardNumber.length() - 4));

// application.yml
server:
  error:
    include-stacktrace: never
    include-message: never
```

---

## 13. Zero-Security Internal Microservices (Kotlin/Java)

**Severity:** Critical (systemic)
**CWE:** CWE-306

### Context

Common in Kubernetes-native microservices that rely entirely on network-level security (service mesh, NetworkPolicy). The service has NO `spring-boot-starter-security` dependency at all. All endpoints are unauthenticated. This is a fundamentally different (worse) pattern than misconfigured Spring Security.

### Patterns to Find

```bash
# Confirm no security dependency
grep -rn "spring-boot-starter-security\|spring-security" build.gradle* pom.xml 2>/dev/null
# If zero results → CRITICAL systemic finding

# Confirm no security config
find . -name "*Security*" -o -name "*SecurityConfig*" | grep -v test
grep -rn "@EnableWebSecurity\|SecurityFilterChain\|WebSecurityConfigurerAdapter" --include="*.kt" --include="*.java" .

# Count exposed endpoints (for impact assessment)
grep -rn "@GetMapping\|@PostMapping\|@PutMapping\|@DeleteMapping\|@PatchMapping" --include="*.kt" --include="*.java" . | grep -v test | wc -l
```

### Reporting Strategy

Do NOT list every endpoint as a separate finding. Instead:

1. **One Critical finding**: "No Spring Security — all N endpoints unauthenticated" (systemic)
2. **Individual findings only for high-impact operations**: loan disbursement, fund transfer, manual adjustment, FX rate update, admin operations — these get their own findings because they represent distinct attack scenarios with different impacts
3. **Group IDOR findings**: endpoints that accept user-controlled IDs without ownership checks

### Common Patterns in Bank Jago Internal Services

```kotlin
// Pattern: "private" prefix provides ZERO security — just naming convention
@RestController
@RequestMapping("/private/manual-adjustment")  // NOT actually private
class ManualAdjustmentController { ... }

// Pattern: Optional idempotency key defeats deduplication
@PostMapping("/transfer/intrabank")
fun createIntraBankTransaction(
    @RequestBody request: IntraBankTransactionRequestDto,
    @RequestHeader(IDEMPOTENCY_KEY) idempotencyKey: String? = null,  // Optional = double-spend risk
): ResponseEntity<*> {
    intraBankTransactionCoordinator.doTransaction(
        request,
        idempotencyKey?.takeIf { it.isNotBlank() } ?: uuidWrapper.randomUUID(),  // Auto-UUID = no idempotency
    )
}

// Pattern: Mass assignment via Map<String, Any> in financial DTOs
data class HoldBalanceRequestDto(
    val sourceAccountNo: String,
    val transactionAmount: BigDecimal,
    val additionalPayload: Map<String, Any>? = null,  // Accepts ANYTHING
)
```

### Key Differences from Misconfigured Security

| Aspect | Misconfigured Security | Zero Security |
|--------|----------------------|---------------|
| Dependency | Has spring-security | No security dependency |
| Fix effort | Config change | Architecture change |
| Scanner approach | Check filter chain rules | Count exposed endpoints |
| Report framing | "Gaps in auth" | "No auth layer exists" |
| Typical context | External-facing app | Internal K8s microservice |
| Trust model | Gateway + app auth | Network-only (insufficient) |

### Remediation for Zero-Security Services

```kotlin
// Minimum viable: service-to-service JWT validation
implementation("org.springframework.boot:spring-boot-starter-security")
implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")

// SecurityConfig.kt
@Configuration
@EnableWebSecurity
class SecurityConfig {
    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain = http
        .authorizeHttpRequests { auth ->
            auth.requestMatchers("/actuator/health", "/actuator/info").permitAll()
            auth.requestMatchers("/private/admin/**").hasRole("ADMIN")
            auth.anyRequest().authenticated()
        }
        .oauth2ResourceServer { it.jwt {} }
        .build()
}
```

---

## Integration with scode Steps

| Step | How This Scanner Integrates |
|---|---|
| Step 1 (Recon) | Identify Spring Boot version, actuator config, security dependencies |
| Step 2 (Threat Model) | Map controllers → security annotations → gaps |
| Step 3 (Scan) | Run all 12 pattern checks above |
| Step 4 (Validate) | Use `validation-decision-trees.md` for Spring-specific FP elimination |
| Step 5 (Report) | Group by root cause (e.g., "missing default-deny" affects 5 endpoints) |

## Checklist

- [ ] Actuator exposure checked (config + security filter)
- [ ] All controllers have auth annotations (class or method level)
- [ ] SecurityFilterChain has default-deny (`anyRequest().authenticated()`)
- [ ] No SpEL with user input
- [ ] No direct entity binding (DTO layer exists)
- [ ] No `enableDefaultTyping` or unsafe `@JsonTypeInfo`
- [ ] No hardcoded secrets in config files
- [ ] Keycloak config validates audience and requires SSL
- [ ] CORS has explicit origin allowlist (no wildcard + credentials)
- [ ] No string concatenation in SQL queries
- [ ] No user-controlled URLs in RestTemplate/WebClient
- [ ] Async methods propagate security context
- [ ] No sensitive data in log statements
