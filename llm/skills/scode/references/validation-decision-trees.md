---
name: ref-validation-decision-trees
description: "Framework-specific decision trees for eliminating false positives (React, Next.js, Spring, Django, etc.). Use during sc4 validation."
---

# Validation Decision Trees

Framework-specific decision trees for eliminating false positives during Step 4 validation.

## How to Use

For each finding from Step 3, identify the framework context and follow the relevant decision tree. If you reach "FALSE POSITIVE", reclassify. If you reach "CONFIRMED", keep the finding.

---

## XSS Decision Trees

### React/JSX

```
Found user input in JSX?
├── Is it inside dangerouslySetInnerHTML?
│   ├── YES → Is the input sanitized (DOMPurify, sanitize-html)?
│   │   ├── YES → Check sanitizer config (is it strict enough?) → LIKELY FALSE POSITIVE
│   │   └── NO → CONFIRMED (High)
│   └── NO → Is it in a href/src attribute?
│       ├── YES → Does it allow javascript: protocol?
│       │   ├── YES → CONFIRMED (Medium)
│       │   └── NO (validated/prefixed with https://) → FALSE POSITIVE
│       └── NO → React auto-escapes → FALSE POSITIVE
```

### Next.js Specific

- **Server Components**: no client-side XSS possible (but check for SSR injection into `<script>` tags or JSON-LD)
- `getServerSideProps` returning unsanitized data: React still escapes on render → FALSE POSITIVE for XSS
- `next/head` with user input: potential meta tag injection (check if `<meta http-equiv>` can be set)
- API routes returning HTML without `Content-Type: application/json` → CONFIRMED if user input reflected
- `next/image` with user-controlled `src`: check `remotePatterns` config for SSRF, not XSS

### Spring Boot (Server-rendered)

```
Found user input in template?
├── Thymeleaf?
│   ├── th:text → FALSE POSITIVE (auto-escapes)
│   ├── th:utext → CONFIRMED (High — no escaping)
│   ├── th:attr with href/src → Check for javascript: protocol
│   └── th:fragment with user-controlled name → CONFIRMED (template injection)
├── JSP?
│   ├── <c:out value="${var}"/> → FALSE POSITIVE (escapes by default)
│   ├── ${variable} directly in HTML → CONFIRMED (High)
│   └── <%=variable%> → CONFIRMED (High)
└── ResponseEntity?
    ├── Content-Type: text/html + user input in body → CONFIRMED (High)
    └── Content-Type: application/json → FALSE POSITIVE
```

---

## SQL Injection Decision Trees

### Spring Data JPA

```
Found SQL-like pattern with user input?
├── Is it a Spring Data repository method (findBy*, countBy*)?
│   └── YES → FALSE POSITIVE (Spring generates parameterized queries)
├── Is it @Query with :paramName or ?1 syntax?
│   └── YES → FALSE POSITIVE (parameterized)
├── Is it @Query with string concatenation (+ variable)?
│   └── YES → CONFIRMED (High)
├── Is it EntityManager.createNativeQuery() with concatenation?
│   └── YES → CONFIRMED (High)
├── Is it Criteria API with user input in field names?
│   └── YES → CONFIRMED (Medium — field name injection)
├── Is it JdbcTemplate with ? placeholders?
│   └── YES → FALSE POSITIVE (parameterized)
└── Is it JdbcTemplate with string concatenation?
    └── YES → CONFIRMED (High)
```

### Sort/OrderBy Injection

```
User controls Sort parameter?
├── Is it Spring Data Pageable from request?
│   ├── Does the app validate sort property against allowlist?
│   │   ├── YES → FALSE POSITIVE
│   │   └── NO → Can arbitrary column names be injected?
│   │       ├── YES (native query with ORDER BY ${sort}) → CONFIRMED (Medium)
│   │       └── NO (JPA validates entity fields) → LOW (info disclosure of field names)
├── Is it used in @Query with SpEL #{#pageable}?
│   └── YES (native query) → CONFIRMED (Medium — bypasses JPA validation)
└── Is Sort.by() called with user input directly?
    └── YES → Same as Pageable analysis above
```

---

## SSRF Decision Trees

### RestTemplate / WebClient

```
User input reaches URL parameter of HTTP client?
├── Is the URL fully user-controlled?
│   └── YES → CONFIRMED (High/Critical)
├── Is only a path segment user-controlled (base URL hardcoded)?
│   ├── Can path traversal reach other hosts? (../ or @)
│   │   ├── YES → CONFIRMED (High)
│   │   └── NO → Is the base URL internal (service mesh)?
│   │       ├── YES → CONFIRMED (Medium — internal SSRF)
│   │       └── NO → LOW (limited SSRF)
├── Is only a query parameter user-controlled?
│   └── Generally LOW (but check if downstream interprets it as URL)
├── Is there URL validation?
│   ├── Allowlist of domains? → Check bypass (DNS rebinding, redirects, open redirects)
│   ├── Blocklist of IPs? → Check bypass (decimal IP, IPv6, DNS rebinding, 0x7f000001)
│   └── Protocol check only (https://)? → CONFIRMED (redirects can bypass to internal)
└── Does the response body get returned to the user?
    ├── YES → Severity +1 (data exfiltration possible)
    └── NO (blind) → Still confirmed but lower impact
```

### Next.js API Routes

```
fetch() in API route or Server Component with user input?
├── Same analysis as RestTemplate above
├── Additional: Does next.config.js have rewrites/redirects with user input?
│   └── YES → Check if destination can be manipulated → CONFIRMED if so
└── Server Actions calling external APIs with user-controlled params?
    └── Apply same decision tree as above
```

---

## Access Control Decision Trees

### Spring Security

```
Endpoint without explicit auth annotation?
├── Is there a class-level @PreAuthorize?
│   └── YES → FALSE POSITIVE (inherited)
├── Is there a SecurityFilterChain covering this path?
│   ├── .authenticated() or .hasRole() on this path? → FALSE POSITIVE
│   ├── .permitAll() on this path? → Is this intentional (login, public API)?
│   │   ├── YES → FALSE POSITIVE
│   │   └── NO (sensitive operation) → CONFIRMED (Medium-High)
│   └── Path not matched by any rule? → Check default
├── Is the controller in a package scanned by component scan?
│   └── NO → FALSE POSITIVE (not actually registered)
└── Is there a default-deny rule (anyRequest().authenticated())?
    ├── YES + this path not explicitly permitted → FALSE POSITIVE (caught by default)
    └── NO default deny → CONFIRMED (missing default deny is itself a finding)
```

### IDOR (Insecure Direct Object Reference)

```
Endpoint accesses resource by user-supplied ID?
├── Is there @PreAuthorize with ownership check (e.g., #id == principal.id)?
│   └── YES → FALSE POSITIVE
├── Does the service layer filter by authenticated user?
│   └── YES (e.g., findByIdAndUserId()) → FALSE POSITIVE
├── Is the ID a UUID (non-guessable)?
│   └── YES → LOW (not a fix, but reduces exploitability)
└── Sequential/guessable ID + no ownership check?
    └── CONFIRMED (High)
```

### Next.js Middleware Auth

```
Protected route without auth check?
├── Is there middleware.ts matching this route?
│   ├── YES + checks session/token → FALSE POSITIVE
│   └── NO or route not in matcher → Check page-level auth
├── Does the page/layout check session server-side?
│   └── YES (getServerSession, auth()) → FALSE POSITIVE
└── Client-only auth check (useSession redirect)?
    └── CONFIRMED (Medium — API data still accessible without auth)
```

---

## Deserialization Decision Trees

### Jackson

```
Found ObjectMapper usage?
├── Is enableDefaultTyping() or activateDefaultTyping() called?
│   └── YES → CONFIRMED (Critical — RCE via gadget chains)
├── Is @JsonTypeInfo(use=Id.CLASS) on any model?
│   └── YES → CONFIRMED (High — polymorphic deserialization)
├── Is @JsonTypeInfo(use=Id.MINIMAL_CLASS) on any model?
│   └── YES → CONFIRMED (High — same risk as Id.CLASS)
├── Is @JsonTypeInfo(use=Id.NAME) with @JsonSubTypes?
│   └── YES → FALSE POSITIVE (closed type set)
├── Standard @RequestBody with POJO?
│   └── FALSE POSITIVE (Spring default ObjectMapper is safe)
└── Custom ObjectMapper bean with non-default config?
    └── Review config for polymorphic type handling
```

### Java Native Deserialization

```
Found ObjectInputStream.readObject()?
├── Is the input from untrusted source (network, user upload, message queue)?
│   └── YES → CONFIRMED (Critical — RCE)
├── Is there a ValidatingObjectInputStream or look-ahead filter?
│   ├── YES → Check allowlist strictness → LIKELY FALSE POSITIVE if tight
│   └── NO → CONFIRMED (Critical)
└── Is it reading from a trusted, integrity-protected source?
    └── LOW (but still a code smell)
```

---

## Mass Assignment Decision Trees

```
Controller binds request body to object?
├── Is it a DTO (separate from entity)?
│   ├── YES → Does DTO contain sensitive fields (role, isAdmin, balance)?
│   │   ├── YES → CONFIRMED (High)
│   │   └── NO → FALSE POSITIVE
│   └── NO (binds directly to entity) → Does entity have sensitive fields?
│       ├── YES + no @JsonIgnore on them → CONFIRMED (High)
│       └── YES + @JsonIgnore present → FALSE POSITIVE
├── Is there @JsonIgnoreProperties on the class?
│   └── YES → Check if sensitive fields are listed → FALSE POSITIVE if covered
└── Is there @InitBinder with setAllowedFields?
    └── YES → Check if sensitive fields are excluded → likely FALSE POSITIVE
```

### Spring Boot Specific Patterns

```
@ModelAttribute binding (form data)?
├── Same tree as above, but also check:
├── Is WebDataBinder.setDisallowedFields() configured?
│   └── YES → FALSE POSITIVE (but check for bypass via field aliases)
└── Is it a @RequestParam map (Map<String, String>)?
    └── Not mass assignment — developer explicitly handles each field
```

---

## CORS Decision Trees

```
Found @CrossOrigin or CorsConfiguration?
├── origins = "*" (or addAllowedOriginPattern("*"))?
│   ├── allowCredentials = true? → CONFIRMED (Critical)
│   │   (Note: Spring actually blocks this combo — verify it compiles)
│   └── allowCredentials = false? → LOW (no credential theft, but check sensitive data)
├── Origin from request header reflected dynamically?
│   ├── YES + allowCredentials = true → CONFIRMED (Critical)
│   └── YES + allowCredentials = false → LOW
├── Specific origins listed?
│   ├── Are any attacker-registrable? (expired domains, *.example.com subdomain patterns)
│   │   ├── YES → CONFIRMED (Medium)
│   │   └── NO → FALSE POSITIVE
│   └── Is null origin allowed? → CONFIRMED (Medium — sandboxed iframes send null)
└── CORS only on non-sensitive endpoints (public data)?
    └── FALSE POSITIVE (no sensitive data exposed cross-origin)
```

---

## Path Traversal Decision Trees

```
User input used in file path?
├── Is it passed to Spring's ResourceLoader / ClassPathResource?
│   ├── ClassPathResource → Limited to classpath → LOW
│   └── FileSystemResource with user input → CONFIRMED (High)
├── Is there path normalization (Paths.get().normalize())?
│   ├── YES + starts-with check after normalization → FALSE POSITIVE
│   └── YES but check before normalization → CONFIRMED (bypass possible)
├── Is the filename from an upload (multipart)?
│   ├── Is only the filename used (not full path from client)?
│   │   ├── YES + sanitized (strip ../) → FALSE POSITIVE
│   │   └── NO → CONFIRMED (Medium)
│   └── Is UUID/random name generated server-side?
│       └── YES → FALSE POSITIVE
└── Spring Content / Spring Resource server?
    └── Check if resource paths are scoped to a root directory
```

---

## CSRF Decision Trees

```
State-changing endpoint (POST/PUT/DELETE)?
├── Is Spring Security CSRF protection enabled (default: YES)?
│   ├── YES → Is the endpoint excluded via csrf().ignoringRequestMatchers()?
│   │   ├── YES → Is it an API endpoint with token auth (no cookies)?
│   │   │   ├── YES → FALSE POSITIVE (CSRF not applicable for token auth)
│   │   │   └── NO (cookie-based auth) → CONFIRMED (Medium)
│   │   └── NO (CSRF protection active) → FALSE POSITIVE
│   └── NO (csrf().disable()) → Is the app purely API with token auth?
│       ├── YES (JWT/Bearer in Authorization header) → FALSE POSITIVE
│       └── NO (session cookies used) → CONFIRMED (Medium)
└── Next.js API route?
    ├── Does it use SameSite=Strict/Lax cookies? → LOW (browser mitigates)
    ├── Does it verify Origin/Referer header? → FALSE POSITIVE
    └── No CSRF protection + cookie auth → CONFIRMED (Medium)
```

---

## Secrets/Credential Exposure Decision Trees

```
Found hardcoded secret/key/password?
├── Is it in a test file or test resources?
│   ├── YES → Is it a real credential (connects to real service)?
│   │   ├── YES → CONFIRMED (Medium)
│   │   └── NO (test-only value like "password123") → FALSE POSITIVE
├── Is it in application.properties/yml?
│   ├── Is it a placeholder (${ENV_VAR})?
│   │   └── YES → FALSE POSITIVE
│   ├── Is it a default for local dev only (spring.profiles: local)?
│   │   └── LOW (but flag if it could leak to prod)
│   └── Is it a production credential committed to repo?
│       └── CONFIRMED (Critical)
├── Is it in .env.example or .env.local.example?
│   └── FALSE POSITIVE (template file, not real secrets)
└── Is it in client-side code (React/Next.js)?
    ├── NEXT_PUBLIC_* env var → Is it meant to be public (analytics ID)?
    │   ├── YES → FALSE POSITIVE
    │   └── NO (API secret key) → CONFIRMED (Critical)
    └── Hardcoded in source → CONFIRMED (High)
```

---

## Common False Positive Patterns

The top 10 false positives encountered in Spring Boot + React/Next.js code reviews, with explanations of why they're false positives and what to verify before dismissing.

### 1. React JSX Auto-Escaping (reported as XSS)

**Why it's a false positive:** React's rendering engine automatically escapes all values embedded in JSX via `{}` interpolation. The value is treated as text content, not HTML. `<script>` becomes the literal string `<script>` in the DOM.

**What to verify before dismissing:**
- Confirm the value is NOT inside `dangerouslySetInnerHTML`
- Confirm it's not being used in a `href`, `src`, or event handler attribute where `javascript:` protocol could execute
- Confirm no `ref` manipulation is inserting it via `.innerHTML`

---

### 2. Spring Data Derived Queries (reported as SQLi)

**Why it's a false positive:** Spring Data JPA generates parameterized queries from method names like `findByUsername(String username)`. The framework uses prepared statements internally — there is no string concatenation in the generated SQL.

**What to verify before dismissing:**
- Confirm it's actually a derived query method (follows naming convention)
- Confirm there's no `@Query` annotation overriding the derived behavior
- Confirm the repository interface extends `JpaRepository` or similar Spring Data interface

---

### 3. @RequestBody with Jackson Default Config (reported as deserialization)

**Why it's a false positive:** Spring Boot's default `ObjectMapper` does NOT enable polymorphic type handling. Without `enableDefaultTyping()` or `@JsonTypeInfo(use=Id.CLASS)`, Jackson only deserializes into the declared POJO type — no gadget chain exploitation is possible.

**What to verify before dismissing:**
- Check for custom `ObjectMapper` beans that might enable default typing
- Check for `@JsonTypeInfo` annotations on the target class or its fields
- Check `application.properties` for `spring.jackson.default-property-inclusion` or mapper features

---

### 4. Pageable Sort Parameter (reported as SQLi when JPA validates)

**Why it's a false positive:** When using Spring Data JPA (not native queries), the `Sort` parameter from `Pageable` is validated against the entity's field names. Invalid field names throw an exception rather than being injected into SQL.

**What to verify before dismissing:**
- Confirm the repository method uses JPQL, not a native query
- If `@Query(nativeQuery=true)` with `#{#pageable}`, this IS vulnerable — reclassify as CONFIRMED
- Check if there's a custom `Sort` handling that bypasses JPA validation

---

### 5. RestTemplate with Hardcoded Base URL + Path Variable (reported as full SSRF)

**Why it's a false positive:** When the base URL is hardcoded (e.g., `https://api.internal.com/`) and only a path segment comes from user input, the attack surface is limited to that specific service. Full SSRF (reaching arbitrary hosts) requires controlling the scheme+host.

**What to verify before dismissing:**
- Confirm the base URL is truly hardcoded (not from config that could be manipulated)
- Check if path traversal (`../`) or URL encoding could escape the base path
- Check if the `@` character in the path could redefine the host (e.g., `http://base@evil.com`)
- If UriComponentsBuilder is used, it may handle these safely

---

### 6. @PreAuthorize at Class Level (reported as missing auth)

**Why it's a false positive:** `@PreAuthorize` at the class level applies to ALL methods in that controller. Individual methods inherit the class-level security constraint unless explicitly overridden.

**What to verify before dismissing:**
- Confirm `@EnableMethodSecurity` (or `@EnableGlobalMethodSecurity`) is active
- Check if any method has its own `@PreAuthorize` that might be MORE permissive
- Confirm the class-level annotation has the correct SpEL expression

---

### 7. SecurityFilterChain Default-Deny Catching Unlisted Paths

**Why it's a false positive:** When `SecurityFilterChain` ends with `.anyRequest().authenticated()`, any path not explicitly configured with `.permitAll()` requires authentication. An unlisted endpoint is protected by default.

**What to verify before dismissing:**
- Confirm `anyRequest().authenticated()` (or `.denyAll()`) is the last rule
- Check ordering: if multiple `SecurityFilterChain` beans exist, confirm the default-deny chain has the lowest `@Order` (catches everything else)
- Verify no `WebSecurity.ignoring()` patterns that bypass the filter chain entirely

---

### 8. Thymeleaf th:text (reported as XSS when it auto-escapes)

**Why it's a false positive:** `th:text` performs HTML entity escaping automatically. Characters like `<`, `>`, `&`, `"` are escaped to their entity equivalents. Only `th:utext` renders unescaped HTML.

**What to verify before dismissing:**
- Confirm it's `th:text` and NOT `th:utext`
- Check if the value is also used in `th:attr` for `href`/`src` (different context, different escaping needs)
- Check for `th:inline="javascript"` blocks where escaping rules differ

---

### 9. Spring CSRF Protection Enabled by Default (reported as missing CSRF)

**Why it's a false positive:** Spring Security enables CSRF protection by default for all state-changing requests. Unless explicitly disabled with `csrf().disable()` or `csrf(c -> c.disable())`, protection is active.

**What to verify before dismissing:**
- Search for `csrf().disable()` or `.csrf(AbstractHttpConfigurer::disable)` in security config
- Check if specific paths are excluded via `csrf().ignoringRequestMatchers()`
- For REST APIs using only Bearer token auth (no cookies), CSRF protection is unnecessary anyway

---

### 10. BCrypt Password Storage (reported as 'weak crypto' by pattern matchers)

**Why it's a false positive:** Pattern-based scanners flag any use of "crypt" or detect BCrypt as a "custom crypto implementation." BCrypt is an industry-standard password hashing algorithm specifically designed for secure password storage. Spring Security's `BCryptPasswordEncoder` uses a strong work factor by default.

**What to verify before dismissing:**
- Confirm it's `BCryptPasswordEncoder` (not a custom implementation)
- Check the strength/work factor (default 10 is acceptable, <8 is weak)
- Confirm passwords aren't ALSO stored in plaintext elsewhere (log files, audit tables)
- Verify it's not being used for non-password crypto (BCrypt has a 72-byte input limit)

---

## Quick Reference: Validation Checklist

Before marking any finding as FALSE POSITIVE, confirm:

1. **Framework version** — older versions may lack protections assumed here
2. **Custom configuration** — defaults may be overridden in config files
3. **Transitive data flow** — the safe function may receive already-tainted data from an unsafe source
4. **Multiple contexts** — a value safe in one context (HTML body) may be unsafe in another (JavaScript, URL)
5. **Defense in depth** — even if one layer protects, note if other layers are missing (for recommendations)
