---
name: ref-spring-boot-mass-assignment
description: "Spring Boot Map<String,Object> DTO patterns enabling mass assignment and force-flag injection. Use with vuln-spring-boot or vuln-api."
---

# Spring Boot Mass Assignment Patterns

## Critical Pattern: Map<String, Any> in Request DTOs

When a DTO accepts `additionalPayload: Map<String, Any>?` or similar untyped maps:

### Detection
```bash
grep -rn "Map<String, Any>" --include="*.kt" --include="*.java" | grep -i "dto\|request\|model"
```

### Validation Steps

1. **Is it persisted?** Check if the field exists on the `@Document` / `@Entity` model
2. **Is it used in business logic?** Search for `.get("fieldname")` patterns:
   ```bash
   grep -rn "additionalPayload\|additional_payload" --include="*.kt" | grep -v test
   ```
3. **What does it control?** Common dangerous patterns:
   - `force = (additionalPayload?.get("force") ?: false) as Boolean` → bypass validation
   - `skipFdsCheck = additionalPayload?.get("skipFds")` → bypass fraud detection
   - Passed to downstream Kafka events → influences other services

### Amplifying Factors

- Global `FAIL_ON_UNKNOWN_PROPERTIES = false` on ObjectMapper → any JSON field silently accepted
- `@JsonIgnoreProperties(ignoreUnknown = true)` on DTOs → same effect per-class
- No `@JsonProperty(access = READ_ONLY)` on server-populated fields
- `var` (mutable) fields on data classes → can be modified after binding

### Severity Assessment

| Scenario | Severity |
|----------|----------|
| Map stored but never read downstream | Low (data pollution) |
| Map read but only for logging/display | Medium |
| Map controls business logic (force, skip, bypass) | High |
| Map controls financial operations + no auth | Critical |

### Real-World Example (ms-transaction-coordinator)

```kotlin
// HoldBalanceRequestDto.kt — accepts arbitrary map from request
val additionalPayload: Map<String, Any>? = null,

// DebitTransactionExecutor.kt:1110 — uses it to force transactions
force = (transaction.additionalPayload?.get("force") ?: false) as Boolean

// Also checked in:
// - HoldAuthorizationService (skip failure notification)
// - TransactionFdsCheckerService (fraud detection bypass)
// - EventProducerService (passed to Kafka events)
```

### Remediation

1. Replace `Map<String, Any>` with strongly-typed DTO containing only allowed fields
2. Add `@JsonProperty(access = JsonProperty.Access.READ_ONLY)` for server-populated fields
3. Remove `force`/`skip` flags from request DTOs — these should be service-level decisions
4. If map is needed for extensibility, use allowlist validation:
   ```kotlin
   val ALLOWED_KEYS = setOf("note", "reference")
   val sanitized = additionalPayload?.filterKeys { it in ALLOWED_KEYS }
   ```
