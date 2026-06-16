# Phase 4: Business Logic Testing

## Gate: Client-side controls bypassed, license/auth tested, role separation verified

## Steps

### 4.1 Client-Side Validation Bypass

**Approach:** Identify checks enforced client-side only, bypass via:
1. **Binary patching** — NOP out validation (dnSpy for .NET, x64dbg for native)
2. **Memory editing** — Change values at runtime (Cheat Engine, x64dbg)
3. **Traffic modification** — Intercept and alter request/response in proxy
4. **Config tampering** — Modify local files the app reads

**Common client-side-only controls:**
- Input length/format validation
- Price/quantity limits
- Role/permission display (UI hides features but API allows)
- Date/time restrictions
- Feature flags stored locally

### 4.2 License / Activation Bypass

**.NET license checks:**
```
1. Decompile with dnSpy
2. Search: "license", "trial", "expire", "activate", "serial"
3. Find validation method → patch return value to true
4. Recompile and test
```

**Java license checks:**
```
1. Decompile with JADX/JD-GUI
2. Find license validator class
3. Modify bytecode (Recaf) or replace class in JAR
4. Re-sign JAR if needed: jarsigner -keystore debug.keystore app.jar alias
```

**Native license:**
- Find license check function (string xrefs → "invalid license", "trial expired")
- Patch conditional jump (JZ → JNZ or NOP)
- Document the bypass but note: license bypass alone is often low severity for internal pentests

### 4.3 Role / Authorization Testing

1. Log in as low-privilege user
2. Map all functions available in UI
3. Log in as high-privilege user (admin)
4. Map additional functions
5. As low-privilege user, attempt admin operations via:
   - Direct API calls (captured from admin session)
   - Binary patching (enable hidden UI elements)
   - Memory editing (change role flag in memory)
   - Config tampering (role stored in local file/registry)

### 4.4 Data Tampering

- Modify request parameters (price, quantity, user ID)
- Change response data before app processes it (proxy intercept)
- Test negative values, zero values, overflow values
- Test concurrent operations (race conditions via multiple app instances)

### 4.5 Offline Mode Abuse

If app works offline:
- What data is cached locally? (full database? credentials?)
- Can offline actions be replayed with modifications?
- Does sync validate integrity of offline changes?
- Can you create conflicting state (offline edit + online edit)?

### 4.6 Update Mechanism

- Does the app check for updates over HTTP (not HTTPS)? → MitM update injection
- Is the update binary signature-verified?
- Can you serve a malicious update via DNS spoofing?
- Update URL hardcoded? Redirectable?

## Severity Guidelines

| Finding | Typical Severity | Escalation Path |
|---------|-----------------|-----------------|
| License bypass | Low-Medium | Chain: bypass → access paid features → data access |
| Client-side price manipulation | High | If server doesn't re-validate |
| Role bypass (UI only) | Medium | If server enforces → Low |
| Role bypass (API accepts) | High-Critical | Direct privilege escalation |
| Offline data exposure | Medium-High | Depends on data sensitivity |
| Insecure update (HTTP) | High | Code execution via update MitM |
| DLL hijack + privileged service | High | Local privilege escalation |

## Handoff
If memory corruption discovered during patching/fuzzing → invoke xdev for full exploit development.
