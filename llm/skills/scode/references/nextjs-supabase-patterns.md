---
name: ref-nextjs-supabase-patterns
description: "Next.js + Supabase auth/RLS security patterns and common misconfigurations. Use when reviewing Next.js+Supabase apps."
---

# Common Vulnerability Patterns & False Positives: Next.js + Supabase + AWS S3

## Known False Positives

### 1. XSS via React JSX Text Interpolation
**Pattern**: User data stored in DB → rendered via `{value}` in JSX
**Why it's a false positive**: React auto-escapes all text content in JSX. `<`, `>`, `&`, `"` are escaped automatically.
**True sinks**: Only `dangerouslySetInnerHTML`, `href` attributes with `javascript:` protocol, and `src` attributes are real XSS vectors in React.

### 2. SQL Injection via Supabase JS Client
**Pattern**: User input passed to `.eq()`, `.ilike()`, `.in()`, `.filter()`
**Why it's a false positive**: Supabase JS client parameterizes all values server-side via PostgREST. These are NOT vulnerable to SQL injection.
**True sinks**: Only `.rpc()` with string interpolation inside the SQL function, or unescaped LIKE wildcards (`%`, `_`) in `.ilike()` patterns (which is a LIKE pattern manipulation issue, not SQLi).

### 3. Workflow Bypass When Precondition Is Structurally Enforced
**Pattern**: Endpoint Y doesn't check condition X before performing action.
**Why it's often a false positive**: If the resource operated on by endpoint Y can ONLY be created by endpoint Z (which enforces condition X), then the check at Y is redundant — not missing.
**Example**: "Publish without payment check" is a false positive if invitations are only created by the admin verify endpoint (which requires payment confirmation).
**How to verify**: Trace all code paths that INSERT the resource. If all paths enforce the condition, it's structurally guaranteed.

### 4. IDOR When UUIDs Are Used
**Pattern**: Endpoint takes an ID parameter without ownership check.
**Why it's often lower severity**: UUIDv4 has 122 bits of entropy — enumeration is impractical. Still report if ownership check is missing, but note the UUID mitigation.

## Real Vulnerability Patterns

### 1. dangerouslySetInnerHTML with Weak Sanitizer
**Pattern**: User data → regex-based sanitizer → dangerouslySetInnerHTML
**Why it's real**: Regex sanitizers are fundamentally bypassable. Common bypasses:
- Unquoted event handlers: `<img src=x onerror=alert(1)>`
- SVG vectors: `<svg onload=alert(1)>`
- javascript: URIs: `<a href="javascript:alert(1)">`
**Fix**: Use DOMPurify with allowlist.

### 2. CSP unsafe-inline + XSS Sink
**Pattern**: CSP has `script-src 'unsafe-inline'` AND a dangerouslySetInnerHTML sink exists
**Why it's real**: The two together form a complete XSS chain. CSP won't block inline event handlers injected via the sink.

### 3. Presigned S3 URL Without Content-Length
**Pattern**: aws4fetch sign() without Content-Length in headers
**Why it's real**: The presigned URL will accept any file size. Client-side limits are trivially bypassed.
**Note**: May be mitigated by S3 bucket policy (configured outside codebase) — flag as "needs dynamic testing."

### 4. Rate Limiter Fail-Open
**Pattern**: Rate limiter returns `allowed: true` on database error
**Why it's real**: During DB outages, all rate-limited endpoints become unprotected.
**Severity modifier**: Downgrade if attacker cannot easily trigger DB errors.

### 5. CSV Formula Injection via Public Input
**Pattern**: Public endpoint accepts text → stored → exported to CSV without formula escaping
**Why it's real**: Characters `= + - @` at start of cell trigger formula execution in Excel/Sheets.
**Fix**: Prefix with single quote or tab.

### 6. Unsalted Hash for "Anonymous" Tracking
**Pattern**: SHA-256(user-agent + date) without secret salt
**Why it's real**: User-Agent strings are from a small, known set. Precomputation is trivial.

### 7. JsonLd Script Tag Breakout (Theoretical)
**Pattern**: `JSON.stringify(data)` inside `dangerouslySetInnerHTML` within a `<script type="application/ld+json">` tag
**Why it's often a false positive**: JSON.stringify doesn't escape `</script>`, but the data flowing into JsonLd is typically admin-controlled (template names, static schemas). Only report if user-controlled data actually flows into the component's props.
**How to verify**: Search all usages of the JsonLd component and trace the `data` prop source.

### 8. SVG Upload XSS (Admin-Only)
**Pattern**: SVG files allowed in upload, no sanitization, stored on S3
**Why it's often lower severity**: If SVGs are rendered via `<img>` tag in the app, scripts are sandboxed. Only exploitable if the raw S3 URL is opened directly in a browser.
**Severity modifier**: Downgrade if admin-only upload AND in-app rendering uses `<img>`. Still report as defense-in-depth gap.

### 9. Webhook Timing Attack
**Pattern**: `secret !== process.env.WEBHOOK_SECRET` (non-constant-time comparison)
**Why it's often lower severity**: Practical timing attacks over the network require thousands of precise measurements. If the webhook only dispatches notifications (no state mutation), impact is limited to notification spam even if secret is extracted.
**Severity**: Low unless the webhook can modify financial/auth state.

## Supabase-Specific Notes

- **RLS bypass via createAdminClient()**: Not a vulnerability IF ownership is checked in application code before/after. But it means RLS provides zero safety net — security relies entirely on app logic.
- **profiles.role field**: If RLS allows users to UPDATE their own profile row without column restrictions, role escalation is possible. Check if Zod schema on the API endpoint restricts which fields can be set.
- **Public RLS policies (USING true)**: Verify exactly what data is exposed. A public SELECT on `platform_settings` might only return non-sensitive fields if the API endpoint filters columns.
