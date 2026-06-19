---
name: ref-proven-patterns
description: "Vulnerability patterns that reliably produce real findings in bug bounty. Use to prioritize scanning effort."
---

# Proven Code Review Patterns

High-hit-rate findings from past reviews. Check these first during Step 3 scanning before running full scanner methodology.

## Pattern 1: Raw SQL with String Interpolation

**Scanner:** injection
**Check:** `grep -rn "f\"SELECT\|f\"INSERT\|f\"UPDATE\|f\"DELETE\|.format(.*SELECT\|%s.*SELECT" --include="*.py" --include="*.java" --include="*.js"`
**FP filter:** Exclude ORM `.filter()`, `.query()`, parameterized `?` or `:param`
**Severity:** Critical (if user input reaches it)

## Pattern 2: Missing Auth Middleware on New Routes

**Scanner:** access-control
**Check:** Compare route definitions against auth middleware application. Look for routes added after initial auth setup that bypass the middleware chain.
**Pattern:** Express `app.get('/admin/...')` without `requireAuth`, Spring `@RequestMapping` without `@PreAuthorize`, Django view without `@login_required`
**Severity:** High-Critical

## Pattern 3: Hardcoded JWT Secret in Config

**Scanner:** authn-session
**Check:** `grep -rn "secret.*=\|JWT_SECRET\|signing_key\|HMAC_KEY" --include="*.env*" --include="*.yaml" --include="*.json" --include="*.py" --include="*.js"`
**FP filter:** Exclude test files, exclude references to env var lookups (`os.environ`, `process.env`)
**Severity:** Critical (allows token forgery)

## Pattern 4: SSRF in Webhook/Callback URLs

**Scanner:** ssrf
**Check:** Find endpoints accepting URLs (webhook registration, callback URLs, import/fetch features). Trace if URL reaches `fetch()`, `requests.get()`, `http.Get()` without allowlist.
**Pattern:** `/api/webhooks`, `/api/import`, `/api/fetch`, `callback_url` parameter
**Severity:** High-Critical (cloud metadata access)

## Pattern 5: Mass Assignment on User Update

**Scanner:** api / access-control
**Check:** Find user update endpoints. Check if request body is spread directly into model update without field allowlist.
**Pattern:** `User.update(req.body)`, `serializer.save()` without `fields=`, `Object.assign(user, req.body)`
**Severity:** High (role escalation via `{"role": "admin"}`)

## Pattern 6: Secrets in Error Responses

**Scanner:** data-exposure
**Check:** Find error handlers. Check if stack traces, DB connection strings, or internal paths leak in non-dev mode.
**Pattern:** `res.status(500).json({ error: err })`, `traceback.format_exc()` in response, missing `DEBUG=False` check
**Severity:** Medium-High

## Pattern 7: Insecure Direct Object Reference (IDOR)

**Scanner:** access-control
**Check:** Find endpoints with path params (`/api/users/:id`, `/api/orders/:id`). Check if handler verifies the authenticated user owns the requested resource.
**Pattern:** `db.find(req.params.id)` without `where: { userId: req.user.id }`
**Severity:** High

---

## When to Add New Patterns

Add after review when:
- Pattern produced a confirmed High+ finding
- Applies across multiple tech stacks or projects
- Can be checked in <5 minutes with grep + code trace
