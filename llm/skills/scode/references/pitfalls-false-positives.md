---
name: ref-pitfalls-false-positives
description: "Common false positive patterns and framework-aware rules to avoid reporting non-issues. Use during sc3 scanning and sc4 validation."
---

## Pitfalls (False Positive Prevention)

- **ORM parameterization protects against SQLi** — Django ORM `.filter()`, SQLAlchemy `.query()`, JPA `@Query` with named params, ActiveRecord `.where()` are all parameterized. Only report SQLi if raw SQL strings with concatenation/f-strings are used. `Model.objects.raw(f"SELECT * FROM x WHERE id={user_input}")` is vulnerable; `Model.objects.filter(id=user_input)` is NOT.
- **React/Vue/Angular auto-escape output** — JSX `{variable}` is escaped by default. Only report XSS if: `dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`, or `bypassSecurityTrustHtml()` is used. Verify the rendering method before claiming stored XSS.
- **`@PreAuthorize` on one method doesn't cover the class** — Spring Security method-level annotations only apply to the annotated method. Other methods in the same controller may be unprotected. Check EACH method independently.
- **`eval()` in build/config scripts isn't RCE** — `eval()` in webpack.config.js, Makefile, setup.py, or test files is not exploitable in production. Only report if `eval()` is in request-handling code with user-controlled input reaching it.
- **Hardcoded credentials in test files aren't production secrets** — `test_password = "admin123"` in `tests/test_auth.py` is a test fixture. Only report if: (a) the credential is in production code, (b) it matches a real service, or (c) it's committed to a non-test config file.
- **`Math.random()` isn't always a vulnerability** — it's only a finding when used for security-sensitive purposes (tokens, session IDs, CSRF tokens, cryptographic keys). Using it for UI randomization, A/B testing, or non-security shuffling is fine.
- **Missing rate limiting alone is Low severity** — "no rate limit on /login" without demonstrating successful brute-force is theoretical. Downgrade to Info unless you can show: (a) no account lockout, (b) no CAPTCHA, (c) feasible password space.
- **CORS `*` on public APIs is by design** — if the API serves public data (no auth required), `Access-Control-Allow-Origin: *` is correct behavior, not a misconfiguration. Only report if credentials are involved.
- **`allowBackup=true` in Android is Info, not Medium** — modern Android (12+) encrypts backups by default. Only escalate if: sensitive data is stored in plaintext SharedPreferences AND the app targets SDK < 31.
- **Dependency CVEs need reachability analysis** — a CVE in a transitive dependency is only exploitable if the vulnerable function is actually called by the application. Don't report `lodash` prototype pollution if the app never calls `_.merge()` with user input. Check the call path.

---
