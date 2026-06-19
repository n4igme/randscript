---
name: vuln-authn-session
description: "Scan for authentication & session management vulnerabilities (broken auth, JWT flaws, session fixation). Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Step 3h: Authentication & Session Management Vulnerabilities

Scan for flaws in authentication mechanisms, session handling, and credential management.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Vulnerability Patterns

### Broken Authentication
- Missing or weak password policies
- No brute-force protection / account lockout
- Credential stuffing vectors (no rate limiting on login)
- Password reset flaws (predictable tokens, no expiry, token reuse)
- Missing MFA on sensitive operations

**Grep patterns**: `login`, `authenticate`, `password`, `credential`, `signIn`, `logIn`, `resetPassword`, `forgotPassword`, `verifyToken`

### JWT Vulnerabilities
- Algorithm confusion (`alg: none`, RS256→HS256 downgrade)
- Weak signing secrets (short/guessable keys)
- Missing expiration (`exp`) or not-before (`nbf`) validation
- Token not invalidated on logout/password change
- Sensitive data in JWT payload without encryption
- JWK/JWKS injection

**Grep patterns**: `jwt`, `jsonwebtoken`, `sign(`, `verify(`, `decode(`, `algorithm`, `HS256`, `RS256`, `secret`, `JWT_SECRET`, `expiresIn`

### Session Management
- Session fixation (session ID not rotated after login)
- Insecure session storage (localStorage for auth tokens)
- Missing `HttpOnly`, `Secure`, `SameSite` cookie flags
- Session tokens in URL parameters
- No session expiration / infinite session lifetime
- Session not invalidated on logout

**Grep patterns**: `session`, `cookie`, `Set-Cookie`, `localStorage`, `sessionStorage`, `httpOnly`, `secure`, `sameSite`, `maxAge`, `expires`, `destroy(`, `invalidate(`

### OAuth/OIDC Flaws
- Missing or weak `state` parameter (CSRF on OAuth flow)
- Open redirect in `redirect_uri` validation
- Token leakage via referrer headers
- Insecure token storage post-OAuth

**Grep patterns**: `oauth`, `oidc`, `redirect_uri`, `state`, `authorization_code`, `access_token`, `refresh_token`, `client_secret`, `grant_type`

### Credential Storage
- Plaintext password storage
- Weak hashing (MD5, SHA1 without salt)
- Missing or weak salt
- Secrets/API keys hardcoded in source

**Grep patterns**: `bcrypt`, `argon2`, `scrypt`, `pbkdf2`, `md5`, `sha1`, `hashSync`, `compareSync`, `salt`, `hash(`

## Process

For each priority target from threat-model.md:

1. **Map auth flows** — identify login, registration, password reset, token refresh, logout endpoints
2. **Inspect token handling** — how are sessions/JWTs created, validated, stored, and invalidated?
3. **Check protections** — rate limiting, lockout, token rotation, secure flags
4. **Verify logout** — does logout actually destroy the session/invalidate the token?
5. **Assess impact** — account takeover, session hijacking, privilege escalation

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Authentication & Session Management

**Date**: {date}
**Scanner**: vuln-authn-session

## Findings

### VULN-AUTH-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Broken Auth / JWT Flaw / Session Fixation / OAuth Flaw / Credential Storage}
**Location**: `{file}:{line}`
**CWE**: CWE-{287|384|613|306|916|521}

**Description**:
{What the vulnerability is}

**Vulnerable Code**:
```{lang}
{code snippet}
`` `

**Attack Scenario**:
1. {Step-by-step exploitation}

**Proof of Concept**:
{Exploit payload/request}

**Impact**:
{What attacker gains — account takeover, session hijack, etc.}

**Remediation**:
```{lang}
{fixed code}
`` `

---
```


## Positive Observations

While scanning, note any strong security patterns relevant to this scanner's domain. Add them to the `# Positive Security Observations` section at the end of `vulnerabilities.md`:

```markdown
- {scanner-name}: {what the codebase does well in this area}
```
## Rules

- **Only report confirmed auth/session flaws** — verify the weakness is actually exploitable.
- **Check for compensating controls** — WAF rate limiting, IP blocking, or other mitigations.
- **Include the exact attack scenario** showing how an attacker exploits the flaw.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — Authentication & Session Management` section, replace it entirely. See `sc3-vuln-scan` idempotency rule.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
