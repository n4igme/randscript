# Teleport Remote Access Proxy Assessment

## Overview

Gravitational Teleport is an identity-aware access proxy for SSH, Kubernetes, databases, and web applications. When exposed to the internet, it reveals significant infrastructure details via unauthenticated endpoints.

## Detection Signals

| Signal | Indicator |
|--------|-----------|
| Subdomain pattern | `teleport-proxy.*`, `teleport.*`, `tp.*`, `access.*` |
| Response headers | `Cache-Control: no-cache, no-store, must-revalidate` + CSP with `wss:` |
| Cookie | `__Host-grv_csrf` (HttpOnly, Secure, SameSite=None) |
| Redirect | 302 → `/web` on root path |
| Meta tag | `grv_csrf_token`, `grv_bearer_token` in HTML |

## Unauthenticated Endpoints

### /webapi/ping (CRITICAL — always check first)

Returns full proxy configuration:
```bash
curl -sk "https://teleport-proxy.target.com/webapi/ping" | python3 -m json.tool
```

**Information disclosed:**
- `server_version` — exact Teleport version for CVE targeting
- `edition` — "ent" (Enterprise) or "oss" (Community)
- `cluster_name` — Kubernetes cluster identifier
- `auth.type` — "oidc", "saml", "github", "local"
- `auth.second_factor` — "otp", "webauthn", "off"
- `auth.oidc.name` — SSO provider name
- `auth.oidc.IssuerURL` — SSO issuer (e.g., accounts.google.com)
- `auth.default_session_ttl` — session duration
- `proxy.kube.enabled` — Kubernetes access proxy
- `proxy.ssh.listen_addr` — SSH proxy
- `proxy.ssh.public_addr` — public hostname
- `proxy.db.postgres_listen_addr` — PostgreSQL proxy
- `proxy.db.mysql_listen_addr` — MySQL proxy
- `proxy.tls_routing_enabled` — all services on single port
- `auto_update.tools_version` — update channel version

### /.well-known/openid-configuration

OIDC discovery document (Teleport acts as its own OIDC provider):
```bash
curl -sk "https://teleport-proxy.target.com/.well-known/openid-configuration"
```

Reveals: issuer URL, JWKS URI, supported grants/scopes/claims.

### /.well-known/jwks-oidc

Public signing keys:
```bash
curl -sk "https://teleport-proxy.target.com/.well-known/jwks-oidc"
```

### /webapi/sites

Requires session cookie — returns "missing session cookie" error (confirms endpoint exists).

### /webapi/auth/type

May return auth configuration details.

## CVE Mapping

| Version Range | CVE | Impact |
|--------------|-----|--------|
| < 14.3.20 | CVE-2024-6468 | Auth bypass via SAML |
| < 15.4.7 | CVE-2024-52529 | Privilege escalation |
| < 16.4.12 | CVE-2025-27567 | Session hijack |

Always check: https://goteleport.com/docs/changelog/

## Attack Vectors

### 1. Social Engineering (if Google SSO)
- Teleport login page is accessible
- Attacker can craft phishing targeting employees with "Login using Google SSO" button
- If 2FA is "otp" (TOTP), phishing proxy (evilginx2) can capture both password + OTP

### 2. Session TTL Abuse
- Long session TTLs (12h+) mean stolen cookies remain valid for extended periods
- Combined with XSS on any same-origin page → session theft

### 3. Kubernetes Access
- If `proxy.kube.enabled: true`, successful auth grants kubectl access
- Teleport issues short-lived certs for K8s API access
- Cluster name disclosure aids targeting

### 4. Database Access
- If `proxy.db.postgres_listen_addr` or `mysql_listen_addr` is set, successful auth grants direct DB access
- Combined with credential discovery elsewhere → database compromise

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| /webapi/ping accessible + version disclosed | Medium (5.3) |
| + Kubernetes proxy enabled | Medium-High (6.5) |
| + Database proxy enabled | High (7.0) |
| + auth.second_factor: "off" | High (7.5) |
| + Known CVE for disclosed version | Critical (9.0+) |

## Remediation

1. Restrict `/webapi/ping` to authenticated users
2. Place Teleport behind VPN or IP allowlist for initial access
3. Disable OIDC discovery if not needed for external integrations
4. Ensure `second_factor` is never "off" in production
5. Keep Teleport updated (security patches are frequent)
6. Monitor for brute-force against SSO flow
