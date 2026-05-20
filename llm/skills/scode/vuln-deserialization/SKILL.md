---
name: vuln-deserialization
description: "Step 3e of bug bounty workflow. Scan for insecure deserialization and XXE vulnerabilities. Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Step 3e: Deserialization & XXE

Scan for insecure deserialization and XML External Entity injection.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for data formats and parsing
- If either is missing, tell the user which step to run first

## Applicability

Skip if the codebase has no deserialization or XML parsing — no `serialize`/`pickle`/`ObjectInputStream`/`Marshal`/`yaml.load` usage and no XML/SOAP endpoints. Report "Not applicable" and skip.

## Vulnerability Patterns

### Insecure Deserialization
- `pickle.loads()` / `pickle.load()` with user data (Python)
- `unserialize()` with user input (PHP)
- `ObjectInputStream.readObject()` with untrusted data (Java)
- `Marshal.load()` with user data (Ruby)
- `yaml.load()` without SafeLoader (Python)
- `JSON.parse()` with reviver that instantiates classes
- `node-serialize`, `serialize-javascript` with user input

**Grep patterns**: `pickle.load`, `unserialize`, `readObject`, `Marshal.load`, `yaml.load`, `deserialize`, `fromJSON`

### XML External Entity (XXE)
- XML parsing without disabling external entities
- DTD processing enabled on user-supplied XML
- SOAP endpoints accepting raw XML
- SVG upload/processing (SVG is XML)
- Office document parsing (DOCX/XLSX are XML-based)

**Grep patterns**: `XMLParser`, `DocumentBuilder`, `SAXParser`, `etree.parse`, `xml.dom`, `lxml`, `FEATURE_EXTERNAL_ENTITIES`, `DOCTYPE`

### What Makes It Exploitable
- User can supply the serialized data or XML directly
- No integrity check (signature, HMAC) on serialized data
- XML parser has default (unsafe) configuration
- Deserialized objects trigger dangerous operations (gadget chains)

## Process

1. **Find all deserialization calls** — grep for language-specific deserialize functions
2. **Trace data source** — is the input user-controlled or from a trusted internal source?
3. **Check for integrity validation** — is the data signed/verified before deserializing?
4. **Find all XML parsers** — check their configuration for external entity handling
5. **Check file upload** — are XML-based formats (SVG, DOCX) parsed unsafely?

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Deserialization & XXE

**Date**: {date}
**Scanner**: vuln-deserialization

## Findings

### VULN-DS-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Insecure Deserialization / XXE}
**Location**: `{file}:{line}`
**CWE**: CWE-{502|611}

**Description**:
{How untrusted data reaches unsafe deserialization/XML parsing}

**Vulnerable Code**:
```{lang}
{code showing unsafe call}
`` `

**Attack Scenario**:
{Payload that achieves RCE or file read}

**Impact**:
{RCE, local file read, SSRF via XXE, DoS via billion laughs}

**Remediation**:
{Use safe alternatives, disable external entities, validate before deserializing}

---
```

## Rules

- **Deserialization of untrusted data is almost always Critical** — it often leads to RCE.
- **Check XML parser defaults** — many are unsafe by default.
- **Don't forget file uploads** — SVG and Office formats are XML attack vectors.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — Deserialization - **Append to `./assessment/vulnerabilities.md`** and confirm. XXE` section, replace it entirely. See `sc3-vuln-scan` idempotency rule.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
