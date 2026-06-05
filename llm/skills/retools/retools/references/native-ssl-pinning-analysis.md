# Finding SSL Pinning in Obfuscated Native Android Libraries

## Problem

Obfuscated Android native libs (`.so`) have mangled JNI function names and no obvious
"ssl_pinning" symbol. You need to locate the pinning function for bypass.

## Strategy: String-based Xref Tracing

Don't guess from function names. Trace from known strings backward.

### Step 1: Identify the binary

```bash
# Find which .so contains the obfuscated JNI class
grep -rl "Java_<class_prefix>" /path/to/lib/

# Confirm SSL pinning exists in that binary
strings -a <binary.so> | grep -i "sha256//\|SHA-256\|X509\|getEncoded\|CertificatePinner\|checkServerTrusted"
```

### Step 2: Get string file offsets

```bash
strings -t x -a <binary.so> | grep "sha256//\|public key hash"
```

### Step 3: Calculate Ghidra virtual addresses

For ELF with base offset (Ghidra typically loads at 0x00100000):
```
VA = rodata_VA + (string_file_offset - rodata_file_offset)
```

If file offset == VA in section headers (common for .so), just add Ghidra's image base.

Parse ELF to find .rodata section offset, or use Ghidra's string search directly.

### Step 4: Find the pinning function via xrefs

```bash
curl -s "http://127.0.0.1:8080/xrefs_to?address=0x<string_VA>"
```

All pinning-related strings typically converge on ONE function.

### Step 5: Decompile and analyze

```bash
curl -s -X POST -d "FUN_<address>" http://127.0.0.1:8080/decompile
```

## Common SSL Pinning Implementations in Native Android

| Library | Key strings | Pattern |
|---------|------------|---------|
| libcurl/mbedTLS | `sha256//`, `;sha256//`, `vtls/vtls.c` | SHA-256 of pubkey, base64 compare via memcmp |
| OkHttp native | `sha256/`, `CertificatePinner` | Base64 pin list, JNI calls to Java crypto |
| Custom mbedTLS | `X509`, `peer certificate`, `SHA-256` | Raw cert comparison or pubkey hash |
| BoringSSL/OpenSSL | `ssl_ctx`, `X509_STORE`, `verify_callback` | Custom verify callback |
| Flutter (BoringSSL) | In libflutter.so, `ssl_crypto_x509` | SecurityContext with hardcoded certs |

## Bypass Points (for Frida)

Once you find the function:

1. **Hook the pinning function** — force return success (0)
2. **Hook memcmp inside it** — return 0 when called with pin-length args
3. **Hook the hash computation** — replace computed hash with expected pin
4. **Patch the binary** — NOP the comparison branch

## Pitfalls

- `/methods` endpoint has a 99-result limit. Use `/list_functions` for the full list (7000+).
- `/strings` endpoint also has a limit (~99). For comprehensive string search, use `strings` CLI on the binary file directly.
- JNI vtable offset `0x538` = `NewStringUTF` on arm64. Seeing this in decompiled code means the function returns a Java string.
- Obfuscated function names (e.g., `oOoOoOo0000`) give no hint about purpose. Always trace from strings/data, not names.
- The pinning function may NOT be a JNI export — it's often an internal C function called by the TLS handshake code.
