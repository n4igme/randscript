# Burp Browser Cookie Extraction (macOS)

## When to Use
When Burp MCP SSE bridge isn't working or you need session cookies from Burp's pre-wired browser for authenticated testing via curl.

## Problem
Burp MCP (mcp-burp.jar) uses SSE transport on port 9876. The jar connects TO Burp's SSE extension but doesn't expose its own server. The SSE protocol requires establishing a listener BEFORE sending messages on the same session ID. This often fails from CLI tools.

## Workaround: Direct Cookie DB Extraction

Burp's pre-wired Chromium browser stores cookies at:
```
~/.BurpSuite/pre-wired-browser/Default/Cookies
```

### Step 1: Get Encryption Key
```python
import subprocess
result = subprocess.run(
    ['security', 'find-generic-password', '-s', 'Chromium Safe Storage', '-w'],
    capture_output=True, text=True
)
key_password = result.stdout.strip()
```

### Step 2: Derive AES Key
```python
import hashlib
key = hashlib.pbkdf2_hmac('sha1', key_password.encode(), b'saltysalt', 1003, dklen=16)
```

### Step 3: Decrypt Cookies (AES-128-CBC)
```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sqlite3

db_path = "~/.BurpSuite/pre-wired-browser/Default/Cookies"
conn = sqlite3.connect(db_path)
cursor = conn.cursor()
cursor.execute("SELECT host_key, name, encrypted_value FROM cookies WHERE host_key LIKE '%target%'")

for host, name, enc_value in cursor.fetchall():
    if enc_value[:3] == b'v10':
        enc_data = enc_value[3:]
        iv = b' ' * 16
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(enc_data) + decryptor.finalize()
        # Remove PKCS7 padding
        pad_len = decrypted[-1]
        if 0 < pad_len <= 16:
            decrypted = decrypted[:-pad_len]
        # First block (16 bytes) decrypts to garbage due to CBC IV mismatch
        # Find printable ASCII suffix - actual value starts after garbage prefix
        raw = decrypted.decode('utf-8', errors='replace')
        # Strip non-printable prefix (typically 32 chars of garbage + ">S" marker)
        # The real value follows the last non-printable character
```

### Pitfall: CBC First Block Corruption
The first 16 bytes of decrypted output are garbage because Chromium uses a different IV internally than the space-filled IV we provide. The actual cookie value appears after a ~32-byte garbage prefix. Look for patterns like `>S` followed by the real value, or find the longest printable ASCII suffix.

### Pitfall: v10 vs AES-GCM
Newer Chromium versions (100+) may use AES-GCM instead of AES-CBC. Format: `v10` + 12-byte nonce + ciphertext + 16-byte tag. Try GCM first, fall back to CBC.

## Burp MCP Architecture (for reference)
- Burp listens on port 9876 (SSE extension from BApp Store)
- mcp-burp.jar (in hermes config) is a stdio-to-SSE bridge client
- Port 8080 is Burp's HTTP proxy (not API)
- The MCP tools: get_proxy_http_history, get_proxy_http_history_regex, send_http1_request, send_http2_request
- All require `count` and `offset` params
- Response entries are newline-separated JSON, not array
