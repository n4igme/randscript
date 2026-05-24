# Proprietary Crypto & Validation Reversing

When targets use custom validation logic (license keys, proprietary tokens, custom HMAC, obfuscated signing), this reference provides a systematic approach to reverse-engineer and bypass them.

---

## When This Applies

- License key validation (CTF challenges, software protection)
- Custom API signing (non-standard HMAC, proprietary hash)
- Token generation with predictable algorithms
- Obfuscated client-side validation (JS, WASM)
- Custom checksum/CRC in binary protocols
- Proprietary session token formats

---

## 1. Algorithm Identification

### Step 1: Classify the Validation Type

| Pattern | Likely Algorithm | Approach |
|---------|-----------------|----------|
| Fixed-length hex/alphanumeric, grouped with dashes | License key (checksum-based) | Constraint solving |
| Base64 blob with consistent structure | Custom token (may contain JSON/fields) | Decode + structure analysis |
| Hex string matching hash length (32/40/64 chars) | MD5/SHA1/SHA256 with custom salt | Identify salt/pepper, brute-force or preimage |
| Numeric with check digit | Luhn/Verhoeff/custom modular arithmetic | Identify the modulus and weights |
| JWT-like (3 dot-separated base64 segments) | Modified JWT or custom signed token | Check if standard JWT tools work first |

### Step 2: Identify Constants

Look for magic numbers that reveal the algorithm:

| Constant | Algorithm |
|----------|-----------|
| `1103515245` | Linear Congruential Generator (LCG) — glibc |
| `6364136223846793005` | LCG — Knuth |
| `0x5DEECE66D` | Java `Random` LCG |
| `0x6c078965` | Mersenne Twister |
| `0x9e3779b9` | Golden ratio (TEA/XTEA cipher, hash functions) |
| `0x67452301`, `0xefcdab89` | MD5 init vectors |
| `0x6a09e667` | SHA-256 init vector |
| `0x61C88647` | Fibonacci hashing |
| `Math.imul` + large multiplier | LCG variant |

---

## 2. Constraint Solving Approach

For license key / checksum validation with multiple constraints:

### Step 1: List All Constraints

Extract each `if`/`return` condition from the validation function:

```
Constraint 1: format check (length, charset, grouping)
Constraint 2: first nibble/byte must be in set {A, C}
Constraint 3: relationship between parts (B ^ A) & 0xFF === 0x37
Constraint 4: divisibility check (C % 7 === 0)
Constraint 5: derived value (D = f(A, B, C))
```

### Step 2: Solve in Dependency Order

Start with independent constraints, then solve dependent ones:

```
1. Choose A freely (satisfying constraint 2)
2. Derive B from A (constraint 3)
3. Choose C independently (constraint 4)
4. Compute D from A, B, C (constraint 5)
```

### Step 3: Verify Programmatically

```javascript
// ALWAYS copy the EXACT validation function from source
// Don't re-implement from your understanding — copy verbatim
function validateKey(key) { /* exact source code */ }

// Test your solution
console.log(validateKey("A000-0037-0007-D9A9")); // must be true
```

**Critical rule:** Copy the validation function exactly as-is from the target. Don't paraphrase or simplify. Subtle differences (operator precedence, integer overflow, signed vs unsigned) will produce wrong results.

---

## 3. Linear Congruential Generator (LCG) Reversing

LCGs are the most common "custom crypto" in CTF and license key systems:

```
next = (a * current + c) mod m
```

### Identifying LCG Parameters

| Parameter | Common Values |
|-----------|--------------|
| Multiplier (a) | `1103515245`, `214013`, `1664525`, `6364136223846793005` |
| Increment (c) | `12345`, `2531011`, `1337`, `1013904223` |
| Modulus (m) | `2^32`, `2^31`, `2^16`, `0xFFFF`, `0xFFFFFFFF` |

### Reversing LCG (finding previous state)

```python
# Forward: next = (a * state + c) % m
# Reverse: state = (next - c) * modinv(a, m) % m

from sympy import mod_inverse

def lcg_reverse(output, a, c, m):
    a_inv = mod_inverse(a, m)
    return (a_inv * (output - c)) % m
```

### Predicting from Output

If you can observe multiple outputs, recover parameters:

```python
# Given outputs s0, s1, s2:
# s1 = a*s0 + c (mod m)
# s2 = a*s1 + c (mod m)
# Therefore: a = (s2 - s1) * modinv(s1 - s0, m) (mod m)
#            c = s1 - a*s0 (mod m)
```

---

## 4. XOR-Based Validation

### Simple XOR Checksum

```javascript
// Pattern: XOR all bytes, compare to expected
let check = 0;
for (let i = 0; i < data.length; i++) {
    check ^= data[i];
}
return check === EXPECTED;
```

**Bypass:** Set the last byte to `EXPECTED ^ (XOR of all other bytes)`.

### Rolling XOR with Shift

```javascript
// Pattern: XOR with rotating shift
let check = SEED;
for (let i = 0; i < data.length; i++) {
    check = ((check << 3) | (check >>> 29)) ^ data[i];
}
return check === EXPECTED;
```

**Approach:** Work backwards from EXPECTED, applying inverse operations (right-shift, XOR) to determine what the last byte must be.

---

## 5. Modular Arithmetic Validation

### Check Digit (Luhn-like)

```javascript
// Pattern: weighted sum mod N === 0
let sum = 0;
for (let i = 0; i < digits.length; i++) {
    sum += digits[i] * weights[i];
}
return sum % N === 0;
```

**Bypass:** Choose all digits freely except one, then compute the last digit as:
```
lastDigit = (N - (partialSum % N)) % N / weight[lastPos]
```

### Divisibility Constraints

```javascript
// C % 7 === 0
// Solution: C can be 0x0007, 0x000E, 0x0015, ... any multiple of 7
```

Pick the smallest valid value unless other constraints restrict it.

---

## 6. JavaScript-Specific Pitfalls

### Integer Overflow Behavior

```javascript
// JavaScript numbers are 64-bit float — no natural overflow at 2^32
// BUT: bitwise operators truncate to 32-bit signed integer
0xFFFFFFFF | 0    // → -1 (signed 32-bit)
0xFFFFFFFF >>> 0  // → 4294967295 (unsigned 32-bit)

// Math.imul() — true 32-bit integer multiplication
Math.imul(0xA030, 1103515245)  // Correct 32-bit result
// vs: 0xA030 * 1103515245     // May lose precision for large values
```

### Operator Precedence Traps

```javascript
// & has LOWER precedence than === and ==
(B ^ (A & 0xFF)) & 0xFF === 0x37
// Parses as: (B ^ (A & 0xFF)) & (0xFF === 0x37)
// Which is: (B ^ (A & 0xFF)) & false → 0

// The ACTUAL code likely has explicit parens:
((B ^ (A & 0xFF)) & 0xFF) === 0x37
```

**Always test with the exact source code, not your interpretation.**

### parseInt() Behavior

```javascript
parseInt("0x1F", 16)  // 31
parseInt("1F", 16)    // 31
parseInt("0xG", 16)   // 0 (stops at invalid char)
parseInt("", 16)      // NaN
```

---

## 7. Obfuscated Client-Side Validation

### JavaScript Deobfuscation

```bash
# Tools (in order of preference):
# 1. de4js — https://lelinhtinh.github.io/de4js/
# 2. synchrony — npm install -g deobfuscator
# 3. webcrack — npm install -g webcrack
# 4. Manual: beautify + rename variables + trace execution

# Quick beautify:
npx prettier --parser babel obfuscated.js > readable.js

# AST-based deobfuscation:
npx webcrack obfuscated.js > deobfuscated.js
```

### WASM Validation

If validation is in WebAssembly:
1. Use `wasm-decompile` (from wabt toolkit) for pseudo-C output
2. Use Ghidra with WASM loader for full analysis
3. Look for exported functions matching validation names
4. Trace the function's memory reads to find constants

---

## 8. Systematic Solving Workflow

```
1. EXTRACT — Copy the exact validation function from source
2. IDENTIFY — Classify algorithm type (LCG, XOR, modular, hash-based)
3. CONSTANTS — Find magic numbers, identify known algorithms
4. CONSTRAINTS — List all conditions that must be satisfied
5. ORDER — Determine dependency graph (which constraints depend on others)
6. SOLVE — Work from independent constraints to dependent ones
7. VERIFY — Run the EXACT source function with your solution
8. DOCUMENT — Record the algorithm, solution method, and valid inputs
```

---

## 9. Common CTF/Challenge Patterns

| Challenge Type | Typical Validation | Solving Approach |
|---------------|-------------------|------------------|
| License key (hex groups) | Format + checksum + LCG | Constraint solving |
| JWT with custom signing | Modified HMAC or symmetric | Find key in source/config |
| PIN/OTP validation | Time-based or counter-based | Predict next value from observed |
| Encrypted cookie | AES-ECB or XOR with static key | ECB block manipulation or key extraction |
| Custom hash comparison | Timing side-channel | Byte-by-byte brute force |
| Obfuscated password check | String comparison after transforms | Reverse the transforms |

---

## 10. Tools

| Tool | Use Case |
|------|----------|
| `z3` (Python) | SMT solver for complex constraint systems |
| `angr` | Symbolic execution for binary validation |
| `CyberChef` | Quick encoding/decoding/crypto operations |
| `hashcat` | Brute-force known hash formats |
| `node --inspect` | Debug JS validation step-by-step |
| `Python sympy` | Modular arithmetic (mod_inverse, CRT) |

### Z3 Example (Complex Constraints)

```python
from z3 import *

A, B, C, D = BitVecs('A B C D', 16)
s = Solver()

# Constraint 1: first nibble is 0xA or 0xC
s.add(Or(LShR(A, 12) == 0xA, LShR(A, 12) == 0xC))

# Constraint 2: (B ^ (A & 0xFF)) & 0xFF == 0x37
s.add((B ^ (A & 0xFF)) & 0xFF == 0x37)

# Constraint 3: C % 7 == 0, C > 0
s.add(URem(C, 7) == 0)
s.add(C > 0)

# Constraint 4: D == LCG(seed)
seed = (A ^ B ^ C) & 0xFFFF
# Note: Z3 BitVec multiplication handles overflow naturally
s.add(D == (seed * 1103515245 + 1337) & 0xFFFF)

if s.check() == sat:
    m = s.model()
    print(f"Key: {m[A].as_long():04X}-{m[B].as_long():04X}-{m[C].as_long():04X}-{m[D].as_long():04X}")
```
