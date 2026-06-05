## Phase 1: Vulnerability Analysis

### Gate: root cause identified, trigger conditions documented, exploitability assessed

**Techniques:**

1. **Crash Triage:**
   ```bash
   # ASAN output analysis
   # Register state at crash (RIP/PC, RSP/SP, controlled registers)
   # Signal type: SIGSEGV (read/write?), SIGBUS, SIGABRT
   # Faulting instruction context
   ```

2. **Root Cause Classification:**
   - UAF: object freed, dangling pointer dereferenced — what allocator? what size?
   - OOB: buffer bounds exceeded — by how much? controlled length?
   - Type confusion: wrong vtable/type used — what types are confused?
   - Integer overflow: arithmetic wraps — where does the result flow?
   - Race condition: TOCTOU window — how wide? can it be widened?
   - Format string: user input as format — stack read/write primitive?

3. **Constraint Mapping:**
   - What bytes are controlled in the overflow/write?
   - What's the allocation size? (heap exploitation strategy depends on this)
   - What's the time window? (race conditions)
   - What code paths reach the vulnerability from attacker input?
   - Are there size/character/alignment restrictions?

4. **Exploitability Assessment:**
   | Rating | Criteria |
   |--------|----------|
   | Trivial | Direct PC control, no mitigations, large controlled buffer |
   | Moderate | Requires info leak + heap shaping, standard mitigations |
   | Complex | Tight constraints, multiple bugs needed, modern mitigations |
   | Theoretical | Proven vulnerable but no practical path to exploitation |

**Reference:** `references/linux-userland.md`, `references/windows-userland.md` (crash triage sections)

---
