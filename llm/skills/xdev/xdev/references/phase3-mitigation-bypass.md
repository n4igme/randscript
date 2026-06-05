## Phase 3: Mitigation Assessment & Bypass

### Gate: all relevant mitigations identified, bypass strategy selected

**Techniques:**

1. **Mitigation Enumeration:**
   ```bash
   # Linux
   checksec --file=./binary
   cat /proc/sys/kernel/randomize_va_space  # ASLR level
   cat /proc/sys/kernel/kptr_restrict       # KASLR leak protection
   dmesg | grep -i "SMEP\|SMAP\|CET"
   
   # Windows
   # Check PE headers: ASLR, DEP, CFG, CET, ACG
   # Process mitigation policies via Get-ProcessMitigation
   
   # macOS/iOS
   # PAC (arm64e), PPL, AMFI, sandbox profile
   ```

2. **Bypass Selection Matrix:**
   | Mitigation | Bypass Strategy |
   |-----------|-----------------|
   | ASLR | Info leak, partial overwrite, brute force (32-bit) |
   | DEP/NX | ROP/JOP chain, mprotect/VirtualProtect, JIT page abuse |
   | Stack canary | Info leak canary, overwrite past canary to other target, format string |
   | CFI | Counterfeit objects (COOP), valid-but-wrong targets, JIT |
   | CET (shadow stack) | Overwrite non-return control flow, signal frame abuse |
   | SMEP/SMAP | Kernel ROP, physmap spray, ret2dir |
   | PAC (ARM64) | PAC oracle, signing gadgets, PAC-less code paths, dyld interposing abuse |
   | MTE (ARM64) | Brute force (16 tags), use-before-tag-check, speculative bypass |
   | Sandbox | Escape via IPC, shared memory, permitted syscalls, GPU process pivot |
   | SELinux | Transition to permissive domain, exploit allowed operations |

3. **Gadget Discovery:**
   ```bash
   # ROP gadgets
   ROPgadget --binary ./target --ropchain
   ropper -f ./target --search "pop rdi"
   # JOP gadgets
   ROPgadget --binary ./target --jop
   # Kernel gadgets
   ROPgadget --binary vmlinux --ropchain
   ```

**Reference:** `references/mitigation-bypass.md`, `references/arm64-exploitation.md`, `references/ios-webkit-chain.md`

---
