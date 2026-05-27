# Fix Verification (Redo/Reassessment Engagements)

Methodology for verifying previously reported findings during reassessment.

---

### Fix Verification (Redo/Reassessment Engagements)

When redoing a pentest or reassessing previously reported findings:

1. **Test ALL gateways/paths to the same backend** — a fix applied to one gateway (e.g., `microservices.prod.bfi.co.id`) may NOT be applied to another gateway routing to the same service (e.g., `microservices.prod.bravo.bfi.co.id`). In the BFI redo, F-1 was "fixed" on one gateway but the Bravo gateway remained fully vulnerable.
2. **Test the exact same PoC** — don't assume the fix works. Replay the original exploit steps verbatim.
3. **Test adjacent endpoints** — if `/master/v1/general` was fixed, check `/master/v1/address/province`, `/master/v1/bank`, etc.
4. **Document fix status per gateway:**
   ```markdown
   | Gateway | Endpoint | Previous Status | Current Status |
   |---------|----------|----------------|----------------|
   | microservices.prod.bfi.co.id | /master/v1/general | Vuln (GET/POST/PATCH) | Fixed (401) |
   | microservices.prod.bravo.bfi.co.id | /master/v1/general | Vuln (GET/POST/PATCH) | STILL VULNERABLE |
   ```
5. **Incomplete fixes are findings** — document as "Incomplete Remediation" with reference to the original finding ID. Severity remains the same (or higher if the incomplete fix creates false confidence).