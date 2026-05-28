# Cross-Skill Triggers

Formalized integration points between `ptest` and other security skills. When a trigger condition is met during any phase, load the referenced skill and follow its workflow.

## Trigger Table

| Trigger Condition | Skill | Phase | Action |
|-------------------|-------|-------|--------|
| Bug bounty program with rules of engagement | `opsec` | Pre-Engagement | Configure headers, UA, rate limits, attribution |
| OSINT gathering begins | `osint` | 1 | Load for structured person/org reconnaissance |
| API endpoints discovered (REST, GraphQL, gRPC) | `atest` | 3, 5, 6 | Load for API-specific testing (auth, BOLA, injection) |
| Cloud infrastructure identified (AWS/GCP/Azure) | `ctest` | 2, 5, 6 | Load for cloud-specific attacks (S3, metadata, IAM) |
| Web3/blockchain components found (smart contracts, wallets) | `w3hunt` | 1, 5, 6 | Load for Web3 bug bounty methodology |
| Source code obtained (source maps, .git, debug, client-provided) | `scode` | Any | Load for structured code review (steps 1-5) |
| Mobile app in scope or APK discovered | `mtest` | 1, 3, 6 | Load for mobile-specific testing |
| Binary/firmware analysis needed | `retools` | 3, 6 | Load for reverse engineering (Ghidra, radare2) |
| Custom exploit development required | `xdev` | 6 | Load for exploit dev (ROP, heap, format string) |

## Integration Details

### opsec → Pre-Engagement

**When:** Every bug bounty engagement, before first request is sent.

**What to extract from opsec skill:**
- Exposure scoring (are we leaving fingerprints?)
- Attribution controls (headers, UA, proxy)
- Rate limit compliance
- Account separation (don't use personal accounts)

**Output:** OPSEC configuration in `state.yaml` under `config.opsec`.

---

### osint → Phase 1

**When:** Phase 1 OSINT Gathering technique begins.

**Trigger:** Always load for bug bounty targets. Skip only for internal pentests where target info is already provided.

**What osint adds that ptest alone misses:**
- Structured person OSINT (employees, developers, admins)
- Organization mapping (subsidiaries, acquisitions, shared infra)
- Breach data correlation (credentials from past breaches)
- Social media intelligence (developer tweets leaking infra details)
- Dark web monitoring (leaked source, credentials, internal docs)

**Feed back:** Discovered assets, emails, credentials → add to Phase 1 output and scope.md.

---

### atest → Phase 3, 5, 6

**When:** API endpoints are discovered during enumeration (Phase 3) or need testing (Phase 5-6).

**Trigger conditions:**
- Swagger/OpenAPI spec found
- REST API endpoints enumerated (JSON responses, /api/ paths)
- GraphQL endpoint discovered (/graphql, introspection)
- gRPC service detected (HTTP/2, protobuf content-type)

**What atest adds that ptest alone misses:**
- BOLA/IDOR systematic testing with ID manipulation
- Mass assignment / parameter pollution
- JWT attack chains (none alg, key confusion, claim tampering)
- Rate limit bypass techniques specific to APIs
- GraphQL-specific attacks (batching, nested queries, introspection)
- API versioning bypass (v1 vs v2 auth differences)

**Feed back:** API findings → ptest findings-log with source: "atest"

---

### ctest → Phase 2, 5, 6

**When:** Cloud infrastructure is identified during reconnaissance.

**Trigger conditions:**
- AWS services detected (S3 buckets, CloudFront, ELB, Lambda URLs)
- GCP services detected (Cloud Storage, Cloud Functions, App Engine)
- Azure services detected (Blob Storage, Azure Functions, App Service)
- Metadata endpoint accessible (169.254.169.254)
- Cloud-specific headers in responses (x-amz-*, x-goog-*, x-ms-*)

**What ctest adds that ptest alone misses:**
- Cloud-specific SSRF (metadata service, IMDSv1/v2)
- S3/GCS/Blob misconfiguration testing
- IAM privilege escalation paths
- Serverless function abuse
- Container escape techniques
- Cloud credential harvesting from exposed services

**Feed back:** Cloud findings → ptest findings-log with source: "ctest"

---

### w3hunt → Phase 1, 5, 6

**When:** Web3/blockchain components are part of the target.

**Trigger conditions:**
- Smart contract addresses in scope
- DeFi protocol being tested
- Wallet integration endpoints found
- Blockchain RPC endpoints discovered
- Token/NFT functionality in the application

**What w3hunt adds that ptest alone misses:**
- Smart contract vulnerability patterns (reentrancy, flash loans, oracle manipulation)
- Immunefi-specific reporting format
- On-chain vs off-chain attack surface distinction
- MEV/frontrunning considerations
- Bridge/cross-chain vulnerabilities

**Feed back:** Web3 findings → ptest findings-log with source: "w3hunt"

---

### scode → Any Phase

**When:** Source code becomes available through any means.

**Trigger conditions (existing in ptest):**
- Phase 1: Source map (`.js.map`) discovered
- Phase 3: Git repository exposed (`.git/`)
- Phase 3: Debug endpoint leaks source
- Phase 5: Client provides source for white-box assessment
- Phase 6: Decompiled mobile app code (from `mtest`)
- Any phase: CTF/Dojo challenge with source code

**Integration workflow (existing):**
1. Trigger → note in current phase checklist
2. Load `scode`, run steps 1-5
3. Findings feed into ptest findings-log with source: "code review"
4. Exploitable endpoints get fast-tracked to Phase 6

---

### mtest → Phase 1, 3, 6

**When:** Mobile application is in scope or discovered during recon.

**Trigger conditions:**
- iOS/Android app listed in program scope
- APK/IPA download link found
- Mobile API endpoints discovered (different from web API)
- Deep links / URL schemes found

**What mtest adds that ptest alone misses:**
- APK/IPA static analysis (hardcoded secrets, certificate pinning)
- Mobile-specific API testing (device tokens, push notifications)
- Deep link injection
- Intent/URL scheme hijacking
- Local storage analysis (SQLite, SharedPreferences, Keychain)
- SSL pinning bypass for traffic interception

**Feed back:** Mobile findings → ptest findings-log with source: "mtest". Decompiled code → trigger `scode`.

---

### retools → Phase 3, 6

**When:** Binary analysis is needed.

**Trigger conditions:**
- Desktop application in scope (Windows/macOS/Linux binary)
- Firmware file obtained
- Custom protocol needs reverse engineering
- Obfuscated/packed binary discovered
- Hardware device in scope

**What retools adds:**
- Ghidra/radare2 decompilation workflow
- Binary vulnerability discovery (buffer overflow, format string, UAF)
- Protocol reverse engineering
- Anti-debug/anti-tamper bypass

---

### xdev → Phase 6

**When:** A vulnerability is confirmed but needs custom exploit development.

**Trigger conditions:**
- Buffer overflow confirmed but needs ROP chain
- Heap corruption found but needs exploitation primitive
- Format string vulnerability needs payload crafting
- Race condition needs precise timing exploit
- Deserialization gadget chain needed

**What xdev adds:**
- Exploit development methodology (Linux/Windows)
- ROP/JOP chain construction
- Heap exploitation techniques
- Shellcode development
- Exploit reliability and cleanup

---

## Chain Patterns

Common multi-skill chains:

1. **Web app with API:** `ptest` → Phase 3 discovers API → `atest` → findings feed back
2. **Full-stack with mobile:** `ptest` → Phase 1 finds APK → `mtest` → decompiled code → `scode`
3. **Cloud-hosted target:** `ptest` → Phase 2 finds AWS → `ctest` → SSRF to metadata → back to `ptest` Phase 6
4. **Source code leak:** `ptest` → Phase 3 finds .git → `scode` → hardcoded creds → `ptest` Phase 6 exploitation
5. **DeFi protocol:** `ptest` → Phase 1 identifies blockchain → `w3hunt` → smart contract audit
6. **Binary target:** `ptest` → Phase 3 finds desktop app → `retools` → vuln found → `xdev` → exploit

## Finding Attribution

When a finding comes from a cross-skill workflow, tag it in findings-log.md:

```markdown
### F-3: Hardcoded AWS Key in Mobile App
- **Source:** mtest → scode (cross-skill chain)
- **Discovery phase:** Phase 3 (enumeration)
- **Skill chain:** ptest/Phase 1 (APK found) → mtest/Step 2 (decompile) → scode/Step 3 (secret scan)
```
