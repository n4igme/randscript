# Reference File Index

Quick lookup: what you found → which reference to load.

---

## By Discovery (what you encountered in code)

| You Found | Load This Reference |
|-----------|---|
| SQL query with string concatenation / f-string | `vuln-injection.md` |
| `exec()`, `eval()`, `system()`, `child_process.exec()` | `vuln-injection.md` |
| Template rendering with user input (Jinja2, EJS, Pug) | `vuln-injection.md` (SSTI) |
| `innerHTML`, `dangerouslySetInnerHTML`, `v-html` | `vuln-injection.md` (XSS) |
| MongoDB query with `$where` or operator injection | `vuln-injection.md` (NoSQL) |
| Missing `@PreAuthorize` / `@Secured` / auth middleware | `vuln-access-control.md` |
| IDOR pattern (user ID from request used in query) | `vuln-access-control.md` |
| No Spring Security dependency at all | `zero-auth-microservice-pattern.md` |
| Hardcoded API key / secret / password | `vuln-data-exposure.md` |
| Verbose error messages / stack traces in response | `vuln-data-exposure.md` |
| PII logged without masking | `vuln-data-exposure.md` |
| HTTP client with user-controlled URL | `vuln-ssrf.md` |
| `fetch()` / `axios` / `RestTemplate` with dynamic URL | `vuln-ssrf.md` |
| `ObjectInputStream.readObject()` / `pickle.loads()` | `vuln-deserialization.md` |
| XML parser without disabled external entities | `vuln-deserialization.md` (XXE) |
| `JSON.parse()` + deep merge / lodash.merge | `vuln-deserialization.md`, `vuln-nodejs.md` |
| CORS `*` / missing CSP / debug mode enabled | `vuln-misconfig.md` |
| Default credentials in config | `vuln-misconfig.md` |
| Race condition opportunity (check-then-act) | `vuln-logic.md` |
| Business logic (pricing, workflow, state machine) | `vuln-logic.md` |
| Missing rate limiting on sensitive endpoint | `vuln-logic.md` |
| JWT handling / custom token validation | `vuln-authn-session.md` |
| OAuth implementation / redirect_uri handling | `vuln-authn-session.md` |
| Session fixation / cookie without flags | `vuln-authn-session.md` |
| `Math.random()` for security / weak hash (MD5/SHA1) | `vuln-crypto.md` |
| Custom HMAC / homegrown token signing | `vuln-crypto.md`, `vuln-custom-crypto.md` |
| Hardcoded encryption key / static IV | `vuln-crypto.md` |
| File upload without validation | `vuln-file-path.md` |
| `path.join()` / `path.resolve()` with user input | `vuln-file-path.md`, `vuln-nodejs.md` |
| Zip/archive extraction (yauzl, adm-zip, ZipInputStream) | `vuln-file-path.md`, `vuln-nodejs.md` |
| Open redirect / `location.href = userInput` | `vuln-client-side.md` |
| Prototype pollution (`__proto__`, `constructor.prototype`) | `vuln-client-side.md`, `vuln-nodejs.md` |
| Outdated dependency with known CVE | `vuln-dependency.md` |
| Private npm registry / internal package names | `vuln-dependency.md` (confusion) |
| GraphQL schema / resolver | `vuln-api.md` |
| Mass assignment (extra fields in request body) | `vuln-api.md`, `spring-boot-mass-assignment-patterns.md` |
| Regex with nested quantifiers / user-controlled regex | `vuln-dos.md` |
| Unbounded query / missing pagination | `vuln-dos.md` |
| Buffer operations / pointer arithmetic (C/C++/Rust unsafe) | `vuln-memory.md` |
| Solidity `call` / `delegatecall` / reentrancy guard | `vuln-web3-reentrancy.md` |
| Solidity arithmetic without SafeMath (pre-0.8) | `vuln-web3-arithmetic.md` |
| Solidity `onlyOwner` / access control modifiers | `vuln-web3-access.md` |
| Flash loan / oracle price feed | `vuln-web3-mev.md` |
| ERC20/ERC721 token implementation | `vuln-web3-token.md` |
| AMM / lending / bridge contract | `vuln-web3-defi.md` |
| NFT metadata / randomness / royalty | `vuln-web3-nft.md` |
| Storage slots / assembly / gas optimization | `vuln-web3-evm.md` |
| Restaking, Account Abstraction, L2/Rollup, Intent-based | `vuln-web3-modern.md` |
| Foundry fork PoC development for Immunefi | `foundry-poc-cookbook.md` |
| Real exploit post-mortems by vuln class | `web3-real-exploits-database.md` |
| Immunefi report format, severity, rejection reasons | `immunefi-report-template.md` |
| Oracle manipulation math, profitability calculations | `web3-economic-feasibility.md` |
| Terraform / Dockerfile / K8s manifest / CI config | `vuln-infra.md` |
| Helm values / Istio AuthorizationPolicy / NetworkPolicy | `deployment-security-checks.md` |
| Spring Boot actuator / SpEL / `@RequestBody` binding | `vuln-spring-boot.md` |
| `Map<String, Any>` in Spring DTO | `spring-boot-mass-assignment-patterns.md` |
| Next.js + Supabase patterns | `nextjs-supabase-patterns.md` |
| `require()` / `module.createRequire()` with dynamic path | `vuln-nodejs.md` |
| `vm.runInContext()` / `vm2` sandbox | `vuln-nodejs.md` |
| Node.js `serialize` / `unserialize` | `vuln-nodejs.md` |
| React Native / Flutter / Xamarin decompiled code | `vuln-mobile-code.md` |
| Android BuildConfig / strings.xml / SharedPreferences | `vuln-mobile-code.md` |
| iOS Info.plist / Keychain usage / cert pinning | `vuln-mobile-code.md` |

---

## By Scanner (which reference each scanner uses)

| Scanner ID | Name | Reference |
|-----------|------|-----------|
| 3a | injection | `vuln-injection.md` |
| 3b | access-control | `vuln-access-control.md` |
| 3c | data-exposure | `vuln-data-exposure.md` |
| 3d | ssrf | `vuln-ssrf.md` |
| 3e | deserialization | `vuln-deserialization.md` |
| 3f | misconfig | `vuln-misconfig.md` |
| 3g | logic | `vuln-logic.md` |
| 3h | authn-session | `vuln-authn-session.md` |
| 3i | crypto | `vuln-crypto.md` |
| 3j | file-path | `vuln-file-path.md` |
| 3k | client-side | `vuln-client-side.md` |
| 3l | dependency | `vuln-dependency.md` |
| 3m | api | `vuln-api.md` |
| 3o | dos | `vuln-dos.md` |
| 3p | memory | `vuln-memory.md` |
| 3t | infra | `vuln-infra.md` |
| 3u | spring-boot | `vuln-spring-boot.md` |
| 3v | deployment-security | `deployment-security-checks.md` |
| 3w | nodejs | `vuln-nodejs.md` |
| 3x | custom-crypto | `vuln-custom-crypto.md` |
| 3y | mobile-code | `vuln-mobile-code.md` |
| 3n-i | web3-reentrancy | `vuln-web3-reentrancy.md` |
| 3n-ii | web3-arithmetic | `vuln-web3-arithmetic.md` |
| 3n-iii | web3-access | `vuln-web3-access.md` |
| 3n-iv | web3-mev | `vuln-web3-mev.md` |
| 3n-v | web3-token | `vuln-web3-token.md` |
| 3q | web3-defi | `vuln-web3-defi.md` |
| 3r | web3-nft | `vuln-web3-nft.md` |
| 3s | web3-evm | `vuln-web3-evm.md` |

---

## By Step (what you're doing)

| Step | Relevant References |
|------|-------------------|
| 1 — Recon | `recon.md` |
| 2 — Threat Model | `threat-model.md` |
| 3 — Scanning | All `vuln-*.md` files (see scanner table above) |
| 4 — Validation | `validation.md`, `validation-decision-trees.md` |
| 5 — Reporting | `reporting.md` |
| Cross-cutting | `ptest-integration.md`, `zero-auth-microservice-pattern.md` |

---

## Supplementary References

| Reference | Purpose |
|-----------|---------|
| `spring-boot-mass-assignment-patterns.md` | Map<String,Any> DTOs, force-flag injection |
| `zero-auth-microservice-pattern.md` | Detection + reporting for services with no auth |
| `deployment-security-checks.md` | Helm, Istio, NetworkPolicy, mTLS |
| `nextjs-supabase-patterns.md` | Next.js + Supabase-specific patterns |
| `ptest-integration.md` | Using black-box pentest findings to guide code review |
| `validation-decision-trees.md` | Framework-specific false-positive elimination |
| `foundry-poc-cookbook.md` | Foundry fork setup, flash loan interfaces, attack templates |
| `web3-real-exploits-database.md` | Real incidents per vuln class with post-mortem links |
| `immunefi-report-template.md` | Immunefi severity scale, report structure, rejection reasons |
| `web3-economic-feasibility.md` | Pool manipulation math, flash loan fees, profitability framework |

---

## All Reference Files (alphabetical)

```
deployment-security-checks.md        — Helm values, Istio AuthorizationPolicy, NetworkPolicy, mTLS
nextjs-supabase-patterns.md          — Next.js + Supabase auth/RLS patterns
ptest-integration.md                 — Handoff from ptest black-box to scode white-box
recon.md                             — Step 1: codebase mapping, entry points, data flows
reporting.md                         — Step 5: report structure, PoC generation
spring-boot-mass-assignment-patterns.md — Map<String,Any> DTOs, force-flag injection
threat-model.md                      — Step 2: STRIDE, attack trees, priority targets
validation.md                        — Step 4: data flow tracing, FP elimination
validation-decision-trees.md         — Framework-specific FP decision trees
vuln-access-control.md               — IDOR, missing authz, privilege escalation
vuln-api.md                          — Mass assignment, GraphQL, rate limiting
vuln-authn-session.md                — Broken auth, JWT, session fixation, OAuth
vuln-client-side.md                  — Open redirect, clickjacking, prototype pollution
vuln-crypto.md                       — Weak algorithms, key management, TLS
vuln-custom-crypto.md                — Proprietary validation, LCG, custom HMAC, homegrown tokens
vuln-data-exposure.md                — Secrets, verbose errors, PII in logs
vuln-dependency.md                   — Known CVEs, dependency confusion, supply chain
vuln-deserialization.md              — Unsafe deserialize, XXE
vuln-dos.md                          — ReDoS, algorithmic complexity, resource exhaustion
vuln-file-path.md                    — Unrestricted upload, path traversal, LFI, Zip Slip
vuln-infra.md                        — Terraform, Dockerfile, K8s, CI/CD, Helm
vuln-injection.md                    — SQL, command, SSTI, XSS, NoSQL
vuln-logic.md                        — Race conditions, rate limiting, workflow bypass
vuln-memory.md                       — Buffer overflow, use-after-free, format strings
vuln-misconfig.md                    — CORS, CSP, debug mode, default creds
vuln-mobile-code.md                  — Android/iOS decompiled code, React Native, Flutter, cert pinning
vuln-nodejs.md                       — path.join traversal, require() RCE, Zip Slip, prototype pollution, vm escape, ReDoS
vuln-spring-boot.md                  — Actuator, security annotations, SpEL, mass assignment
vuln-ssrf.md                         — User-controlled URLs, internal access
vuln-web3-access.md                  — Access control, proxy, upgradeability
vuln-web3-arithmetic.md              — Integer overflow, precision loss
vuln-web3-defi.md                    — AMM, lending, bridge, governance
vuln-web3-evm.md                     — Storage slots, returnbomb, gas griefing
vuln-web3-modern.md                  — Restaking, Account Abstraction, L2/Rollup, Intent-based
vuln-web3-mev.md                     — Front-running, flash loan, oracle manipulation
vuln-web3-nft.md                     — Metadata, randomness, royalty bypass
vuln-web3-reentrancy.md              — Reentrancy, unchecked calls, delegatecall
vuln-web3-token.md                   — Token flaws, signature replay
web3-economic-feasibility.md         — Pool manipulation math, flash loan fees, profitability
web3-immunefi-hunting-strategy.md    — Pre-engagement target selection for web3 bug bounty
web3-real-exploits-database.md       — Real exploit post-mortems by vulnerability class
zero-auth-microservice-pattern.md    — Detection, reporting strategy for zero-auth services
foundry-poc-cookbook.md               — Foundry fork setup, flash loan interfaces, attack templates
immunefi-report-template.md          — Immunefi severity scale, report structure, rejection reasons
```
