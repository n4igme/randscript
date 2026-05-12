# Skill Map — Offensive Security Reference

> **How to use:** Match the user's intent against the **Triggers** field below.
> Load the full skill file (from **File** field) only when the user's task requires that skill's detailed methodology.
> Multiple skills may be relevant — load the most specific one first.

**Total skills:** 49

---

## scrapling-skill
**File:** `scrapling-skill.md`
**Triggers:** web scraping, crawling, anti-bot bypass, Cloudflare, Scrapling, headless browser, spider, data extraction, stealth browsing, JavaScript rendering
**Summary:** Web scraping with Scrapling library — anti-bot bypass (Cloudflare Turnstile), stealth headless browsing, spider framework, adaptive parsing, and JS rendering. Use when scraping sites with protections or building crawlers.

---

## bug-bounty
**File:** `bug-bounty.md`
**Triggers:** bug bounty, recon, subdomain enumeration, asset discovery, HackerOne, vulnerability hunting, IDOR, SSRF, XSS, auth bypass, race condition, reporting, triage, A-to-B chaining, disclosed reports
**Summary:** Complete bug bounty workflow from recon to report. Covers subdomain enumeration, asset discovery, fingerprinting, scope retrieval, vulnerability hunting across all major classes, A→B bug chaining, validation gates, and report writing templates.

---

## gabut-exitium
**File:** `gabut-exitium.md`
**Triggers:** hunting methodology, workflow, mindset, session planning, target selection, critical thinking, anomaly detection, developer psychology
**Summary:** Meta-methodology for bug bounty sessions. 5-phase non-linear hunting workflow combined with critical thinking framework (developer psychology, anomaly detection, What-If experiments). Use at session start or when feeling stuck.

---

## karpathy-guidelines
**File:** `karpathy-guidelines.md`
**Triggers:** coding guidelines, code quality, refactoring, simplicity, surgical changes, LLM coding mistakes
**Summary:** Behavioral guidelines to reduce common LLM coding mistakes. Think before coding, simplicity first, surgical changes, goal-driven execution.

---

## offensive-advanced-redteam
**File:** `offensive-advanced-redteam.md`
**Triggers:** red team, C2, command and control, infrastructure, redirectors, beacon, data exfiltration, covert channel, advanced persistent threat
**Summary:** Advanced red team operations — C2 infrastructure setup, redirectors, beacon configuration, data exfiltration channels, and operational security for long-term engagements.

---

## offensive-ai-security
**File:** `offensive-ai-security.md`
**Triggers:** AI security, LLM attacks, prompt injection, indirect injection, AI pentest, chatbot exploitation, system prompt extraction, AI governance, ASI01-ASI10
**Summary:** AI/LLM penetration testing — prompt injection (direct/indirect), system prompt extraction, chatbot IDOR, ASCII smuggling, exfiltration channels, RCE via code tools, and AI governance testing (ASI01-ASI10).

---

## offensive-basic-exploitation
**File:** `offensive-basic-exploitation.md`
**Triggers:** buffer overflow, stack overflow, basic exploitation, Linux exploitation, shellcode injection, return address overwrite, NOP sled, mitigations disabled
**Summary:** Foundational Linux exploitation with mitigations disabled. Buffer overflows, stack smashing, return address overwrites, NOP sleds, and basic shellcode injection. Starting point for exploit development.

---

## offensive-bug-identification
**File:** `offensive-bug-identification.md`
**Triggers:** kernel bugs, driver analysis, eBPF, dynamic analysis, static analysis, bug classes, vulnerability identification, root cause analysis
**Summary:** Systematic bug identification in kernel/driver code. Static and dynamic analysis, eBPF tracing, fuzzer-found crash analysis, and vulnerability classification by root cause.

---

## offensive-cms-wordpress-vercel
**File:** `offensive-cms-wordpress-vercel.md`
**Triggers:** WordPress, Vercel, Next.js, CMS, wp-admin, plugin vulnerabilities, theme exploits, wp-json, xmlrpc, Next.js data leaks
**Summary:** CMS-specific assessment for WordPress and Vercel/Next.js. Version fingerprinting, plugin/theme enumeration, wp-json API testing, xmlrpc attacks, and Next.js-specific data exposure patterns.

---

## offensive-crash-analysis
**File:** `offensive-crash-analysis.md`
**Triggers:** crash analysis, exploitability assessment, triage, ASAN, debugger, memory corruption, crash dump, root cause, exploitable crash
**Summary:** Crash analysis and exploitability assessment. Triage fuzzer-found crashes, determine exploitability, use ASAN/debuggers for root cause analysis, and classify memory corruption types.

---

## offensive-deserialization
**File:** `offensive-deserialization.md`
**Triggers:** deserialization, insecure deserialization, Java deserialization, PHP unserialize, Python pickle, .NET deserialization, gadget chains, ysoserial
**Summary:** Insecure deserialization attacks across languages — Java (ysoserial), PHP (unserialize), Python (pickle), .NET, Go, Ruby, and Kubernetes/container contexts. Gadget chain construction and bypass techniques.

---

## offensive-edr-evasion
**File:** `offensive-edr-evasion.md`
**Triggers:** EDR, endpoint detection, evasion, antivirus bypass, unhooking, syscalls, process injection, AMSI bypass, ETW patching, behavioral detection
**Summary:** EDR/AV evasion techniques — userland unhooking, direct/indirect syscalls, AMSI/ETW patching, process injection variants, behavioral detection bypass, and endpoint architecture analysis.

---

## offensive-exploit-dev-course
**File:** `offensive-exploit-dev-course.md`
**Triggers:** exploit development course, fuzzing lab, GoogleTest, harness writing, vulnerability research training, AFL++, libFuzzer
**Summary:** Structured exploit development course — fuzzing foundations, harness writing with GoogleTest/libFuzzer/AFL++, corpus curation, and progressive vulnerability research exercises.

---

## offensive-exploit-development
**File:** `offensive-exploit-development.md`
**Triggers:** heap exploitation, use-after-free, edge internals, browser exploitation, egghunting, heap spray, type confusion, V8, renderer exploit
**Summary:** Advanced exploit development — heap exploitation (UAF, heap spray, type confusion), browser internals (Edge/V8/renderer), egghunting, and modern mitigation bypass for complex targets.

---

## offensive-fast-checking
**File:** `offensive-fast-checking.md`
**Triggers:** quick security check, fast audit, security checklist, rapid assessment, low-hanging fruit, common misconfigurations
**Summary:** Rapid security assessment checklist — authentication, access control, business logic, file handling, and common misconfigurations. Use for quick first-pass testing or time-boxed engagements.

---

## offensive-file-upload
**File:** `offensive-file-upload.md`
**Triggers:** file upload, upload bypass, webshell, content-type bypass, extension bypass, magic bytes, polyglot file, image upload RCE
**Summary:** File upload vulnerability exploitation — extension/content-type/magic-byte bypass, polyglot files, webshell upload, path traversal via filename, and client-side validation bypass.

---

## offensive-fuzzing-course
**File:** `offensive-fuzzing-course.md`
**Triggers:** fuzzing course, AFL++ setup, coverage-guided fuzzing, fuzzing infrastructure, crash reproduction, fuzzing workflow
**Summary:** Comprehensive fuzzing course — AFL++/libFuzzer/Honggfuzz setup, coverage-guided fuzzing, corpus management, crash reproduction, and building fuzzing infrastructure from scratch.

---

## offensive-fuzzing
**File:** `offensive-fuzzing.md`
**Triggers:** fuzzing, AFL++, libFuzzer, Honggfuzz, Boofuzz, syzkaller, greybox fuzzing, mutation, corpus, crash triage, harness
**Summary:** Practical fuzzing methodology — target identification, fuzzer selection (AFL++, libFuzzer, Honggfuzz, Boofuzz, syzkaller), harness writing, corpus curation, mutation strategies, coverage measurement, and crash triage.

---

## offensive-graphql
**File:** `offensive-graphql.md`
**Triggers:** GraphQL, introspection, batching attack, GraphQL injection, query complexity, nested queries, GraphQL IDOR, schema extraction
**Summary:** GraphQL-specific attacks — introspection abuse, batching/aliasing for brute force, nested query DoS, authorization bypass via field-level access, and schema extraction when introspection is disabled.

---

## offensive-idor
**File:** `offensive-idor.md`
**Triggers:** IDOR, insecure direct object reference, access control, horizontal privilege escalation, UUID guessing, parameter tampering, broken object-level authorization
**Summary:** IDOR hunting methodology — identifying reference patterns, horizontal/vertical escalation, blind IDOR detection, UUID/GUID prediction, multi-step IDOR chains, and bypass techniques for access control checks.

---

## offensive-initial-access
**File:** `offensive-initial-access.md`
**Triggers:** initial access, phishing, payload delivery, macro, HTA, ISO, LNK, DLL sideloading, MOTW bypass, email gateway bypass
**Summary:** Modern initial access techniques — payload delivery (macros, HTA, ISO/IMG, LNK, DLL sideloading), MOTW bypass, email gateway evasion, and defensive control circumvention for red team engagements.

---

## offensive-jwt
**File:** `offensive-jwt.md`
**Triggers:** JWT, JSON Web Token, algorithm confusion, alg none, RS256 to HS256, kid injection, jku, jwk, token forgery, HMAC brute force
**Summary:** JWT attack methodology — algorithm confusion (alg:none, RS256→HS256), weak HMAC brute force, kid parameter injection (SQLi, path traversal), jku/x5u header injection, JWKS cache poisoning, and mobile JWT extraction.

---

## offensive-keylogger-arch
**File:** `offensive-keylogger-arch.md`
**Triggers:** keylogger, SetWindowsHookEx, keyboard capture, input monitoring, novel research, window title capture
**Summary:** Novel keylogger architecture research — alternative capture methods beyond SetWindowsHookEx, window title extraction techniques, and IOC-aware design for research purposes.

---

## offensive-mitigations
**File:** `offensive-mitigations.md`
**Triggers:** kernel mitigations, KASLR, KPTI, SMEP, SMAP, CFI, exploit mitigations, bypass mitigations, kernel hardening
**Summary:** Modern kernel exploit mitigations and bypass techniques — KASLR, KPTI, SMEP/SMAP, CFI/CET, and memory isolation. Understanding what protections exist and known bypass approaches.

---

## offensive-oauth
**File:** `offensive-oauth.md`
**Triggers:** OAuth, OIDC, OpenID Connect, authorization code, token theft, redirect_uri bypass, state parameter, OAuth misconfiguration
**Summary:** OAuth/OIDC attack methodology — redirect_uri manipulation, authorization code interception, state parameter bypass, token leakage, scope escalation, and IdP-specific misconfigurations.

---

## offensive-open-redirect
**File:** `offensive-open-redirect.md`
**Triggers:** open redirect, URL redirect, redirect bypass, login redirect, OAuth redirect chain, parameter redirect, host confusion
**Summary:** Open redirect discovery and exploitation — bypass techniques for redirect validation, chaining with OAuth/SSO for token theft, and filter evasion patterns across frameworks.

---

## offensive-osint-methodology
**File:** `offensive-osint-methodology.md`
**Triggers:** OSINT methodology, intelligence gathering, reconnaissance framework, information collection, target profiling, attack surface mapping
**Summary:** Structured OSINT methodology for offensive operations — systematic intelligence gathering, target profiling, attack surface mapping, and converting raw data into actionable findings.

---

## offensive-osint
**File:** `offensive-osint.md`
**Triggers:** OSINT, open source intelligence, email discovery, domain recon, social media, leaked credentials, breach data, Shodan, certificate transparency
**Summary:** Comprehensive OSINT toolkit and techniques — email/domain/social discovery, breach data analysis, Shodan/Censys, certificate transparency, GitHub dorking, and secret scanning scripts.

---

## offensive-parameter-pollution
**File:** `offensive-parameter-pollution.md`
**Triggers:** parameter pollution, HPP, HTTP parameter pollution, duplicate parameters, server-side parsing, parameter precedence, WAF bypass via HPP
**Summary:** HTTP Parameter Pollution (HPP) — server-side vs client-side, parameter precedence across frameworks, WAF bypass via duplicate params, and exploitation in OAuth/payment/access-control flows.

---

## offensive-race-condition
**File:** `offensive-race-condition.md`
**Triggers:** race condition, TOCTOU, concurrency, parallel requests, limit bypass, double spend, race window, single-packet attack
**Summary:** Race condition exploitation — TOCTOU vulnerabilities, limit/rate bypass via parallel requests, single-packet attack technique, double-spend scenarios, and identifying race windows in business logic.

---

## offensive-rce
**File:** `offensive-rce.md`
**Triggers:** RCE, remote code execution, command injection, code injection, OS command, eval injection, template injection to RCE, deserialization to RCE
**Summary:** Remote Code Execution vectors — OS command injection, code injection (eval/exec), template injection escalation, deserialization chains, and language-specific RCE patterns across web frameworks.

---

## offensive-request-smuggling
**File:** `offensive-request-smuggling.md`
**Triggers:** request smuggling, HTTP smuggling, CL.TE, TE.CL, HTTP desync, transfer-encoding, content-length conflict, frontend-backend desync, H2 smuggling
**Summary:** HTTP Request Smuggling — CL.TE/TE.CL/TE.TE variants, HTTP/2 downgrade smuggling, detection techniques, exploitation for access control bypass and cache poisoning, and H2-specific desync attacks.

---

## offensive-shellcode
**File:** `offensive-shellcode.md`
**Triggers:** shellcode, shellcode writing, position-independent code, encoder, staged payload, msfvenom, custom shellcode, null-free, syscall shellcode
**Summary:** Shellcode development — writing position-independent code, null-byte elimination, encoders/decoders, staged payloads, syscall-based shellcode, and custom payload generation beyond msfvenom.

---

## offensive-sqli
**File:** `offensive-sqli.md`
**Triggers:** SQL injection, SQLi, union-based, blind SQLi, error-based, time-based, sqlmap, second-order injection, database extraction, stacked queries
**Summary:** SQL injection methodology — union-based, error-based, boolean/time-based blind, stacked queries, out-of-band extraction, second-order injection, sqlmap usage, and database-specific techniques.

---

## offensive-ssrf
**File:** `offensive-ssrf.md`
**Triggers:** SSRF, server-side request forgery, internal network, cloud metadata, IMDS, IP bypass, DNS rebinding, URL parser confusion, gopher protocol
**Summary:** SSRF exploitation — IP/URL filter bypass, DNS rebinding, cloud metadata (AWS/GCP/Azure IMDS), protocol smuggling (gopher/dict), URL parser differentials, and blind SSRF detection techniques.

---

## offensive-ssti
**File:** `offensive-ssti.md`
**Triggers:** SSTI, server-side template injection, Jinja2, Twig, Freemarker, template engine, sandbox escape, template RCE
**Summary:** Server-Side Template Injection — detection polyglots, engine identification (Jinja2/Twig/Freemarker/Velocity/Pebble), sandbox escape techniques, and escalation to RCE per template engine.

---

## offensive-vuln-classes
**File:** `offensive-vuln-classes.md`
**Triggers:** vulnerability classes, vuln taxonomy, attack patterns, security testing categories, comprehensive vuln list, testing methodology
**Summary:** Comprehensive vulnerability class reference — categorized attack patterns across web, API, mobile, and infrastructure. Use as a checklist when testing or to identify which specific skill to load.

---

## offensive-waf-bypass
**File:** `offensive-waf-bypass.md`
**Triggers:** WAF bypass, web application firewall, filter evasion, encoding bypass, payload obfuscation, Cloudflare bypass, ModSecurity, AWS WAF
**Summary:** WAF bypass techniques — encoding tricks, payload obfuscation, chunked transfer abuse, HTTP/2 specifics, vendor-specific bypasses (Cloudflare, AWS WAF, ModSecurity), and universal evasion patterns.

---

## offensive-windows-boundaries
**File:** `offensive-windows-boundaries.md`
**Triggers:** Windows security boundaries, privilege escalation, kernel exploitation, Win32k, token manipulation, ACL, Windows internals, object manager
**Summary:** Windows trust/security boundaries — kernel vs user mode, session isolation, integrity levels, token manipulation, Win32k attack surface, object manager, ACLs, and privilege escalation across boundaries.

---

## offensive-windows-mitigations
**File:** `offensive-windows-mitigations.md`
**Triggers:** Windows mitigations, DEP, ASLR, CFG, CET, ACG, Windows Defender, exploit guard, process mitigation policies
**Summary:** Windows exploit mitigations deep-dive — DEP, ASLR, CFG/XFG, CET, ACG, process mitigation policies, Exploit Guard, and known bypass techniques for each protection mechanism.

---

## offensive-xss
**File:** `offensive-xss.md`
**Triggers:** XSS, cross-site scripting, reflected XSS, stored XSS, DOM XSS, CSP bypass, script injection, event handlers, JavaScript injection
**Summary:** XSS methodology — reflected/stored/DOM variants, context-aware payload crafting, CSP bypass techniques, event handler injection, mutation XSS, and framework-specific sink/source patterns.

---

## offensive-xxe
**File:** `offensive-xxe.md`
**Triggers:** XXE, XML external entity, XML injection, DTD, SSRF via XXE, file read via XXE, blind XXE, out-of-band XXE, parameter entities
**Summary:** XML External Entity attacks — in-band/blind/OOB extraction, DTD abuse, SSRF via XXE, file read, parameter entity tricks, and XXE in non-obvious contexts (SVG, DOCX, SOAP, RSS).

---

## osint-methodology
**File:** `osint-methodology.md`
**Triggers:** OSINT framework, intelligence cycle, source evaluation, pivot analysis, digital footprint, attribution, operational security
**Summary:** Full OSINT methodology framework — intelligence cycle, source evaluation, pivot techniques, digital footprint analysis, attribution methods, and operational security during collection.

---

## report-writing
**File:** `report-writing.md`
**Triggers:** vulnerability report, bug report, security report writing, CVSS scoring, proof of concept, impact statement, remediation advice
**Summary:** Security report writing — structure, CVSS 3.1 scoring, impact articulation, PoC formatting, remediation recommendations, and templates by vulnerability class. Use when writing or reviewing findings.

---

## security-arsenal
**File:** `security-arsenal.md`
**Triggers:** security tools, tool list, pentest tools, Burp Suite, nuclei, ffuf, nmap, recon tools, exploitation frameworks
**Summary:** Curated security tool arsenal — categorized tools for recon, scanning, exploitation, and post-exploitation. Installation commands, usage patterns, and when to pick which tool.

---

## triage-validation
**File:** `triage-validation.md`
**Triggers:** triage, validation, false positive, bug validation, severity assessment, exploitability confirmation, reproduction steps
**Summary:** Finding triage and validation — confirming exploitability, ruling out false positives, severity assessment, reproduction step verification, and go/no-go gates before reporting.

---

## web2-recon
**File:** `web2-recon.md`
**Triggers:** web recon, subdomain enumeration, port scanning, directory bruteforce, technology fingerprinting, asset discovery, DNS enumeration
**Summary:** Web application reconnaissance — subdomain enumeration, DNS analysis, port scanning, directory/file discovery, technology fingerprinting, and attack surface mapping for web targets.

---

## web2-vuln-classes
**File:** `web2-vuln-classes.md`
**Triggers:** web vulnerabilities, OWASP, web app security, injection flaws, broken authentication, security misconfiguration, web attack taxonomy
**Summary:** Web application vulnerability classes — comprehensive taxonomy aligned with OWASP, covering injection, auth, access control, SSRF, cryptographic failures, and security misconfiguration patterns.

---

## web3-audit
**File:** `web3-audit.md`
**Triggers:** smart contract, Solidity, blockchain audit, DeFi, reentrancy, flash loan, EVM, token security, Web3 security
**Summary:** Web3/smart contract security auditing — Solidity vulnerabilities (reentrancy, flash loans, oracle manipulation), EVM internals, DeFi-specific attack patterns, and token security review methodology.

---
