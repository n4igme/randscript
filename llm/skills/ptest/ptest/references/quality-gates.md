## Mandatory Quality Gates

### Pre-Report Gate 0 (MANDATORY before writing any finding)

Before drafting any finding report, answer these 3 questions. One NO = KILL the finding and move on.

1. **Can the attacker do this RIGHT NOW with a real HTTP request?**
   - Not "theoretically possible" — demonstrate with an actual request/response
   - If it requires external conditions outside attacker control (Chainlink malfunction, sequencer downtime, specific server load), it's borderline

2. **What does the victim LOSE?**
   - Map to CIA triad: confidentiality (data exposed), integrity (data modified), availability (data deleted/DoS)
   - "The server responds differently" is NOT impact. Quantify: how many users, what data, what dollar value
   - If the answer is only "information disclosure of non-sensitive data" — severity is Low at best

3. **Can it be reproduced in 10 minutes from scratch?**
   - Fresh browser, no prior state, following only your written steps
   - If it requires lucky timing, specific victim behavior beyond "click a link", or network position — document those dependencies explicitly
   - If you can't demo it reproducibly at least 3/5 attempts, do not file

**Kill signals (instant NO):**
- Finding requires privileged access an attacker can't obtain
- Finding is already known/documented behavior (check program policy)
- Finding is on the program's "never submit" list (self-XSS, logout CSRF, missing headers without impact)
- Impact is purely theoretical with no concrete demonstration

**PoC script quality (MANDATORY):**
- Every PoC script MUST run without errors (`python3 script.py` → no SyntaxError, no KeyError)
- Test the script locally before including in report — f-strings with dicts inside don't work in Python < 3.12, API responses may be rate-limited or return unexpected status codes
- Handle error cases: rate limiting (429), missing keys in response, connection timeouts
- Hardcode fallback values (e.g., previously registered client_id) when rate limits prevent fresh registration
- If the attack chain requires user interaction (OAuth consent, clicking a link), document exactly what the tester should do to complete the proof
- Include REAL tested values in the PoC output — actual codes, error codes, tickets, timestamps from your testing session. Generic placeholders ("YOUR_SESSION_COOKIE", "victim@example.com") make the PoC look untested
- Print discovered values explicitly (e.g., `[+] The verification code is: {code}`) — don't just say "found" without showing what was found
- For brute-force PoCs: narrow the demo range so the correct value is hit within seconds (proves the concept without running for hours)
- Make execution self-contained: handle auth via browser automation (Playwright), don't require manual cookie extraction. Usage should be `python3 poc.py --run <target>` at most
- **REAL DATA REQUIRED** — PoC scripts MUST contain actual tested values (real emails, real error codes, real tickets/tokens observed during testing) as comments or defaults. Never use placeholder values like `victim@example.com` or `YOUR_SESSION_COOKIE` without also embedding the real tested data. The user expects to see the actual evidence inline.
- **Minimal user input** — PoC should require as few arguments as possible. If auth is needed, handle it programmatically (e.g., Playwright login) rather than asking the user to paste cookies. Ideal: `python3 poc.py --run <email>` with everything else automated.
- **Clear oracle output** — when brute-forcing, print the EXACT found value prominently: `[+] The verification code is: 938450`. Don't just say "CORRECT code found" without showing what it is.
- **Narrowed demo range** — for PoC demonstrations, narrow the brute-force range to hit the known-correct value quickly (e.g., start=938050, end=938550) so the triager sees the oracle trigger without waiting hours.

### Local Exploit Verification Gate (Phase 6 → 7 transition, MANDATORY)

Before advancing from Phase 6, every confirmed exploit MUST be locally verified when possible.

**Verification procedure:**
1. **Re-read the actual source/target behavior** — don't rely on notes from earlier analysis. Re-fetch/re-read the code.
2. **Simulate the environment locally** — install the same libraries (yauzl, express, spring-boot, etc.), replicate the file structure, run the exploit against your local simulation.
3. **Verify each chain link independently** — test validation bypass, test payload delivery, test execution separately before combining.
4. **Compare your assumptions vs actual code** — check function signatures, required interfaces, return value handling, error paths.
5. **Document verification result** — add "Locally verified: YES/NO (reason)" to the finding.

**When local verification is NOT possible:**
- Target uses proprietary/closed-source backend (no source available)
- Environment requires specific cloud services that can't be replicated
- Exploit depends on race conditions or timing that can't be simulated

In these cases, document: "Local verification not possible: {reason}. Confidence level: HIGH/MEDIUM/LOW based on {evidence}."

**Real-world save (Dojo #51, May 2026):** Initial exploit had wrong plugin interface (`module.exports = { result: flag }` instead of required `get()`, `getName()`, `run()` methods). Also had wrong first-nibble constraint (`0xA || 0xB` instead of actual `0xA || 0xC`). Local simulation caught both before submission.

---
