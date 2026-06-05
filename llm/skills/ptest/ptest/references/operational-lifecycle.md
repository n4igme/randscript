## Operational Lifecycle

### Execution Loop

1. **Read State** — check `./ptest-output/state.yaml` to determine active gateway.
2. **Read Checklist** — check the phase's `checklist.md` for pending techniques.
3. **Pick Technique** — select next pending technique.
4. **Execute** — run the technique using the tools specified in the phase skill file.
5. **Document** — record findings using the Finding Template above.
6. **Update Checklist** — mark technique status in `checklist.md`:
   - `DONE` — technique executed successfully (findings or no findings)
   - `SKIPPED (reason)` — technique not applicable or tool unavailable
   - `FAILED (reason)` — technique attempted but did not succeed
7. **Update Findings Log** — append to `./ptest-output/findings-log.md`.
8. **Repeat** until phase exit criteria are met.

### Full-Coverage Enforcement (Phase 5 & 6)

**CRITICAL LESSON (BFI, May 2026):** 545 subdomains discovered, 186 live hosts confirmed, but nuclei only scanned 15 hosts and exploitation only tested 11 vectors on 6 hosts. This gap went unnoticed until Round 4 when the operator asked "did we do phase 5 & 6 for all subdomains?"

**Mandatory coverage rules:**
1. **Phase 5 (Vuln Assessment):** Nuclei MUST run against ALL live hosts, not just "interesting" ones. Generate target list from live-subs.txt, not hand-picked hosts.
2. **Phase 6 (Exploitation):** Every technique must be tested against ALL applicable hosts. "Tested /actuator on 3 hosts" is insufficient when 186 are live.
3. **Batch testing pattern:** Group hosts by response code (200/401/403/302), test each group with appropriate techniques:
   - 200 hosts: full path discovery, JS bundle analysis, API endpoint testing
   - 401 hosts: auth bypass, WAF bypass, method testing
   - 403 hosts: case variation bypass, path traversal, encoding bypass
   - 302 hosts: redirect_uri testing, open redirect
4. **Coverage tracking:** Before requesting gateway sign-off, verify: `hosts_tested / total_live_hosts >= 95%`. Document any gaps.
5. **SPA catch-all detection:** If multiple paths return identical response size, it's a SPA catch-all (not real endpoints). Mark as "SPA — backend on gateway" and test the gateway instead.

**Batch testing script pattern:**
```bash
# Generate untested hosts
comm -23 <(sort all-live-hosts.txt) <(sort already-tested.txt) > remaining.txt
# Nuclei on remaining
nuclei -l remaining.txt -severity critical,high,medium -o results.txt
# CORS on all
while read url; do curl -sk -H "Origin: https://evil.com" "$url/" -D- | grep -i "access-control"; done < all-live-hosts.txt
```

### Gateway Transition (`next`)

1. **Self-Audit (MANDATORY, before asking user)** — for EACH subdomain/host in the master list, verify:
   - Was gobuster/ffuf run? (check for output file)
   - Were phase-specific mandatory checks completed? (actuator, swagger, admin, prefixes)
   - Was the result triaged? (gobuster output reviewed, unique responses investigated)
   - If dismissed: is the dismissal documented with evidence?
   Print a coverage matrix: `tested_hosts / total_live_hosts` — if < 95%, DO NOT request sign-off.
2. **Coverage Audit** — verify checklist shows sufficient technique coverage.
3. **Mandatory Tool Check** — confirm all mandatory tools for the phase were executed.
4. **Evidence Check** — confirm all findings have supporting evidence.
5. **Exit Criteria** — evaluate against the phase's exit criteria (see Gateway Map).
6. **Sign-off** — ask user: *"Phase [X] complete. [N] findings documented. Coverage: X/Y hosts tested. Ready to advance to [next phase]?"*
7. **Update State** — update `./ptest-output/state.yaml`: mark gateway as PASSED, unlock next.

**LINE WORKS lesson (June 2026):** Agent declared Phases 3-5 complete but: (a) hadn't run gobuster on 4/8 subdomains, (b) Phase 4 output files (asset-inventory.md, entry-points.md, dismissed.md, scope-confirmation.md) didn't exist, (c) Phase 5 nuclei never ran against all hosts, (d) Phase 2→3 handoff verification was never performed (28/36 subdomains unprobed). User had to ask "did we miss something?" FIVE times across phases before all gaps were caught. 

**Hard rule:** Before writing `PASSED` to state.yaml, run `ls ptest-output/<phase-dir>/` and verify EVERY required output file exists and is non-empty. If ANY file is missing → phase is NOT done. No exceptions, no "I'll do it later." This is a mechanical check, not a judgment call.

**If exit criteria are NOT met:**
1. List specific unmet criteria.
2. Suggest which techniques to run to satisfy them.
3. Do NOT advance — gateway remains OPEN.
4. Ask: *"Want to address these gaps, or override with justification?"*
5. If user overrides, record justification in checklist and proceed.

If no sign-off response within the session, continue executing remaining techniques in the current phase rather than blocking.

---
