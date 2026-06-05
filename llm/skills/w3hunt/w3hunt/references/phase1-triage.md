# Phase 1: Triage & Scope (15 min)

### Gate: GO/NO-GO decision made, prerequisites checked

Pure decision phase — no setup, no deep analysis. Answer these in order:

1. **Is the program live?** — `curl -sL -o /dev/null -w "%{http_code}" <url>` → 200/301 = live
2. **Prior C4/Sherlock contest?** — GitHub search `org:{protocol} contest` or `audit`. If yes, known issues will be rejected.
3. **Does it have web/app scope?** — Check scope tab → "Websites and Applications" category
4. **Does it have SC scope?** — Check scope tab → "Smart Contracts" category
5. **Oracle prerequisites (if SC):** verify all 3 pass (see "Pattern transferability prerequisite check" in Strategy section)

**Decision:**
- Web scope exists → **GO** (web-first)
- No web scope, SC prerequisites pass → **GO** (SC-first)
- No web scope, SC prerequisites fail → **NO-GO** (move to next target)
- SC prerequisites fail → still GO if web scope exists (web-only hunt)

**Scope validation rule (HARD GATE):**
Verify the vulnerable contract IS in the scope list OR directly called by an in-scope contract. If neither → DO NOT SUBMIT.

**Asset scope verification steps:**
1. Get the exact address of the vulnerable contract on the target chain
2. Check if that address appears in the program's "Assets in Scope" list
3. If NOT listed: trace the call chain — does an in-scope contract call it?
4. If yes to (3): submit with the IN-SCOPE contract as primary asset, explain the call chain
5. If no to both (2) and (3): DO NOT SUBMIT

**Common trap:** Infrastructure contracts (oracles, swappers, routers) are often NOT in scope even though in-scope vaults depend on them.
