# Security Skills — Changelog

## 2026-06-19

### ptest v5.0.0
- Compressed 8 phases → 6: merged Enumerate+AttackSurface → "Enumerate & Confirm", VulnAssess+Exploit → "Assess & Exploit", PostExploit+Chain&Escalate → "Post-Exploit & Impact"
- Added discovery loop-back mechanism (discovery-queue.md drains at phase exit)
- Mandatory human checkpoint moved to Phase 3 exit (before exploitation begins)
- Reference files unchanged — routing table remapped to load multiple refs per phase
- Effort rebalanced: P1 15%, P2 20%, P3 15%, P4 30%, P5 15%, P6 5%

### mtest v4.0.0
- Compressed 10 phases → 7: merged Traffic+Surface, Runtime+VulnAnalysis, API+Exploitation
- Added Phase Entry Protocol, time_tracking in state.yaml, discovery loop-back
- Extracted TWA/Intent Scheme inline content → `references/twa-webview-apps.md`
- Merged two cross-skill trigger tables into one
- Reference files unchanged — routing remapped to load multiple refs per phase

### atest v1.3.0
- Added Phase Entry Protocol, time_tracking in state.yaml
- Extracted pitfalls + output handling to `references/pitfalls.md` (~80 lines removed from SKILL.md)
- Deduplicated BlueSpider cookie-bypass pitfall (was duplicated verbatim)
- Fixed mtest handoff reference (Phase 9 → Phase 6)
- Fixed version (was 1.0.1, notes said 1.2.0)

### ctest v1.2.0
- Added Quick Reference section with phases, states, commands, key rules, time caps
- Added Phase Entry Protocol (load ref → create checklist → record timestamp)
- Added discovery loop-back mechanism (discovery-queue.md drains at phase exit)
- Added findings.jsonl procedure with cross-skill chaining metadata
- Added N/A phase guidance (especially Phase 4 containers)
- Added frontmatter notes for version history
- Cleaned up stray blank lines

### scode v1.2.0
- Added Quick Reference section with steps, states, commands, key rules, scanner groups
- Added Step Entry Protocol (load ref → verify state → record timestamp)
- Added findings.jsonl cross-skill chaining procedure with status transitions
- Removed duplicate Gate Enforcement block
- Fixed version mismatch (was 1.0.1, notes said 1.1.0)
- Added frontmatter notes for version history

### w3hunt v2.2.0
- Deduplicated Gate Enforcement (3x → 1x, kept in `next` procedure)
- Deduplicated Postmortem (2x → 1x, kept command procedure version)
- Added Phase Entry Protocol (load ref → record timestamp → check budget)
- Added findings.jsonl cross-skill chaining procedure
- Fixed version mismatch (was 1.4.0, should be 2.1.0+)
- Added frontmatter notes for version history

### adtest v1.1.0
- Added Phase Entry Protocol (load ref → record timestamp → check credential inventory)
- Added credential-driven discovery loop-back (new cred in any phase → test against all attack vectors)
- Added findings.jsonl cross-skill chaining procedure
- Added N/A phase guidance (Kerberos without SPNs, Relay with signing enforced)
- Fixed version (was 1.0.0, CHANGELOG said 1.0.1)
- Added frontmatter notes for version history

### ttest v1.1.0
- Added Phase Entry Protocol (load ref → record timestamp → confirm app type context)
- Added findings.jsonl cross-skill chaining procedure
- Added Abandon & Pivot Heuristics (per-phase guidance for when to stop/pivot)
- Added N/A phase guidance (offline apps, simple utilities)
- Fixed version (was 1.0.0, CHANGELOG said 1.0.1)
- Added frontmatter notes for version history

### xdev v1.1.0
- Added Phase Entry Protocol (load ref → record timestamp → review primitives state)
- Added time_tracking to state.yaml (was the only skill missing it)
- Added findings.jsonl cross-skill chaining procedure (includes reliability field)
- Added N/A phase guidance (firmware with no mitigations, info-leak-only scope)
- Fixed stale cross-skill references (ptest Phase 7 → Phase 5, mtest Phase 9 → Phase 5)
- Added retools to related_skills
- Added frontmatter notes for version history

### opsec v1.2.0
- Added Phase Entry Protocol (load ref → record timestamp)
- Deduplicated Gate Enforcement (was duplicated in script invocation section)
- Fixed version (was 1.0.1, CHANGELOG said 1.1.0)
- Added frontmatter notes for version history

### osint v1.2.0
- Added Phase Entry Protocol (load methodology → record timestamp → review seeds)
- Added time_tracking to state.yaml
- Added N/A phase guidance (person with no domains, no emails discovered)
- Fixed stale ptest cross-skill reference (Phase 6 → Phase 4)
- Fixed version (was 1.0.2, notes said 1.1.0)
- Added frontmatter notes for version history

### retools v1.1.0
- Added cross-skill trigger table (into/out of retools)
- Removed duplicate references (were listed in both Verification and Additional References)
- Added frontmatter notes for version history

### adtest v1.0.1
- Extracted pitfalls to `references/pitfalls.md` (grouped by category, deduplicated)
- Added command procedures, state.yaml schema, gate enforcement, script invocation, finding template
- Added `scripts/state_manager.py` and `scripts/gate_check.py`

### ttest v1.0.1
- Added command procedures, state.yaml schema, gate enforcement, script invocation, finding template
- Added `scripts/state_manager.py` and `scripts/gate_check.py`

### opsec v1.1.0
- Extracted to hub model: Phase 2, 4, 5, 6, Report Template, Pitfalls → `references/`
- SKILL.md reduced from 515 to 227 lines

---

## Prior versions (from SKILL.md frontmatter notes)

### ptest
- v4.7.0: Trigger table extracted to references. Pitfalls deduplicated. New attack recipes. SKILL.md 717→590 lines.
- v4.6.2: Deduplicated pitfalls (19→6 entries).
- v4.6.0: Hub model — SKILL.md handles routing, phase content in references/.

### atest
- v1.2.0: Auth-gate pitfall, expanded CORS testing, no-token abandon heuristic.
- v1.1.0: Time budgets, abandon heuristics, bola_scanner.py, state_manager.py.

### mtest
- v3.0.0: Hub model — SKILL.md is routing + framework, phase content in references/.

### w3hunt
- v2.1.0: Hub model — SKILL.md is routing + strategy, phase content in references/.
- v1.4.0: Current version.

### scode
- v1.1.0: Per-scanner time caps, proven patterns, ROI metrics, output strategy.

### xdev
- v1.0.2: Current version.

### osint
- v1.0.2: Quick Reference, state.yaml schema, gates, command procedures.

### ctest
- v1.1.1: Current version.

### retools
- v1.0.1: Current version.
