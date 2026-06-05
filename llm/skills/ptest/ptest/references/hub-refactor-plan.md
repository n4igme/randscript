# ptest Hub Model Refactor Plan

**Status:** Planned (2026-05-28)
**Goal:** Convert SKILL.md from hybrid (hub + inline phase content) to pure routing hub (~4KB)

## Current State (v4.4.0)

```
ptest/
  SKILL.md                  ← hub + duplicated phase content (~894 lines, ~7-9KB)
  recon-passive.md          ← Phase 1 v3.0.0 (442 lines)
  recon-active.md           ← Phase 2 v3.0.0 (468 lines)
  enumeration.md            ← Phase 3 v3.0.0 (346 lines)
  attack-surface.md         ← Phase 4 v3.0.0 (225 lines)
  vuln-assessment.md        ← Phase 5 v3.0.0 (299 lines)
  exploit.md                ← Phase 6 v3.0.0 (288 lines)
  post-exploit.md           ← Phase 7 v3.0.0 (253 lines)
  report.md                 ← Phase 8 v3.0.0 (145 lines)
  escalate-finding.md       ← cross-phase (70 lines)
  references/
    phase6-exploitation-framework.md   ← Phase 6 v4.x (918 lines)
    phase7-post-exploitation-framework.md ← Phase 7 v4.x (703 lines)
    phase8-reporting-process.md        ← Phase 8 v4.x (337 lines)
    (100+ technique references)
  templates/
  scripts/
```

## Problems

1. **Triple duplication (Phase 6-8):** root file + references/ file + SKILL.md inline excerpts
2. **Version drift:** root files are v3 skeletons, references are evolved v4 battle-tested content
3. **SKILL.md bloat:** inline Phase 4/5/7 checklists duplicate standalone files
4. **Missing references (Phase 1-5):** no deep-dive v4 reference files for these phases
5. **Root files not in linked_files:** skill_view file_path may not resolve root .md files

## Target State

```
ptest/
  SKILL.md                  ← pure hub (~4KB routing only)
  README.md
  escalate-finding.md       ← cross-phase, keep at root
  references/
    phase1-passive-recon.md         ← merged from root + SKILL.md env-prefix
    phase2-active-recon.md          ← merged from root
    phase3-enumeration.md           ← merged from root
    phase4-attack-surface.md        ← merged from root + SKILL.md inline
    phase5-vuln-assessment.md       ← merged from root + SKILL.md inline
    phase6-exploitation-framework.md    ← already exists (source of truth)
    phase7-post-exploitation-framework.md ← already exists (source of truth)
    phase8-reporting-process.md          ← already exists (source of truth)
    (100+ technique references stay)
  templates/
  scripts/
```

## Execution Steps

### Step 1: Create Phase 1-5 reference files
Merge root v3 content + any SKILL.md inline content into proper reference files:
- `references/phase1-passive-recon.md` ← from `recon-passive.md` + SKILL.md "Env-Prefix Quick-Win Check"
- `references/phase2-active-recon.md` ← from `recon-active.md`
- `references/phase3-enumeration.md` ← from `enumeration.md`
- `references/phase4-attack-surface.md` ← from `attack-surface.md` + SKILL.md Phase 4 section (dismissal rules, prioritization matrix)
- `references/phase5-vuln-assessment.md` ← from `vuln-assessment.md` + SKILL.md Phase 5 checklist

### Step 2: Refactor SKILL.md
Remove from SKILL.md:
- Phase 1 "Env-Prefix Quick-Win Check" section (→ phase1 reference)
- Phase 4 full checklist + prioritization matrix + dismissal rules (→ phase4 reference)
- Phase 5 technique checklist (→ phase5 reference)
- Phase 6 HTTP Method Testing + technique references table (→ already in phase6 reference)
- Phase 7 "No Shell" checklist (→ already in phase7 reference)

Add to SKILL.md:
- Phase Routing table (which file to load per phase)
- One-line exit criteria per phase (keep in Gateway Map)

Keep in SKILL.md:
- Quick Reference block
- Commands table
- Setup (preflight, start, resume)
- Gateway Map (with exit criteria)
- Quality Gates (Pre-Report Gate 0, Local Verification Gate)
- Finding Template + ID + deduplication
- Effort Allocation
- Operational Lifecycle (execution loop, gateway transition)
- Escalation Protocol
- Cleanup
- Scope-Aware Checklist Generation table (used at `start` time)
- Guardrails (all)
- Cross-skill triggers
- Multi-target structure

### Step 3: Delete root-level phase files
After confirming references/ versions are complete:
- Delete `recon-passive.md`, `recon-active.md`, `enumeration.md`
- Delete `attack-surface.md`, `vuln-assessment.md`
- Delete `exploit.md`, `post-exploit.md`, `report.md`
- Keep `escalate-finding.md` at root (cross-phase)

### Step 4: Verify
- All phases loadable via `skill_view(name='ptest', file_path='references/phaseN-*.md')`
- SKILL.md under 4-5KB
- No content loss (all v3 + v4 content preserved in references)
- Scripts still reference correct paths

## Decision Points

1. **Scope-Aware Checklist table:** Keep in SKILL.md (used at `start`, not phase-specific)
2. **Cross-skill triggers:** Keep in SKILL.md (fires during Phase 1-3, needs early visibility)
3. **escalate-finding.md:** Keep at root (cross-phase, loaded on demand via escalate command)
4. **Scripts (phase1_passive.py etc.):** Keep as-is — they generate checklists, don't contain technique docs

## Estimated Impact
- SKILL.md: 894 lines → ~350-400 lines (~4KB)
- One extra skill_view call per phase transition (negligible)
- No content loss — everything preserved in references/
- Clearer source of truth — one file per phase, no version drift
