# State Manager / Gate Check Consolidation

Completed June 2026. All 10 engagement skills now use thin wrappers over shared libraries.

## Current Architecture

- `security/scripts/base_state.py` — BaseStateManager class with init/advance/abandon/add_finding/mark_na
- `security/scripts/base_gate.py` — BaseGateChecker with skill-specific phase gates
- `security/scripts/postmortem.py` — shared retrospective script
- Each skill's `scripts/config.py` — per-skill constants (NAME, OUTPUT_DIR, PHASES, GATEWAYS, SUBDIRS, BUDGET_HOURS)
- Each skill's `scripts/state_manager.py` — thin wrapper (~25 lines) importing from base_state
- Each skill's `scripts/gate_check.py` — thin wrapper (~25 lines) importing from base_gate

## Why This Matters

- Bug fixes in base classes propagate to all skills instantly
- Adding a new skill = config + 2 thin wrappers, no copy-paste
- State schema is consistent across all engagement types
- All wrappers verified: `python3 -m py_compile` passes

## Migration Pattern (for future skills)

1. Create skill directory: `security/<skill-name>/`
2. Create `scripts/config.py` with `SKILL_CONFIG` constants
3. Create thin `scripts/state_manager.py` (~25 lines) importing from `base_state.BaseStateManager`
4. Create thin `scripts/gate_check.py` (~25 lines) importing from `base_gate.BaseGateChecker`
5. Write `SKILL.md` with all mandatory sections (see "Security Skill Construction Pattern" in this SKILL.md)
6. Add `references/` directory for phase-specific detail
7. Update `security/README.md` if adding a new top-level skill

**Rule:** Never copy-paste state_manager.py or gate_check.py logic. Always extend the shared base classes.

Historical note: Prior to this, all 10 skills had diverged copies of state_manager.py/gate_check.py
with 136–375 lines each. Any bug fix had to be applied 10 times.
