#!/usr/bin/env python3
"""opsec gate_check — verify phase deliverables before advancement."""
import os
import yaml


PHASE_GATES = {
    1: {
        "name": "Identity Inventory",
        "checks": ["inventory_exists"],
    },
    2: {
        "name": "Exposure Assessment",
        "checks": ["exposure_documented"],
    },
    3: {
        "name": "Severity Scoring",
        "checks": ["scoring_done"],
    },
    4: {
        "name": "Chain Analysis",
        "checks": ["chain_mapped"],
    },
    5: {
        "name": "Remediation",
        "checks": ["remediation_planned"],
    },
    6: {
        "name": "Periodic Audit",
        "checks": ["audit_checklist"],
    },
}


def check_gate(workdir, phase=None):
    """Verify phase gate. Returns {passed, phase, name, met, unmet, warnings}."""
    state_path = os.path.join(workdir, "opsec-output", "state.yaml")

    if not os.path.exists(state_path):
        return {"passed": False, "phase": 0, "name": "", "met": [], "unmet": ["opsec-output/state.yaml not found"], "warnings": []}

    with open(state_path) as f:
        state = yaml.safe_load(f)

    if phase is None:
        phase = state.get("current_phase", 1)

    gate = PHASE_GATES.get(phase)
    if not gate:
        return {"passed": False, "phase": phase, "name": "", "met": [], "unmet": [f"Unknown phase {phase}"], "warnings": []}

    met, unmet, warnings = [], [], []
    checks = gate.get("checks", [])
    outdir = os.path.join(workdir, "opsec-output")

    if "inventory_exists" in checks:
        inv_path = os.path.join(outdir, "inventory.md")
        if os.path.exists(inv_path) and os.path.getsize(inv_path) > 50:
            met.append("inventory.md exists and populated")
        else:
            unmet.append("inventory.md missing or empty — list all identifiers")

        # Check we have at least some identifiers
        identifiers = state.get("identifiers", {})
        total = sum(len(v) for v in identifiers.values() if isinstance(v, list))
        if total >= 1:
            met.append(f"Identifiers tracked: {total}")
        else:
            warnings.append("No identifiers in state — update state.yaml with handles/emails/domains")

    if "exposure_documented" in checks:
        exp_path = os.path.join(outdir, "exposure.md")
        if os.path.exists(exp_path) and os.path.getsize(exp_path) > 100:
            met.append("exposure.md documented")
        else:
            unmet.append("exposure.md missing — run git audit, profile cross-links, breach checks")

    if "scoring_done" in checks:
        score_path = os.path.join(outdir, "scoring.md")
        if os.path.exists(score_path) and os.path.getsize(score_path) > 50:
            met.append("scoring.md exists")
        else:
            unmet.append("scoring.md missing — rate findings by severity")

        # Check findings exist
        findings = state.get("findings", {})
        total = sum(findings.values())
        if total > 0:
            met.append(f"Findings scored: {total}")
        else:
            warnings.append("Zero findings — either OPSEC is perfect or assessment was incomplete")

    if "chain_mapped" in checks:
        chain_path = os.path.join(outdir, "chain-map.md")
        if os.path.exists(chain_path) and os.path.getsize(chain_path) > 50:
            met.append("chain-map.md exists")
        else:
            unmet.append("chain-map.md missing — map identity cross-reference chains")

        hops = state.get("chain_hops_to_real_identity")
        if hops is not None:
            met.append(f"Chain hops documented: {hops}")
            if hops < 3:
                warnings.append(f"Only {hops} hops to real identity — weak compartmentalization")
        else:
            warnings.append("chain_hops_to_real_identity not set in state")

    if "remediation_planned" in checks:
        rem_path = os.path.join(outdir, "remediation-plan.md")
        if os.path.exists(rem_path) and os.path.getsize(rem_path) > 50:
            met.append("remediation-plan.md exists")
        else:
            unmet.append("remediation-plan.md missing — generate prioritized fix plan")

    if "audit_checklist" in checks:
        audit_path = os.path.join(outdir, "audit-checklist.md")
        if os.path.exists(audit_path) and os.path.getsize(audit_path) > 50:
            met.append("audit-checklist.md exists")
        else:
            unmet.append("audit-checklist.md missing — generate quarterly audit checklist")

    passed = len(unmet) == 0
    return {"passed": passed, "phase": phase, "name": gate["name"], "met": met, "unmet": unmet, "warnings": warnings}


def print_gate_status(result):
    """Pretty-print gate check."""
    icon = "✅" if result["passed"] else "❌"
    print(f"\n{icon} Phase {result['phase']} ({result.get('name', '')}) Gate Check")
    print("=" * 50)
    if result["met"]:
        for m in result["met"]:
            print(f"  ✓ {m}")
    if result["unmet"]:
        print("  Blocking:")
        for u in result["unmet"]:
            print(f"  ✗ {u}")
    if result["warnings"]:
        for w in result["warnings"]:
            print(f"  ⚠ {w}")
    return result["passed"]


if __name__ == "__main__":
    import sys
    workdir = sys.argv[1] if len(sys.argv) > 1 else "."
    phase = int(sys.argv[2]) if len(sys.argv) > 2 else None
    result = check_gate(workdir, phase)
    print_gate_status(result)
    sys.exit(0 if result["passed"] else 1)
