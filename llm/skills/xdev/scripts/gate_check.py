#!/usr/bin/env python3
"""xdev gate_check — verify phase deliverables before advancement."""
import os
import yaml


PHASE_GATES = {
    1: {
        "name": "Vulnerability Analysis",
        "checks": ["root_cause_documented", "crash_reproducible"],
    },
    2: {
        "name": "Primitive Development",
        "checks": ["has_primitive"],
    },
    3: {
        "name": "Mitigation Bypass",
        "checks": ["mitigations_assessed"],
    },
    4: {
        "name": "Exploit Construction",
        "checks": ["exploit_exists", "reliability_tested"],
    },
    5: {
        "name": "Documentation",
        "checks": ["report_exists"],
    },
}


def check_gate(workdir, phase=None):
    """Verify phase gate. Returns {passed, phase, name, met, unmet, warnings}."""
    state_path = os.path.join(workdir, "xdev-output", "state.yaml")

    if not os.path.exists(state_path):
        return {"passed": False, "phase": 0, "name": "", "met": [], "unmet": ["xdev-output/state.yaml not found"], "warnings": []}

    with open(state_path) as f:
        state = yaml.safe_load(f)

    if phase is None:
        phase = state.get("current_phase", 1)

    gate = PHASE_GATES.get(phase)
    if not gate:
        return {"passed": False, "phase": phase, "name": "", "met": [], "unmet": [f"Unknown phase {phase}"], "warnings": []}

    met, unmet, warnings = [], [], []
    checks = gate.get("checks", [])
    outdir = os.path.join(workdir, "xdev-output")

    if "root_cause_documented" in checks:
        rc_path = os.path.join(outdir, "phase1-analysis", "root-cause.md")
        if os.path.exists(rc_path) and os.path.getsize(rc_path) > 50:
            met.append("root-cause.md documented")
        else:
            unmet.append("root-cause.md missing — identify the bug before building exploits")

    if "crash_reproducible" in checks:
        crash_path = os.path.join(outdir, "phase1-analysis", "crash-triage.md")
        if os.path.exists(crash_path) and os.path.getsize(crash_path) > 30:
            met.append("crash-triage.md exists")
        else:
            unmet.append("crash-triage.md missing — document crash reproduction")

    if "has_primitive" in checks:
        primitives = state.get("primitives", {})
        achieved = [k for k, v in primitives.items() if v]
        if achieved:
            met.append(f"Primitives achieved: {', '.join(achieved)}")
        else:
            unmet.append("No primitives developed (need at least one of: info_leak, arb_read, arb_write, code_exec)")

        # Check for output files
        prim_dir = os.path.join(outdir, "phase2-primitives")
        if os.path.isdir(prim_dir):
            items = [f for f in os.listdir(prim_dir) if not f.startswith(".")]
            if items:
                met.append(f"Primitive artifacts: {len(items)} files")
            else:
                warnings.append("phase2-primitives/ is empty — document your primitive code")

    if "mitigations_assessed" in checks:
        bypassed = state.get("mitigations_bypassed", [])
        mit_dir = os.path.join(outdir, "phase3-mitigations")

        if os.path.isdir(mit_dir):
            items = [f for f in os.listdir(mit_dir) if not f.startswith(".")]
            if items:
                met.append(f"Mitigation analysis: {len(items)} files")
            else:
                unmet.append("phase3-mitigations/ is empty — document mitigation state")
        else:
            unmet.append("phase3-mitigations/ directory missing")

        if bypassed:
            met.append(f"Bypassed: {', '.join(bypassed)}")

        # Check target.md has mitigation info
        target_path = os.path.join(outdir, "target.md")
        if os.path.exists(target_path):
            with open(target_path) as f:
                content = f.read().lower()
            if "aslr" in content or "dep" in content or "cfi" in content or "none" in content:
                met.append("Mitigations documented in target.md")
            else:
                warnings.append("target.md may not have mitigation details filled in")

    if "exploit_exists" in checks:
        exploit_dir = os.path.join(outdir, "phase4-exploit")
        if os.path.isdir(exploit_dir):
            exploits = [f for f in os.listdir(exploit_dir)
                        if f.endswith((".py", ".c", ".rs", ".sh")) and not f.startswith(".")]
            if exploits:
                met.append(f"Exploit code: {', '.join(exploits)}")
            else:
                unmet.append("No exploit source in phase4-exploit/ (.py/.c/.rs/.sh)")
        else:
            unmet.append("phase4-exploit/ directory missing")

    if "reliability_tested" in checks:
        reliability = state.get("reliability", "")
        if reliability:
            met.append(f"Reliability documented: {reliability}")
        else:
            unmet.append("Reliability not set — test N≥5 times and record success rate")

    if "report_exists" in checks:
        report_dir = os.path.join(outdir, "phase5-report")
        if os.path.isdir(report_dir):
            reports = [f for f in os.listdir(report_dir) if f.endswith(".md")]
            if reports:
                met.append(f"Report written: {', '.join(reports)}")
            else:
                unmet.append("No report in phase5-report/")
        else:
            unmet.append("phase5-report/ directory missing")

    # Dead ends warning
    dead_ends = state.get("dead_ends", [])
    if len(dead_ends) >= 5:
        warnings.append(f"{len(dead_ends)} dead ends recorded — reassess exploitability")

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
