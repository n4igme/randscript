#!/usr/bin/env python3
"""mtest gate_check — verify phase deliverables exist before advancement."""
import os
import yaml


PHASE_GATES = {
    1: {
        "name": "Preflight",
        "dir": "phase1-preflight",
        "required_files": [],
        "check_scope": True,
        "min_items": 0,
    },
    2: {
        "name": "Static Analysis",
        "dir": "phase2-static",
        "required_files": [],
        "min_items": 1,  # at least one output file (strings, endpoints, etc.)
    },
    3: {
        "name": "Protection Bypass",
        "dir": "phase3-protection",
        "required_files": [],
        "min_items": 1,  # bypass script or documentation
    },
    4: {
        "name": "Traffic Analysis",
        "dir": "phase4-traffic",
        "required_files": [],
        "min_items": 1,
    },
    5: {
        "name": "Attack Surface",
        "dir": "phase5-attack-surface",
        "required_files": ["attack-surface-map.md"],
        "min_items": 0,
    },
    6: {
        "name": "Runtime Testing",
        "dir": "phase6-runtime",
        "required_files": [],
        "min_items": 2,  # at least 2 test category outputs
    },
    7: {
        "name": "Vuln Analysis",
        "dir": "phase7-vuln-analysis",
        "required_files": [],
        "check_attack_surface_coverage": True,
        "min_items": 3,
    },
    8: {
        "name": "API Testing",
        "dir": "phase8-api",
        "required_files": [],
        "min_items": 1,
    },
    9: {
        "name": "Exploitation",
        "dir": "phase9-exploitation",
        "required_files": [],
        "check_poc_for_high": True,
        "min_items": 0,
    },
    10: {
        "name": "Reporting",
        "dir": "phase10-reporting",
        "required_files": [],
        "min_items": 0,
    },
}


def check_gate(workdir, phase=None):
    """
    Verify phase gate requirements.

    Returns:
        dict: {passed, phase, name, met, unmet, warnings}
    """
    output_dir = os.path.join(workdir, "mtest-output")
    state_path = os.path.join(output_dir, "state.yaml")

    if not os.path.exists(state_path):
        return {"passed": False, "phase": 0, "met": [], "unmet": ["state.yaml not found"], "warnings": []}

    with open(state_path) as f:
        state = yaml.safe_load(f)

    if phase is None:
        phase = state.get("current_phase", 1)

    gate = PHASE_GATES.get(phase)
    if not gate:
        return {"passed": False, "phase": phase, "met": [], "unmet": [f"Unknown phase {phase}"], "warnings": []}

    phase_dir = os.path.join(output_dir, gate["dir"])
    met = []
    unmet = []
    warnings = []

    # Check scope.md exists (Phase 1 gate)
    if gate.get("check_scope"):
        scope_path = os.path.join(output_dir, "scope.md")
        if os.path.exists(scope_path) and os.path.getsize(scope_path) > 20:
            met.append("scope.md exists with content")
        else:
            unmet.append("scope.md missing or empty")

    # Check phase directory
    if not os.path.isdir(phase_dir):
        # N/A phases are OK if documented
        gateways = state.get("gateways", {})
        gate_key = f"{phase}_{'_'.join(gate['name'].lower().split())}"
        # Check if marked N/A
        for k, v in gateways.items():
            if str(phase) in k and v == "N/A":
                met.append(f"Phase marked N/A in state.yaml")
                return {"passed": True, "phase": phase, "name": gate["name"],
                        "met": met, "unmet": [], "warnings": []}
        unmet.append(f"Directory missing: {gate['dir']}/")
        return {"passed": False, "phase": phase, "name": gate["name"],
                "met": met, "unmet": unmet, "warnings": warnings}

    met.append(f"Directory exists: {gate['dir']}/")

    # Check required files
    for req_file in gate.get("required_files", []):
        fpath = os.path.join(phase_dir, req_file)
        if not os.path.exists(fpath):
            unmet.append(f"Missing: {gate['dir']}/{req_file}")
        elif os.path.getsize(fpath) < 20:
            unmet.append(f"Empty/stub: {gate['dir']}/{req_file}")
        else:
            met.append(f"Exists: {gate['dir']}/{req_file}")

    # Check minimum output items (files in phase dir)
    items = [f for f in os.listdir(phase_dir)
             if os.path.isfile(os.path.join(phase_dir, f)) and not f.startswith(".")]
    min_req = gate.get("min_items", 0)
    if len(items) >= min_req:
        met.append(f"Output files: {len(items)} (min: {min_req})")
    else:
        unmet.append(f"Only {len(items)} output files (min: {min_req})")

    # Phase 7 special: check attack surface coverage
    if gate.get("check_attack_surface_coverage"):
        asm_path = os.path.join(output_dir, "phase5-attack-surface", "attack-surface-map.md")
        if os.path.exists(asm_path):
            with open(asm_path) as f:
                features = [l for l in f.readlines() if l.strip().startswith("- ") or l.strip().startswith("| ")]
            feature_count = len(features)
            if feature_count > 0 and len(items) < feature_count // 2:
                warnings.append(f"Attack surface has {feature_count} features but only {len(items)} tested")

    # Phase 9 special: check PoCs exist for High+ findings
    if gate.get("check_poc_for_high"):
        findings_path = os.path.join(output_dir, "findings.jsonl")
        if os.path.exists(findings_path):
            import json
            high_count = 0
            with open(findings_path) as f:
                for line in f:
                    try:
                        finding = json.loads(line)
                        if finding.get("severity", "").lower() in ("critical", "high"):
                            high_count += 1
                    except json.JSONDecodeError:
                        pass
            poc_dir = os.path.join(phase_dir, "poc")
            poc_count = len(os.listdir(poc_dir)) if os.path.isdir(poc_dir) else 0
            if high_count > 0 and poc_count == 0:
                unmet.append(f"{high_count} Critical/High findings but no PoCs in phase9-exploitation/poc/")
            elif high_count > 0:
                met.append(f"PoCs exist ({poc_count}) for {high_count} High+ findings")

    # Check findings count warning
    findings_count = state.get("findings_count", 0)
    if phase >= 7 and findings_count == 0:
        warnings.append("Zero findings at Phase 7+ — is bypass working?")

    passed = len(unmet) == 0
    return {"passed": passed, "phase": phase, "name": gate["name"],
            "met": met, "unmet": unmet, "warnings": warnings}


def print_gate_status(result):
    """Pretty-print gate check result."""
    icon = "✅" if result["passed"] else "❌"
    print(f"\n{icon} Phase {result['phase']} ({result.get('name', '')}) Gate Check")
    print("=" * 50)

    if result["met"]:
        print("\n  Met:")
        for m in result["met"]:
            print(f"    ✓ {m}")
    if result["unmet"]:
        print("\n  NOT Met (blocking):")
        for u in result["unmet"]:
            print(f"    ✗ {u}")
    if result["warnings"]:
        print("\n  Warnings:")
        for w in result["warnings"]:
            print(f"    ⚠ {w}")

    if result["passed"]:
        print(f"\n  → Ready to advance to Phase {result['phase'] + 1}")
    else:
        print(f"\n  → Fix {len(result['unmet'])} issue(s) before advancing.")

    return result["passed"]
