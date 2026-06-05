#!/usr/bin/env python3
"""atest gate_check — verify phase deliverables before advancement."""
import os
import yaml


PHASE_GATES = {
    1: {
        "name": "Scope & Recon",
        "dir": "phase1-recon",
        "required_files": ["endpoints.md", "auth-flow.md"],
        "check_token": True,
    },
    2: {
        "name": "AuthN/AuthZ",
        "dir": "phase2-authz",
        "required_files": [],
        "min_items": 1,
    },
    3: {
        "name": "Injection & Logic",
        "dir": "phase3-injection",
        "required_files": [],
        "min_items": 1,
    },
    4: {
        "name": "Reporting",
        "dir": "report",
        "required_files": [],
        "min_items": 0,
    },
}


def check_gate(workdir, phase=None):
    """Verify phase gate. Returns {passed, phase, name, met, unmet, warnings}."""
    output_dir = os.path.join(workdir, "atest-output")
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
    met, unmet, warnings = [], [], []

    if not os.path.isdir(phase_dir):
        unmet.append(f"Directory missing: {gate['dir']}/")
        return {"passed": False, "phase": phase, "name": gate["name"], "met": met, "unmet": unmet, "warnings": warnings}

    met.append(f"Directory exists: {gate['dir']}/")

    # Required files
    for req_file in gate.get("required_files", []):
        fpath = os.path.join(phase_dir, req_file)
        if not os.path.exists(fpath):
            unmet.append(f"Missing: {gate['dir']}/{req_file}")
        elif os.path.getsize(fpath) < 20:
            unmet.append(f"Empty: {gate['dir']}/{req_file}")
        else:
            met.append(f"Exists: {gate['dir']}/{req_file}")

    # Min output items
    min_req = gate.get("min_items", 0)
    if min_req > 0:
        items = [f for f in os.listdir(phase_dir) if not f.startswith(".")]
        if len(items) >= min_req:
            met.append(f"Output files: {len(items)} (min: {min_req})")
        else:
            unmet.append(f"Only {len(items)} output files (min: {min_req})")

    # Phase 1: token acquired
    if gate.get("check_token"):
        scope = state.get("config", {})
        # Check if auth mechanism is "none" (no token needed)
        auth = state.get("engagement", {}).get("auth_mechanism", "")
        if auth == "none":
            met.append("Auth: none (no token needed)")
        else:
            # Look for token evidence in auth-flow.md
            auth_path = os.path.join(phase_dir, "auth-flow.md")
            if os.path.exists(auth_path):
                with open(auth_path) as f:
                    content = f.read()
                if "bearer" in content.lower() or "token" in content.lower() or "jwt" in content.lower():
                    met.append("Token acquisition documented")
                else:
                    warnings.append("auth-flow.md exists but no token evidence found")
            else:
                unmet.append("No auth-flow.md — token not documented")

    # Findings warning
    findings_count = state.get("findings_count", 0)
    if phase >= 3 and findings_count == 0:
        warnings.append("Zero findings at Phase 3 — check abandon heuristics")

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
