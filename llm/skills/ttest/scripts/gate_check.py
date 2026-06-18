#!/usr/bin/env python3
"""ttest gate_check — verify phase deliverables before advancement."""
import os
import yaml
from typing import Dict, List, Optional


PHASE_GATES = {
    1: {
        "name": "Recon & Setup",
        "dir": "phase1-recon",
        "required_files": ["app-info.md"],
        "min_items": 0,
    },
    2: {
        "name": "Traffic",
        "dir": "phase2-traffic",
        "required_files": [],
        "min_items": 1,
    },
    3: {
        "name": "Local Analysis",
        "dir": "phase3-local",
        "required_files": [],
        "min_items": 1,
    },
    4: {
        "name": "Business Logic",
        "dir": "phase4-logic",
        "required_files": [],
        "min_items": 1,
    },
    5: {
        "name": "Reporting",
        "dir": "report",
        "required_files": [],
        "min_items": 0,
    },
}


def check_gate(workdir: str, phase: Optional[int] = None) -> Dict:
    """Verify phase gate. Returns {passed, phase, name, met, unmet, warnings}."""
    output_dir = os.path.join(workdir, "ttest-output")
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
    met: List[str] = []
    unmet: List[str] = []
    warnings: List[str] = []

    if not os.path.isdir(phase_dir):
        unmet.append(f"Directory missing: {gate['dir']}/")
        return {"passed": False, "phase": phase, "name": gate["name"], "met": met, "unmet": unmet, "warnings": warnings}

    met.append(f"Directory exists: {gate['dir']}/")

    for req_file in gate.get("required_files", []):
        fpath = os.path.join(phase_dir, req_file)
        if not os.path.exists(fpath):
            unmet.append(f"Missing: {gate['dir']}/{req_file}")
        elif os.path.getsize(fpath) < 20:
            unmet.append(f"Empty: {gate['dir']}/{req_file}")
        else:
            met.append(f"Exists: {gate['dir']}/{req_file}")

    min_req = gate.get("min_items", 0)
    if min_req > 0:
        items = [f for f in os.listdir(phase_dir) if not f.startswith(".")]
        if len(items) >= min_req:
            met.append(f"Output files: {len(items)} (min: {min_req})")
        else:
            unmet.append(f"Only {len(items)} output files (min: {min_req})")

    # Phase 1: verify app-info.md documents app type, version, architecture
    if phase == 1:
        info_path = os.path.join(phase_dir, "app-info.md")
        if os.path.exists(info_path):
            with open(info_path) as f:
                content = f.read().lower()
            documented = []
            for keyword in ("type", "version", "architecture"):
                if keyword in content:
                    documented.append(keyword)
            if documented:
                met.append(f"app-info.md documents: {', '.join(documented)}")
            else:
                warnings.append("app-info.md exists but missing type/version/architecture details")

    # Phase 3: warn if zero findings — local storage is typically the richest source
    findings_count = state.get("findings_count", 0)
    if phase == 3 and findings_count == 0:
        warnings.append("Zero findings at Phase 3 — local storage is typically the richest source")

    # General late-phase zero-findings warning
    if phase >= 4 and findings_count == 0:
        warnings.append("Zero findings at Phase 4+ — check abandon heuristics")

    passed = len(unmet) == 0
    return {"passed": passed, "phase": phase, "name": gate["name"], "met": met, "unmet": unmet, "warnings": warnings}


def print_gate_status(result: dict) -> bool:
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
