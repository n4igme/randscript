#!/usr/bin/env python3
"""ptest gate_check — verify phase deliverables exist before advancement."""
import os
import yaml
from datetime import datetime


# Required deliverables per phase (files that MUST exist with content)
PHASE_GATES = {
    1: {
        "name": "Passive Recon",
        "dir": "recon-passive",
        "required_files": ["checklist.md"],
        "required_content": {
            "checklist.md": ["DONE", "FAILED", "N/A"],  # at least one technique marked
        },
        "min_techniques_done": 3,
    },
    2: {
        "name": "Active Recon",
        "dir": "recon-active",
        "required_files": ["checklist.md"],
        "required_content": {
            "checklist.md": ["DONE", "FAILED", "N/A"],
        },
        "min_techniques_done": 3,
    },
    3: {
        "name": "Enumeration",
        "dir": "enumeration",
        "required_files": ["checklist.md"],
        "required_content": {
            "checklist.md": ["DONE", "FAILED", "N/A"],
        },
        "min_techniques_done": 5,
    },
    4: {
        "name": "Attack Surface",
        "dir": "attack-surface",
        "required_files": ["checklist.md"],
        "min_techniques_done": 1,
    },
    5: {
        "name": "Vuln Assessment",
        "dir": "vuln-assessment",
        "required_files": ["checklist.md"],
        "required_content": {
            "checklist.md": ["DONE", "FAILED", "N/A"],
        },
        "min_techniques_done": 5,
    },
    6: {
        "name": "Exploitation",
        "dir": "exploit",
        "required_files": ["checklist.md", "credential-inventory.md"],
        "min_techniques_done": 3,
    },
    7: {
        "name": "Post-Exploitation",
        "dir": "post-exploit",
        "required_files": ["checklist.md"],
        "min_techniques_done": 1,
    },
    8: {
        "name": "Reporting",
        "dir": "report",
        "required_files": [],
        "min_techniques_done": 0,
    },
}


def check_gate(workdir, phase=None):
    """
    Verify phase gate requirements are met.

    Args:
        workdir: engagement directory (contains ptest-output/)
        phase: phase number to check (default: current from state.yaml)

    Returns:
        dict: {passed: bool, phase: int, met: [...], unmet: [...], warnings: [...]}
    """
    output_dir = os.path.join(workdir, "ptest-output")
    state_path = os.path.join(output_dir, "state.yaml")

    if not os.path.exists(state_path):
        return {"passed": False, "phase": 0, "met": [], "unmet": ["state.yaml not found"], "warnings": []}

    with open(state_path) as f:
        state = yaml.safe_load(f)

    if phase is None:
        phase = state.get("current_phase", 1) if isinstance(state, dict) else 1

    gate = PHASE_GATES.get(phase)
    if not gate:
        return {"passed": False, "phase": phase, "met": [], "unmet": [f"Unknown phase {phase}"], "warnings": []}

    phase_dir = os.path.join(output_dir, gate["dir"])
    met = []
    unmet = []
    warnings = []

    # Check directory exists
    if not os.path.isdir(phase_dir):
        unmet.append(f"Directory missing: {gate['dir']}/")
        return {"passed": False, "phase": phase, "met": met, "unmet": unmet, "warnings": warnings}

    met.append(f"Directory exists: {gate['dir']}/")

    # Check required files
    for req_file in gate.get("required_files", []):
        fpath = os.path.join(phase_dir, req_file)
        if not os.path.exists(fpath):
            unmet.append(f"Missing: {gate['dir']}/{req_file}")
        elif os.path.getsize(fpath) < 10:
            unmet.append(f"Empty/stub: {gate['dir']}/{req_file} ({os.path.getsize(fpath)} bytes)")
        else:
            met.append(f"Exists: {gate['dir']}/{req_file}")

    # Check content markers (techniques done)
    checklist_path = os.path.join(phase_dir, "checklist.md")
    techniques_done = 0
    if os.path.exists(checklist_path):
        with open(checklist_path) as f:
            content = f.read()
        for marker in ["DONE", "FAILED", "N/A", "SKIPPED"]:
            techniques_done += content.upper().count(marker)

        min_req = gate.get("min_techniques_done", 0)
        if techniques_done >= min_req:
            met.append(f"Techniques completed: {techniques_done} (min: {min_req})")
        else:
            unmet.append(f"Only {techniques_done} techniques done (min: {min_req})")

        # Check for PENDING items still remaining
        pending = content.upper().count("PENDING")
        if pending > 0:
            warnings.append(f"{pending} techniques still PENDING")

    # Phase 6 special: credential-inventory.md must have content
    if phase == 6:
        cred_path = os.path.join(phase_dir, "credential-inventory.md")
        if os.path.exists(cred_path):
            with open(cred_path) as f:
                cred_content = f.read()
            if len(cred_content) < 50:
                unmet.append("credential-inventory.md exists but has no real content")
            else:
                met.append("credential-inventory.md has content")

    # Check findings exist (warning only, not blocking)
    findings_count = state.get("findings_count", 0)
    if phase >= 5 and findings_count == 0:
        warnings.append(f"Zero findings at Phase {phase} — review stuck-playbook?")

    passed = len(unmet) == 0
    return {"passed": passed, "phase": phase, "name": gate["name"], "met": met, "unmet": unmet, "warnings": warnings}


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
        print(f"\n  → Cannot advance. Fix {len(result['unmet'])} issue(s) above.")

    return result["passed"]


def check_all_gates(workdir):
    """Check all phases, report overall status."""
    output_dir = os.path.join(workdir, "ptest-output")
    state_path = os.path.join(output_dir, "state.yaml")

    if not os.path.exists(state_path):
        print("No active engagement.")
        return

    with open(state_path) as f:
        state = yaml.safe_load(f)

    current = state.get("current_phase", 1) if isinstance(state, dict) else 1

    print(f"\nptest Gate Audit — Current Phase: {current}")
    print("=" * 50)

    for p in range(1, current + 1):
        result = check_gate(workdir, p)
        status = "✅ PASSED" if result["passed"] else "❌ GAPS"
        detail = ""
        if result["unmet"]:
            detail = f" ({len(result['unmet'])} issues)"
        print(f"  Phase {p} ({PHASE_GATES[p]['name']:20s}): {status}{detail}")

    print()
