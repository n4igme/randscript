#!/usr/bin/env python3
"""adtest gate_check — verify phase deliverables before advancement."""
import os
import yaml


PHASE_GATES = {
    1: {
        "name": "Recon & Enum",
        "dir": "phase1-recon",
        "required_files": ["domain-info.md"],
        "check_bloodhound": True,
    },
    2: {
        "name": "Cred Harvest",
        "dir": "phase2-creds",
        "required_files": [],
        "check_credentials": True,
    },
    3: {
        "name": "Kerberos",
        "dir": "phase3-kerberos",
        "required_files": [],
        "min_items": 1,
    },
    4: {
        "name": "Relay & Delegation",
        "dir": "phase4-relay",
        "required_files": [],
        "min_items": 1,
    },
    5: {
        "name": "PrivEsc & Lateral",
        "dir": "phase5-privesc",
        "required_files": ["attack-path.md"],
        "check_da": True,
    },
    6: {
        "name": "Reporting",
        "dir": "report",
        "required_files": [],
        "min_items": 0,
    },
}


def check_gate(workdir: str, phase: int | None = None) -> dict:
    """Verify phase gate. Returns {passed, phase, name, met, unmet, warnings}."""
    output_dir = os.path.join(workdir, "adtest-output")
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
    met: list[str] = []
    unmet: list[str] = []
    warnings: list[str] = []

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

    if gate.get("check_bloodhound"):
        bh_dir = os.path.join(output_dir, "bloodhound")
        if os.path.isdir(bh_dir):
            bh_items = [f for f in os.listdir(bh_dir) if not f.startswith(".")]
            if bh_items:
                met.append(f"BloodHound data: {len(bh_items)} files")
            else:
                warnings.append("bloodhound/ exists but is empty — collect SharpHound/BloodHound data")
        else:
            warnings.append("No bloodhound/ directory — BloodHound data not collected")

    if gate.get("check_credentials"):
        cred_count = state.get("credentials_count", 0)
        if cred_count > 0:
            met.append(f"Credentials harvested: {cred_count}")
        else:
            warnings.append("No credentials harvested — consider password spraying, Responder, or LLMNR poisoning")

    if gate.get("check_da"):
        attack_path = os.path.join(phase_dir, "attack-path.md")
        if os.path.isfile(attack_path):
            with open(attack_path) as f:
                content = f.read().lower()
            if "domain admin" in content:
                met.append("Domain Admin path documented")
            else:
                warnings.append("attack-path.md exists but no Domain Admin path found — document partial results")
        else:
            warnings.append("No attack-path.md — DA path not documented")

    findings_count = state.get("findings_count", 0)
    if phase >= 4 and findings_count == 0:
        warnings.append("Zero findings at Phase 4+ — check abandon heuristics")

    passed = len(unmet) == 0
    return {"passed": passed, "phase": phase, "name": gate["name"], "met": met, "unmet": unmet, "warnings": warnings}


def print_gate_status(result: dict) -> bool:
    """Pretty-print gate check."""
    icon = "PASS" if result["passed"] else "FAIL"
    print(f"\n[{icon}] Phase {result['phase']} ({result.get('name', '')}) Gate Check")
    print("=" * 50)
    if result["met"]:
        for m in result["met"]:
            print(f"  + {m}")
    if result["unmet"]:
        print("  Blocking:")
        for u in result["unmet"]:
            print(f"  - {u}")
    if result["warnings"]:
        for w in result["warnings"]:
            print(f"  ! {w}")
    return result["passed"]
