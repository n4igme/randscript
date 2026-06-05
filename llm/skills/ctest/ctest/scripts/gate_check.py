#!/usr/bin/env python3
"""ctest gate_check — verify phase deliverables before advancement."""
import os
import yaml


PHASE_GATES = {
    1: {
        "name": "Scope & Discovery",
        "dir": "phase1-discovery",
        "required_files": [],
        "checks": ["scope_md_exists", "provider_identified"],
        "min_items": 1,
    },
    2: {
        "name": "IAM & Access",
        "dir": "phase2-iam",
        "required_files": [],
        "checks": ["access_level_documented"],
        "min_items": 1,
    },
    3: {
        "name": "Service Exploitation",
        "dir": "phase3-services",
        "required_files": [],
        "checks": [],
        "min_items": 1,
    },
    4: {
        "name": "Container & Orchestration",
        "dir": "phase4-containers",
        "required_files": [],
        "checks": ["k8s_or_na"],
        "min_items": 0,
    },
    5: {
        "name": "Reporting",
        "dir": "phase5-report",
        "required_files": [],
        "min_items": 0,
    },
}


def check_gate(workdir, phase=None):
    """Verify phase gate. Returns {passed, phase, name, met, unmet, warnings}."""
    output_dir = os.path.join(workdir, "ctest-output")
    state_path = os.path.join(output_dir, "state.yaml")

    if not os.path.exists(state_path):
        return {"passed": False, "phase": 0, "name": "", "met": [], "unmet": ["state.yaml not found"], "warnings": []}

    with open(state_path) as f:
        state = yaml.safe_load(f)

    if phase is None:
        phase = state.get("current_phase", 1)

    gate = PHASE_GATES.get(phase)
    if not gate:
        return {"passed": False, "phase": phase, "name": "", "met": [], "unmet": [f"Unknown phase {phase}"], "warnings": []}

    phase_dir = os.path.join(output_dir, gate["dir"])
    met, unmet, warnings = [], [], []

    # Check directory exists
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

    # Phase-specific checks
    engagement = state.get("engagement", {})
    checks = gate.get("checks", [])

    if "scope_md_exists" in checks:
        scope_path = os.path.join(output_dir, "scope.md")
        if os.path.exists(scope_path) and os.path.getsize(scope_path) > 20:
            met.append("scope.md exists and populated")
        else:
            unmet.append("scope.md missing or empty")

    if "provider_identified" in checks:
        provider = engagement.get("provider", "")
        if provider:
            met.append(f"Provider identified: {provider}")
        else:
            unmet.append("No cloud provider set in engagement.provider")

    if "access_level_documented" in checks:
        access = engagement.get("access_level", "")
        if access:
            met.append(f"Access level documented: {access}")
        else:
            warnings.append("access_level not set — document what credentials you have")

    if "k8s_or_na" in checks:
        # Phase 4 is N/A if no K8s/containers in scope — check for justification
        items = []
        if os.path.isdir(phase_dir):
            items = [f for f in os.listdir(phase_dir) if not f.startswith(".")]
        if len(items) == 0:
            # Check if marked N/A in gateways
            gateways = state.get("gateways", {})
            gw_val = gateways.get("4_containers", "")
            if gw_val == "N/A":
                met.append("Phase 4 marked N/A (no containers in scope)")
            else:
                unmet.append("No output in phase4-containers/ and not marked N/A")
        else:
            met.append(f"Container testing output: {len(items)} files")

    # Findings warning
    findings_count = state.get("findings_count", 0)
    if phase >= 3 and findings_count == 0:
        warnings.append("Zero findings at Phase 3+ — check abandon heuristics")

    # Credential staleness warning
    if phase >= 2:
        started = state.get("engagement", {}).get("started", "")
        if started:
            try:
                from datetime import datetime, timezone
                start_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                days = (now - start_dt).days
                if days > 3:
                    warnings.append(f"Engagement started {days} days ago — re-verify credentials still valid")
            except (ValueError, TypeError):
                pass

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
