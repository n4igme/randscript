#!/usr/bin/env python3
"""w3hunt gate_check — verify phase deliverables before advancement."""
import os
import yaml


PHASE_GATES = {
    1: {
        "name": "Triage",
        "checks": ["go_nogo_documented"],
    },
    2: {
        "name": "Recon",
        "checks": ["recon_minimum"],
    },
    3: {
        "name": "Web Assessment",
        "checks": ["web_tested_or_hardened"],
    },
    4: {
        "name": "SC Audit",
        "checks": ["sc_tested_or_skipped"],
    },
    5: {
        "name": "Exploit & Submit",
        "checks": ["poc_validated"],
    },
}


def check_gate(workdir, phase=None):
    """Verify phase gate. Returns {passed, phase, name, met, unmet, warnings}."""
    state_path = os.path.join(workdir, "state.yaml")

    if not os.path.exists(state_path):
        return {"passed": False, "phase": 0, "name": "", "met": [], "unmet": ["state.yaml not found"], "warnings": []}

    with open(state_path) as f:
        state = yaml.safe_load(f)

    if phase is None:
        phase = state.get("current_phase", 1)

    gate = PHASE_GATES.get(phase)
    if not gate:
        return {"passed": False, "phase": phase, "name": "", "met": [], "unmet": [f"Unknown phase {phase}"], "warnings": []}

    met, unmet, warnings = [], [], []
    checks = gate.get("checks", [])

    if "go_nogo_documented" in checks:
        # Phase 1: need scope.txt + GO decision
        scope_path = os.path.join(workdir, "scope.txt")
        if os.path.exists(scope_path) and os.path.getsize(scope_path) > 50:
            met.append("scope.txt exists and populated")
        else:
            unmet.append("scope.txt missing or empty — run Phase 1 triage")

        # Check prerequisites
        prereqs = state.get("prerequisites", {})
        if prereqs.get("program_live") is True:
            met.append("Program confirmed live")
        elif prereqs.get("program_live") is False:
            unmet.append("Program not live — cannot proceed")
        else:
            unmet.append("program_live not checked")

    if "recon_minimum" in checks:
        # Phase 2: minimum viable recon (at least 3 of 5 items)
        recon_items = 0
        if os.path.exists(os.path.join(workdir, "subdomains.txt")):
            recon_items += 1
            met.append("subdomains.txt exists")
        if os.path.exists(os.path.join(workdir, "github-repos.txt")):
            recon_items += 1
            met.append("github-repos.txt exists")
        if os.path.exists(os.path.join(workdir, "api-endpoints.txt")):
            recon_items += 1
            met.append("api-endpoints.txt exists")
        if os.path.exists(os.path.join(workdir, "frontend-recon.txt")):
            recon_items += 1
            met.append("frontend-recon.txt exists")
        if os.path.exists(os.path.join(workdir, "recon-summary.txt")):
            recon_items += 1
            met.append("recon-summary.txt exists")

        if recon_items < 3:
            unmet.append(f"Only {recon_items}/5 recon items complete (need ≥3)")

    if "web_tested_or_hardened" in checks:
        # Phase 3: either findings exist or "web hardened" documented
        findings_dir = os.path.join(workdir, "findings")
        has_findings = os.path.isdir(findings_dir) and len(os.listdir(findings_dir)) > 0

        if has_findings:
            count = len([f for f in os.listdir(findings_dir) if f.endswith(".md")])
            met.append(f"Web findings: {count}")
        else:
            # Check if documented as hardened
            recon_summary = os.path.join(workdir, "recon-summary.txt")
            hardened = False
            if os.path.exists(recon_summary):
                with open(recon_summary) as f:
                    content = f.read().lower()
                if "hardened" in content or "no findings" in content or "dead" in content:
                    hardened = True
                    met.append("Web layer documented as hardened/dead")
            if not hardened:
                unmet.append("No findings AND web not documented as hardened — test more or document")

    if "sc_tested_or_skipped" in checks:
        # Phase 4: SC tested or explicitly skipped
        scope = state.get("scope", {})
        has_sc = scope.get("has_sc", False)

        if not has_sc:
            met.append("No SC in scope — Phase 4 N/A")
        else:
            # Check prerequisites
            prereqs = state.get("prerequisites", {})
            oracle_pass = all([
                prereqs.get("oracle_permissionless"),
                prereqs.get("oracle_swap_onchain"),
                prereqs.get("oracle_slippage_derived"),
            ])
            findings_dir = os.path.join(workdir, "findings")
            has_findings = os.path.isdir(findings_dir) and len(os.listdir(findings_dir)) > 0

            if has_findings:
                met.append("SC findings exist")
            elif not oracle_pass:
                met.append("SC oracle prerequisites failed — pivot documented")
            else:
                unmet.append("SC in scope, prerequisites pass, but no findings or skip justification")

    if "poc_validated" in checks:
        # Phase 5: PoC exists and has been run
        poc_dir = os.path.join(workdir, "poc")
        if os.path.isdir(poc_dir):
            pocs = [f for f in os.listdir(poc_dir) if f.endswith(".py")]
            if pocs:
                met.append(f"PoC scripts: {len(pocs)}")
            else:
                unmet.append("poc/ directory exists but no .py scripts")
        else:
            unmet.append("poc/ directory missing — no exploit validated")

        # Check submission
        submissions = os.path.join(workdir, "submissions.yaml")
        if os.path.exists(submissions):
            met.append("submissions.yaml exists — report submitted")
        else:
            warnings.append("No submissions.yaml — has report been submitted?")

    # Time budget warning
    target = state.get("target", {})
    started = target.get("started", "")
    if started:
        try:
            from datetime import datetime, timezone
            start_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            hours = (now - start_dt).total_seconds() / 3600
            if hours > 6 and state.get("findings_count", 0) == 0:
                warnings.append(f"Budget: {hours:.1f}h elapsed, zero findings — consider abandoning")
            elif hours > 8:
                warnings.append(f"Budget: {hours:.1f}h elapsed — exceeding 8h target")
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
