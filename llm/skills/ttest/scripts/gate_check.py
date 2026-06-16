"""ttest gate checker — verify phase completion before advancing."""
import os
import yaml


def _read_state(workdir):
    path = os.path.join(workdir, "ttest-output", "state.yaml")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return yaml.safe_load(f)


def check_gate(workdir, phase=None):
    """Check if current phase gate is satisfied."""
    state = _read_state(workdir)
    if not state:
        return {"passed": False, "reason": "No active engagement", "unmet": []}

    current = phase or state["current_phase"]
    outdir = os.path.join(workdir, "ttest-output")
    unmet = []

    if current == 1:
        # Gate: app type identified, proxy working, tools ready
        recon_dir = os.path.join(outdir, "phase1-recon")
        if not os.path.exists(os.path.join(recon_dir, "app-type.md")):
            unmet.append("app-type.md not created (identify app type)")
        if not os.path.exists(os.path.join(recon_dir, "proxy-config.md")):
            unmet.append("proxy-config.md not created (document proxy setup)")

    elif current == 2:
        # Gate: all protocols intercepted, API surface mapped
        traffic_dir = os.path.join(outdir, "phase2-traffic")
        if not os.listdir(traffic_dir) if os.path.exists(traffic_dir) else True:
            unmet.append("No traffic analysis output files")

    elif current == 3:
        # Gate: storage audited, secrets scanned, DLL hijack tested
        local_dir = os.path.join(outdir, "phase3-local")
        if not os.listdir(local_dir) if os.path.exists(local_dir) else True:
            unmet.append("No local analysis output files")

    elif current == 4:
        # Gate: client-side controls bypassed, license/auth tested
        logic_dir = os.path.join(outdir, "phase4-logic")
        if not os.listdir(logic_dir) if os.path.exists(logic_dir) else True:
            unmet.append("No business logic testing output")

    elif current == 5:
        # Gate: report delivered
        report_dir = os.path.join(outdir, "report")
        if not os.listdir(report_dir) if os.path.exists(report_dir) else True:
            unmet.append("No report generated")

    passed = len(unmet) == 0
    return {"passed": passed, "phase": current, "unmet": unmet}


def print_gate_status(result):
    """Pretty-print gate check result."""
    status = "✅ PASSED" if result["passed"] else "❌ NOT MET"
    print(f"[ttest] Phase {result.get('phase', '?')} Gate: {status}")
    if not result["passed"]:
        for item in result["unmet"]:
            print(f"  ⚠ {item}")
