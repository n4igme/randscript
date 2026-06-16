"""adtest gate checker — verify phase completion before advancing."""
import os
import yaml


def _read_state(workdir):
    path = os.path.join(workdir, "adtest-output", "state.yaml")
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
    outdir = os.path.join(workdir, "adtest-output")
    unmet = []

    if current == 1:
        recon_dir = os.path.join(outdir, "phase1-recon")
        if not os.path.exists(os.path.join(recon_dir, "domain-info.md")):
            unmet.append("domain-info.md not created")
        bh_dir = os.path.join(recon_dir, "bloodhound")
        if not os.listdir(bh_dir) if os.path.exists(bh_dir) else True:
            unmet.append("No BloodHound data collected")
        if not os.path.exists(os.path.join(recon_dir, "users.txt")):
            unmet.append("users.txt not created")

    elif current == 2:
        cred_file = os.path.join(outdir, "phase2-creds", "credential-inventory.md")
        if not os.path.exists(cred_file):
            unmet.append("No credential-inventory.md (need at least 1 cred)")
        elif state.get("credentials_count", 0) == 0:
            unmet.append("Zero credentials harvested")

    elif current == 3:
        kerberos_dir = os.path.join(outdir, "phase3-kerberos")
        if not os.listdir(kerberos_dir) if os.path.exists(kerberos_dir) else True:
            unmet.append("No Kerberos attack output")

    elif current == 4:
        relay_dir = os.path.join(outdir, "phase4-relay")
        if not os.listdir(relay_dir) if os.path.exists(relay_dir) else True:
            unmet.append("No relay/delegation testing output")

    elif current == 5:
        attack_path = os.path.join(outdir, "phase5-privesc", "attack-path.md")
        if not os.path.exists(attack_path):
            unmet.append("attack-path.md not documented")

    elif current == 6:
        report_dir = os.path.join(outdir, "report")
        if not os.listdir(report_dir) if os.path.exists(report_dir) else True:
            unmet.append("No report generated")

    passed = len(unmet) == 0
    return {"passed": passed, "phase": current, "unmet": unmet}


def print_gate_status(result):
    """Pretty-print gate check result."""
    status = "✅ PASSED" if result["passed"] else "❌ NOT MET"
    print(f"[adtest] Phase {result.get('phase', '?')} Gate: {status}")
    if not result["passed"]:
        for item in result["unmet"]:
            print(f"  ⚠ {item}")
