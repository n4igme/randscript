"""ttest state manager — engagement lifecycle for thick client pentesting."""
import os
import yaml
from datetime import datetime


def _state_path(workdir):
    return os.path.join(workdir, "ttest-output", "state.yaml")


def _read_state(workdir):
    path = _state_path(workdir)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return yaml.safe_load(f)


def _write_state(workdir, state):
    path = _state_path(workdir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        yaml.dump(state, f, default_flow_style=False, sort_keys=False)


def init_state(workdir, name, app_type="unknown", platform="windows", targets=None):
    """Initialize a new ttest engagement."""
    outdir = os.path.join(workdir, "ttest-output")
    for subdir in ["phase1-recon", "phase2-traffic", "phase3-local", "phase4-logic", "report"]:
        os.makedirs(os.path.join(outdir, subdir), exist_ok=True)

    state = {
        "engagement": {
            "name": name,
            "started": datetime.now().isoformat(),
            "app_type": app_type,
            "platform": platform,
            "targets": targets or [],
        },
        "gateways": {
            "1_recon_setup": "OPEN",
            "2_traffic": "LOCKED",
            "3_local_analysis": "LOCKED",
            "4_business_logic": "LOCKED",
            "5_reporting": "LOCKED",
        },
        "findings_count": 0,
        "current_phase": 1,
        "time_tracking": {f"phase_{i}_start": "" for i in range(1, 6)},
        "notes": "",
    }
    state["time_tracking"].update({f"phase_{i}_end": "" for i in range(1, 6)})
    state["time_tracking"]["phase_1_start"] = datetime.now().isoformat()
    _write_state(workdir, state)

    # Write scope.md
    scope_path = os.path.join(outdir, "scope.md")
    with open(scope_path, "w") as f:
        f.write(f"# Scope: {name}\n\n")
        f.write(f"- App Type: {app_type}\n")
        f.write(f"- Platform: {platform}\n")
        f.write(f"- Targets: {', '.join(targets or ['TBD'])}\n")

    print(f"[ttest] Initialized: {name} ({app_type}/{platform})")
    print(f"[ttest] Output: {outdir}")
    return state


def status(workdir):
    """Print current engagement status."""
    state = _read_state(workdir)
    if not state:
        print("[ttest] No active engagement. Run init_state() to start.")
        return None
    eng = state["engagement"]
    phase = state["current_phase"]
    findings = state["findings_count"]
    print(f"─── ttest status ───────────────────────────")
    print(f"Target:   {eng['name']} ({eng['app_type']}/{eng['platform']})")
    print(f"Phase:    {phase}/5")
    print(f"Findings: {findings}")
    print(f"─────────────────────────────────────────────")
    for gw, st in state["gateways"].items():
        print(f"  {gw}: {st}")
    return state


def advance_phase(workdir):
    """Advance to next phase."""
    state = _read_state(workdir)
    if not state:
        print("[ttest] No active engagement.")
        return False
    phase = state["current_phase"]
    if phase >= 5:
        print("[ttest] Already at final phase.")
        return False

    gateway_keys = list(state["gateways"].keys())
    state["gateways"][gateway_keys[phase - 1]] = "PASSED"
    state["time_tracking"][f"phase_{phase}_end"] = datetime.now().isoformat()
    state["gateways"][gateway_keys[phase]] = "OPEN"
    state["current_phase"] = phase + 1
    state["time_tracking"][f"phase_{phase + 1}_start"] = datetime.now().isoformat()
    _write_state(workdir, state)
    print(f"[ttest] Advanced: Phase {phase} → Phase {phase + 1}")
    return True


def add_finding(workdir, finding_id, title, severity, category, location, description=""):
    """Add a finding."""
    state = _read_state(workdir)
    if not state:
        return
    state["findings_count"] += 1
    _write_state(workdir, state)

    findings_log = os.path.join(workdir, "ttest-output", "findings-log.md")
    with open(findings_log, "a") as f:
        f.write(f"\n## [{finding_id}] {title}\n")
        f.write(f"**Severity:** {severity} | **Category:** {category}\n")
        f.write(f"**Location:** {location}\n")
        if description:
            f.write(f"{description}\n")
    print(f"[ttest] Finding added: {finding_id} ({severity})")


def abandon(workdir, reason):
    """Abandon engagement."""
    state = _read_state(workdir)
    if not state:
        return
    for key in state["gateways"]:
        if state["gateways"][key] in ("OPEN", "LOCKED"):
            state["gateways"][key] = "ABORTED"
    state["notes"] = f"Aborted: {reason}"
    _write_state(workdir, state)
    print(f"[ttest] Engagement aborted: {reason}")
