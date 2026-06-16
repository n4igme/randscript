"""adtest state manager — engagement lifecycle for AD pentesting."""
import os
import yaml
from datetime import datetime


def _state_path(workdir):
    return os.path.join(workdir, "adtest-output", "state.yaml")


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


def init_state(workdir, name, domain, dc_ip, access_level="authenticated", targets=None):
    """Initialize a new adtest engagement."""
    outdir = os.path.join(workdir, "adtest-output")
    for subdir in ["phase1-recon", "phase1-recon/bloodhound", "phase2-creds",
                   "phase3-kerberos", "phase4-relay", "phase5-privesc", "report"]:
        os.makedirs(os.path.join(outdir, subdir), exist_ok=True)

    state = {
        "engagement": {
            "name": name,
            "started": datetime.now().isoformat(),
            "domain": domain,
            "dc_ip": dc_ip,
            "access_level": access_level,
            "targets": targets or [],
        },
        "gateways": {
            "1_recon_enum": "OPEN",
            "2_cred_harvest": "LOCKED",
            "3_kerberos": "LOCKED",
            "4_relay_delegation": "LOCKED",
            "5_privesc_lateral": "LOCKED",
            "6_reporting": "LOCKED",
        },
        "findings_count": 0,
        "credentials_count": 0,
        "current_phase": 1,
        "da_achieved": False,
        "time_tracking": {f"phase_{i}_start": "" for i in range(1, 7)},
        "notes": "",
    }
    state["time_tracking"].update({f"phase_{i}_end": "" for i in range(1, 7)})
    state["time_tracking"]["phase_1_start"] = datetime.now().isoformat()
    _write_state(workdir, state)

    scope_path = os.path.join(outdir, "scope.md")
    with open(scope_path, "w") as f:
        f.write(f"# Scope: {name}\n\n")
        f.write(f"- Domain: {domain}\n")
        f.write(f"- DC: {dc_ip}\n")
        f.write(f"- Access Level: {access_level}\n")

    print(f"[adtest] Initialized: {name} ({domain})")
    print(f"[adtest] Output: {outdir}")
    return state


def status(workdir):
    """Print current engagement status."""
    state = _read_state(workdir)
    if not state:
        print("[adtest] No active engagement. Run init_state() to start.")
        return None
    eng = state["engagement"]
    print(f"─── adtest status ──────────────────────────")
    print(f"Target:   {eng['name']} ({eng['domain']})")
    print(f"Phase:    {state['current_phase']}/6")
    print(f"Findings: {state['findings_count']} | Creds: {state['credentials_count']}")
    print(f"DA:       {'✅ ACHIEVED' if state['da_achieved'] else '❌ Not yet'}")
    print(f"─────────────────────────────────────────────")
    for gw, st in state["gateways"].items():
        print(f"  {gw}: {st}")
    return state


def advance_phase(workdir):
    """Advance to next phase."""
    state = _read_state(workdir)
    if not state:
        return False
    phase = state["current_phase"]
    if phase >= 6:
        print("[adtest] Already at final phase.")
        return False
    gateway_keys = list(state["gateways"].keys())
    state["gateways"][gateway_keys[phase - 1]] = "PASSED"
    state["time_tracking"][f"phase_{phase}_end"] = datetime.now().isoformat()
    state["gateways"][gateway_keys[phase]] = "OPEN"
    state["current_phase"] = phase + 1
    state["time_tracking"][f"phase_{phase + 1}_start"] = datetime.now().isoformat()
    _write_state(workdir, state)
    print(f"[adtest] Advanced: Phase {phase} → Phase {phase + 1}")
    return True


def add_finding(workdir, finding_id, title, severity, asset, technique=""):
    """Add a finding."""
    state = _read_state(workdir)
    if not state:
        return
    state["findings_count"] += 1
    _write_state(workdir, state)
    findings_log = os.path.join(workdir, "adtest-output", "findings-log.md")
    with open(findings_log, "a") as f:
        f.write(f"\n## [{finding_id}] {title}\n")
        f.write(f"**Severity:** {severity} | **Asset:** {asset}\n")
        if technique:
            f.write(f"**Technique:** {technique}\n")
    print(f"[adtest] Finding added: {finding_id} ({severity})")


def add_credential(workdir, username, cred_type, source, access_level=""):
    """Track discovered credentials."""
    state = _read_state(workdir)
    if not state:
        return
    state["credentials_count"] += 1
    _write_state(workdir, state)
    cred_file = os.path.join(workdir, "adtest-output", "phase2-creds", "credential-inventory.md")
    if not os.path.exists(cred_file):
        with open(cred_file, "w") as f:
            f.write("# Credential Inventory\n\n")
            f.write("| # | Username | Type | Source | Access Level |\n")
            f.write("|---|----------|------|--------|-------------|\n")
    with open(cred_file, "a") as f:
        n = state["credentials_count"]
        f.write(f"| {n} | {username} | {cred_type} | {source} | {access_level} |\n")
    print(f"[adtest] Credential #{state['credentials_count']}: {username} ({cred_type})")


def mark_da(workdir, method):
    """Mark Domain Admin achieved."""
    state = _read_state(workdir)
    if not state:
        return
    state["da_achieved"] = True
    state["notes"] = f"DA achieved via: {method}"
    _write_state(workdir, state)
    print(f"[adtest] 🎯 Domain Admin achieved via: {method}")


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
    print(f"[adtest] Engagement aborted: {reason}")
