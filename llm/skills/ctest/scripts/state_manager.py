#!/usr/bin/env python3
"""ctest state manager — lifecycle operations for cloud pentest engagements."""
import os
import yaml
from datetime import datetime


PHASES = {
    1: "discovery",
    2: "iam_access",
    3: "service_exploitation",
    4: "containers",
    5: "reporting",
}

GATEWAYS = {
    1: "1_discovery",
    2: "2_iam_access",
    3: "3_service_exploitation",
    4: "4_containers",
    5: "5_reporting",
}


def _state_path(workdir):
    return os.path.join(workdir, "ctest-output", "state.yaml")


def read_state(workdir):
    """Read state.yaml. Returns dict or None."""
    path = _state_path(workdir)
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        return yaml.safe_load(f)


def save_state(workdir, state):
    """Write state dict to state.yaml."""
    path = _state_path(workdir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        yaml.dump(state, f, default_flow_style=False, sort_keys=False)


def init_state(workdir, name, provider="aws", scope_type="authenticated",
               access_level="none", target_assets=None):
    """Initialize engagement. Called by `start` command."""
    target_assets = target_assets or []
    outdir = os.path.join(workdir, "ctest-output")
    for subdir in ("phase1-discovery", "phase2-iam", "phase3-services",
                   "phase4-containers", "phase5-report", "escalations"):
        os.makedirs(os.path.join(outdir, subdir), exist_ok=True)

    now = datetime.now().isoformat()
    state = {
        "engagement": {
            "name": name,
            "started": now,
            "provider": provider,
            "scope_type": scope_type,
            "access_level": access_level,
            "target_assets": target_assets,
        },
        "gateways": {
            "1_discovery": "OPEN",
            "2_iam_access": "LOCKED",
            "3_service_exploitation": "LOCKED",
            "4_containers": "LOCKED",
            "5_reporting": "LOCKED",
        },
        "findings_count": 0,
        "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "escalations_count": 0,
        "current_phase": 1,
        "time_tracking": {
            "phase_1_start": now,
            "phase_1_end": "",
            "phase_2_start": "",
            "phase_2_end": "",
            "phase_3_start": "",
            "phase_3_end": "",
            "phase_4_start": "",
            "phase_4_end": "",
            "phase_5_start": "",
            "phase_5_end": "",
        },
        "notes": "",
    }
    save_state(workdir, state)

    # Write scope.md
    scope_md = os.path.join(outdir, "scope.md")
    with open(scope_md, "w") as f:
        f.write(f"# Cloud Pentest Scope\n\n")
        f.write(f"**Engagement:** {name}\n")
        f.write(f"**Provider:** {provider}\n")
        f.write(f"**Scope Type:** {scope_type}\n")
        f.write(f"**Access Level:** {access_level}\n")
        f.write(f"**Started:** {now}\n\n")
        f.write(f"## Target Assets\n\n")
        for asset in target_assets:
            f.write(f"- {asset}\n")
        f.write(f"\n## Rules of Engagement\n\n- TBD\n")
        f.write(f"\n## Out of Scope\n\n- TBD\n")

    # Write findings-log.md
    findings_log = os.path.join(outdir, "findings-log.md")
    with open(findings_log, "w") as f:
        f.write(f"# Findings Log — {name}\n\n")
        f.write("| ID | Severity | Service | Title | Phase |\n")
        f.write("|----|---------:|---------|-------|-------|\n")

    print(f"✓ ctest engagement initialized: {name}")
    print(f"  Provider: {provider} | Scope: {scope_type} | Access: {access_level}")
    print(f"  Output: {outdir}/")
    return state


def status(workdir):
    """Print engagement status."""
    state = read_state(workdir)
    if not state:
        print("No active ctest engagement. Use init_state() to start.")
        return None

    eng = state["engagement"]
    phase = state["current_phase"]
    findings = state["findings_count"]
    sev = state.get("findings_by_severity", {})

    print(f"\n─── ctest status ───────────────────────────")
    print(f"  Engagement: {eng['name']}")
    print(f"  Provider:   {eng['provider']} | Scope: {eng['scope_type']}")
    print(f"  Phase:      {phase} ({PHASES.get(phase, '?')})")
    print(f"  Findings:   {findings} (C:{sev.get('critical',0)} H:{sev.get('high',0)} "
          f"M:{sev.get('medium',0)} L:{sev.get('low',0)} I:{sev.get('info',0)})")
    print(f"  Gateways:")
    for gw_key, gw_val in state["gateways"].items():
        icon = "●" if gw_val == "OPEN" else ("✓" if gw_val == "PASSED" else "○")
        print(f"    {icon} {gw_key}: {gw_val}")
    print(f"─────────────────────────────────────────────")
    return state


def advance_phase(workdir):
    """Advance to next phase. Returns new phase number or None if blocked."""
    state = read_state(workdir)
    if not state:
        print("No active engagement.")
        return None

    phase = state["current_phase"]
    if phase >= 5:
        print("Already at final phase.")
        return None

    now = datetime.now().isoformat()

    # Mark current phase as PASSED
    current_gw = GATEWAYS[phase]
    state["gateways"][current_gw] = "PASSED"
    state["time_tracking"][f"phase_{phase}_end"] = now

    # Open next phase
    next_phase = phase + 1
    next_gw = GATEWAYS[next_phase]
    state["gateways"][next_gw] = "OPEN"
    state["current_phase"] = next_phase
    state["time_tracking"][f"phase_{next_phase}_start"] = now

    save_state(workdir, state)
    print(f"✓ Phase {phase} ({PHASES[phase]}) → PASSED")
    print(f"✓ Phase {next_phase} ({PHASES[next_phase]}) → OPEN")
    return next_phase


def add_finding(workdir, finding_id, title, severity, service, resource,
                description="", phase=None):
    """Add a finding. Updates state + findings-log.md."""
    state = read_state(workdir)
    if not state:
        print("No active engagement.")
        return None

    if phase is None:
        phase = state["current_phase"]

    state["findings_count"] += 1
    sev_key = severity.lower()
    if sev_key in state.get("findings_by_severity", {}):
        state["findings_by_severity"][sev_key] += 1

    save_state(workdir, state)

    # Append to findings-log.md
    outdir = os.path.join(workdir, "ctest-output")
    log_path = os.path.join(outdir, "findings-log.md")
    with open(log_path, "a") as f:
        f.write(f"| {finding_id} | {severity} | {service} | {title} | {phase} |\n")

    print(f"✓ Finding added: {finding_id} [{severity}] {title}")
    return finding_id


def mark_na(workdir, phase, reason):
    """Mark a phase as N/A with justification."""
    state = read_state(workdir)
    if not state:
        return None

    gw = GATEWAYS.get(phase)
    if not gw:
        print(f"Unknown phase {phase}")
        return None

    state["gateways"][gw] = "N/A"
    state["notes"] = (state.get("notes", "") or "") + f"\nPhase {phase} N/A: {reason}"
    save_state(workdir, state)
    print(f"✓ Phase {phase} ({PHASES[phase]}) marked N/A: {reason}")
    return state


def abandon(workdir, reason):
    """Abandon engagement."""
    state = read_state(workdir)
    if not state:
        return None

    now = datetime.now().isoformat()
    state["engagement"]["status"] = "aborted"
    state["engagement"]["aborted_at"] = now
    state["notes"] = (state.get("notes", "") or "") + f"\nAborted: {reason}"

    for gw_key, gw_val in state["gateways"].items():
        if gw_val == "LOCKED":
            state["gateways"][gw_key] = "ABORTED"

    save_state(workdir, state)
    print(f"✗ Engagement aborted: {reason}")
    return state


def should_abandon(workdir, budget_hours=8):
    """Check if engagement should be abandoned. Returns (bool, reason)."""
    state = read_state(workdir)
    if not state:
        return False, ""

    started = state["engagement"].get("started", "")
    if not started:
        return False, ""

    try:
        start_dt = datetime.fromisoformat(started)
        elapsed = (datetime.now() - start_dt).total_seconds() / 3600
    except (ValueError, TypeError):
        return False, ""

    findings = state["findings_count"]

    if elapsed > budget_hours * 0.75 and findings == 0:
        return True, f"{elapsed:.1f}h elapsed (75% of {budget_hours}h budget), zero findings"

    if elapsed > budget_hours:
        return True, f"{elapsed:.1f}h elapsed — over {budget_hours}h budget"

    return False, ""
