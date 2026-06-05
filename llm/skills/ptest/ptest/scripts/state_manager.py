#!/usr/bin/env python3
"""ptest state manager — lifecycle operations for web/infra pentest engagements."""
import os
import yaml
from datetime import datetime


PHASES = {
    1: "passive_recon",
    2: "active_recon",
    3: "enumeration",
    4: "attack_surface",
    5: "vuln_assessment",
    6: "exploitation",
    7: "post_exploitation",
    8: "reporting",
}

GATEWAYS = {
    1: "1_passive_recon",
    2: "2_active_recon",
    3: "3_enumeration",
    4: "4_attack_surface",
    5: "5_vuln_assessment",
    6: "6_exploitation",
    7: "7_post_exploitation",
    8: "8_reporting",
}


def _state_path(workdir):
    return os.path.join(workdir, "ptest-output", "state.yaml")


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


def init_state(workdir, name, scope_type="web", targets=None,
               exclusions=None, budget_hours=None):
    """Initialize engagement. Called by `start` command."""
    targets = targets or []
    exclusions = exclusions or []
    outdir = os.path.join(workdir, "ptest-output")

    subdirs = [
        "recon-passive", "recon-active", "enumeration",
        "attack-surface", "vuln-assessment", "exploit",
        "post-exploit", "report", "escalations"
    ]
    for subdir in subdirs:
        os.makedirs(os.path.join(outdir, subdir), exist_ok=True)

    now = datetime.now().isoformat()
    state = {
        "engagement": {
            "name": name,
            "started": now,
            "scope_type": scope_type,
        },
        "config": {
            "seclists_path": "",
            "targets": targets,
            "exclusions": exclusions,
            "budget_hours": budget_hours,
        },
        "gateways": {
            "1_passive_recon": "OPEN",
            "2_active_recon": "LOCKED",
            "3_enumeration": "LOCKED",
            "4_attack_surface": "LOCKED",
            "5_vuln_assessment": "LOCKED",
            "6_exploitation": "LOCKED",
            "7_post_exploitation": "LOCKED",
            "8_reporting": "LOCKED",
        },
        "findings_count": 0,
        "findings_by_severity": {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        },
        "escalations_count": 0,
        "current_phase": 1,
        "time_tracking": {
            f"phase_{i}_start": (now if i == 1 else "")
            for i in range(1, 9)
        },
        "notes": "",
    }
    # Add end timestamps
    for i in range(1, 9):
        state["time_tracking"][f"phase_{i}_end"] = ""

    save_state(workdir, state)

    # Write scope.md
    scope_path = os.path.join(outdir, "scope.md")
    with open(scope_path, "w") as f:
        f.write(f"# Pentest Scope\n\n")
        f.write(f"**Engagement:** {name}\n")
        f.write(f"**Type:** {scope_type}\n")
        f.write(f"**Started:** {now}\n\n")
        f.write("## Targets\n\n")
        for t in targets:
            f.write(f"- {t}\n")
        f.write("\n## Exclusions\n\n")
        for e in exclusions:
            f.write(f"- {e}\n")
        f.write("\n## Out of Scope\n\n- TBD\n")
        f.write("\n## Authorization\n\n- [ ] Written authorization confirmed\n")

    # Write findings-log.md
    log_path = os.path.join(outdir, "findings-log.md")
    with open(log_path, "w") as f:
        f.write(f"# Findings Log — {name}\n\n")
        f.write("| ID | Severity | Asset | Title | Phase | Status |\n")
        f.write("|----|----------|-------|-------|-------|--------|\n")

    print(f"✓ ptest engagement initialized: {name}")
    print(f"  Scope: {scope_type} | Targets: {len(targets)}")
    print(f"  Output: {outdir}/")
    return state


def status(workdir):
    """Print engagement status."""
    state = read_state(workdir)
    if not state:
        print("No active ptest engagement. Use init_state() to start.")
        return None

    eng = state["engagement"]
    phase = state["current_phase"]
    findings = state["findings_count"]
    sev = state.get("findings_by_severity", {})

    print(f"\n─── ptest status ───────────────────────────")
    print(f"  Engagement: {eng['name']}")
    print(f"  Scope:      {eng['scope_type']}")
    print(f"  Phase:      {phase} ({PHASES.get(phase, '?')})")
    print(f"  Findings:   {findings} (C:{sev.get('critical',0)} H:{sev.get('high',0)} "
          f"M:{sev.get('medium',0)} L:{sev.get('low',0)} I:{sev.get('info',0)})")
    print(f"  Escalations: {state.get('escalations_count', 0)}")
    print(f"  Gateways:")
    for gw_key, gw_val in state["gateways"].items():
        icon = "●" if gw_val == "OPEN" else ("✓" if gw_val == "PASSED" else "○")
        print(f"    {icon} {gw_key}: {gw_val}")
    print(f"─────────────────────────────────────────────")
    return state


def advance_phase(workdir):
    """Advance to next phase."""
    state = read_state(workdir)
    if not state:
        print("No active engagement.")
        return None

    phase = state["current_phase"]
    if phase >= 8:
        print("Already at final phase.")
        return None

    now = datetime.now().isoformat()
    current_gw = GATEWAYS[phase]
    state["gateways"][current_gw] = "PASSED"
    state["time_tracking"][f"phase_{phase}_end"] = now

    next_phase = phase + 1
    next_gw = GATEWAYS[next_phase]
    state["gateways"][next_gw] = "OPEN"
    state["current_phase"] = next_phase
    state["time_tracking"][f"phase_{next_phase}_start"] = now

    save_state(workdir, state)
    print(f"✓ Phase {phase} ({PHASES[phase]}) → PASSED")
    print(f"✓ Phase {next_phase} ({PHASES[next_phase]}) → OPEN")
    return next_phase


def add_finding(workdir, finding_id, title, severity, asset,
                description="", phase=None, status_val="confirmed"):
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
    outdir = os.path.join(workdir, "ptest-output")
    log_path = os.path.join(outdir, "findings-log.md")
    with open(log_path, "a") as f:
        f.write(f"| {finding_id} | {severity} | {asset} | {title} | {phase} | {status_val} |\n")

    print(f"✓ Finding added: {finding_id} [{severity}] {title}")
    return finding_id


def escalate(workdir, finding_id, title, severity, asset):
    """Escalate a critical finding."""
    state = read_state(workdir)
    if not state:
        return None

    state["escalations_count"] = state.get("escalations_count", 0) + 1
    esc_num = state["escalations_count"]
    save_state(workdir, state)

    outdir = os.path.join(workdir, "ptest-output")
    esc_path = os.path.join(outdir, "escalations", f"escalation-{esc_num}.md")
    with open(esc_path, "w") as f:
        f.write(f"# Escalation {esc_num}\n\n")
        f.write(f"**Finding:** {finding_id}\n")
        f.write(f"**Severity:** {severity}\n")
        f.write(f"**Asset:** {asset}\n")
        f.write(f"**Title:** {title}\n")
        f.write(f"**Time:** {datetime.now().isoformat()}\n\n")
        f.write("## Details\n\nTBD\n\n## Immediate Action Required\n\nTBD\n")

    print(f"🚨 ESCALATION #{esc_num}: {finding_id} [{severity}] {title}")
    return esc_num


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


def should_abandon(workdir, budget_hours=None):
    """Check if engagement should be abandoned. Returns (bool, reason)."""
    state = read_state(workdir)
    if not state:
        return False, ""

    budget = budget_hours or state.get("config", {}).get("budget_hours")
    if not budget:
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

    if elapsed > budget * 0.75 and findings == 0:
        return True, f"{elapsed:.1f}h elapsed (75% of {budget}h budget), zero findings"

    if elapsed > budget:
        return True, f"{elapsed:.1f}h elapsed — over {budget}h budget"

    return False, ""
