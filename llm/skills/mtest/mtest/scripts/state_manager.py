#!/usr/bin/env python3
"""mtest State Manager — read state, advance phases, record findings."""
import os, yaml
from datetime import datetime

def read_state(workdir):
    """Read current engagement state."""
    state_path = os.path.join(workdir, "mtest-output/state.yaml")
    if not os.path.isfile(state_path):
        print("No state.yaml found. Run phase1_preflight first.")
        return None
    with open(state_path) as f:
        return yaml.safe_load(f)

def save_state(workdir, state):
    """Write state back."""
    from hermes_tools import write_file
    state_path = os.path.join(workdir, "mtest-output/state.yaml")
    write_file(state_path, yaml.dump(state, default_flow_style=False))

def status(workdir):
    """Print current engagement status."""
    state = read_state(workdir)
    if not state:
        return

    phase = state["current_phase"]
    findings = state["findings_count"]
    app = state["engagement"]["package_id"]
    started = state["engagement"]["started"]

    print(f"Engagement: {state['engagement']['name']}")
    print(f"  Target: {app}")
    print(f"  Started: {started}")
    print(f"  Current phase: {phase}")
    print(f"  Findings: {findings}")
    print(f"\\n  Gateways:")
    for gate, status in state["gateways"].items():
        marker = "→" if gate.startswith(f"{phase}_") else " "
        print(f"    {marker} {gate}: {status}")

def advance(workdir):
    """Advance to next phase."""
    state = read_state(workdir)
    if not state:
        return

    current = state["current_phase"]
    now = datetime.now().isoformat()

    # Mark current phase end
    state["time_tracking"][f"phase_{current}_end"] = now

    # Find current gateway key and mark PASSED
    for key in state["gateways"]:
        if key.startswith(f"{current}_"):
            state["gateways"][key] = "PASSED"
            break

    # Advance
    next_phase = current + 1
    if next_phase > 10:
        print("All phases complete!")
        return

    state["current_phase"] = next_phase
    state["time_tracking"][f"phase_{next_phase}_start"] = now

    # Unlock next gateway
    for key in state["gateways"]:
        if key.startswith(f"{next_phase}_"):
            state["gateways"][key] = "OPEN"
            break

    save_state(workdir, state)
    print(f"Advanced: Phase {current} → Phase {next_phase}")
    print(f"  Phase {current} duration: {state['time_tracking'][f'phase_{current}_start']} to {now}")

def mark_na(workdir, phase_num, reason):
    """Mark a phase as N/A with justification."""
    state = read_state(workdir)
    if not state:
        return

    for key in state["gateways"]:
        if key.startswith(f"{phase_num}_"):
            state["gateways"][key] = "N/A"
            break

    state["notes"] = state.get("notes", "") + f"\\nPhase {phase_num} N/A: {reason}"
    save_state(workdir, state)
    print(f"Phase {phase_num} marked N/A: {reason}")

def add_finding(workdir, title, severity, confidence, platform, component, feature, description, steps, impact, remediation):
    """Create a new finding file and increment counter."""
    from hermes_tools import write_file

    state = read_state(workdir)
    if not state:
        return

    state["findings_count"] += 1
    fid = f"MTEST-{state['findings_count']:03d}"

    finding = f"""# {fid}: {title}

**Severity:** {severity}
**Confidence:** {confidence}
**Platform:** {platform}
**Component:** {component}
**Feature:** {feature}

## Description
{description}

## Steps to Reproduce
{steps}

## Impact
{impact}

## Remediation
{remediation}
"""
    findings_dir = os.path.join(workdir, "mtest-output/findings")
    os.makedirs(findings_dir, exist_ok=True)
    write_file(os.path.join(findings_dir, f"{fid}.md"), finding)
    save_state(workdir, state)

    print(f"Finding created: {fid} [{severity}] {title}")
    print(f"  File: mtest-output/findings/{fid}.md")
    return fid


if __name__ == "__main__":
    pass
