#!/usr/bin/env python3
"""xdev state manager — lifecycle operations for exploit development engagements."""
import os
import yaml
from datetime import datetime


PHASES = {
    1: "vuln_analysis",
    2: "primitive_dev",
    3: "mitigation_bypass",
    4: "exploit_construction",
    5: "documentation",
}

GATEWAYS = {
    1: "1_analysis",
    2: "2_primitives",
    3: "3_mitigations",
    4: "4_construction",
    5: "5_documentation",
}


def _state_path(workdir):
    return os.path.join(workdir, "xdev-output", "state.yaml")


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


def init_state(workdir, name, platform="linux", architecture="x86_64",
               vuln_class="uaf", target_version="", goal="rce"):
    """Initialize engagement. Called by `start` command."""
    outdir = os.path.join(workdir, "xdev-output")
    for subdir in ("phase1-analysis", "phase2-primitives", "phase3-mitigations",
                   "phase4-exploit", "phase4-exploit/payload", "phase5-report"):
        os.makedirs(os.path.join(outdir, subdir), exist_ok=True)

    now = datetime.now().isoformat()
    state = {
        "engagement": {
            "name": name,
            "started": now,
            "platform": platform,
            "architecture": architecture,
            "vuln_class": vuln_class,
            "target_version": target_version,
            "goal": goal,
        },
        "gateways": {
            "1_analysis": "OPEN",
            "2_primitives": "LOCKED",
            "3_mitigations": "LOCKED",
            "4_construction": "LOCKED",
            "5_documentation": "LOCKED",
        },
        "primitives": {
            "info_leak": False,
            "arb_read": False,
            "arb_write": False,
            "code_exec": False,
        },
        "mitigations_bypassed": [],
        "reliability": "",
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
        "dead_ends": [],
        "notes": "",
    }
    save_state(workdir, state)

    # Write target.md
    target_md = os.path.join(outdir, "target.md")
    with open(target_md, "w") as f:
        f.write(f"# Exploit Target\n\n")
        f.write(f"**Name:** {name}\n")
        f.write(f"**Platform:** {platform}\n")
        f.write(f"**Architecture:** {architecture}\n")
        f.write(f"**Vuln Class:** {vuln_class}\n")
        f.write(f"**Target Version:** {target_version}\n")
        f.write(f"**Goal:** {goal}\n\n")
        f.write(f"## Mitigations (fill during Phase 1)\n\n")
        f.write(f"- ASLR: ?\n- DEP/NX: ?\n- CFI: ?\n- Stack canary: ?\n")
        f.write(f"- SMEP/SMAP: ?\n- PAC: ?\n- Sandbox: ?\n")

    # Write findings-log.md
    log_path = os.path.join(outdir, "findings-log.md")
    with open(log_path, "w") as f:
        f.write(f"# Exploit Development Log — {name}\n\n")
        f.write("## Dead Ends\n\n")
        f.write("## Breakthroughs\n\n")

    print(f"✓ xdev engagement initialized: {name}")
    print(f"  Platform: {platform}/{architecture} | Vuln: {vuln_class} | Goal: {goal}")
    print(f"  Output: {outdir}/")
    return state


def status(workdir):
    """Print engagement status."""
    state = read_state(workdir)
    if not state:
        print("No active xdev engagement. Use init_state() to start.")
        return None

    eng = state["engagement"]
    phase = state["current_phase"]
    prims = state.get("primitives", {})
    bypassed = state.get("mitigations_bypassed", [])
    reliability = state.get("reliability", "untested")

    print(f"\n─── xdev status ────────────────────────────")
    print(f"  Target:       {eng['name']}")
    print(f"  Platform:     {eng['platform']}/{eng['architecture']}")
    print(f"  Vuln class:   {eng['vuln_class']}")
    print(f"  Goal:         {eng['goal']}")
    print(f"  Phase:        {phase} ({PHASES.get(phase, '?')})")
    print(f"  Primitives:   leak={'✓' if prims.get('info_leak') else '✗'} "
          f"read={'✓' if prims.get('arb_read') else '✗'} "
          f"write={'✓' if prims.get('arb_write') else '✗'} "
          f"exec={'✓' if prims.get('code_exec') else '✗'}")
    print(f"  Bypassed:     {', '.join(bypassed) if bypassed else 'none'}")
    print(f"  Reliability:  {reliability}")
    print(f"  Dead ends:    {len(state.get('dead_ends', []))}")
    print(f"─────────────────────────────────────────────")
    return state


def advance_phase(workdir):
    """Advance to next phase."""
    state = read_state(workdir)
    if not state:
        print("No active engagement.")
        return None

    phase = state["current_phase"]
    if phase >= 5:
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


def set_primitive(workdir, primitive, value=True):
    """Set a primitive status. primitive: info_leak|arb_read|arb_write|code_exec."""
    state = read_state(workdir)
    if not state:
        return None
    if primitive in state.get("primitives", {}):
        state["primitives"][primitive] = value
        save_state(workdir, state)
        print(f"✓ Primitive '{primitive}' = {value}")
    else:
        print(f"✗ Unknown primitive: {primitive}")
    return state


def add_bypass(workdir, mitigation):
    """Record a mitigation bypass."""
    state = read_state(workdir)
    if not state:
        return None
    bypassed = state.get("mitigations_bypassed", [])
    if mitigation not in bypassed:
        bypassed.append(mitigation)
        state["mitigations_bypassed"] = bypassed
        save_state(workdir, state)
        print(f"✓ Mitigation bypassed: {mitigation}")
    return state


def add_dead_end(workdir, description):
    """Document a dead end (saves future time)."""
    state = read_state(workdir)
    if not state:
        return None
    dead_ends = state.get("dead_ends", [])
    dead_ends.append({"description": description, "timestamp": datetime.now().isoformat()})
    state["dead_ends"] = dead_ends
    save_state(workdir, state)
    print(f"✗ Dead end recorded: {description}")
    return state


def set_reliability(workdir, reliability):
    """Set reliability estimate (e.g., '85%', '9/10', 'low - race dependent')."""
    state = read_state(workdir)
    if not state:
        return None
    state["reliability"] = reliability
    save_state(workdir, state)
    print(f"✓ Reliability: {reliability}")
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
