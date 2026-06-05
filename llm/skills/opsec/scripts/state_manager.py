#!/usr/bin/env python3
"""opsec state manager — lifecycle operations for OPSEC self-assessments."""
import os
import yaml
from datetime import datetime


PHASES = {
    1: "inventory",
    2: "exposure",
    3: "scoring",
    4: "chain",
    5: "remediation",
    6: "audit",
}

GATEWAYS = {
    1: "1_inventory",
    2: "2_exposure",
    3: "3_scoring",
    4: "4_chain",
    5: "5_remediation",
    6: "6_audit",
}


def _state_path(workdir):
    return os.path.join(workdir, "opsec-output", "state.yaml")


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


def init_state(workdir, subject, handles=None, emails=None, domains=None):
    """Initialize assessment."""
    outdir = os.path.join(workdir, "opsec-output")
    os.makedirs(outdir, exist_ok=True)

    now = datetime.now().isoformat()
    state = {
        "assessment": {
            "subject": subject,
            "started": now,
            "status": "active",
            "type": "full",  # full | quarterly | post-incident
        },
        "current_phase": 1,
        "gateways": {
            "1_inventory": "OPEN",
            "2_exposure": "LOCKED",
            "3_scoring": "LOCKED",
            "4_chain": "LOCKED",
            "5_remediation": "LOCKED",
            "6_audit": "LOCKED",
        },
        "identifiers": {
            "handles": handles or [],
            "emails": emails or [],
            "domains": domains or [],
        },
        "findings": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        },
        "chain_hops_to_real_identity": None,
        "remediation_items": 0,
        "notes": "",
    }
    save_state(workdir, state)

    # Write inventory.md template
    inv_path = os.path.join(outdir, "inventory.md")
    with open(inv_path, "w") as f:
        f.write(f"# Identity Inventory — {subject}\n\n")
        f.write(f"**Date:** {now}\n\n")
        f.write("## Identifiers\n\n")
        f.write("- Real name:\n- Aliases/nicknames:\n")
        f.write("- Handles (list all):\n")
        if handles:
            for h in handles:
                f.write(f"  - {h}\n")
        f.write("- Email addresses:\n")
        if emails:
            for e in emails:
                f.write(f"  - {e}\n")
        f.write("- Phone numbers:\n- Domains owned:\n")
        if domains:
            for d in domains:
                f.write(f"  - {d}\n")
        f.write("- Employer/org:\n- Location:\n- Profiles (URLs):\n")

    print(f"✓ opsec assessment initialized: {subject}")
    print(f"  Output: {outdir}/")
    return state


def status(workdir):
    """Print assessment status."""
    state = read_state(workdir)
    if not state:
        print("No active opsec assessment. Use init_state() to start.")
        return None

    assess = state["assessment"]
    phase = state["current_phase"]
    findings = state.get("findings", {})
    total = sum(findings.values())
    hops = state.get("chain_hops_to_real_identity")

    print(f"\n─── opsec status ───────────────────────────")
    print(f"  Subject:    {assess['subject']}")
    print(f"  Type:       {assess['type']}")
    print(f"  Phase:      {phase} ({PHASES.get(phase, '?')})")
    print(f"  Findings:   {total} "
          f"(🔴{findings.get('critical',0)} 🟠{findings.get('high',0)} "
          f"🟡{findings.get('medium',0)} 🟢{findings.get('low',0)})")
    if hops is not None:
        print(f"  Chain hops: {hops} (to real identity)")
    print(f"  Remediation items: {state.get('remediation_items', 0)}")
    print(f"─────────────────────────────────────────────")
    return state


def advance_phase(workdir):
    """Advance to next phase."""
    state = read_state(workdir)
    if not state:
        print("No active assessment.")
        return None

    phase = state["current_phase"]
    if phase >= 6:
        print("Already at final phase.")
        return None

    current_gw = GATEWAYS[phase]
    state["gateways"][current_gw] = "PASSED"

    next_phase = phase + 1
    next_gw = GATEWAYS[next_phase]
    state["gateways"][next_gw] = "OPEN"
    state["current_phase"] = next_phase

    save_state(workdir, state)
    print(f"✓ Phase {phase} ({PHASES[phase]}) → PASSED")
    print(f"✓ Phase {next_phase} ({PHASES[next_phase]}) → OPEN")
    return next_phase


def add_finding(workdir, severity, description, source="public"):
    """Add an exposure finding. severity: critical|high|medium|low."""
    state = read_state(workdir)
    if not state:
        return None

    sev_key = severity.lower()
    if sev_key in state.get("findings", {}):
        state["findings"][sev_key] += 1
    save_state(workdir, state)

    icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
    print(f"  {icons.get(sev_key, '?')} [{severity.upper()}] {description} (source: {source})")
    return state


def set_chain_hops(workdir, hops):
    """Set the chain hops to real identity metric."""
    state = read_state(workdir)
    if not state:
        return None
    state["chain_hops_to_real_identity"] = hops
    save_state(workdir, state)
    quality = "good (3+)" if hops >= 3 else ("acceptable (2)" if hops == 2 else "BAD (≤1)")
    print(f"✓ Chain hops to real identity: {hops} — {quality}")
    return state


def add_remediation(workdir, priority, action):
    """Add a remediation item."""
    state = read_state(workdir)
    if not state:
        return None
    state["remediation_items"] = state.get("remediation_items", 0) + 1
    save_state(workdir, state)
    print(f"  P{priority}: {action}")
    return state


def abandon(workdir, reason):
    """Abandon assessment."""
    state = read_state(workdir)
    if not state:
        return None

    state["assessment"]["status"] = "aborted"
    state["assessment"]["aborted_at"] = datetime.now().isoformat()
    state["notes"] = (state.get("notes", "") or "") + f"\nAborted: {reason}"

    for gw_key, gw_val in state["gateways"].items():
        if gw_val == "LOCKED":
            state["gateways"][gw_key] = "ABORTED"

    save_state(workdir, state)
    print(f"✗ Assessment aborted: {reason}")
    return state
