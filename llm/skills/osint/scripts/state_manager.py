#!/usr/bin/env python3
"""osint state manager — lifecycle operations for OSINT reconnaissance engagements."""
import os
import yaml
from datetime import datetime


PHASES = {
    1: "seed",
    2: "handles",
    3: "emails",
    4: "domains",
    5: "social",
    6: "breaches",
    7: "chain_report",
}

GATEWAYS = {
    1: "1_seed",
    2: "2_handles",
    3: "3_emails",
    4: "4_domains",
    5: "5_social",
    6: "6_breaches",
    7: "7_chain_report",
}


def _state_path(workdir):
    return os.path.join(workdir, "osint-output", "state.yaml")


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


def init_state(workdir, target, names=None, handles=None, emails=None,
               domains=None, phones=None, locations=None):
    """Initialize engagement. Called by `start` command."""
    outdir = os.path.join(workdir, "osint-output")
    os.makedirs(outdir, exist_ok=True)

    now = datetime.now().isoformat()
    state = {
        "engagement": {
            "target": target,
            "started": now,
            "status": "active",
        },
        "current_phase": 1,
        "gateways": {
            "1_seed": "OPEN",
            "2_handles": "LOCKED",
            "3_emails": "LOCKED",
            "4_domains": "LOCKED",
            "5_social": "LOCKED",
            "6_breaches": "LOCKED",
            "7_chain_report": "LOCKED",
        },
        "seeds": {
            "names": names or [],
            "handles": handles or [],
            "emails": emails or [],
            "domains": domains or [],
            "phones": phones or [],
            "locations": locations or [],
        },
        "findings_count": 0,
        "platforms_checked": 0,
        "chain_links": 0,
        "notes": "",
    }
    save_state(workdir, state)

    # Write seeds.md
    seeds_md = os.path.join(outdir, "seeds.md")
    with open(seeds_md, "w") as f:
        f.write(f"# OSINT Seeds — {target}\n\n")
        f.write(f"**Started:** {now}\n\n")
        f.write("## Identifiers\n\n")
        if names:
            f.write("**Names:**\n")
            for n in names:
                f.write(f"- {n}\n")
        if handles:
            f.write("\n**Handles:**\n")
            for h in handles:
                f.write(f"- {h}\n")
        if emails:
            f.write("\n**Emails:**\n")
            for e in emails:
                f.write(f"- {e}\n")
        if domains:
            f.write("\n**Domains:**\n")
            for d in domains:
                f.write(f"- {d}\n")
        if phones:
            f.write("\n**Phones:**\n")
            for p in phones:
                f.write(f"- {p}\n")
        if locations:
            f.write("\n**Locations:**\n")
            for loc in locations:
                f.write(f"- {loc}\n")

    print(f"✓ osint engagement initialized: {target}")
    print(f"  Seeds: {sum(len(v) for v in state['seeds'].values())} identifiers")
    print(f"  Output: {outdir}/")
    return state


def status(workdir):
    """Print engagement status."""
    state = read_state(workdir)
    if not state:
        print("No active osint engagement. Use init_state() to start.")
        return None

    eng = state["engagement"]
    phase = state["current_phase"]
    seeds = state.get("seeds", {})
    seed_count = sum(len(v) for v in seeds.values())

    print(f"\n─── osint status ───────────────────────────")
    print(f"  Target:     {eng['target']}")
    print(f"  Phase:      {phase} ({PHASES.get(phase, '?')})")
    print(f"  Seeds:      {seed_count} identifiers")
    print(f"  Platforms:  {state.get('platforms_checked', 0)} checked")
    print(f"  Findings:   {state.get('findings_count', 0)}")
    print(f"  Chains:     {state.get('chain_links', 0)} links")
    print(f"─────────────────────────────────────────────")
    return state


def advance_phase(workdir):
    """Advance to next phase."""
    state = read_state(workdir)
    if not state:
        print("No active engagement.")
        return None

    phase = state["current_phase"]
    if phase >= 7:
        print("Already at final phase.")
        return None

    now = datetime.now().isoformat()
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


def add_finding(workdir, platform, handle_or_data, source="public", confidence="high"):
    """Add a discovered identity finding."""
    state = read_state(workdir)
    if not state:
        return None

    state["findings_count"] = state.get("findings_count", 0) + 1
    state["platforms_checked"] = state.get("platforms_checked", 0) + 1
    save_state(workdir, state)

    print(f"✓ Finding #{state['findings_count']}: {platform} — {handle_or_data} "
          f"[{confidence}, {source}]")
    return state


def add_chain_link(workdir, from_id, to_id, link_type, strength="strong"):
    """Add a cross-reference chain link."""
    state = read_state(workdir)
    if not state:
        return None

    state["chain_links"] = state.get("chain_links", 0) + 1
    save_state(workdir, state)

    print(f"✓ Chain link #{state['chain_links']}: {from_id} —[{link_type}]→ {to_id} ({strength})")
    return state


def increment_platforms(workdir, count=1):
    """Increment platforms checked counter."""
    state = read_state(workdir)
    if not state:
        return None
    state["platforms_checked"] = state.get("platforms_checked", 0) + count
    save_state(workdir, state)
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
