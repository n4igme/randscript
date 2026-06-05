#!/usr/bin/env python3
"""osint gate_check — verify phase deliverables before advancement."""
import os
import yaml


PHASE_GATES = {
    1: {
        "name": "Seed Collection",
        "checks": ["has_seeds"],
    },
    2: {
        "name": "Handle Correlation",
        "checks": ["platforms_checked"],
    },
    3: {
        "name": "Email Discovery",
        "checks": ["emails_searched"],
    },
    4: {
        "name": "Domain Recon",
        "checks": ["domains_checked"],
    },
    5: {
        "name": "Social Media",
        "checks": ["social_checked"],
    },
    6: {
        "name": "Breach Checks",
        "checks": ["breaches_checked"],
    },
    7: {
        "name": "Chain & Report",
        "checks": ["report_exists"],
    },
}


def check_gate(workdir, phase=None):
    """Verify phase gate. Returns {passed, phase, name, met, unmet, warnings}."""
    state_path = os.path.join(workdir, "osint-output", "state.yaml")

    if not os.path.exists(state_path):
        return {"passed": False, "phase": 0, "name": "", "met": [], "unmet": ["osint-output/state.yaml not found"], "warnings": []}

    with open(state_path) as f:
        state = yaml.safe_load(f)

    if phase is None:
        phase = state.get("current_phase", 1)

    gate = PHASE_GATES.get(phase)
    if not gate:
        return {"passed": False, "phase": phase, "name": "", "met": [], "unmet": [f"Unknown phase {phase}"], "warnings": []}

    met, unmet, warnings = [], [], []
    checks = gate.get("checks", [])
    outdir = os.path.join(workdir, "osint-output")

    if "has_seeds" in checks:
        seeds = state.get("seeds", {})
        total = sum(len(v) for v in seeds.values() if isinstance(v, list))
        if total >= 1:
            met.append(f"Seeds collected: {total} identifiers")
        else:
            unmet.append("No seeds — need at least 1 unique identifier")

        # Check for uniqueness (common name alone is insufficient)
        has_unique = (len(seeds.get("handles", [])) > 0 or
                      len(seeds.get("emails", [])) > 0 or
                      len(seeds.get("domains", [])) > 0 or
                      len(seeds.get("phones", [])) > 0)
        if not has_unique and len(seeds.get("names", [])) > 0:
            warnings.append("Only names as seeds — common names produce false positives. Add a handle/email/domain.")

    if "platforms_checked" in checks:
        platforms = state.get("platforms_checked", 0)
        if platforms >= 3:
            met.append(f"Platforms checked: {platforms} (min: 3)")
        else:
            unmet.append(f"Only {platforms} platforms checked (need ≥3)")

        handles_file = os.path.join(outdir, "handles.md")
        if os.path.exists(handles_file) and os.path.getsize(handles_file) > 30:
            met.append("handles.md documented")
        else:
            unmet.append("handles.md missing or empty")

    if "emails_searched" in checks:
        emails_file = os.path.join(outdir, "emails.md")
        if os.path.exists(emails_file) and os.path.getsize(emails_file) > 30:
            met.append("emails.md documented")
        else:
            unmet.append("emails.md missing or empty — run git commit mining + domain patterns")

    if "domains_checked" in checks:
        domains_file = os.path.join(outdir, "domains.md")
        seeds = state.get("seeds", {})
        if not seeds.get("domains"):
            met.append("No domains in seeds — Phase 4 trivially passed")
        elif os.path.exists(domains_file) and os.path.getsize(domains_file) > 30:
            met.append("domains.md documented")
        else:
            unmet.append("domains.md missing — run DNS/WHOIS/crt.sh on known domains")

    if "social_checked" in checks:
        social_file = os.path.join(outdir, "social.md")
        if os.path.exists(social_file) and os.path.getsize(social_file) > 30:
            met.append("social.md documented")
        else:
            unmet.append("social.md missing — check bot-friendly platforms")

    if "breaches_checked" in checks:
        breaches_file = os.path.join(outdir, "breaches.md")
        if os.path.exists(breaches_file) and os.path.getsize(breaches_file) > 30:
            met.append("breaches.md documented")
        else:
            unmet.append("breaches.md missing — run HIBP/breach checks on discovered emails")

    if "report_exists" in checks:
        report_file = os.path.join(outdir, "report.md")
        chain_file = os.path.join(outdir, "chain-map.md")
        if os.path.exists(chain_file) and os.path.getsize(chain_file) > 30:
            met.append("chain-map.md exists")
        else:
            unmet.append("chain-map.md missing — build cross-reference chain")
        if os.path.exists(report_file) and os.path.getsize(report_file) > 50:
            met.append("report.md exists")
        else:
            unmet.append("report.md missing — compile final report")

    # Staleness warning
    started = state.get("engagement", {}).get("started", "")
    if started:
        try:
            from datetime import datetime, timezone
            start_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            days = (now - start_dt).days
            if days > 7:
                warnings.append(f"Started {days} days ago — profiles may have changed, verify findings")
        except (ValueError, TypeError):
            pass

    passed = len(unmet) == 0
    return {"passed": passed, "phase": phase, "name": gate["name"], "met": met, "unmet": unmet, "warnings": warnings}


def print_gate_status(result):
    """Pretty-print gate check."""
    icon = "✅" if result["passed"] else "❌"
    print(f"\n{icon} Phase {result['phase']} ({result.get('name', '')}) Gate Check")
    print("=" * 50)
    if result["met"]:
        for m in result["met"]:
            print(f"  ✓ {m}")
    if result["unmet"]:
        print("  Blocking:")
        for u in result["unmet"]:
            print(f"  ✗ {u}")
    if result["warnings"]:
        for w in result["warnings"]:
            print(f"  ⚠ {w}")
    return result["passed"]


if __name__ == "__main__":
    import sys
    workdir = sys.argv[1] if len(sys.argv) > 1 else "."
    phase = int(sys.argv[2]) if len(sys.argv) > 2 else None
    result = check_gate(workdir, phase)
    print_gate_status(result)
    sys.exit(0 if result["passed"] else 1)
