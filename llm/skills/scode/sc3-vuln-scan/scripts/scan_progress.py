#!/usr/bin/env python3
"""Scanner progress tracker for sc3-vuln-scan. Tracks which scanners are done/pending/skipped."""
import os, yaml
from datetime import datetime

# Only scanners that have actual standalone SKILL.md skills
SCANNERS = [
    "injection", "access-control", "data-exposure", "ssrf", "deserialization",
    "misconfig", "logic", "authn-session", "crypto", "file-path",
    "client-side", "dependency", "api",
    "nodejs", "spring-boot", "custom-crypto", "mobile-code", "deployment-security",
    "web3-reentrancy", "web3-arithmetic", "web3-access", "web3-mev", "web3-token",
    "web3-defi", "web3-nft", "web3-evm", "web3-restaking", "web3-aa", "web3-l2", "web3-intents",
    "dos", "memory", "infra",
]

SKIP_RULES = {
    "web3": ["web3-reentrancy", "web3-arithmetic", "web3-access", "web3-mev",
             "web3-token", "web3-defi", "web3-nft", "web3-evm",
             "web3-restaking", "web3-aa", "web3-l2", "web3-intents"],
    "native": ["memory"],
    "infra": ["infra", "deployment-security"],
    "spring": ["spring-boot"],
    "nodejs": ["nodejs"],
    "mobile": ["mobile-code"],
}

STATE_FILE = "assessment/scan-state.yaml"


def _path(workdir):
    return os.path.join(workdir, STATE_FILE)


def load(workdir):
    p = _path(workdir)
    if not os.path.isfile(p):
        return None
    with open(p) as f:
        return yaml.safe_load(f)


def save(workdir, state):
    p = _path(workdir)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        yaml.dump(state, f, default_flow_style=False, sort_keys=False)


def init(workdir, has_web3=False, has_native=False, has_infra=True, has_spring=False, has_nodejs=True, has_mobile=False):
    """Initialize scanner progress. Call before running scanners."""
    progress = {}
    for s in SCANNERS:
        skip = False
        if not has_web3 and s in SKIP_RULES["web3"]:
            skip = True
        if not has_native and s in SKIP_RULES["native"]:
            skip = True
        if not has_infra and s in SKIP_RULES["infra"]:
            skip = True
        if not has_spring and s in SKIP_RULES["spring"]:
            skip = True
        if not has_nodejs and s in SKIP_RULES["nodejs"]:
            skip = True
        if not has_mobile and s in SKIP_RULES["mobile"]:
            skip = True
        progress[s] = "SKIPPED" if skip else "PENDING"

    state = {
        "started": datetime.now().isoformat(),
        "scanners": progress,
        "findings": 0,
    }
    save(workdir, state)

    pending = sum(1 for v in progress.values() if v == "PENDING")
    skipped = sum(1 for v in progress.values() if v == "SKIPPED")
    print(f"Scan initialized: {pending} scanners applicable, {skipped} skipped")
    return state


def done(workdir, scanner, findings=0):
    """Mark scanner as DONE."""
    state = load(workdir)
    if not state:
        print("No scan state. Run init() first.")
        return
    if scanner not in state["scanners"]:
        print(f"Unknown scanner: {scanner}")
        return
    state["scanners"][scanner] = f"DONE ({findings})"
    state["findings"] += findings
    save(workdir, state)

    total_pending = sum(1 for v in state["scanners"].values() if v == "PENDING")
    print(f"✓ {scanner}: {findings} findings. {total_pending} scanners remaining.")


def skip(workdir, scanner, reason="not applicable"):
    """Mark scanner as skipped."""
    state = load(workdir)
    if not state:
        return
    state["scanners"][scanner] = f"SKIPPED ({reason})"
    save(workdir, state)


def status(workdir):
    """Print scanner progress summary."""
    state = load(workdir)
    if not state:
        print("No scan state found.")
        return

    scanners = state["scanners"]
    done_list = [k for k, v in scanners.items() if v.startswith("DONE")]
    pending = [k for k, v in scanners.items() if v == "PENDING"]
    skipped = [k for k, v in scanners.items() if v.startswith("SKIPPED")]

    print(f"Scan Progress: {len(done_list)}/{len(done_list)+len(pending)} complete "
          f"({len(skipped)} skipped, {state['findings']} total findings)")

    if pending:
        print(f"  Next: {', '.join(pending[:5])}")
    else:
        print("  ✓ All scanners complete — ready for sc4-validate")


def next_scanner(workdir):
    """Return next pending scanner name, or None."""
    state = load(workdir)
    if not state:
        return None
    for s, v in state["scanners"].items():
        if v == "PENDING":
            return s
    return None
