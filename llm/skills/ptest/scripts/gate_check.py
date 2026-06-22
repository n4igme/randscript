#!/usr/bin/env python3
"""ptest gate_check — thin wrapper over base_gate."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
from base_gate import BaseGateChecker, print_gate_status as _print_gate_status
from config import SKILL_CONFIG

checker = BaseGateChecker(
    output_dir=SKILL_CONFIG["OUTPUT_DIR"],
    phase_gates={
        1: {"name": "Phase 1: Passive Recon", "dir": SKILL_CONFIG['SUBDIRS'][0], "required_files": []},
        2: {"name": "Phase 2: Active Recon", "dir": SKILL_CONFIG['SUBDIRS'][1], "required_files": []},
        3: {"name": "Phase 3: Enumerate & Confirm", "dir": SKILL_CONFIG['SUBDIRS'][2], "required_files": []},
        4: {"name": "Phase 4: Assess & Exploit", "dir": SKILL_CONFIG['SUBDIRS'][3], "required_files": []},
        5: {"name": "Phase 5: Post-Exploit & Impact", "dir": SKILL_CONFIG['SUBDIRS'][4], "required_files": []},
        6: {"name": "Phase 6: Report", "dir": SKILL_CONFIG['SUBDIRS'][5], "required_files": []},
    },
)

def check_gate(workdir, phase=None):
    return checker.check_gate(workdir, phase)

def print_gate_status(result):
    return _print_gate_status(result)
