#!/usr/bin/env python3
"""retools gate_check — thin wrapper over base_gate."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
from base_gate import BaseGateChecker, print_gate_status as _print_gate_status
from config import SKILL_CONFIG

checker = BaseGateChecker(
    output_dir=SKILL_CONFIG["OUTPUT_DIR"],
    phase_gates={
        1: {"name": "Phase 1: Triage", "dir": SKILL_CONFIG['SUBDIRS'][0], "required_files": []},
    },
)

def check_gate(workdir, phase=None):
    return checker.check_gate(workdir, phase)

def print_gate_status(result):
    return _print_gate_status(result)
