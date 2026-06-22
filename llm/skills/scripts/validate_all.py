#!/usr/bin/env python3
"""Validate all security skill infrastructure: configs, scripts, schema, cross-refs."""
from __future__ import annotations

import os
import sys
import json
import re
import importlib
import importlib.util
from pathlib import Path

SECURITY_ROOT = Path(__file__).resolve().parent.parent
SKILLS_WITH_WRAPPERS = [
    'adtest', 'atest', 'ctest', 'intuition-engine', 'mtest',
    'opsec', 'osint', 'ptest', 'ptest-scan', 'retools',
    'scode', 'ttest', 'tyk-gateway-audit', 'w3hunt', 'xdev',
]

REQUIRED_FINDING_FIELDS = {'id', 'skill', 'severity', 'type', 'target', 'summary', 'timestamp', 'confidence'}


def check_configs() -> list:
    """Verify all skill configs have matching PHASES/GATEWAYS/SUBDIRS."""
    issues = []
    for skill in SKILLS_WITH_WRAPPERS:
        config_path = SECURITY_ROOT / skill / "scripts" / "config.py"
        if not config_path.exists():
            issues.append(f"{skill}: missing scripts/config.py")
            continue

        spec = importlib.util.spec_from_file_location("config", config_path)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception as e:
            issues.append(f"{skill}: config.py import error: {e}")
            continue

        cfg = mod.SKILL_CONFIG
        p = len(cfg.get('PHASES', {}))
        g = len(cfg.get('GATEWAYS', {}))
        s = len(cfg.get('SUBDIRS', []))

        if p != g:
            issues.append(f"{skill}: PHASES({p}) != GATEWAYS({g})")
        if p != s:
            issues.append(f"{skill}: PHASES({p}) != SUBDIRS({s})")
        if 'BUDGET_HOURS' not in cfg:
            issues.append(f"{skill}: missing BUDGET_HOURS")
        if 'OUTPUT_DIR' not in cfg:
            issues.append(f"{skill}: missing OUTPUT_DIR")

    return issues


def check_wrappers() -> list:
    """Verify state_manager.py and gate_check.py exist and import cleanly."""
    issues = []
    sys.path.insert(0, str(SECURITY_ROOT / "scripts"))

    for skill in SKILLS_WITH_WRAPPERS:
        scripts_dir = SECURITY_ROOT / skill / "scripts"
        for wrapper in ['state_manager.py', 'gate_check.py']:
            fpath = scripts_dir / wrapper
            if not fpath.exists():
                issues.append(f"{skill}: missing scripts/{wrapper}")
                continue

            # Test import
            spec = importlib.util.spec_from_file_location(
                f"{skill}_{wrapper}", fpath,
                submodule_search_locations=[str(scripts_dir)]
            )
            mod = importlib.util.module_from_spec(spec)
            try:
                old_path = sys.path[:]
                sys.path.insert(0, str(scripts_dir))
                spec.loader.exec_module(mod)
                sys.path[:] = old_path
            except Exception as e:
                issues.append(f"{skill}: {wrapper} import error: {e}")
                sys.path[:] = old_path

    return issues


def check_skill_md_sections() -> list:
    """Verify required sections exist in all SKILL.md files."""
    issues = []
    required = {
        'evidence-standards': 'evidence-standards',
        'severity-mapping': 'severity-mapping',
        'Postmortem': 'postmortem',
        'findings.jsonl': 'findings.jsonl',
    }

    for skill in SKILLS_WITH_WRAPPERS:
        skill_md = SECURITY_ROOT / skill / "SKILL.md"
        if not skill_md.exists():
            issues.append(f"{skill}: SKILL.md not found")
            continue

        content = skill_md.read_text()
        for label, pattern in required.items():
            if pattern.lower() not in content.lower():
                issues.append(f"{skill}: SKILL.md missing '{label}'")

        # Check for duplicate Avoid when
        if content.count('**Avoid when:**') > 1:
            issues.append(f"{skill}: duplicate '**Avoid when:**' blocks")

    return issues


def validate_findings_jsonl(path: Path) -> list:
    """Validate a findings.jsonl file against schema."""
    issues = []
    if not path.exists():
        return []

    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                issues.append(f"{path}:{lineno}: invalid JSON: {e}")
                continue

            missing = REQUIRED_FINDING_FIELDS - set(obj.keys())
            if missing:
                issues.append(f"{path}:{lineno}: missing fields: {missing}")

            # Validate severity
            if 'severity' in obj:
                valid_sev = {'critical', 'high', 'medium', 'low', 'info'}
                if obj['severity'].lower() not in valid_sev:
                    issues.append(f"{path}:{lineno}: invalid severity '{obj['severity']}'")

            # Validate confidence
            if 'confidence' in obj:
                valid_conf = {'confirmed', 'probable', 'theoretical'}
                conf = obj['confidence']
                if isinstance(conf, str) and conf.lower() not in valid_conf:
                    # Also allow numeric 0.0-1.0
                    try:
                        float(conf)
                    except ValueError:
                        issues.append(f"{path}:{lineno}: invalid confidence '{conf}'")

    return issues


def validate_state_yaml(path: Path) -> list:
    """Validate a state.yaml against expected schema."""
    import yaml
    issues = []
    if not path.exists():
        return []

    try:
        with open(path) as f:
            state = yaml.safe_load(f)
    except Exception as e:
        return [f"{path}: YAML parse error: {e}"]

    if not isinstance(state, dict):
        return [f"{path}: root is not a dict"]

    # Required top-level keys
    required_keys = {'engagement', 'gateways', 'findings_count'}
    missing = required_keys - set(state.keys())
    if missing:
        issues.append(f"{path}: missing keys: {missing}")

    # Validate engagement
    eng = state.get('engagement', {})
    if not isinstance(eng, dict):
        issues.append(f"{path}: engagement is not a dict")
    elif 'name' not in eng:
        issues.append(f"{path}: engagement.name missing")

    # Validate gateways
    gw = state.get('gateways', {})
    if isinstance(gw, dict):
        valid_states = {'OPEN', 'LOCKED', 'PASSED', 'ABORTED', 'N/A', 'ABANDONED'}
        for key, val in gw.items():
            if val not in valid_states:
                issues.append(f"{path}: gateway '{key}' has invalid state '{val}'")

    # Validate current_phase
    if 'current_phase' in state:
        cp = state['current_phase']
        if not isinstance(cp, int) or cp < 1:
            issues.append(f"{path}: current_phase must be int >= 1, got {cp}")

    return issues


def run_cross_refs() -> list:
    """Run check_cross_refs.py and capture issues."""
    import subprocess
    result = subprocess.run(
        [sys.executable, str(SECURITY_ROOT / "scripts" / "check_cross_refs.py")],
        capture_output=True, text=True
    )
    if 'FAIL' in result.stdout:
        return [line.strip() for line in result.stdout.split('\n')
                if line.strip().startswith(('INVALID:', '  '))]
    return []


def main():
    print("=" * 60)
    print("Security Skills — Full Validation Suite")
    print("=" * 60)

    all_issues = []

    # 1. Config validation
    print("\n[1/5] Checking configs...")
    issues = check_configs()
    all_issues.extend(issues)
    print(f"  {'PASS' if not issues else 'FAIL'}: {len(issues)} issue(s)")
    for i in issues:
        print(f"    - {i}")

    # 2. Wrapper imports
    print("\n[2/5] Checking wrapper imports...")
    issues = check_wrappers()
    all_issues.extend(issues)
    print(f"  {'PASS' if not issues else 'FAIL'}: {len(issues)} issue(s)")
    for i in issues:
        print(f"    - {i}")

    # 3. SKILL.md sections
    print("\n[3/5] Checking SKILL.md required sections...")
    issues = check_skill_md_sections()
    all_issues.extend(issues)
    print(f"  {'PASS' if not issues else 'FAIL'}: {len(issues)} issue(s)")
    for i in issues:
        print(f"    - {i}")

    # 4. Cross-references
    print("\n[4/5] Checking cross-references...")
    issues = run_cross_refs()
    all_issues.extend(issues)
    print(f"  {'PASS' if not issues else 'FAIL'}: {len(issues)} issue(s)")
    for i in issues:
        print(f"    - {i}")

    # 5. Scan for any existing findings.jsonl and validate
    print("\n[5/5] Validating existing findings.jsonl files...")
    jsonl_files = list(SECURITY_ROOT.rglob("findings.jsonl"))
    issues = []
    for jf in jsonl_files:
        issues.extend(validate_findings_jsonl(jf))
    all_issues.extend(issues)
    if jsonl_files:
        print(f"  Found {len(jsonl_files)} file(s), {'PASS' if not issues else 'FAIL'}: {len(issues)} issue(s)")
    else:
        print("  No findings.jsonl files found (OK — none created yet)")

    # Summary
    print("\n" + "=" * 60)
    total = len(all_issues)
    print(f"{'PASS' if total == 0 else 'FAIL'}: {total} total issue(s)")
    print("=" * 60)
    return 1 if total > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
