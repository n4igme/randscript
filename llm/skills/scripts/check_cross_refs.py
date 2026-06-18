#!/usr/bin/env python3
"""Cross-skill reference integrity checker.

Validates that phase numbers referenced in cross-skill trigger tables
match the actual phase structure of the target skill.
"""

import re
import sys
from pathlib import Path

SECURITY_ROOT = Path(__file__).resolve().parent.parent
SKILLS = [d.name for d in SECURITY_ROOT.iterdir()
          if d.is_dir() and (d / "SKILL.md").exists()]


def extract_phase_count(skill_name: str) -> dict:
    skill_file = SECURITY_ROOT / skill_name / "SKILL.md"
    if not skill_file.exists():
        return {"phases": None, "error": "SKILL.md not found"}

    text = skill_file.read_text()
    # Only match phase numbers in gateway keys (e.g., "3_emails: LOCKED")
    # or explicit "Phase N" preceded by word boundary (not port numbers)
    gateway_nums = re.findall(r'^\s+(\d+)_\w+:\s+(?:OPEN|LOCKED|PASSED|N/A)', text, re.MULTILINE)
    if gateway_nums:
        return {"phases": max(int(n) for n in gateway_nums), "error": None}

    # Fallback: match "Phase N" in markdown headers or table cells only
    header_nums = re.findall(r'(?:^#+\s.*Phase\s+|^\|\s*(?:\*\*)?)\s*(\d+)\b', text, re.MULTILINE)
    if header_nums:
        return {"phases": max(int(n) for n in header_nums), "error": None}

    # Last resort: "Step N" in headers
    step_nums = re.findall(r'^#+\s.*Step\s+(\d+)', text, re.MULTILINE)
    if step_nums:
        return {"phases": max(int(n) for n in step_nums), "error": None}

    return {"phases": None, "error": "no phase/step numbers found"}


def extract_cross_refs(skill_name: str) -> list:
    skill_file = SECURITY_ROOT / skill_name / "SKILL.md"
    if not skill_file.exists():
        return []

    text = skill_file.read_text()
    refs = []

    for match in re.finditer(r'(\w+)\s+Phase\s+(\d+)', text):
        target_skill = match.group(1).lower()
        phase_num = int(match.group(2))
        if target_skill in SKILLS and target_skill != skill_name:
            refs.append({
                "source": skill_name,
                "target": target_skill,
                "phase": phase_num,
                "context": text[max(0, match.start()-30):match.end()+30].strip()
            })

    return refs


def check_reference_files(skill_name: str) -> list:
    skill_file = SECURITY_ROOT / skill_name / "SKILL.md"
    if not skill_file.exists():
        return []

    text = skill_file.read_text()
    issues = []

    for match in re.finditer(r'`(references/[\w\-]+\.md)`', text):
        ref_path = SECURITY_ROOT / skill_name / match.group(1)
        if not ref_path.exists():
            issues.append(f"  {skill_name}: missing {match.group(1)}")

    for match in re.finditer(r'`(scripts/[\w\-]+\.py)`', text):
        script_path = SECURITY_ROOT / skill_name / match.group(1)
        if not script_path.exists():
            issues.append(f"  {skill_name}: missing {match.group(1)}")

    return issues


def main():
    print(f"Checking {len(SKILLS)} skills: {', '.join(sorted(SKILLS))}\n")

    phase_counts = {}
    for skill in SKILLS:
        result = extract_phase_count(skill)
        phase_counts[skill] = result["phases"]
        if result["error"]:
            print(f"  WARN: {skill} — {result['error']}")

    print("\nPhase counts:")
    for skill in sorted(SKILLS):
        count = phase_counts[skill]
        print(f"  {skill}: {count or '?'} phases")

    print("\nCross-reference checks:")
    issues = []
    for skill in sorted(SKILLS):
        refs = extract_cross_refs(skill)
        for ref in refs:
            max_phase = phase_counts.get(ref["target"])
            if max_phase and ref["phase"] > max_phase:
                issues.append(
                    f"  INVALID: {ref['source']} references "
                    f"{ref['target']} Phase {ref['phase']} "
                    f"(max is {max_phase})"
                )

    if issues:
        for issue in issues:
            print(issue)
    else:
        print("  All cross-skill phase references are valid.")

    print("\nMissing reference/script files:")
    missing = []
    for skill in sorted(SKILLS):
        missing.extend(check_reference_files(skill))

    if missing:
        for m in missing:
            print(m)
    else:
        print("  All referenced files exist.")

    total_issues = len(issues) + len(missing)
    print(f"\n{'PASS' if total_issues == 0 else 'FAIL'}: "
          f"{total_issues} issue(s) found.")
    return 1 if total_issues > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
