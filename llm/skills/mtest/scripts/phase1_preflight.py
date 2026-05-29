#!/usr/bin/env python3
"""mtest Phase 1: Preflight — verify tools, create output structure, initialize state."""
import os, sys, yaml
from datetime import datetime

def run(workdir, target_apk, package_id, platform="android", engagement_name=""):
    """
    Args:
        workdir: engagement working directory
        target_apk: path to APK/IPA file
        package_id: app package ID (e.g., com.example.app)
        platform: android|ios|both
        engagement_name: human-readable name
    """
    from hermes_tools import terminal, write_file

    outdir = os.path.join(workdir, "mtest-output")
    os.makedirs(outdir, exist_ok=True)

    # Create subdirectories
    dirs = [
        "phase1-preflight", "phase2-static/android", "phase2-static/ios",
        "phase3-protection/scripts", "phase4-traffic",
        "phase5-attack-surface", "phase6-runtime/screenshots",
        "phase6-runtime/frida-output", "phase7-vuln-analysis/per-feature",
        "phase8-api", "phase9-exploitation/poc", "phase9-exploitation/evidence",
        "phase10-reporting", "findings"
    ]
    for d in dirs:
        os.makedirs(os.path.join(outdir, d), exist_ok=True)

    # Verify tools
    tools = {
        "jadx": "jadx --version 2>/dev/null || echo MISSING",
        "apktool": "apktool --version 2>/dev/null || echo MISSING",
        "frida": "frida --version 2>/dev/null || echo MISSING",
        "adb": "adb version 2>/dev/null | head -1 || echo MISSING",
        "objection": "objection version 2>/dev/null || echo MISSING",
    }

    results = {}
    missing = []
    for tool, cmd in tools.items():
        r = terminal(cmd)
        version = r["output"].strip().split("\\n")[0]
        if "MISSING" in version:
            missing.append(tool)
            results[tool] = "NOT FOUND"
        else:
            results[tool] = version

    # Check device
    device_check = terminal("adb devices | grep -v 'List' | grep -v '^$'")
    device = device_check["output"].strip()

    # Check target APK exists
    apk_exists = os.path.isfile(target_apk)

    # Create state.yaml
    now = datetime.now().isoformat()
    state = {
        "engagement": {
            "name": engagement_name or os.path.basename(workdir),
            "target_app": target_apk,
            "package_id": package_id,
            "bundle_id": "",
            "started": now,
            "platforms": [platform],
        },
        "gateways": {
            "1_preflight": "OPEN",
            "2_static_analysis": "LOCKED",
            "3_protection_bypass": "LOCKED",
            "4_traffic_analysis": "LOCKED",
            "5_attack_surface": "LOCKED",
            "6_runtime_testing": "LOCKED",
            "7_vulnerability_analysis": "LOCKED",
            "8_api_testing": "LOCKED",
            "9_exploitation": "LOCKED",
            "10_reporting": "LOCKED",
        },
        "findings_count": 0,
        "current_phase": 1,
        "time_tracking": {f"phase_{i}_start": "" for i in range(1, 11)},
        "notes": "",
    }
    state["time_tracking"].update({f"phase_{i}_end": "" for i in range(1, 11)})
    state["time_tracking"]["phase_1_start"] = now

    write_file(os.path.join(outdir, "state.yaml"), yaml.dump(state, default_flow_style=False))

    # Create scope.md
    scope = f"""# Engagement Scope

- **Target:** {engagement_name or package_id}
- **Package:** {package_id}
- **Platform:** {platform}
- **APK Path:** {target_apk}
- **Started:** {now}
- **Type:** grey-box (rooted device)

## Rules of Engagement
- Testing on personal rooted device only
- No production user data access
- Report all findings via internal process
"""
    write_file(os.path.join(outdir, "scope.md"), scope)

    # Tool verification report
    tool_report = "# Preflight Tool Verification\\n\\n"
    for tool, ver in results.items():
        status = "✓" if tool not in missing else "✗"
        tool_report += f"- [{status}] {tool}: {ver}\\n"
    tool_report += f"\\n## Device\\n{device or 'No device connected'}\\n"
    tool_report += f"\\n## Target APK\\n{'✓ Found' if apk_exists else '✗ NOT FOUND'}: {target_apk}\\n"

    write_file(os.path.join(outdir, "phase1-preflight/tool-verification.md"), tool_report)

    # Summary
    print(f"Phase 1 Preflight Complete:")
    print(f"  Output dir: {outdir}")
    print(f"  Target: {package_id} ({target_apk})")
    print(f"  Device: {device or 'NONE'}")
    print(f"  Tools OK: {len(results) - len(missing)}/{len(results)}")
    if missing:
        print(f"  Missing: {', '.join(missing)}")
    if not apk_exists:
        print(f"  ⚠️  APK not found at {target_apk}")
    print(f"  State: {outdir}/state.yaml")
    print(f"  Scope: {outdir}/scope.md")

    gate_pass = apk_exists and len(missing) <= 1 and device
    print(f"\\n  Gate: {'PASS ✓' if gate_pass else 'FAIL ✗ — fix issues above'}")
    return gate_pass


if __name__ == "__main__":
    # Usage: called via execute_code with args filled in
    pass
