#!/usr/bin/env python3
"""mtest Phase 3: Protection Assessment & Bypass — detect RASP, root detection, SSL pinning."""
import os

def run(workdir, package_id, device_serial=None):
    """
    Args:
        workdir: engagement working directory
        package_id: app package ID
        device_serial: adb device serial (optional)
    """
    from hermes_tools import terminal, write_file

    outdir = os.path.join(workdir, "mtest-output/phase3-protection")
    os.makedirs(os.path.join(outdir, "scripts"), exist_ok=True)
    adb = f"adb -s {device_serial}" if device_serial else "adb"

    results = {"protections": [], "bypassed": [], "failed": []}

    # 1. Detect protection mechanisms from static analysis
    print("[*] Detecting protection mechanisms...")
    jadx_dir = os.path.join(workdir, "mtest-output/phase2-static/android/jadx_out/sources")

    checks = {
        "root_detection": [
            "su", "Superuser", "magisk", "kernelsu", "RootBeer",
            "isRooted", "checkRoot", "detectRoot"
        ],
        "frida_detection": [
            "frida", "27042", "gum-js-loop", "LIBFRIDA",
            "frida-agent", "re.frida.server"
        ],
        "ssl_pinning": [
            "CertificatePinner", "X509TrustManager", "network_security_config",
            "ssl_pinning", "okhttp3.CertificatePinner", "TrustManagerImpl"
        ],
        "emulator_detection": [
            "isEmulator", "Build.FINGERPRINT", "generic",
            "google_sdk", "Genymotion"
        ],
        "tamper_detection": [
            "PackageManager.GET_SIGNATURES", "checkSignature",
            "integrity", "SafetyNet", "PlayIntegrity"
        ],
        "debug_detection": [
            "isDebuggerConnected", "TracerPid", "Debug.isDebugger"
        ],
    }

    for category, keywords in checks.items():
        pattern = "|".join(keywords)
        r = terminal(f"grep -rlE '{pattern}' {jadx_dir} 2>/dev/null | head -5")
        if r["output"].strip():
            results["protections"].append(category)
            count = len(r["output"].strip().split("\\n"))
            print(f"    [{category}] detected in {count} files")

    if not results["protections"]:
        print("    No protections detected — app is unprotected")
        write_file(os.path.join(outdir, "assessment.md"),
                   "# Protection Assessment\\n\\nNo client-side protections detected. Phase 3 N/A.")
        print("\\n  Gate: PASS (N/A — no protections)")
        return results

    # 2. Attempt SSL pinning bypass
    if "ssl_pinning" in results["protections"]:
        print("\\n[*] Testing SSL pinning bypass...")
        # Check if flutter
        flutter_check = terminal(f"ls {workdir}/mtest-output/phase2-static/android/flutter-api-paths.txt 2>/dev/null")
        is_flutter = bool(flutter_check["output"].strip())

        if is_flutter:
            print("    Flutter app — use flutter_ssl_bypass.js + iptables DNAT")
            results["bypassed"].append("ssl_pinning (flutter — needs flutter_ssl_bypass.js + iptables)")
        else:
            # Try launching with ssl bypass script
            script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ssl_pinning_bypass.js")
            if os.path.isfile(script_path):
                print(f"    Attempting bypass with ssl_pinning_bypass.js...")
                r = terminal(f"timeout 10 frida -U -f {package_id} -l {script_path} --no-pause 2>&1 | tail -10")
                if "Error" not in r["output"] and r["exit_code"] == 0:
                    results["bypassed"].append("ssl_pinning")
                    print("    ✓ SSL pinning bypass loaded successfully")
                else:
                    print(f"    ✗ Bypass failed: {r['output'].split(chr(10))[-1]}")
                    results["failed"].append("ssl_pinning")
            else:
                print(f"    Script not found: {script_path}")

    # 3. Attempt root detection bypass
    if "root_detection" in results["protections"]:
        print("\\n[*] Testing root detection bypass...")
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "root_bypass.js")
        if os.path.isfile(script_path):
            r = terminal(f"timeout 10 frida -U -f {package_id} -l {script_path} --no-pause 2>&1 | tail -10")
            if "Error" not in r["output"] and r["exit_code"] == 0:
                results["bypassed"].append("root_detection")
                print("    ✓ Root detection bypass loaded successfully")
            else:
                print(f"    ✗ Bypass failed: {r['output'].split(chr(10))[-1]}")
                results["failed"].append("root_detection")

    # 4. Combined launch test
    if results["bypassed"]:
        print("\\n[*] Testing combined bypass launch...")
        scripts = []
        for b in results["bypassed"]:
            if "ssl" in b:
                scripts.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "ssl_pinning_bypass.js"))
            if "root" in b:
                scripts.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "root_bypass.js"))

        load_args = " ".join(f"-l {s}" for s in scripts if os.path.isfile(s))
        r = terminal(f"timeout 15 frida -U -f {package_id} {load_args} --no-pause 2>&1 | tail -5")
        if r["exit_code"] == 0:
            print("    ✓ App launches with all bypasses active")
        else:
            print(f"    ⚠️  Combined launch issue: {r['output'].strip().split(chr(10))[-1]}")

    # Write assessment report
    report = "# Protection Assessment\\n\\n"
    report += "## Detected Protections\\n"
    for p in results["protections"]:
        status = "✓ bypassed" if p in results["bypassed"] else ("✗ failed" if p in results["failed"] else "⚠️ not tested")
        report += f"- {p}: {status}\\n"
    report += "\\n## Bypass Scripts Used\\n"
    report += "- ssl_pinning_bypass.js\\n- root_bypass.js\\n- flutter_ssl_bypass.js (if Flutter)\\n"
    if results["failed"]:
        report += "\\n## Failed Bypasses\\n"
        for f in results["failed"]:
            report += f"- {f}: needs manual investigation\\n"

    write_file(os.path.join(outdir, "assessment.md"), report)

    # Summary
    print(f"\\n{'='*50}")
    print(f"Phase 3 Protection Assessment:")
    print(f"  Detected: {', '.join(results['protections'])}")
    print(f"  Bypassed: {', '.join(results['bypassed']) or 'none'}")
    print(f"  Failed: {', '.join(results['failed']) or 'none'}")
    gate = len(results["failed"]) == 0
    print(f"\\n  Gate: {'PASS ✓' if gate else 'PARTIAL — some bypasses failed, may need manual work'}")

    return results


if __name__ == "__main__":
    pass
