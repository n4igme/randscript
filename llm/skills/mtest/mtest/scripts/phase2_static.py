#!/usr/bin/env python3
"""mtest Phase 2: Static Analysis — decompile, framework detection, secrets, endpoints."""
import os, re

def run(workdir, target_apk, package_id):
    """
    Args:
        workdir: engagement working directory (contains mtest-output/)
        target_apk: path to APK file
        package_id: app package ID
    """
    from hermes_tools import terminal, write_file

    outdir = os.path.join(workdir, "mtest-output/phase2-static/android")
    os.makedirs(outdir, exist_ok=True)

    results = {"framework": "native", "secrets": [], "endpoints": [], "components": {}}

    # 1. Decompile
    jadx_out = os.path.join(outdir, "jadx_out")
    if not os.path.isdir(jadx_out):
        print("[*] Decompiling with jadx...")
        r = terminal(f"jadx -d {jadx_out} {target_apk} 2>&1 | tail -5", timeout=300)
        print(f"    {r['output'].strip().split(chr(10))[-1]}")
    else:
        print("[*] jadx_out exists, skipping decompile")

    # 2. Framework detection
    print("[*] Detecting framework...")
    r = terminal(f"unzip -l {target_apk} 2>/dev/null")
    apk_contents = r["output"]

    if "libflutter.so" in apk_contents or "libapp.so" in apk_contents:
        results["framework"] = "flutter"
    elif "index.android.bundle" in apk_contents or "libhermes.so" in apk_contents:
        results["framework"] = "react_native"
    elif "libil2cpp.so" in apk_contents:
        results["framework"] = "unity_il2cpp"
    elif re.search(r"assemblies/.*\\.dll|libmonodroid", apk_contents):
        results["framework"] = "xamarin"

    print(f"    Framework: {results['framework']}")

    # 3. Manifest analysis
    print("[*] Analyzing manifest...")
    manifest_path = os.path.join(jadx_out, "resources/AndroidManifest.xml")
    if os.path.isfile(manifest_path):
        with open(manifest_path) as f:
            manifest = f.read()

        # Exported components
        exported = re.findall(r'android:name="([^"]+)"[^>]*android:exported="true"', manifest)
        # Debuggable
        debuggable = 'android:debuggable="true"' in manifest
        # AllowBackup
        allow_backup = 'android:allowBackup="true"' in manifest or 'android:allowBackup' not in manifest
        # Deep links
        deeplinks = re.findall(r'android:scheme="([^"]+)"', manifest)
        # Permissions
        permissions = re.findall(r'<uses-permission android:name="([^"]+)"', manifest)
        has_internet = "android.permission.INTERNET" in permissions

        results["components"] = {
            "exported": exported[:20],
            "debuggable": debuggable,
            "allow_backup": allow_backup,
            "deeplinks": list(set(deeplinks)),
            "has_internet": has_internet,
            "permissions_count": len(permissions),
        }

        manifest_report = f"# Manifest Analysis\\n\\n"
        manifest_report += f"- Debuggable: {debuggable}\\n"
        manifest_report += f"- AllowBackup: {allow_backup}\\n"
        manifest_report += f"- Internet permission: {has_internet}\\n"
        manifest_report += f"- Permissions: {len(permissions)}\\n"
        manifest_report += f"- Exported components: {len(exported)}\\n"
        for c in exported[:20]:
            manifest_report += f"  - {c}\\n"
        manifest_report += f"- Deep link schemes: {', '.join(set(deeplinks)) or 'none'}\\n"
        write_file(os.path.join(outdir, "manifest-analysis.md"), manifest_report)
    else:
        print("    ⚠️  Manifest not found in jadx output")

    # 4. Secrets scan
    print("[*] Scanning for secrets...")
    patterns = [
        r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*.",
        r"(?i)(password|passwd|pwd)\s*[=:]\s*.",
        r"(?i)firebase[a-z]*\s*[=:]\s*.",
        r"AIza[0-9A-Za-z_-]{35}",
        r"(?i)aws[_-]?(access|secret)[_-]?key[_-]?id?\s*[=:]\s*.",
        r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    ]

    secrets_cmd = "grep -rnE '{}' {} 2>/dev/null | head -100".format(
        '|'.join(patterns),
        os.path.join(jadx_out, "sources/")
    )
    r = terminal(secrets_cmd, timeout=60)
    secrets_raw = r["output"].strip()

    if secrets_raw:
        results["secrets"] = secrets_raw.split("\\n")[:50]
        write_file(os.path.join(outdir, "secrets.txt"), secrets_raw)
        print(f"    Found {len(results['secrets'])} potential secrets")
    else:
        print("    No secrets found")
        write_file(os.path.join(outdir, "secrets.txt"), "# No secrets found")

    # 5. Endpoint extraction
    print("[*] Extracting endpoints...")
    grep_pattern = 'https?://[^\"<> ]*'
    r = terminal(f"grep -rohE '{grep_pattern}' {jadx_out}/sources/ 2>/dev/null | sort -u", timeout=60)
    endpoints = [e for e in r["output"].strip().split("\\n") if e and not e.startswith("http://schemas")]
    results["endpoints"] = endpoints

    write_file(os.path.join(outdir, "endpoints.txt"), "\\n".join(endpoints))
    print(f"    Found {len(endpoints)} unique endpoints")

    # 6. Flutter-specific: extract strings from libapp.so
    if results["framework"] == "flutter":
        print("[*] Flutter detected — extracting libapp.so strings...")
        r = terminal(f"unzip -o {target_apk} 'lib/arm64-v8a/libapp.so' -d /tmp/flutter_extract 2>/dev/null")
        libapp = "/tmp/flutter_extract/lib/arm64-v8a/libapp.so"
        if os.path.isfile(libapp):
            r = terminal(f"strings {libapp} | grep -E '^/(api|auth|account|user|v[0-9])' | sort -u")
            flutter_paths = r["output"].strip()
            write_file(os.path.join(outdir, "flutter-api-paths.txt"), flutter_paths)
            print(f"    Flutter API paths: {len(flutter_paths.splitlines())} found")

            r = terminal(f"strings {libapp} | grep -oE 'https?://[^ ]+' | sort -u")
            flutter_urls = r["output"].strip()
            write_file(os.path.join(outdir, "flutter-urls.txt"), flutter_urls)
            print(f"    Flutter URLs: {len(flutter_urls.splitlines())} found")

    # 7. Offline app detection
    if not results["components"].get("has_internet", True) and len(endpoints) < 3:
        print("\\n  ⚠️  OFFLINE APP DETECTED — Phase 4 & 8 will be N/A")
        results["offline"] = True

    # Summary
    print(f"\\n{'='*50}")
    print(f"Phase 2 Static Analysis Summary:")
    print(f"  Framework: {results['framework']}")
    print(f"  Secrets: {len(results['secrets'])} potential")
    print(f"  Endpoints: {len(results['endpoints'])} unique")
    print(f"  Exported components: {len(results['components'].get('exported', []))}")
    print(f"  Deep links: {', '.join(results['components'].get('deeplinks', [])) or 'none'}")
    print(f"  Debuggable: {results['components'].get('debuggable', 'unknown')}")
    print(f"  AllowBackup: {results['components'].get('allow_backup', 'unknown')}")
    if results.get("offline"):
        print(f"  ⚠️  Offline app — no network traffic expected")
    print(f"\\n  Output: {outdir}/")
    print(f"  Gate: PASS ✓" if results["endpoints"] or results["framework"] != "native" else "  Gate: needs manual review")

    return results


if __name__ == "__main__":
    pass
