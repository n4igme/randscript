#!/usr/bin/env python3
"""mtest Phase 4: Traffic Analysis — verify proxy, capture baseline, map API surface."""
import os, re

def run(workdir, package_id, proxy_host="127.0.0.1", proxy_port=8080, device_serial=None):
    """
    Args:
        workdir: engagement working directory
        package_id: app package ID
        proxy_host: proxy IP (Burp/Caido)
        proxy_port: proxy port
        device_serial: adb device serial (optional)
    """
    from hermes_tools import terminal, write_file

    outdir = os.path.join(workdir, "mtest-output/phase4-traffic")
    os.makedirs(outdir, exist_ok=True)
    adb = f"adb -s {device_serial}" if device_serial else "adb"

    results = {"proxy_ok": False, "endpoints": [], "auth_type": "unknown", "issues": []}

    # 1. Verify proxy is running
    print("[*] Verifying proxy...")
    r = terminal(f"curl -s -o /dev/null -w '%{{http_code}}' -x http://{proxy_host}:{proxy_port} http://example.com", timeout=10)
    if "200" in r["output"]:
        results["proxy_ok"] = True
        print(f"    ✓ Proxy active at {proxy_host}:{proxy_port}")
    else:
        print(f"    ✗ Proxy not responding at {proxy_host}:{proxy_port}")
        results["issues"].append("Proxy not running")

    # 2. Check device proxy settings
    print("[*] Checking device proxy config...")
    r = terminal(f"{adb} shell settings get global http_proxy")
    current_proxy = r["output"].strip()
    if f"{proxy_host}:{proxy_port}" in current_proxy or current_proxy == ":0":
        print(f"    Device proxy: {current_proxy or 'not set'}")
    else:
        print(f"    Device proxy: {current_proxy}")
        print(f"    Setting proxy to {proxy_host}:{proxy_port}...")
        terminal(f"{adb} shell settings put global http_proxy {proxy_host}:{proxy_port}")

    # 3. Check CA cert installed
    print("[*] Checking CA certificate...")
    r = terminal(f"{adb} shell ls /system/etc/security/cacerts/ 2>/dev/null | wc -l")
    cert_count = r["output"].strip()
    print(f"    System CA certs: {cert_count}")

    # 4. Check iptables for invisible proxy (Flutter/apps ignoring system proxy)
    print("[*] Checking iptables redirect rules...")
    r = terminal(f"{adb} shell su -c 'iptables -t nat -L OUTPUT 2>/dev/null' | grep -i dnat")
    if r["output"].strip():
        print(f"    iptables DNAT active: {r['output'].strip().split(chr(10))[0]}")
    else:
        print("    No iptables redirect (OK for native apps, needed for Flutter)")

    # 5. Analyze captured traffic (if Burp export exists)
    # Look for any exported requests in the traffic dir
    print("[*] Checking for captured traffic...")
    traffic_files = []
    for f in os.listdir(outdir):
        if f.endswith(('.xml', '.json', '.har', '.txt')):
            traffic_files.append(f)

    if traffic_files:
        print(f"    Found {len(traffic_files)} traffic files")
        # Parse HAR if available
        for tf in traffic_files:
            if tf.endswith('.har'):
                import json
                with open(os.path.join(outdir, tf)) as f:
                    try:
                        har = json.load(f)
                        entries = har.get("log", {}).get("entries", [])
                        for entry in entries:
                            url = entry.get("request", {}).get("url", "")
                            method = entry.get("request", {}).get("method", "")
                            if url:
                                results["endpoints"].append(f"{method} {url}")
                    except json.JSONDecodeError:
                        pass
    else:
        print("    No traffic captured yet — launch app and interact with all features")
        print("    Then export from Burp: Project > Save selected items")

    # 6. Cross-reference with static endpoints
    static_endpoints = os.path.join(workdir, "mtest-output/phase2-static/android/endpoints.txt")
    if os.path.isfile(static_endpoints):
        with open(static_endpoints) as f:
            static_eps = [l.strip() for l in f if l.strip()]
        print(f"\\n[*] Static endpoints to verify in traffic: {len(static_eps)}")
        # Extract base URLs
        base_urls = set()
        for ep in static_eps:
            match = re.match(r'(https?://[^/]+)', ep)
            if match:
                base_urls.add(match.group(1))
        if base_urls:
            print(f"    Base URLs to monitor:")
            for url in sorted(base_urls)[:10]:
                print(f"      {url}")
            write_file(os.path.join(outdir, "base-urls.txt"), "\\n".join(sorted(base_urls)))

    # Write setup report
    report = f"""# Traffic Analysis Setup

## Proxy
- Host: {proxy_host}:{proxy_port}
- Status: {'✓ Active' if results['proxy_ok'] else '✗ Not responding'}
- Device proxy: {current_proxy}

## Next Steps
1. Launch app with bypass scripts active
2. Complete full user journey (register/login → all features → logout)
3. Export captured requests from Burp/Caido
4. Save as HAR or XML to {outdir}/

## Endpoints to Watch
- Auth flow (login, OTP, token refresh)
- Financial operations (transfer, payment)
- Profile/PII endpoints
- File upload/download
- WebSocket connections
"""
    write_file(os.path.join(outdir, "setup-report.md"), report)

    # Summary
    print(f"\\n{'='*50}")
    print(f"Phase 4 Traffic Analysis:")
    print(f"  Proxy: {'✓' if results['proxy_ok'] else '✗'} {proxy_host}:{proxy_port}")
    print(f"  Captured endpoints: {len(results['endpoints'])}")
    if results["issues"]:
        print(f"  Issues: {', '.join(results['issues'])}")
    print(f"\\n  Gate: {'PASS ✓' if results['proxy_ok'] else 'BLOCKED — fix proxy first'}")

    return results


if __name__ == "__main__":
    pass
