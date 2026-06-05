#!/usr/bin/env python3
"""w3hunt Phase 3: Web Assessment — automated checks for DeFi frontend vulnerabilities.

Targets CSP bypass, CORS misconfiguration, source map leaks, wallet interaction flaws,
and DeFi-specific frontend attack patterns.

Usage:
    from phase3_web import run
    results = run(target="https://app.protocol.io", workdir="~/PenTest/Hunting/Immunefi/protocol")
"""
import json
import re
from hermes_tools import terminal, write_file


def _curl(url, method="GET", headers=None, body=None, timeout=10, include_headers=False):
    """Execute curl, return (status_code, body, resp_headers)."""
    cmd = f'curl -sk -w "\\n---CODE:%{{http_code}}---" -X {method} --max-time {timeout}'
    if include_headers:
        cmd += " -D /tmp/w3_headers.txt"
    if headers:
        for k, v in headers.items():
            cmd += f' -H "{k}: {v}"'
    if body:
        cmd += f" -d '{body}'"
    cmd += f' "{url}"'
    resp = terminal(cmd, timeout=timeout + 5)
    output = resp.get("output", "")
    code_match = re.search(r'---CODE:(\d+)---', output)
    code = code_match.group(1) if code_match else "000"
    body_text = re.sub(r'\n---CODE:\d+---$', '', output)
    resp_headers = ""
    if include_headers:
        h = terminal("cat /tmp/w3_headers.txt 2>/dev/null", timeout=3)
        resp_headers = h.get("output", "")
    return code, body_text, resp_headers


def check_csp_bypass(target):
    """Check CSP for stale/takeover-able domains."""
    findings = []
    code, body, headers = _curl(target, include_headers=True)

    csp_match = re.search(r'content-security-policy[^:]*:\s*([^\r\n]+)', headers, re.IGNORECASE)
    if not csp_match:
        findings.append({"type": "no_csp", "severity": "medium",
                         "detail": "No Content-Security-Policy header — XSS has no CSP mitigation"})
        print("  ⚠️  No CSP header")
        return findings

    csp = csp_match.group(1)

    # Extract script-src domains
    script_src = re.search(r"script-src\s+([^;]+)", csp)
    if script_src:
        domains = re.findall(r'https?://([a-zA-Z0-9._-]+)', script_src.group(1))
        if "'unsafe-inline'" in script_src.group(1):
            findings.append({"type": "csp_unsafe_inline", "severity": "medium",
                             "detail": "CSP allows 'unsafe-inline' in script-src"})
            print("  ⚠️  CSP has unsafe-inline")
        if "'unsafe-eval'" in script_src.group(1):
            findings.append({"type": "csp_unsafe_eval", "severity": "medium",
                             "detail": "CSP allows 'unsafe-eval' in script-src"})

        # Check each CSP domain for NXDOMAIN (takeover opportunity)
        for domain in set(domains):
            if any(x in domain for x in ["googleapis", "gstatic", "cloudflare", "unpkg", "jsdelivr"]):
                continue
            r = terminal(f'dig +short "{domain}" 2>/dev/null', timeout=5)
            if r.get("exit_code") == 0 and not r.get("output", "").strip():
                findings.append({"type": "csp_stale_domain", "severity": "critical",
                                 "domain": domain,
                                 "detail": f"CSP whitelists {domain} which resolves to NXDOMAIN — register for XSS"})
                print(f"  🔴 CRITICAL: CSP domain {domain} → NXDOMAIN (takeover → XSS on wallet app)")
    else:
        # No script-src means default-src applies
        if "'unsafe-inline'" in csp:
            findings.append({"type": "csp_unsafe_inline", "severity": "medium",
                             "detail": "CSP default-src allows 'unsafe-inline'"})

    return findings


def check_cors(target):
    """Check CORS for credential-stealing misconfiguration."""
    findings = []
    origins_to_test = [
        "https://evil.attacker.com",
        "https://app.protocol.io.evil.com",  # Subdomain confusion
        "null",
    ]

    for origin in origins_to_test:
        origin_header = origin if origin != "null" else "null"
        code, body, headers = _curl(target, headers={"Origin": origin_header}, include_headers=True)
        headers_lower = headers.lower()

        if f"access-control-allow-origin: {origin_header.lower()}" in headers_lower:
            if "access-control-allow-credentials: true" in headers_lower:
                findings.append({"type": "cors_credential_steal", "severity": "high",
                                 "origin": origin,
                                 "detail": f"Origin {origin} reflected with credentials — wallet session theft possible"})
                print(f"  🔴 HIGH: CORS reflects {origin} with credentials")
            else:
                findings.append({"type": "cors_reflection", "severity": "low",
                                 "origin": origin, "detail": f"Origin {origin} reflected (no credentials)"})

    return findings


def check_source_maps(target):
    """Check for exposed source maps (full frontend source code)."""
    findings = []
    code, html, _ = _curl(target)

    # Find JS bundles
    scripts = re.findall(r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', html)
    checked = 0

    for script_url in scripts[:15]:
        if script_url.startswith("//"):
            script_url = "https:" + script_url
        elif script_url.startswith("/"):
            script_url = target.rstrip("/") + script_url
        elif not script_url.startswith("http"):
            script_url = target.rstrip("/") + "/" + script_url

        if any(x in script_url for x in ["google", "facebook", "analytics", "gtag"]):
            continue

        map_url = script_url + ".map"
        code, map_body, _ = _curl(map_url)
        if code == "200" and "sourcesContent" in map_body:
            checked += 1
            findings.append({"type": "source_map_exposed", "severity": "high",
                             "url": map_url,
                             "detail": "Full source code exposed — may contain API keys, internal logic, wallet signing code"})
            print(f"  🔴 HIGH: Source map exposed: {map_url.split('/')[-1]}")

            # Extract secrets from source map
            try:
                map_data = json.loads(map_body)
                for content in map_data.get("sourcesContent", [])[:50]:
                    if content:
                        secrets = re.findall(r'(?:PRIVATE_KEY|SECRET|API_KEY|INFURA|ALCHEMY)["\s:=]+["\']([^"\']{10,})["\']', content, re.IGNORECASE)
                        if secrets:
                            findings.append({"type": "secret_in_source_map", "severity": "critical",
                                             "detail": f"Secret found in source map: {secrets[0][:30]}..."})
                            print(f"  🔴 CRITICAL: Secret in source map!")
                            break
            except json.JSONDecodeError:
                pass

    if not findings:
        print(f"  ✓ No source maps exposed ({len(scripts)} scripts checked)")
    return findings


def check_wallet_interaction(target):
    """Check for wallet interaction vulnerabilities in frontend code."""
    findings = []
    code, html, _ = _curl(target)

    # Fetch main JS bundle
    scripts = re.findall(r'src=["\']([^"\']*(?:main|app|index|bundle)[^"\']*\.js)["\']', html)
    js_content = ""
    for script_url in scripts[:3]:
        if script_url.startswith("/"):
            script_url = target.rstrip("/") + script_url
        _, js, _ = _curl(script_url)
        js_content += js

    if not js_content:
        # Try fetching all JS
        all_scripts = re.findall(r'src=["\']([^"\']*\.js)["\']', html)
        for s in all_scripts[:5]:
            if s.startswith("/"):
                s = target.rstrip("/") + s
            if "google" not in s and "analytics" not in s:
                _, js, _ = _curl(s)
                js_content += js

    if not js_content:
        print("  No JS content fetched")
        return findings

    # Check for dangerous patterns
    checks = [
        (r'eth_sign', "eth_sign_usage", "medium",
         "Uses eth_sign (signs arbitrary data — phishing risk if message is crafted by attacker)"),
        (r'signTypedData(?!_v4)', "sign_typed_data_old", "low",
         "Uses old signTypedData (v1/v3) — less secure than v4"),
        (r'permit\(|Permit\(|PERMIT_TYPEHASH', "permit_usage", "info",
         "Uses ERC-2612 permit — check if permit signatures can be replayed"),
        (r'approve\(\s*["\'][^"\']+["\']\s*,\s*["\']0xf{8,}', "infinite_approval", "medium",
         "Requests infinite token approval — user funds at risk if frontend compromised"),
        (r'eval\(|Function\(|innerHTML\s*=', "xss_sink", "medium",
         "XSS sink present (eval/Function/innerHTML) — exploitable if input reaches it"),
        (r'postMessage\(|addEventListener\(["\']message', "postmessage", "medium",
         "postMessage communication — check for origin validation"),
        (r'window\.ethereum|Web3Provider|JsonRpcProvider', "wallet_provider", "info",
         "Direct wallet provider interaction found"),
    ]

    for pattern, vuln_type, severity, detail in checks:
        if re.search(pattern, js_content):
            findings.append({"type": vuln_type, "severity": severity, "detail": detail})
            icon = "🔴" if severity in ("high", "critical") else "⚠️" if severity == "medium" else "ℹ️"
            print(f"  {icon} {detail[:80]}")

    # Check for hardcoded RPC endpoints (potential SSRF relay)
    rpc_urls = re.findall(r'https://[^"\']*(?:infura|alchemy|quicknode|ankr|rpc)[^"\']*', js_content)
    if rpc_urls:
        findings.append({"type": "rpc_endpoints", "severity": "info",
                         "urls": list(set(rpc_urls))[:5],
                         "detail": f"RPC endpoints found: {len(set(rpc_urls))}"})
        print(f"  ℹ️  {len(set(rpc_urls))} RPC endpoints found")

    return findings


def check_security_headers(target):
    """Check missing security headers critical for DeFi frontends."""
    findings = []
    _, _, headers = _curl(target, include_headers=True)
    headers_lower = headers.lower()

    required = [
        ("x-frame-options", "Clickjacking protection missing — attacker can iframe the dApp"),
        ("x-content-type-options", "MIME sniffing not prevented"),
        ("strict-transport-security", "No HSTS — downgrade attack possible"),
    ]

    for header, detail in required:
        if header not in headers_lower:
            sev = "high" if "frame" in header else "low"
            findings.append({"type": f"missing_{header.replace('-','_')}", "severity": sev, "detail": detail})
            if sev == "high":
                print(f"  🔴 {detail}")

    return findings


def run(target, workdir=".", output_dir=None):
    """
    Full Phase 3 web assessment for DeFi frontends.

    Args:
        target: Frontend URL (e.g., "https://app.protocol.io")
        workdir: Hunting working directory
        output_dir: Where to write results (default: {workdir}/phase3-web/)
    """
    if not output_dir:
        output_dir = f"{workdir}/phase3-web"

    target = target.rstrip("/")

    print("=" * 60)
    print("w3hunt Phase 3: Web Assessment")
    print(f"  Target: {target}")
    print("=" * 60)

    all_findings = []

    print("\n[1] CSP Analysis")
    all_findings.extend(check_csp_bypass(target))

    print("\n[2] CORS Check")
    all_findings.extend(check_cors(target))

    print("\n[3] Source Map Exposure")
    all_findings.extend(check_source_maps(target))

    print("\n[4] Wallet Interaction Analysis")
    all_findings.extend(check_wallet_interaction(target))

    print("\n[5] Security Headers")
    all_findings.extend(check_security_headers(target))

    # Summary
    print(f"\n{'='*60}")
    crits = [f for f in all_findings if f.get("severity") == "critical"]
    highs = [f for f in all_findings if f.get("severity") == "high"]
    meds = [f for f in all_findings if f.get("severity") == "medium"]
    print(f"RESULTS: {len(all_findings)} findings")
    print(f"  Critical: {len(crits)} | High: {len(highs)} | Medium: {len(meds)}")

    if crits:
        print(f"\n  CRITICAL FINDINGS (submit immediately):")
        for f in crits:
            print(f"    → {f['type']}: {f['detail'][:80]}")

    terminal(f"mkdir -p {output_dir}", timeout=5)
    write_file(f"{output_dir}/web-findings.json", json.dumps(all_findings, indent=2))
    print(f"\n  Output: {output_dir}/web-findings.json")

    return {"findings": all_findings, "crits": len(crits), "highs": len(highs)}


if __name__ == "__main__":
    pass
