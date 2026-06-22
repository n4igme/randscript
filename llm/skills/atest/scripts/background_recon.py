#!/usr/bin/env python3
"""
Background Recon Scripts for atest/ptest.
Fire these during Phase 1 exit, harvest results in Phase 2/3 entry.

Usage (from execute_code):
    from hermes_tools import terminal
    # Start in background:
    terminal("python3 ~/.hermes/skills/security/ptest/scripts/background_recon.py "
             "--mode auth-diff --base-url https://api.target.com "
             "--endpoints /tmp/endpoints.txt "
             "--token-a 'eyJ...' --token-b 'eyJ...' "
             "--output /tmp/recon-results/auth-diff.json",
             background=True, notify_on_complete=True)
"""

import argparse
import json
import subprocess
import sys
import os
import time
from urllib.parse import urljoin


def curl_request(url, method="GET", headers=None, body=None, timeout=10):
    """Execute curl and return status_code + response body."""
    cmd = ["curl", "-sk", "-o", "-", "-w", "\n__STATUS__%{http_code}",
           "-X", method, "--max-time", str(timeout)]
    if headers:
        for h in headers:
            cmd += ["-H", h]
    if body:
        cmd += ["-d", body]
    cmd.append(url)

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+5)
        output = r.stdout
        if "__STATUS__" in output:
            parts = output.rsplit("__STATUS__", 1)
            body_text = parts[0].strip()
            status = int(parts[1].strip())
            return status, body_text
        return 0, ""
    except (subprocess.TimeoutExpired, Exception):
        return 0, ""


def load_endpoints(filepath):
    """Load endpoints from file (one per line: METHOD /path)."""
    endpoints = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                endpoints.append({"method": parts[0], "path": parts[1]})
            elif len(parts) == 1:
                endpoints.append({"method": "GET", "path": parts[0]})
    return endpoints


def auth_diff(base_url, endpoints, token_a, token_b=None, output_path=None):
    """
    Compare responses across auth levels.
    Flags: unauth access, BOLA candidates, data exposure.
    """
    results = {"bola_candidates": [], "unauth_access": [], "data_exposure": []}

    for ep in endpoints:
        url = urljoin(base_url, ep["path"])
        method = ep["method"]

        # Authenticated request (token A)
        s1, b1 = curl_request(url, method, [f"Authorization: Bearer {token_a}"])

        # Unauthenticated request
        s2, b2 = curl_request(url, method)

        # If token_b provided, test cross-user
        s3, b3 = (0, "")
        if token_b:
            s3, b3 = curl_request(url, method, [f"Authorization: Bearer {token_b}"])

        # Analysis
        if s2 == 200 and s1 == 200:
            results["unauth_access"].append({
                "endpoint": f"{method} {ep['path']}",
                "auth_status": s1, "unauth_status": s2,
                "size_diff": len(b1) - len(b2)
            })

        if token_b and s3 == 200 and s1 == 200 and len(b3) > 50:
            results["bola_candidates"].append({
                "endpoint": f"{method} {ep['path']}",
                "user_a_size": len(b1), "user_b_size": len(b3),
                "bodies_match": b1 == b3
            })

        if s1 == 200 and len(b1) > len(b2) + 100:
            results["data_exposure"].append({
                "endpoint": f"{method} {ep['path']}",
                "auth_size": len(b1), "unauth_size": len(b2),
                "extra_bytes": len(b1) - len(b2)
            })

        time.sleep(0.3)  # Rate limiting courtesy

    results["summary"] = {
        "total_tested": len(endpoints),
        "unauth_access": len(results["unauth_access"]),
        "bola_candidates": len(results["bola_candidates"]),
        "data_exposure": len(results["data_exposure"])
    }

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)

    return results


def param_pollution(base_url, endpoints, token, output_path=None):
    """
    Test parameter pollution on ID-bearing endpoints.
    Tests: array wrapping, negative, zero, MAX_INT, comma-separated.
    """
    results = {"anomalies": []}
    payloads = {
        "array": lambda v: f"{v}[]={v}&{v}[]=2",
        "negative": "-1",
        "zero": "0",
        "max_int": "2147483647",
        "comma": "1,2,3",
    }

    for ep in endpoints:
        if "{" not in ep["path"] and "id" not in ep["path"].lower():
            continue

        for name, payload in payloads.items():
            test_path = ep["path"]
            # Replace path params with payload
            if "{" in test_path:
                import re
                test_path = re.sub(r'\{[^}]+\}', str(payload) if not callable(payload) else "1", test_path)

            url = urljoin(base_url, test_path)
            headers = [f"Authorization: Bearer {token}"]
            status, body = curl_request(url, ep["method"], headers)

            if status in (200, 201) and len(body) > 10:
                results["anomalies"].append({
                    "endpoint": f"{ep['method']} {ep['path']}",
                    "payload_type": name,
                    "status": status,
                    "response_size": len(body)
                })
            time.sleep(0.2)

    results["summary"] = {"total_anomalies": len(results["anomalies"])}

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
    return results


def header_injection(base_url, endpoints, token, output_path=None):
    """
    Test header injection for auth bypass / IP spoofing.
    """
    results = {"bypasses": []}
    inject_headers = [
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Real-IP", "127.0.0.1"),
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
        ("X-Forwarded-Host", "localhost"),
        ("X-Custom-IP-Authorization", "127.0.0.1"),
    ]

    for ep in endpoints:
        url = urljoin(base_url, ep["path"])
        # Baseline (no extra headers)
        base_status, base_body = curl_request(url, ep["method"],
                                              [f"Authorization: Bearer {token}"])

        for hdr_name, hdr_val in inject_headers:
            status, body = curl_request(url, ep["method"],
                                        [f"Authorization: Bearer {token}",
                                         f"{hdr_name}: {hdr_val}"])

            # Flag if response differs significantly
            if status != base_status or abs(len(body) - len(base_body)) > 50:
                results["bypasses"].append({
                    "endpoint": f"{ep['method']} {ep['path']}",
                    "header": f"{hdr_name}: {hdr_val}",
                    "base_status": base_status, "inject_status": status,
                    "size_diff": len(body) - len(base_body)
                })
            time.sleep(0.2)

    results["summary"] = {"total_bypasses": len(results["bypasses"])}

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Background recon for API testing")
    parser.add_argument("--mode", choices=["auth-diff", "param-pollution", "header-injection"],
                        required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--endpoints", required=True, help="File with endpoints")
    parser.add_argument("--token-a", required=True)
    parser.add_argument("--token-b", default=None)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    endpoints = load_endpoints(args.endpoints)
    print(f"[*] Loaded {len(endpoints)} endpoints")
    print(f"[*] Mode: {args.mode}")

    if args.mode == "auth-diff":
        r = auth_diff(args.base_url, endpoints, args.token_a, args.token_b, args.output)
    elif args.mode == "param-pollution":
        r = param_pollution(args.base_url, endpoints, args.token_a, args.output)
    elif args.mode == "header-injection":
        r = header_injection(args.base_url, endpoints, args.token_a, args.output)

    print(f"[+] Done. Results: {json.dumps(r['summary'])}")
    print(f"[+] Output: {args.output}")
