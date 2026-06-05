#!/usr/bin/env python3
"""ctest bucket/storage scanner — find public or misconfigured cloud storage."""
import json
import subprocess
import sys
import os
from datetime import datetime


COMMON_SUFFIXES = [
    "", "-dev", "-stg", "-staging", "-prod", "-production", "-backup",
    "-backups", "-data", "-logs", "-assets", "-static", "-media",
    "-uploads", "-public", "-private", "-internal", "-test", "-tmp",
]


def run_cmd(cmd, timeout=15):
    """Run shell command, return (stdout, success)."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode == 0
    except (subprocess.TimeoutExpired, Exception):
        return "", False


def check_s3_bucket(name):
    """Check S3 bucket existence and permissions."""
    result = {"name": name, "exists": False, "listable": False, "writable": False, "findings": []}

    # Existence check (HEAD)
    out, ok = run_cmd(f'curl -sk -o /dev/null -w "%{{http_code}}" "https://{name}.s3.amazonaws.com/"')
    if out == "404":
        return None  # doesn't exist
    result["exists"] = True

    # List check
    out, ok = run_cmd(f'curl -sk "https://{name}.s3.amazonaws.com/" -o /tmp/s3list.xml -w "%{{http_code}}"')
    if out in ("200",):
        result["listable"] = True
        result["findings"].append({"severity": "high", "issue": "Public listing enabled"})

    # ACL check
    out, ok = run_cmd(f'curl -sk "https://{name}.s3.amazonaws.com/?acl" -o /tmp/s3acl.xml -w "%{{http_code}}"')
    if out == "200":
        acl_content, _ = run_cmd("cat /tmp/s3acl.xml")
        if "AllUsers" in acl_content:
            result["findings"].append({"severity": "high", "issue": "ACL grants AllUsers access"})
        if "AuthenticatedUsers" in acl_content:
            result["findings"].append({"severity": "medium", "issue": "ACL grants AuthenticatedUsers"})

    return result


def check_gcs_bucket(name):
    """Check GCS bucket existence and permissions."""
    result = {"name": name, "exists": False, "listable": False, "findings": []}

    out, ok = run_cmd(f'curl -sk -o /dev/null -w "%{{http_code}}" "https://storage.googleapis.com/{name}"')
    if out == "404":
        return None
    result["exists"] = True

    if out == "200":
        result["listable"] = True
        result["findings"].append({"severity": "high", "issue": "Public listing enabled"})
    elif out == "403":
        result["findings"].append({"severity": "info", "issue": "Exists but ACL'd (403)"})

    return result


def check_azure_blob(name):
    """Check Azure blob container existence."""
    result = {"name": name, "exists": False, "listable": False, "findings": []}

    out, ok = run_cmd(
        f'curl -sk -o /dev/null -w "%{{http_code}}" '
        f'"https://{name}.blob.core.windows.net/?comp=list&restype=container"'
    )
    if out == "404":
        return None
    result["exists"] = True

    if out == "200":
        result["listable"] = True
        result["findings"].append({"severity": "high", "issue": "Public container listing"})

    return result


def generate_names(keywords):
    """Generate bucket name candidates from keywords."""
    names = set()
    for kw in keywords:
        kw = kw.lower().replace(" ", "-")
        for suffix in COMMON_SUFFIXES:
            names.add(f"{kw}{suffix}")
    return sorted(names)


def scan(keywords, providers=None, output_dir="./ctest-output"):
    """
    Main scanner entry point.

    Args:
        keywords: list of company/project names to permute
        providers: list of providers to check ["aws", "gcp", "azure"]. Default: all.
        output_dir: where to write results
    """
    if providers is None:
        providers = ["aws", "gcp", "azure"]

    names = generate_names(keywords)
    print(f"[bucket_scan] Testing {len(names)} names across {providers}")

    results = {"aws": [], "gcp": [], "azure": [], "summary": {"tested": 0, "found": 0, "findings": 0}}

    for name in names:
        results["summary"]["tested"] += 1

        if "aws" in providers:
            r = check_s3_bucket(name)
            if r:
                results["aws"].append(r)
                results["summary"]["found"] += 1
                results["summary"]["findings"] += len(r["findings"])
                status = "🔴 LISTABLE" if r["listable"] else "exists"
                print(f"  S3: {name} — {status}")

        if "gcp" in providers:
            r = check_gcs_bucket(name)
            if r:
                results["gcp"].append(r)
                results["summary"]["found"] += 1
                results["summary"]["findings"] += len(r["findings"])
                status = "🔴 LISTABLE" if r["listable"] else "exists"
                print(f"  GCS: {name} — {status}")

        if "azure" in providers:
            r = check_azure_blob(name)
            if r:
                results["azure"].append(r)
                results["summary"]["found"] += 1
                results["summary"]["findings"] += len(r["findings"])
                status = "🔴 LISTABLE" if r["listable"] else "exists"
                print(f"  Azure: {name} — {status}")

    # Write report
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, "bucket-scan.md")
    with open(report_path, "w") as f:
        f.write(f"# Cloud Storage Scan Results\n\n")
        f.write(f"**Date:** {datetime.now().isoformat()}\n")
        f.write(f"**Keywords:** {', '.join(keywords)}\n")
        f.write(f"**Tested:** {results['summary']['tested']} names\n")
        f.write(f"**Found:** {results['summary']['found']} buckets\n")
        f.write(f"**Findings:** {results['summary']['findings']}\n\n")
        for provider in providers:
            items = results[provider]
            if items:
                f.write(f"## {provider.upper()}\n\n")
                for item in items:
                    f.write(f"### {item['name']}\n")
                    f.write(f"- Listable: {item['listable']}\n")
                    for finding in item.get("findings", []):
                        f.write(f"- **[{finding['severity'].upper()}]** {finding['issue']}\n")
                    f.write("\n")

    print(f"\n[bucket_scan] Done. Report: {report_path}")
    print(f"  Found: {results['summary']['found']} | Findings: {results['summary']['findings']}")
    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: bucket_scan.py <keyword1> [keyword2] ...")
        sys.exit(1)
    scan(sys.argv[1:])
