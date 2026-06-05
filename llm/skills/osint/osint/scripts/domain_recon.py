#!/usr/bin/env python3
"""osint domain recon — DNS records, crt.sh subdomains, MX/SPF, WHOIS summary."""
import subprocess
import re
import json
import os
import sys
from datetime import datetime


def run_cmd(cmd, timeout=20):
    """Run command, return stdout."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def dns_records(domain):
    """Pull all DNS record types."""
    records = {}
    for rtype in ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]:
        out = run_cmd(f"dig +short {domain} {rtype}")
        if out:
            records[rtype] = [l for l in out.split("\n") if l]
    # DMARC
    out = run_cmd(f"dig +short _dmarc.{domain} TXT")
    if out:
        records["DMARC"] = [out]
    return records


def crt_sh_subdomains(domain):
    """Query crt.sh for certificate transparency subdomains."""
    out = run_cmd(
        f'curl -sk "https://crt.sh/?q=%25.{domain}&output=json" 2>/dev/null',
        timeout=30
    )
    if not out:
        return []
    try:
        certs = json.loads(out)
        subs = set()
        for cert in certs:
            names = cert.get("name_value", "")
            for name in names.split("\n"):
                name = name.strip().lower()
                if name.endswith(domain) and "*" not in name:
                    subs.add(name)
        return sorted(subs)
    except (json.JSONDecodeError, KeyError):
        return []


def whois_summary(domain):
    """Extract key WHOIS fields."""
    out = run_cmd(f"whois {domain}")
    if not out:
        return {}
    summary = {}
    patterns = {
        "registrar": r"Registrar:\s*(.+)",
        "created": r"Creat(?:ion|ed)\s*Date:\s*(.+)",
        "expires": r"Expir(?:y|ation)\s*Date:\s*(.+)",
        "registrant_org": r"Registrant\s*Organiz?ation:\s*(.+)",
        "registrant_country": r"Registrant\s*Country:\s*(.+)",
        "name_servers": r"Name Server:\s*(.+)",
    }
    for key, pattern in patterns.items():
        matches = re.findall(pattern, out, re.IGNORECASE)
        if matches:
            if key == "name_servers":
                summary[key] = [m.strip().lower() for m in matches]
            else:
                summary[key] = matches[0].strip()
    return summary


def spf_analysis(txt_records):
    """Extract SPF includes (reveals email/infra vendors)."""
    vendors = []
    for record in txt_records:
        if "v=spf1" in record:
            includes = re.findall(r"include:(\S+)", record)
            vendors.extend(includes)
    return vendors


def recon(domain, output_dir=None):
    """Run full domain recon. Returns results dict."""
    print(f"[domain_recon] Target: {domain}")
    results = {"domain": domain, "timestamp": datetime.now().isoformat()}

    # DNS
    print("  DNS records...", end=" ")
    results["dns"] = dns_records(domain)
    print(f"{sum(len(v) for v in results['dns'].values())} records")

    # SPF vendors
    if "TXT" in results["dns"]:
        results["spf_vendors"] = spf_analysis(results["dns"]["TXT"])

    # crt.sh
    print("  crt.sh subdomains...", end=" ")
    results["subdomains"] = crt_sh_subdomains(domain)
    print(f"{len(results['subdomains'])} found")

    # WHOIS
    print("  WHOIS...", end=" ")
    results["whois"] = whois_summary(domain)
    print(f"{'ok' if results['whois'] else 'empty/redacted'}")

    # Write report
    if output_dir is None:
        output_dir = "./osint-output"
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, f"domain-recon-{domain}.md")

    with open(report_path, "w") as f:
        f.write(f"# Domain Recon: {domain}\n\n")
        f.write(f"**Date:** {results['timestamp']}\n\n")

        f.write("## DNS Records\n\n")
        for rtype, values in results["dns"].items():
            f.write(f"**{rtype}:**\n")
            for v in values:
                f.write(f"- `{v}`\n")
            f.write("\n")

        if results.get("spf_vendors"):
            f.write("## SPF Includes (Vendor Discovery)\n\n")
            for v in results["spf_vendors"]:
                f.write(f"- `{v}`\n")
            f.write("\n")

        if results["subdomains"]:
            f.write(f"## Subdomains ({len(results['subdomains'])})\n\n")
            for sub in results["subdomains"]:
                f.write(f"- {sub}\n")
            f.write("\n")

        if results["whois"]:
            f.write("## WHOIS Summary\n\n")
            for k, v in results["whois"].items():
                if isinstance(v, list):
                    f.write(f"**{k}:** {', '.join(v)}\n")
                else:
                    f.write(f"**{k}:** {v}\n")
            f.write("\n")

    print(f"\n[domain_recon] Report: {report_path}")
    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: domain_recon.py <domain> [output_dir]")
        sys.exit(1)
    out_dir = sys.argv[2] if len(sys.argv) > 2 else None
    recon(sys.argv[1], out_dir)
