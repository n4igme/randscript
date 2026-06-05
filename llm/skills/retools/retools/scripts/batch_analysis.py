#!/usr/bin/env python3
"""retools batch analysis — extract JNI functions, URLs, crypto keys from native libs."""
import subprocess
import re
import os
import sys
import json
from datetime import datetime


def run_cmd(cmd, timeout=30):
    """Run command, return stdout or empty string."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""


def analyze_so(path):
    """Analyze a single .so file. Returns dict of findings."""
    name = os.path.basename(path)
    result = {"file": name, "path": path, "jni_functions": [], "urls": [],
              "crypto_refs": [], "strings_of_interest": [], "imports": []}

    # JNI functions
    out = run_cmd(f"r2 -q -c 'aa; afl~Java_' '{path}'")
    if out:
        for line in out.split("\n"):
            parts = line.split()
            if len(parts) >= 4:
                result["jni_functions"].append({"addr": parts[0], "name": parts[-1]})

    # Strings: URLs, IPs, keys
    out = run_cmd(f"r2 -q -c 'izz' '{path}'")
    if out:
        for line in out.split("\n"):
            s = line.split("ascii")[1].strip() if "ascii" in line else ""
            if not s:
                s = line.split("utf8")[1].strip() if "utf8" in line else ""
            if not s:
                continue

            # URLs
            if re.search(r'https?://', s):
                result["urls"].append(s)
            # IP addresses
            elif re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s):
                result["urls"].append(s)
            # API keys / tokens
            elif re.search(r'(AIza|AKIA|sk_live|sk_test|ghp_|glpat-)', s):
                result["strings_of_interest"].append({"type": "api_key", "value": s})
            # Base64 (long, likely encoded data)
            elif re.search(r'^[A-Za-z0-9+/]{40,}={0,2}$', s):
                result["strings_of_interest"].append({"type": "base64", "value": s[:80]})
            # Crypto-related
            elif re.search(r'(AES|RSA|SHA|HMAC|PBKDF|secp256|curve25519)', s, re.I):
                result["crypto_refs"].append(s)

    # Dangerous imports
    out = run_cmd(f"r2 -q -c 'ii' '{path}'")
    if out:
        dangerous = ["system", "exec", "popen", "dlopen", "ptrace",
                     "SSL_CTX_set_verify", "X509_verify_cert"]
        for line in out.split("\n"):
            for d in dangerous:
                if d in line:
                    result["imports"].append(line.strip())
                    break

    return result


def analyze_directory(lib_dir, output_path=None):
    """Analyze all .so files in a directory."""
    so_files = []
    for root, dirs, files in os.walk(lib_dir):
        for f in files:
            if f.endswith(".so"):
                so_files.append(os.path.join(root, f))

    if not so_files:
        print(f"[batch_analysis] No .so files found in {lib_dir}")
        return []

    print(f"[batch_analysis] Found {len(so_files)} native libraries")
    results = []

    for path in sorted(so_files):
        print(f"  Analyzing: {os.path.basename(path)}...", end=" ")
        r = analyze_so(path)
        findings = len(r["jni_functions"]) + len(r["urls"]) + len(r["crypto_refs"]) + len(r["strings_of_interest"])
        print(f"{findings} findings")
        if findings > 0:
            results.append(r)

    # Write report
    if output_path is None:
        output_path = os.path.join(os.path.dirname(lib_dir), "native-analysis.md")

    with open(output_path, "w") as f:
        f.write(f"# Native Library Analysis\n\n")
        f.write(f"**Date:** {datetime.now().isoformat()}\n")
        f.write(f"**Directory:** {lib_dir}\n")
        f.write(f"**Libraries:** {len(so_files)} total, {len(results)} with findings\n\n")

        for r in results:
            f.write(f"## {r['file']}\n\n")
            if r["jni_functions"]:
                f.write(f"### JNI Functions ({len(r['jni_functions'])})\n")
                for jni in r["jni_functions"]:
                    f.write(f"- `{jni['addr']}` {jni['name']}\n")
                f.write("\n")
            if r["urls"]:
                f.write(f"### URLs/Endpoints ({len(r['urls'])})\n")
                for url in r["urls"][:30]:
                    f.write(f"- `{url}`\n")
                f.write("\n")
            if r["crypto_refs"]:
                f.write(f"### Crypto References ({len(r['crypto_refs'])})\n")
                for c in r["crypto_refs"][:20]:
                    f.write(f"- {c}\n")
                f.write("\n")
            if r["strings_of_interest"]:
                f.write(f"### Interesting Strings ({len(r['strings_of_interest'])})\n")
                for s in r["strings_of_interest"][:20]:
                    f.write(f"- **{s['type']}**: `{s['value']}`\n")
                f.write("\n")
            if r["imports"]:
                f.write(f"### Security-Relevant Imports\n")
                for i in r["imports"]:
                    f.write(f"- `{i}`\n")
                f.write("\n")

    print(f"\n[batch_analysis] Report: {output_path}")
    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: batch_analysis.py <lib_directory> [output_path]")
        print("  Analyzes all .so files in directory for JNI, URLs, keys, crypto.")
        sys.exit(1)
    out = sys.argv[2] if len(sys.argv) > 2 else None
    analyze_directory(sys.argv[1], out)
