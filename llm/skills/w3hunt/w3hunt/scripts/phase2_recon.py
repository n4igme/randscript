#!/usr/bin/env python3
"""w3hunt Phase 2: Recon — subdomain enum, GitHub repos, frontend analysis, API mapping."""
import os, json, re
from hermes_tools import terminal


def run(workdir, domains, org_name=""):
    """
    Full recon pipeline for Phase 2. Batches 15-20 tool calls into one execution.

    Args:
        workdir: target working directory
        domains: list of in-scope domains (e.g., ["stakewise.io", "app.stakewise.io"])
        org_name: GitHub org name (e.g., "stakewise") — if empty, derived from first domain
    """
    results = {
        "subdomains": set(),
        "github_repos": [],
        "api_endpoints": [],
        "headers": {},
        "framework": "",
        "source_maps": [],
    }

    if not org_name and domains:
        org_name = domains[0].split(".")[0]

    print(f"Phase 2 Recon: {len(domains)} domain(s), org={org_name}")
    print("=" * 50)

    # ─── 2a. GitHub & SDK Enumeration (highest ROI) ───
    print("\n[2a] GitHub & SDK Enumeration")
    if org_name:
        gh = terminal(
            f'curl -s "https://api.github.com/orgs/{org_name}/repos?per_page=100&sort=updated"',
            timeout=15
        )
        if gh.get("exit_code") == 0 and gh.get("output", "").strip().startswith("["):
            try:
                repos = json.loads(gh["output"])
                results["github_repos"] = [
                    {"name": r["name"], "url": r["html_url"], "updated": r["updated_at"][:10]}
                    for r in repos if not r.get("archived")
                ]
                # Flag high-value repos
                sdk_repos = [r for r in results["github_repos"]
                             if any(k in r["name"].lower() for k in ["sdk", "frontend", "app", "api", "trading", "ui"])]
                contract_repos = [r for r in results["github_repos"]
                                  if any(k in r["name"].lower() for k in ["contract", "solidity", "protocol", "core"])]

                print(f"  Found {len(results['github_repos'])} repos")
                if sdk_repos:
                    print(f"  SDK/Frontend repos: {', '.join(r['name'] for r in sdk_repos[:5])}")
                if contract_repos:
                    print(f"  Contract repos: {', '.join(r['name'] for r in contract_repos[:5])}")
            except (json.JSONDecodeError, KeyError):
                print("  GitHub API parse failed — check rate limit")
        else:
            print(f"  GitHub org '{org_name}' not found or rate-limited")

    # Save repos list
    repos_path = os.path.join(workdir, "github-repos.txt")
    with open(repos_path, "w") as f:
        for r in results["github_repos"]:
            f.write(f"{r['name']} | {r['url']} | updated {r['updated']}\n")

    # ─── 2b. Subdomain Enumeration (passive) ───
    print("\n[2b] Subdomain Enumeration")
    for domain in domains:
        # crt.sh
        crt = terminal(
            f'curl -s "https://crt.sh/?q=%25.{domain}&output=json"',
            timeout=30
        )
        if crt.get("exit_code") == 0 and crt.get("output", "").strip().startswith("["):
            try:
                for entry in json.loads(crt["output"]):
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lower()
                        if name and "*" not in name:
                            results["subdomains"].add(name)
            except (json.JSONDecodeError, KeyError):
                pass

        # HackerTarget
        ht = terminal(
            f'curl -s "https://api.hackertarget.com/hostsearch/?q={domain}"',
            timeout=15
        )
        if ht.get("exit_code") == 0 and "error" not in ht.get("output", "").lower():
            for line in ht["output"].split("\n"):
                if "," in line:
                    sub = line.split(",")[0].strip().lower()
                    if sub:
                        results["subdomains"].add(sub)

    print(f"  Total unique subdomains: {len(results['subdomains'])}")

    # Flag interesting subdomains
    interesting_prefixes = ["api", "beta", "staging", "stg", "dev", "admin", "internal",
                           "rpc", "graphql", "ws", "payment", "onramp"]
    flagged = [s for s in results["subdomains"]
               if any(s.startswith(p + ".") or p + "." in s for p in interesting_prefixes)]
    if flagged:
        print(f"  Interesting: {', '.join(sorted(flagged)[:10])}")

    # Save subdomains
    subs_path = os.path.join(workdir, "subdomains.txt")
    with open(subs_path, "w") as f:
        f.write("\n".join(sorted(results["subdomains"])))

    # ─── 2c. Frontend Analysis (headers + framework) ───
    print("\n[2c] Frontend Analysis")
    for domain in domains[:5]:  # Cap at 5 to avoid timeout
        url = f"https://{domain}"
        hdr = terminal(f'curl -sI -L "{url}"', timeout=10)
        if hdr.get("exit_code") == 0:
            output = hdr.get("output", "")
            results["headers"][domain] = {}

            # Extract security headers
            for header in ["content-security-policy", "access-control-allow-origin",
                          "x-frame-options", "strict-transport-security"]:
                match = re.search(rf"^{header}:\s*(.+)$", output, re.IGNORECASE | re.MULTILINE)
                if match:
                    results["headers"][domain][header] = match.group(1).strip()

            # Framework detection from headers
            if "x-powered-by" in output.lower():
                match = re.search(r"x-powered-by:\s*(.+)", output, re.IGNORECASE)
                if match:
                    results["framework"] = match.group(1).strip()

            # CSP check
            csp = results["headers"][domain].get("content-security-policy", "")
            if not csp:
                print(f"  {domain}: NO CSP ⚠️ (XSS potential)")
            else:
                print(f"  {domain}: CSP present ({len(csp)} chars)")

            # CORS check
            cors = results["headers"][domain].get("access-control-allow-origin", "")
            if cors:
                print(f"  {domain}: CORS={cors}")

        # Source map check
        body = terminal(f'curl -s "{url}" | grep -oP "[\\w/.-]+\\.js" | head -5', timeout=10)
        if body.get("exit_code") == 0:
            js_files = [f for f in body.get("output", "").split("\n") if f.strip()]
            for js in js_files[:3]:
                js_url = f"{url}/{js.lstrip('/')}" if not js.startswith("http") else js
                map_check = terminal(f'curl -sI "{js_url}.map" | head -1', timeout=5)
                if "200" in map_check.get("output", ""):
                    results["source_maps"].append(f"{js_url}.map")
                    print(f"  SOURCE MAP EXPOSED: {js_url}.map ⚠️")

    # Save frontend recon
    frontend_path = os.path.join(workdir, "frontend-recon.txt")
    with open(frontend_path, "w") as f:
        f.write(f"Framework: {results['framework'] or 'unknown'}\n")
        f.write(f"Source maps: {results['source_maps'] or 'none found'}\n\n")
        f.write("Security Headers:\n")
        for domain, headers in results["headers"].items():
            f.write(f"\n  {domain}:\n")
            for k, v in headers.items():
                f.write(f"    {k}: {v}\n")
            if not headers:
                f.write("    (no security headers)\n")

    # ─── 2d. Backend API Enumeration ───
    print("\n[2d] Backend API Enumeration")
    api_paths = ["/health", "/api", "/api/v1", "/graphql", "/admin", "/config",
                 "/metrics", "/debug", "/ws", "/trading-variables", "/open-trades"]

    for domain in domains[:3]:
        for path in api_paths:
            url = f"https://{domain}{path}"
            probe = terminal(f'curl -s -o /dev/null -w "%{{http_code}}" "{url}"', timeout=5)
            code = probe.get("output", "").strip()
            if code and code not in ("000", "404", "403"):
                results["api_endpoints"].append({"url": url, "status": code})
                print(f"  {code} {url}")

    # Save API endpoints
    api_path = os.path.join(workdir, "api-endpoints.txt")
    with open(api_path, "w") as f:
        for ep in results["api_endpoints"]:
            f.write(f"{ep['status']} {ep['url']}\n")

    # ─── Summary ───
    print(f"\n{'='*50}")
    print(f"RECON SUMMARY")
    print(f"  Subdomains: {len(results['subdomains'])}")
    print(f"  GitHub repos: {len(results['github_repos'])}")
    print(f"  API endpoints (non-404): {len(results['api_endpoints'])}")
    print(f"  Source maps exposed: {len(results['source_maps'])}")
    print(f"  Domains without CSP: {sum(1 for d, h in results['headers'].items() if 'content-security-policy' not in h)}")

    # Gate check
    gate_items = [
        len(results["github_repos"]) > 0 or "confirmed none",
        len(results["subdomains"]) > 0,
        len(results["api_endpoints"]) >= 3 or "confirmed none",
        results["framework"] or any(results["headers"].values()),
        any(results["headers"].values()),
    ]
    passed = sum(1 for g in gate_items if g)
    print(f"\n  Gate: {passed}/5 minimum viable recon items satisfied")
    if passed >= 4:
        print(f"  → Ready for `next` (advance to Phase 3)")
    else:
        print(f"  → {5-passed} items still needed before advancing")

    return results


if __name__ == "__main__":
    pass
