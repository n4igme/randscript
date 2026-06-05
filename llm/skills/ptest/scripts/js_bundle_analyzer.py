#!/usr/bin/env python3
"""ptest JS bundle analyzer — extract endpoints, secrets, routes from JavaScript bundles.

Usage:
    from js_bundle_analyzer import analyze
    results = analyze("https://target.com")
"""
from hermes_tools import terminal, write_file
import re
import json

SECRET_PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key", r"(?:aws_secret|secret_key|secretAccessKey)[\"':\s]*([A-Za-z0-9/+=]{40})"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("Google OAuth", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    ("GitHub Token", r"gh[ps]_[A-Za-z0-9_]{36,}"),
    ("Slack Token", r"xox[baprs]-[0-9a-zA-Z-]{10,}"),
    ("Stripe Key", r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}"),
    ("JWT Token", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
    ("Private Key", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    ("Firebase URL", r"https://[a-z0-9-]+\.firebaseio\.com"),
    ("Supabase Key", r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    ("Mapbox Token", r"pk\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    ("Twilio SID", r"AC[0-9a-f]{32}"),
    ("SendGrid Key", r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    ("Heroku Key", r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    ("Generic Secret", r"(?:secret|password|passwd|token|api_key|apikey|auth)[\s]*[:=][\s]*[\"'][^\"']{8,}[\"']"),
]

ENDPOINT_PATTERNS = [
    # API paths
    r'["\'](/api/[a-zA-Z0-9_/\-{}:.]+)["\']',
    r'["\'](/v[0-9]+/[a-zA-Z0-9_/\-{}:.]+)["\']',
    # Full URLs
    r'["\'](https?://[a-zA-Z0-9._\-]+(?:/[a-zA-Z0-9_/\-{}:.?&=]*))["\']',
    # Relative paths with common prefixes
    r'["\'](/(?:admin|internal|debug|graphql|auth|oauth|webhook|ws|socket|rpc)[a-zA-Z0-9_/\-{}:.]*)["\']',
]

ROUTE_PATTERNS = [
    # React Router / Vue Router / Angular
    r'path:\s*["\']([/][^"\']+)["\']',
    r'Route\s+path=["\']([/][^"\']+)["\']',
    r'navigate\(["\']([/][^"\']+)["\']',
    r'router\.\w+\(["\']([/][^"\']+)["\']',
    # Next.js pages
    r'pages/([a-zA-Z0-9_/\[\]\-]+)',
]


def _fetch(url, timeout=15):
    """Fetch URL content."""
    resp = terminal(f'curl -sk --max-time {timeout} "{url}"', timeout=timeout + 5)
    return resp.get("output", "") if resp.get("exit_code") == 0 else ""


def _discover_bundles(target):
    """Find JS bundle URLs from the target's HTML."""
    html = _fetch(target)
    scripts = re.findall(r'(?:src|href)=["\']([^"\']*\.(?:js|mjs)(?:\?[^"\']*)?)["\']', html)

    bundles = []
    for s in scripts:
        if s.startswith("//"):
            s = "https:" + s
        elif s.startswith("/"):
            s = target.rstrip("/") + s
        elif not s.startswith("http"):
            s = target.rstrip("/") + "/" + s
        # Skip common third-party scripts
        if any(x in s for x in ["google-analytics", "gtag", "facebook", "hotjar", "clarity", "cdn.jsdelivr"]):
            continue
        bundles.append(s)

    # Also check for source maps
    maps = []
    for b in bundles:
        maps.append(b + ".map")
    # Inline sourceMappingURL
    inline_maps = re.findall(r'//# sourceMappingURL=(\S+)', html)
    for m in inline_maps:
        if not m.startswith("http"):
            m = target.rstrip("/") + "/" + m.lstrip("/")
        maps.append(m)

    return bundles, maps


def _extract_from_source_map(map_url):
    """Extract original source from source map."""
    content = _fetch(map_url)
    if not content or "sourcesContent" not in content:
        return None
    try:
        data = json.loads(content)
        sources = data.get("sources", [])
        contents = data.get("sourcesContent", [])
        return {"sources": sources, "contents": contents, "url": map_url}
    except json.JSONDecodeError:
        return None


def _extract_secrets(content, source_name=""):
    """Find secrets in JS content."""
    findings = []
    for name, pattern in SECRET_PATTERNS:
        matches = re.finditer(pattern, content)
        for m in matches:
            # Get surrounding context
            start = max(0, m.start() - 30)
            end = min(len(content), m.end() + 30)
            context = content[start:end].replace("\n", " ")
            findings.append({
                "type": name,
                "value": m.group(0)[:80],
                "context": context,
                "source": source_name,
            })
    return findings


def _extract_endpoints(content):
    """Find API endpoints in JS content."""
    endpoints = set()
    for pattern in ENDPOINT_PATTERNS:
        matches = re.findall(pattern, content)
        for m in matches:
            # Filter noise
            if len(m) < 5 or len(m) > 200:
                continue
            if m.endswith(('.js', '.css', '.png', '.jpg', '.svg', '.ico', '.woff')):
                continue
            endpoints.add(m)
    return sorted(endpoints)


def _extract_routes(content):
    """Find frontend routes."""
    routes = set()
    for pattern in ROUTE_PATTERNS:
        matches = re.findall(pattern, content)
        routes.update(matches)
    return sorted(routes)


def analyze(target, output_dir="./ptest-output/recon-passive"):
    """
    Analyze JS bundles from a target for secrets, endpoints, and routes.

    Args:
        target: Base URL
        output_dir: Where to write results

    Returns:
        dict with: secrets, endpoints, routes, source_maps, bundles_analyzed
    """
    target = target.rstrip("/")
    results = {"secrets": [], "endpoints": [], "routes": [], "source_maps": [], "bundles_analyzed": 0}

    print(f"JS Bundle Analyzer")
    print(f"Target: {target}")
    print(f"{'='*60}")

    # Discover bundles
    bundles, maps = _discover_bundles(target)
    print(f"  Found {len(bundles)} JS bundles, {len(maps)} potential source maps")

    # Analyze each bundle
    for url in bundles:
        print(f"  Analyzing: {url.split('/')[-1][:50]}")
        content = _fetch(url)
        if not content:
            continue
        results["bundles_analyzed"] += 1

        secrets = _extract_secrets(content, url)
        endpoints = _extract_endpoints(content)
        routes = _extract_routes(content)

        results["secrets"].extend(secrets)
        results["endpoints"].extend(endpoints)
        results["routes"].extend(routes)

    # Check source maps (high value — full source code)
    for map_url in maps:
        map_data = _extract_from_source_map(map_url)
        if map_data:
            print(f"  🔴 SOURCE MAP FOUND: {map_url}")
            results["source_maps"].append(map_url)
            # Analyze all source files in the map
            for i, content in enumerate(map_data.get("contents", [])):
                if content:
                    source_name = map_data["sources"][i] if i < len(map_data["sources"]) else f"source_{i}"
                    secrets = _extract_secrets(content, source_name)
                    endpoints = _extract_endpoints(content)
                    results["secrets"].extend(secrets)
                    results["endpoints"].extend(endpoints)

    # Deduplicate
    results["endpoints"] = sorted(set(results["endpoints"]))
    results["routes"] = sorted(set(results["routes"]))

    # Summary
    print(f"\n{'='*60}")
    print(f"RESULTS:")
    print(f"  Bundles analyzed: {results['bundles_analyzed']}")
    print(f"  Source maps found: {len(results['source_maps'])}")
    print(f"  Secrets found: {len(results['secrets'])}")
    print(f"  Endpoints extracted: {len(results['endpoints'])}")
    print(f"  Routes found: {len(results['routes'])}")

    if results["secrets"]:
        print(f"\n  SECRETS:")
        for s in results["secrets"][:10]:
            print(f"    [{s['type']}] {s['value'][:60]}")

    if results["endpoints"]:
        print(f"\n  TOP ENDPOINTS (showing 20):")
        for e in results["endpoints"][:20]:
            print(f"    {e}")

    # Write output
    terminal(f"mkdir -p {output_dir}", timeout=5)
    output = {
        "target": target,
        "bundles_analyzed": results["bundles_analyzed"],
        "source_maps": results["source_maps"],
        "secrets": results["secrets"],
        "endpoints": results["endpoints"],
        "routes": results["routes"],
    }
    write_file(f"{output_dir}/js-analysis.json", json.dumps(output, indent=2))
    print(f"\n  Output: {output_dir}/js-analysis.json")

    return results


if __name__ == "__main__":
    pass
