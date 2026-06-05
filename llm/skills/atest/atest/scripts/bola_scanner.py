#!/usr/bin/env python3
"""atest BOLA/IDOR scanner — systematic cross-user access testing on all endpoints.

Usage (via execute_code):
    from hermes_tools import terminal
    import sys, os
    sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/atest/scripts"))
    import bola_scanner

    results = bola_scanner.scan(
        base_url="https://api.target.com",
        endpoints=[
            {"method": "GET", "path": "/api/users/{id}"},
            {"method": "GET", "path": "/api/orders/{id}"},
            {"method": "PUT", "path": "/api/users/{id}", "body": {"name": "test"}},
        ],
        token_a="eyJ...",  # User A's token
        token_b="eyJ...",  # User B's token
        user_a_id="123",   # User A's resource ID
        user_b_id="456",   # User B's resource ID
    )
"""
import json
from hermes_tools import terminal


def scan(base_url, endpoints, token_a, token_b, user_a_id, user_b_id,
         auth_header="Authorization", auth_prefix="Bearer", timeout=10):
    """
    Test every endpoint for BOLA/IDOR by accessing User B's resources with User A's token.

    Args:
        base_url: API base URL (no trailing slash)
        endpoints: list of {"method": str, "path": str, "body": dict (optional)}
                   Use {id} as placeholder for resource ID
        token_a: User A's auth token
        token_b: User B's auth token
        user_a_id: User A's resource identifier
        user_b_id: User B's resource identifier
        auth_header: Header name for auth (default: Authorization)
        auth_prefix: Token prefix (default: Bearer)
        timeout: Request timeout in seconds

    Returns:
        dict with: vulnerable (list), safe (list), errors (list), summary (str)
    """
    results = {
        "vulnerable": [],
        "safe": [],
        "errors": [],
        "no_auth": [],
    }

    total = len(endpoints)
    print(f"BOLA Scanner: testing {total} endpoints")
    print(f"  Base URL: {base_url}")
    print(f"  User A ID: {user_a_id} | User B ID: {user_b_id}")
    print(f"{'='*60}")

    for i, ep in enumerate(endpoints, 1):
        method = ep.get("method", "GET").upper()
        path_template = ep.get("path", "")
        body = ep.get("body")

        # Substitute User B's ID into path (testing if User A can access B's resource)
        path = path_template.replace("{id}", str(user_b_id))
        url = f"{base_url}{path}"

        # Build curl command — User A's token accessing User B's resource
        cmd = f'curl -sk -o /tmp/bola_resp.json -w "%{{http_code}}" -X {method}'
        cmd += f' -H "{auth_header}: {auth_prefix} {token_a}"'
        cmd += f' -H "Content-Type: application/json"'

        if body and method in ("POST", "PUT", "PATCH"):
            body_json = json.dumps(body).replace('"', '\\"')
            cmd += f' -d "{body_json}"'

        cmd += f' --max-time {timeout} "{url}"'

        # Execute request
        resp = terminal(cmd, timeout=timeout + 5)
        status_code = resp.get("output", "").strip()

        # Read response body
        body_resp = terminal("cat /tmp/bola_resp.json 2>/dev/null", timeout=5)
        resp_body = body_resp.get("output", "")

        # Also test without auth (unauth access)
        cmd_noauth = f'curl -sk -o /tmp/bola_noauth.json -w "%{{http_code}}" -X {method}'
        cmd_noauth += f' -H "Content-Type: application/json"'
        if body and method in ("POST", "PUT", "PATCH"):
            cmd_noauth += f' -d "{body_json}"'
        cmd_noauth += f' --max-time {timeout} "{url}"'

        resp_noauth = terminal(cmd_noauth, timeout=timeout + 5)
        noauth_code = resp_noauth.get("output", "").strip()

        # Analyze results
        entry = {
            "endpoint": f"{method} {path_template}",
            "url_tested": url,
            "status_with_token_a": status_code,
            "status_no_auth": noauth_code,
            "response_length": len(resp_body),
        }

        # Determine if vulnerable
        if status_code in ("200", "201"):
            # User A got 200 on User B's resource — likely BOLA
            # Check if response contains User B's data
            has_user_b_data = str(user_b_id) in resp_body
            entry["contains_target_id"] = has_user_b_data
            entry["response_preview"] = resp_body[:200]

            if has_user_b_data:
                results["vulnerable"].append(entry)
                verdict = "⚠️  VULNERABLE (BOLA confirmed)"
            else:
                # 200 but no user B data — might be own data or generic response
                results["vulnerable"].append(entry)
                verdict = "⚠️  POSSIBLE BOLA (200 OK, verify manually)"
        elif status_code in ("401", "403"):
            results["safe"].append(entry)
            verdict = "✓ Protected"
        elif status_code == "404":
            # Could be safe (proper isolation) or could be resource doesn't exist
            results["safe"].append(entry)
            verdict = "✓ Not found (isolated or non-existent)"
        elif status_code == "000" or not status_code:
            results["errors"].append(entry)
            verdict = "✗ Error (timeout/connection)"
        else:
            results["safe"].append(entry)
            verdict = f"? Unexpected ({status_code})"

        # Check unauth access
        if noauth_code in ("200", "201"):
            results["no_auth"].append(entry)
            verdict += " + NO AUTH REQUIRED"

        print(f"  [{i}/{total}] {method} {path_template} → {status_code} {verdict}")

    # Summary
    print(f"\n{'='*60}")
    print(f"RESULTS:")
    print(f"  Vulnerable (BOLA):  {len(results['vulnerable'])}")
    print(f"  No auth required:   {len(results['no_auth'])}")
    print(f"  Protected:          {len(results['safe'])}")
    print(f"  Errors:             {len(results['errors'])}")

    if results["vulnerable"]:
        print(f"\n  VULNERABLE ENDPOINTS:")
        for v in results["vulnerable"]:
            print(f"    {v['endpoint']} → {v['status_with_token_a']}")
            if v.get("response_preview"):
                print(f"      Preview: {v['response_preview'][:100]}...")

    if results["no_auth"]:
        print(f"\n  NO AUTH REQUIRED:")
        for v in results["no_auth"]:
            print(f"    {v['endpoint']} → {v['status_no_auth']} (no token needed)")

    results["summary"] = (
        f"{len(results['vulnerable'])} BOLA, "
        f"{len(results['no_auth'])} no-auth, "
        f"{len(results['safe'])} safe, "
        f"{len(results['errors'])} errors"
    )

    return results


def scan_from_openapi(base_url, openapi_path, token_a, token_b, user_a_id, user_b_id, **kwargs):
    """
    Parse OpenAPI/Swagger spec and extract endpoints with path parameters for BOLA testing.

    Args:
        openapi_path: path to local OpenAPI JSON file
        (other args same as scan())
    """
    with open(openapi_path) as f:
        spec = json.loads(f.read())

    endpoints = []
    paths = spec.get("paths", {})

    for path, methods in paths.items():
        # Only test paths with ID-like parameters
        if "{" not in path:
            continue

        # Normalize parameter names to {id}
        normalized = path
        for param in ("id", "userId", "user_id", "orderId", "order_id",
                      "accountId", "account_id", "resourceId", "itemId"):
            normalized = normalized.replace(f"{{{param}}}", "{id}")

        # If still has other params, skip (too complex for automated scan)
        import re
        remaining_params = re.findall(r"\{(\w+)\}", normalized)
        remaining_params = [p for p in remaining_params if p != "id"]
        if remaining_params:
            continue

        for method in ("get", "post", "put", "patch", "delete"):
            if method in methods:
                endpoints.append({
                    "method": method.upper(),
                    "path": normalized,
                })

    print(f"Extracted {len(endpoints)} endpoints with ID parameters from OpenAPI spec")
    return scan(base_url, endpoints, token_a, token_b, user_a_id, user_b_id, **kwargs)


def scan_from_recon(base_url, recon_dir, token_a, token_b, user_a_id, user_b_id, **kwargs):
    """
    Auto-discover endpoints from ptest/atest recon output and batch-test for BOLA.

    Reads:
      - js-analysis.json (endpoints extracted from JS bundles)
      - enumeration/*.txt (gobuster/feroxbuster output)
      - Any swagger/openapi JSON found in recon

    Args:
        recon_dir: Path to recon output (e.g., ./ptest-output/recon-passive)
        (other args same as scan())
    """
    import os
    import re

    endpoints = []
    seen_paths = set()

    # 1. JS analysis endpoints
    js_path = os.path.join(recon_dir, "js-analysis.json")
    if os.path.isfile(js_path):
        with open(js_path) as f:
            js_data = json.loads(f.read())
        for ep in js_data.get("endpoints", []):
            # Only keep paths with ID-like parameters
            if re.search(r'/\d+|/\{[^}]+\}|/[a-f0-9-]{36}', ep):
                normalized = re.sub(r'/\d+', '/{id}', ep)
                normalized = re.sub(r'/[a-f0-9-]{36}', '/{id}', normalized)
                if normalized not in seen_paths:
                    seen_paths.add(normalized)
                    endpoints.append({"method": "GET", "path": normalized})

    # 2. Enumeration output (look for paths with numeric IDs)
    enum_dir = os.path.join(os.path.dirname(recon_dir), "enumeration")
    if os.path.isdir(enum_dir):
        for fname in os.listdir(enum_dir):
            fpath = os.path.join(enum_dir, fname)
            if os.path.isfile(fpath):
                with open(fpath) as f:
                    for line in f:
                        # Extract paths from gobuster/feroxbuster output
                        match = re.search(r'(/[^\s]+)', line)
                        if match:
                            path = match.group(1)
                            if re.search(r'/\d+', path):
                                normalized = re.sub(r'/\d+', '/{id}', path)
                                if normalized not in seen_paths:
                                    seen_paths.add(normalized)
                                    endpoints.append({"method": "GET", "path": normalized})

    # 3. Look for swagger/openapi files
    for root, dirs, files in os.walk(recon_dir):
        for f in files:
            if f in ("swagger.json", "openapi.json") or "api-docs" in f:
                return scan_from_openapi(base_url, os.path.join(root, f),
                                         token_a, token_b, user_a_id, user_b_id, **kwargs)

    if not endpoints:
        print("No endpoints with ID parameters found in recon output.")
        print("Provide endpoints manually or run JS bundle analysis first.")
        return {"vulnerable": [], "safe": [], "errors": [], "summary": "No endpoints found"}

    # Add common write methods for discovered endpoints
    expanded = []
    for ep in endpoints:
        expanded.append(ep)
        # Also test PUT/DELETE on same paths
        expanded.append({"method": "PUT", "path": ep["path"], "body": {"test": "bola"}})
        expanded.append({"method": "DELETE", "path": ep["path"]})

    print(f"Auto-discovered {len(endpoints)} endpoints → expanded to {len(expanded)} tests")
    return scan(base_url, expanded, token_a, token_b, user_a_id, user_b_id, **kwargs)


def scan_batch_ids(base_url, path_template, token, id_range=range(1, 50),
                   auth_header="Authorization", auth_prefix="Bearer", timeout=10):
    """
    Enumerate IDs on a single endpoint to find accessible resources.
    Useful when you have one user's token and want to see what else is accessible.

    Args:
        base_url: API base URL
        path_template: Path with {id} placeholder (e.g., "/api/users/{id}")
        token: Auth token to test with
        id_range: Range of IDs to try
        auth_header/auth_prefix: Auth header configuration
        timeout: Per-request timeout

    Returns:
        dict with: accessible (list of IDs that returned 200), denied (count), errors (count)
    """
    results = {"accessible": [], "denied": 0, "errors": 0}

    print(f"ID Enumeration: {path_template}")
    print(f"  Range: {id_range.start}-{id_range.stop-1} ({len(id_range)} IDs)")
    print(f"{'='*60}")

    for id_val in id_range:
        path = path_template.replace("{id}", str(id_val))
        url = f"{base_url}{path}"
        cmd = (f'curl -sk -o /dev/null -w "%{{http_code}}" -X GET '
               f'-H "{auth_header}: {auth_prefix} {token}" '
               f'--max-time {timeout} "{url}"')

        resp = terminal(cmd, timeout=timeout + 5)
        code = resp.get("output", "").strip()

        if code == "200":
            results["accessible"].append(id_val)
            print(f"  ✓ ID {id_val} → 200 (accessible)")
        elif code in ("401", "403"):
            results["denied"] += 1
        elif code == "404":
            pass  # Resource doesn't exist
        else:
            results["errors"] += 1

    print(f"\n{'='*60}")
    print(f"  Accessible: {len(results['accessible'])} | Denied: {results['denied']} | Errors: {results['errors']}")
    if results["accessible"]:
        print(f"  IDs: {results['accessible'][:20]}")

    return results


if __name__ == "__main__":
    pass
