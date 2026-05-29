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


if __name__ == "__main__":
    pass
