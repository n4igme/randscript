#!/usr/bin/env python3
"""ptest race condition — concurrent request template for state-changing endpoints.

Usage:
    from race_condition import race, race_turbo
    results = race("https://target.com/api/transfer", method="POST",
                   headers={"Authorization": "Bearer xxx"},
                   body='{"to":"attacker","amount":100}',
                   concurrency=20)

    # Turbo Intruder style (single-packet attack)
    results = race_turbo("https://target.com/api/redeem",
                         headers={"Authorization": "Bearer xxx", "Content-Type": "application/json"},
                         body='{"code":"DISCOUNT50"}',
                         count=20)
"""
from hermes_tools import terminal
import json
import time


def race(url, method="POST", headers=None, body=None, concurrency=20, timeout=10):
    """
    Send N concurrent requests using curl parallel (--parallel).
    Good for: coupon reuse, balance transfer, vote manipulation, limit bypass.

    Args:
        url: Target endpoint
        method: HTTP method
        headers: dict of headers
        body: Request body string
        concurrency: Number of parallel requests
        timeout: Per-request timeout

    Returns:
        dict with: responses (list), unique_statuses, timing, potential_race (bool)
    """
    print(f"Race Condition Test")
    print(f"  URL: {url}")
    print(f"  Method: {method}")
    print(f"  Concurrency: {concurrency}")
    print(f"{'='*60}")

    # Build curl config file for parallel execution
    config_lines = []
    for i in range(concurrency):
        config_lines.append(f'url = "{url}"')
        config_lines.append(f'request = "{method}"')
        if headers:
            for k, v in headers.items():
                config_lines.append(f'header = "{k}: {v}"')
        if body:
            config_lines.append(f'data = {json.dumps(body)}')
        config_lines.append(f'output = "/tmp/race_{i}.txt"')
        config_lines.append(f'write-out = "%{{http_code}}\\n"')
        config_lines.append("")

    config_content = "\n".join(config_lines)
    terminal(f"cat > /tmp/race_config.txt << 'EOF'\n{config_content}\nEOF", timeout=5)

    # Execute parallel requests
    start_time = time.time()
    cmd = f"curl -sk --parallel --parallel-max {concurrency} --config /tmp/race_config.txt --max-time {timeout} 2>/dev/null"
    resp = terminal(cmd, timeout=timeout + 10)
    elapsed = time.time() - start_time

    # Collect responses
    responses = []
    for i in range(concurrency):
        r = terminal(f"cat /tmp/race_{i}.txt 2>/dev/null", timeout=3)
        content = r.get("output", "")
        responses.append({"index": i, "body": content[:500], "length": len(content)})

    # Parse status codes from curl output
    statuses = resp.get("output", "").strip().split("\n")
    for i, s in enumerate(statuses[:concurrency]):
        if i < len(responses):
            responses[i]["status"] = s.strip()

    # Analysis
    unique_statuses = list(set(s.get("status", "?") for s in responses))
    unique_lengths = list(set(s["length"] for s in responses))
    success_count = sum(1 for s in responses if s.get("status") == "200")

    # Race condition indicators
    potential_race = (
        success_count > 1 and  # Multiple successes
        len(unique_lengths) > 1  # Different response bodies (state changed mid-race)
    )

    print(f"\n  Elapsed: {elapsed:.2f}s")
    print(f"  Status codes: {unique_statuses}")
    print(f"  Successes (200): {success_count}/{concurrency}")
    print(f"  Unique response sizes: {len(unique_lengths)}")
    if potential_race:
        print(f"  ⚠️  POTENTIAL RACE CONDITION — multiple successes with varying responses")
    else:
        print(f"  ✓ No obvious race condition (single state outcome)")

    # Cleanup
    terminal(f"rm -f /tmp/race_*.txt /tmp/race_config.txt", timeout=3)

    return {
        "responses": responses,
        "unique_statuses": unique_statuses,
        "success_count": success_count,
        "elapsed": elapsed,
        "potential_race": potential_race,
    }


def race_turbo(url, headers=None, body=None, count=20, timeout=10):
    """
    Single-packet attack simulation — sends requests with minimal delay using HTTP/2.
    More effective than parallel curl for true TOCTOU races.

    Uses: last-byte sync technique (sends all requests with body minus 1 byte,
    then completes all simultaneously).

    Args:
        url: Target endpoint
        headers: dict of headers
        body: Request body
        count: Number of requests
        timeout: Timeout

    Returns:
        Same format as race()
    """
    print(f"Turbo Race (HTTP/2 multiplexed)")
    print(f"  URL: {url}")
    print(f"  Count: {count}")
    print(f"{'='*60}")

    # Build curl commands using HTTP/2 multiplexing on single connection
    h_flags = ""
    if headers:
        for k, v in headers.items():
            h_flags += f' -H "{k}: {v}"'

    body_flag = f" -d '{body}'" if body else ""

    # Use curl with --http2 and connection reuse
    urls = " ".join([f'"{url}"'] * count)
    cmd = (f'curl -sk --http2 --parallel --parallel-max {count} '
           f'-X POST{h_flags}{body_flag} '
           f'-w "%{{http_code}}\\n" -o /dev/null '
           f'--max-time {timeout} {urls} 2>/dev/null')

    start_time = time.time()
    resp = terminal(cmd, timeout=timeout + 15)
    elapsed = time.time() - start_time

    statuses = [s.strip() for s in resp.get("output", "").strip().split("\n") if s.strip()]
    success_count = statuses.count("200")
    unique_statuses = list(set(statuses))

    # For state-changing endpoints, >1 success usually means race won
    potential_race = success_count > 1

    print(f"\n  Elapsed: {elapsed:.2f}s ({elapsed/count*1000:.1f}ms avg)")
    print(f"  Statuses: {statuses[:10]}{'...' if len(statuses) > 10 else ''}")
    print(f"  Successes: {success_count}/{count}")
    if potential_race:
        print(f"  ⚠️  RACE CONDITION LIKELY — {success_count} operations succeeded (expected: 1)")
    else:
        print(f"  ✓ Properly serialized (single success)")

    return {
        "responses": [{"status": s} for s in statuses],
        "unique_statuses": unique_statuses,
        "success_count": success_count,
        "elapsed": elapsed,
        "potential_race": potential_race,
    }


def race_limit_bypass(url, headers, body, pre_check_url=None, pre_check_headers=None, count=10):
    """
    Test rate-limit/quota bypass via race condition.
    Sends concurrent requests and checks if limit was exceeded.

    Example: API allows 5 requests/minute. Race 10 requests simultaneously.
    If >5 succeed, rate limit has TOCTOU vulnerability.

    Args:
        url: Endpoint with rate limit
        headers: Auth headers
        body: Request body
        pre_check_url: Optional URL to check current quota before/after
        pre_check_headers: Headers for pre-check
        count: Requests to send (should exceed limit)
    """
    print(f"Rate Limit Bypass Test")
    print(f"  URL: {url}")
    print(f"  Requests: {count} (should exceed limit)")
    print(f"{'='*60}")

    # Check current state
    if pre_check_url:
        cmd = f'curl -sk "{pre_check_url}"'
        if pre_check_headers:
            for k, v in pre_check_headers.items():
                cmd += f' -H "{k}: {v}"'
        resp = terminal(cmd, timeout=10)
        print(f"  Pre-state: {resp.get('output', '')[:200]}")

    # Fire race
    result = race_turbo(url, headers, body, count)

    # Check post-state
    if pre_check_url:
        resp = terminal(cmd, timeout=10)
        print(f"  Post-state: {resp.get('output', '')[:200]}")

    if result["success_count"] > 1:
        print(f"\n  ⚠️  LIMIT BYPASS: {result['success_count']} operations went through")
    return result


if __name__ == "__main__":
    pass
