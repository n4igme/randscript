#!/usr/bin/env python3
"""Shared confidence scoring for all security skill findings.

Confidence levels:
  HIGH   — confirmed via multiple independent signals (3x retry, cross-validation, actual exploitation)
  MEDIUM — single strong signal with no contradicting evidence
  LOW    — heuristic match, needs manual verification

Usage:
    from confidence import score_finding, CONFIDENCE_RULES

    finding["confidence"] = score_finding(finding)
"""

# Confidence assignment rules by finding type
CONFIDENCE_RULES = {
    # Type → (default_confidence, upgrade_condition, downgrade_condition)
    "sqli_time_blind": ("medium", "3/3 retries consistent", "1/3 retries or WAF present"),
    "sqli_error_based": ("high", "DB error string in non-WAF response", "WAF block page mentioning SQL"),
    "ssti": ("high", "Template expression evaluated (input≠output)", "Expression reflected as-is"),
    "nosqli": ("medium", "Response significantly larger with operator", "Size difference < 2x"),
    "mass_assignment": ("high", "Field persisted and readable", "200 status but field not in GET response"),
    "ssrf": ("high", "AWS metadata / internal data in response", "Timeout or generic error"),
    "jwt_none_alg": ("high", "200 response with valid user data", "200 but empty/error body"),
    "jwt_empty_sig": ("high", "200 response with valid user data", "200 but different data than real token"),
    "vertical_escalation": ("high", "Admin data in response with user token", "200 but generic/empty response"),
    "auth_bypass_header": ("high", "Full data access via bypass", "200 but redirect/login page"),
    "auth_bypass_path": ("medium", "Different response than 403 for path variant", "Same response as blocked"),
    "cors_credential_steal": ("high", "Origin reflected + credentials: true", "Reflected without credentials"),
    "csp_stale_domain": ("high", "DNS NXDOMAIN confirmed for CSP domain", "Domain resolves but is unused"),
    "subdomain_takeover": ("high", "Service signature matches + CNAME dangling", "CNAME exists but target responds"),
    "open_redirect": ("high", "3xx to attacker domain confirmed", "Redirect to same domain/filtered"),
    "crlf_injection": ("medium", "Injected header in response", "Header appears in body not headers"),
    "race_condition": ("high", "Multiple successes on idempotent operation", "Single success"),
    "bola_idor": ("high", "Other user's PII in response", "200 but own data returned"),
    "xss": ("high", "Payload executes (reflected unencoded)", "Payload reflected but encoded"),
    "source_map_exposed": ("high", "sourcesContent present in response", "404 or empty map"),
    "webview_url_injection": ("high", "WebView opened with attacker URL", "Activity launched but no WebView"),
    "clipboard_read": ("medium", "Logcat shows clipboard access", "No clear evidence of read"),
    "no_auth_required": ("high", "200 with data, no token sent", "200 but login page returned"),
}


def score_finding(finding):
    """
    Assign confidence to a finding based on its type and evidence quality.

    Args:
        finding: dict with at minimum: type, severity

    Returns:
        str: "high", "medium", or "low"
    """
    ftype = finding.get("type", "")
    rule = CONFIDENCE_RULES.get(ftype)

    if not rule:
        # Default scoring based on evidence presence
        if finding.get("evidence") and len(finding.get("evidence", "")) > 50:
            return "medium"
        return "low"

    default_confidence = rule[0]

    # Upgrade/downgrade based on evidence quality
    evidence = finding.get("evidence", "") + finding.get("detail", "")

    # Upgrade indicators
    if any(x in evidence.lower() for x in ["confirmed", "3/3", "persisted", "metadata", "credential"]):
        return "high"

    # Downgrade indicators
    if any(x in evidence.lower() for x in ["timeout", "inconsistent", "waf", "blocked", "1/3"]):
        return "low"

    return default_confidence


def format_finding_with_confidence(finding):
    """Add confidence and format for output."""
    if "confidence" not in finding:
        finding["confidence"] = score_finding(finding)
    return finding


def filter_high_confidence(findings):
    """Return only high/medium confidence findings (skip low)."""
    return [f for f in findings if f.get("confidence", "low") in ("high", "medium")]


def summary_with_confidence(findings):
    """Generate summary grouped by confidence level."""
    high = [f for f in findings if f.get("confidence") == "high"]
    medium = [f for f in findings if f.get("confidence") == "medium"]
    low = [f for f in findings if f.get("confidence") == "low"]
    return {
        "total": len(findings),
        "high_confidence": len(high),
        "medium_confidence": len(medium),
        "low_confidence": len(low),
        "submit_ready": high,  # These can be submitted immediately
        "needs_verification": medium,  # Need manual confirmation
        "likely_false_positive": low,  # Probably noise
    }
