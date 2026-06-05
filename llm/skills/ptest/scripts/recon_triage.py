#!/usr/bin/env python3
"""ptest recon triage — parse recon output, match proven patterns, output prioritized attack list.

Usage:
    from recon_triage import triage
    attacks = triage("./ptest-output")
"""
from hermes_tools import terminal, read_file, write_file
import json
import re
import os

# Pattern rules: (signal, attack_type, severity, description)
PATTERN_RULES = [
    # Tech stack → attack
    (r"spring|actuator|java", "actuator_exposure", "high", "Spring Boot → check /actuator/*, heapdump, path traversal bypass"),
    (r"graphql|graphiql|apollo", "graphql_introspection", "high", "GraphQL → introspection, mutation fuzzing, batching attacks"),
    (r"wordpress|wp-content|wp-json", "wordpress_exploit", "medium", "WordPress → xmlrpc, user enum, plugin vulns, wp-json IDOR"),
    (r"next\.js|nextjs|_next/", "nextjs_ssrf", "high", "Next.js → API routes SSRF, middleware bypass, _next/data exposure"),
    (r"laravel|artisan|APP_KEY", "laravel_debug", "high", "Laravel → debug mode RCE, .env exposure, deserialization"),
    (r"django|csrfmiddleware|wsgi", "django_debug", "medium", "Django → DEBUG=True, admin panel, SSTI in templates"),
    (r"flask|werkzeug|jinja", "flask_debug", "high", "Flask → Werkzeug debugger RCE, SSTI, PIN brute"),
    (r"express|node|npm", "nodejs_prototype", "medium", "Node.js → prototype pollution, SSRF via request libs"),
    (r"keycloak|oauth|openid", "oauth_bypass", "high", "OAuth/OIDC → redirect_uri bypass, token leakage, scope escalation"),
    (r"supabase|firebase", "baas_misconfig", "high", "BaaS → RLS bypass, public buckets, auth bypass"),

    # Infrastructure → attack
    (r"aws|amazonaws|s3\.", "aws_enum", "high", "AWS → S3 bucket ACL, metadata SSRF, IAM escalation"),
    (r"gcp|googleapis|appspot", "gcp_enum", "high", "GCP → bucket enum, SA key exposure, metadata"),
    (r"azure|blob\.core|microsoft", "azure_enum", "medium", "Azure → blob storage, managed identity, tenant info"),
    (r"kubernetes|k8s|kubectl|helm", "k8s_exploit", "critical", "K8s → exposed API, dashboard, etcd, service account tokens"),
    (r"docker|container|registry", "container_escape", "high", "Container → registry exposure, mounted secrets, escape paths"),

    # Specific signals → immediate attacks
    (r"\.git/|\.svn/|\.hg/", "source_leak", "critical", "VCS exposed → full source download, secret extraction"),
    (r"\.env|config\.json|\.aws/credentials", "secret_file", "critical", "Config file exposed → credentials, API keys"),
    (r"swagger|openapi|api-docs", "api_fuzzing", "high", "API docs exposed → full endpoint map, auth bypass testing"),
    (r"debug|stacktrace|traceback", "debug_info", "medium", "Debug info → internal paths, versions, error-based injection"),
    (r"phpmyadmin|adminer|phpinfo", "admin_panel", "high", "Admin tool exposed → default creds, direct DB access"),
    (r"jenkins|gitlab|bamboo|circleci", "cicd_exploit", "critical", "CI/CD exposed → RCE via pipeline, secret extraction"),
    (r"grafana|prometheus|kibana", "monitoring_exploit", "high", "Monitoring exposed → data leakage, SSRF, auth bypass"),
    (r"elasticsearch|solr|redis|mongo", "db_exposed", "critical", "Database exposed → unauthenticated access, data dump"),
    (r"websocket|wss://|socket\.io", "websocket_attack", "medium", "WebSocket → auth bypass, CSWSH, injection via messages"),
    (r"upload|file.*upload|multipart", "file_upload", "high", "File upload → unrestricted type, path traversal, web shell"),
    (r"jwt|bearer|token", "jwt_attack", "high", "JWT → none alg, key confusion, claim manipulation"),
    (r"cors.*origin|access-control", "cors_exploit", "high", "CORS misconfiguration → credential theft, cross-origin data access"),
    (r"redirect|callback|return.*url", "open_redirect", "medium", "Redirect parameter → open redirect, OAuth token theft"),
    (r"xml|soap|wsdl", "xxe_attack", "high", "XML processing → XXE, SSRF via external entities"),
]


def _score_attack(attack_type, hit_count, severity):
    """Score an attack for prioritization."""
    sev_scores = {"critical": 10, "high": 7, "medium": 4, "low": 1}
    return sev_scores.get(severity, 0) * hit_count


def triage(workdir="./ptest-output", output_file=None):
    """
    Parse all recon output files and generate prioritized attack list.

    Args:
        workdir: Engagement output directory
        output_file: Optional path to write attack list (default: {workdir}/attack-plan.md)

    Returns:
        list of dicts: [{attack_type, severity, description, score, signals}]
    """
    if not output_file:
        output_file = f"{workdir}/attack-plan.md"

    print(f"Recon Triage")
    print(f"Workdir: {workdir}")
    print(f"{'='*60}")

    # Gather all recon content
    all_content = ""
    files_read = 0

    # Read all text files in recon directories
    for subdir in ["recon-passive", "recon-active", "enumeration", "attack-surface"]:
        dirpath = f"{workdir}/{subdir}"
        listing = terminal(f"find {dirpath} -type f -name '*.txt' -o -name '*.md' -o -name '*.json' 2>/dev/null", timeout=5)
        if listing.get("exit_code") == 0:
            for filepath in listing.get("output", "").strip().split("\n"):
                if filepath:
                    result = read_file(filepath)
                    if result and result.get("content"):
                        all_content += result["content"] + "\n"
                        files_read += 1

    # Also check js-analysis.json
    js_path = f"{workdir}/recon-passive/js-analysis.json"
    result = read_file(js_path)
    if result and result.get("content"):
        all_content += result["content"] + "\n"
        files_read += 1

    if not all_content:
        print("  No recon output found. Run recon phases first.")
        return []

    print(f"  Parsed {files_read} recon files ({len(all_content)} chars)")

    # Match patterns
    attacks = {}
    content_lower = all_content.lower()

    for signal, attack_type, severity, description in PATTERN_RULES:
        matches = re.findall(signal, content_lower)
        if matches:
            if attack_type not in attacks:
                attacks[attack_type] = {
                    "attack_type": attack_type,
                    "severity": severity,
                    "description": description,
                    "signals": [],
                    "hit_count": 0,
                }
            attacks[attack_type]["hit_count"] += len(matches)
            attacks[attack_type]["signals"].extend(list(set(matches))[:5])

    # Score and sort
    attack_list = list(attacks.values())
    for a in attack_list:
        a["score"] = _score_attack(a["attack_type"], a["hit_count"], a["severity"])
        a["signals"] = list(set(a["signals"]))[:5]

    attack_list.sort(key=lambda x: x["score"], reverse=True)

    # Generate output
    print(f"\n  PRIORITIZED ATTACK PLAN ({len(attack_list)} vectors):")
    md = f"# Attack Plan\n\nGenerated from recon triage. {files_read} files analyzed.\n\n"
    md += "| # | Severity | Attack | Score | Description |\n"
    md += "|---|----------|--------|-------|-------------|\n"

    for i, a in enumerate(attack_list, 1):
        icon = "🔴" if a["severity"] == "critical" else "🟠" if a["severity"] == "high" else "🟡"
        print(f"  {icon} #{i} [{a['severity'].upper()}] {a['attack_type']} (score:{a['score']})")
        print(f"       {a['description']}")
        md += f"| {i} | {a['severity'].upper()} | {a['attack_type']} | {a['score']} | {a['description']} |\n"

    md += f"\n## Signal Details\n\n"
    for a in attack_list[:15]:
        md += f"### {a['attack_type']}\n- Signals: `{'`, `'.join(a['signals'][:5])}`\n- Action: {a['description']}\n\n"

    write_file(output_file, md)
    print(f"\n  Written to: {output_file}")

    return attack_list


if __name__ == "__main__":
    pass
