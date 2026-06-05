#!/usr/bin/env python3
"""opsec exposure_check — automated git email audit + platform presence check.

Usage:
    python3 exposure_check.py --github-user <handle>
    python3 exposure_check.py --github-user <handle> --check-platforms
    python3 exposure_check.py --github-user <handle> --output /path/to/results.md
"""
import argparse
import json
import subprocess
import sys
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError


PLATFORM_URLS = {
    "GitHub": "https://github.com/{handle}",
    "HackerOne": "https://hackerone.com/{handle}",
    "Bugcrowd": "https://bugcrowd.com/{handle}",
    "TryHackMe": "https://tryhackme.com/r/p/{handle}",
    "YouTube": "https://youtube.com/@{handle}",
    "TikTok": "https://tiktok.com/@{handle}",
    "Medium": "https://medium.com/@{handle}",
    "Reddit": "https://reddit.com/user/{handle}",
    "Telegram": "https://t.me/{handle}",
    "Keybase": "https://keybase.io/{handle}",
}


def fetch_json(url):
    """Fetch JSON from URL. Returns dict or None."""
    try:
        req = Request(url, headers={"User-Agent": "opsec-check/1.0"})
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except (HTTPError, URLError, json.JSONDecodeError):
        return None


def git_email_audit(github_user):
    """Extract all emails from GitHub commits across public repos."""
    print(f"\n[*] Git email audit for: {github_user}")
    print("=" * 50)

    # Fetch repos
    repos_url = f"https://api.github.com/users/{github_user}/repos?per_page=100&type=owner"
    repos = fetch_json(repos_url)
    if not repos:
        print("  ✗ Could not fetch repos (rate limited or user not found)")
        return []

    emails_found = set()
    names_found = set()

    for repo in repos:
        if repo.get("fork"):
            continue
        repo_name = repo["name"]
        commits_url = f"https://api.github.com/repos/{github_user}/{repo_name}/commits?per_page=30"
        commits = fetch_json(commits_url)
        if not commits or not isinstance(commits, list):
            continue

        for commit in commits:
            c = commit.get("commit", {})
            for field in ("author", "committer"):
                info = c.get(field, {})
                email = info.get("email", "")
                name = info.get("name", "")
                if email and "noreply" not in email.lower():
                    emails_found.add(email)
                    if name:
                        names_found.add(f"{name} <{email}>")

    # Report
    if emails_found:
        print(f"\n  🔴 Exposed emails ({len(emails_found)}):")
        for e in sorted(emails_found):
            noreply_suggestion = "→ EXPOSED" if "@users.noreply" not in e else "→ OK (noreply)"
            print(f"    - {e} {noreply_suggestion}")
    else:
        print("  ✓ No real emails found in commits (using noreply or no public repos)")

    if names_found:
        print(f"\n  Names associated:")
        for n in sorted(names_found):
            print(f"    - {n}")

    return list(emails_found)


def check_platforms(handle):
    """Check handle presence on bot-friendly platforms."""
    print(f"\n[*] Platform presence check for: {handle}")
    print("=" * 50)

    found = []
    not_found = []

    for platform, url_template in PLATFORM_URLS.items():
        url = url_template.format(handle=handle)
        try:
            req = Request(url, headers={"User-Agent": "opsec-check/1.0"})
            with urlopen(req, timeout=8) as resp:
                if resp.status == 200:
                    found.append((platform, url))
                    print(f"  ✓ {platform}: {url}")
        except HTTPError as e:
            if e.code == 404:
                not_found.append(platform)
            else:
                not_found.append(f"{platform} (HTTP {e.code})")
        except (URLError, TimeoutError):
            not_found.append(f"{platform} (timeout)")

    print(f"\n  Found: {len(found)} | Not found: {len(not_found)}")
    return found


def check_profile_crosslinks(github_user):
    """Check GitHub profile for cross-links to other identities."""
    print(f"\n[*] Profile cross-link check: {github_user}")
    print("=" * 50)

    user_data = fetch_json(f"https://api.github.com/users/{github_user}")
    if not user_data:
        print("  ✗ Could not fetch profile")
        return []

    links = []
    fields = {
        "blog": user_data.get("blog", ""),
        "twitter_username": user_data.get("twitter_username", ""),
        "bio": user_data.get("bio", ""),
        "company": user_data.get("company", ""),
        "location": user_data.get("location", ""),
        "email": user_data.get("email", ""),
    }

    for field, value in fields.items():
        if value:
            links.append((field, value))
            severity = "🟠" if field in ("email", "company", "twitter_username") else "🟡"
            print(f"  {severity} {field}: {value}")

    if not links:
        print("  ✓ No cross-links exposed on profile")

    return links


def write_report(output_path, github_user, emails, platforms, crosslinks):
    """Write results to markdown file."""
    with open(output_path, "w") as f:
        f.write(f"# OPSEC Exposure Check — {github_user}\n\n")
        f.write(f"**Date:** {__import__('datetime').datetime.now().isoformat()}\n\n")

        f.write("## Git Email Audit\n\n")
        if emails:
            for e in sorted(emails):
                f.write(f"- 🔴 {e}\n")
        else:
            f.write("- ✓ Clean (noreply or no commits)\n")

        f.write("\n## Platform Presence\n\n")
        if platforms:
            for plat, url in platforms:
                f.write(f"- ✓ [{plat}]({url})\n")
        else:
            f.write("- No platforms checked\n")

        f.write("\n## Profile Cross-Links\n\n")
        if crosslinks:
            for field, value in crosslinks:
                f.write(f"- {field}: {value}\n")
        else:
            f.write("- ✓ Clean\n")

        f.write("\n## Recommendations\n\n")
        if emails:
            f.write("- [ ] Set `git config --global user.email` to noreply address\n")
            f.write("- [ ] Consider git-filter-repo to rewrite history\n")
        if crosslinks:
            f.write("- [ ] Remove cross-links from GitHub profile sidebar\n")

    print(f"\n[*] Report written: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="OPSEC exposure check")
    parser.add_argument("--github-user", required=True, help="GitHub username to audit")
    parser.add_argument("--check-platforms", action="store_true", help="Check handle on platforms")
    parser.add_argument("--output", help="Write report to file")
    args = parser.parse_args()

    emails = git_email_audit(args.github_user)
    crosslinks = check_profile_crosslinks(args.github_user)

    platforms = []
    if args.check_platforms:
        platforms = check_platforms(args.github_user)

    if args.output:
        write_report(args.output, args.github_user, emails, platforms, crosslinks)

    # Summary
    print(f"\n{'=' * 50}")
    print(f"Summary: {len(emails)} emails exposed, {len(crosslinks)} cross-links, "
          f"{len(platforms)} platform presences")
    if emails:
        print("⚠ ACTION NEEDED: exposed emails in git history")


if __name__ == "__main__":
    main()
