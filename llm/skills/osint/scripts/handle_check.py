#!/usr/bin/env python3
"""osint handle checker — parallel platform enumeration for a username."""
from hermes_tools import terminal


PLATFORMS = [
    # Developer / Security
    {"name": "GitHub", "url": "https://github.com/{}", "check": "200"},
    {"name": "GitHub API", "url": "https://api.github.com/users/{}", "check": "200"},
    {"name": "GitLab", "url": "https://gitlab.com/{}", "check": "200"},
    {"name": "Bitbucket", "url": "https://bitbucket.org/{}/", "check": "200"},
    {"name": "HackerOne", "url": "https://hackerone.com/{}", "check": "200"},
    {"name": "Bugcrowd", "url": "https://bugcrowd.com/{}", "check": "200"},
    {"name": "TryHackMe", "url": "https://tryhackme.com/r/p/{}", "check": "200"},
    {"name": "HackTheBox", "url": "https://app.hackthebox.com/profile/{}", "check": "200"},
    {"name": "CTFtime", "url": "https://ctftime.org/team/list/?q={}", "check": "200"},
    {"name": "npm", "url": "https://www.npmjs.com/~{}", "check": "200"},
    {"name": "PyPI", "url": "https://pypi.org/user/{}/", "check": "200"},
    {"name": "Docker Hub", "url": "https://hub.docker.com/u/{}", "check": "200"},
    {"name": "Keybase", "url": "https://keybase.io/{}", "check": "200"},
    # Social / Content
    {"name": "YouTube", "url": "https://youtube.com/@{}", "check": "200"},
    {"name": "TikTok", "url": "https://tiktok.com/@{}", "check": "200"},
    {"name": "Medium", "url": "https://medium.com/@{}", "check": "200"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{}", "check": "200"},
    {"name": "Telegram", "url": "https://t.me/{}", "check": "200"},
    {"name": "LinkedIn", "url": "https://linkedin.com/in/{}", "check": "200"},
    {"name": "Twitch", "url": "https://twitch.tv/{}", "check": "200"},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{}", "check": "200"},
    {"name": "Gravatar", "url": "https://en.gravatar.com/{}", "check": "200"},
    {"name": "Dev.to", "url": "https://dev.to/{}", "check": "200"},
]


def check(handle, extra_platforms=None):
    """
    Check a handle across all bot-friendly platforms.

    Args:
        handle: username to check
        extra_platforms: optional list of {"name": str, "url": str (with {}), "check": str}

    Returns:
        dict with: found (list), not_found (list), errors (list)
    """
    platforms = PLATFORMS + (extra_platforms or [])
    results = {"found": [], "not_found": [], "errors": []}

    print(f"Checking handle: {handle}")
    print(f"Platforms: {len(platforms)}")
    print("=" * 50)

    for p in platforms:
        url = p["url"].format(handle)
        resp = terminal(
            f'curl -sk -o /dev/null -w "%{{http_code}}" -L --max-time 10 "{url}"',
            timeout=15
        )
        code = resp.get("output", "").strip()

        if code == p["check"]:
            results["found"].append({"platform": p["name"], "url": url, "status": code})
            print(f"  ✓ {p['name']:12s} → {url}")
        elif code in ("000", ""):
            results["errors"].append({"platform": p["name"], "url": url, "error": "timeout"})
            print(f"  ✗ {p['name']:12s} → timeout")
        else:
            results["not_found"].append({"platform": p["name"], "url": url, "status": code})
            print(f"  - {p['name']:12s} → {code}")

    print(f"\n{'='*50}")
    print(f"Found: {len(results['found'])} | Not found: {len(results['not_found'])} | Errors: {len(results['errors'])}")

    return results


def check_variations(base_handle):
    """Check common variations of a handle."""
    variations = [
        base_handle,
        f"{base_handle}_",
        f"_{base_handle}",
        f"{base_handle}0",
        f"{base_handle}1",
        f"the{base_handle}",
        f"{base_handle}dev",
    ]

    all_found = {}
    for v in variations:
        print(f"\n--- Variation: {v} ---")
        results = check(v)
        if results["found"]:
            all_found[v] = results["found"]

    print(f"\n{'='*50}")
    print(f"SUMMARY: {len(all_found)} variations with hits")
    for v, platforms in all_found.items():
        print(f"  {v}: {', '.join(p['platform'] for p in platforms)}")

    return all_found


if __name__ == "__main__":
    pass
