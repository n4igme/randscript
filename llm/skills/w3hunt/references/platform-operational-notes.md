# Platform Operational Notes

## Immunefi

- **Programs churn fast** — programs get paused/removed without notice. ALWAYS verify program is live (HTTP 200 on `/bug-bounty/{slug}/information/`) before starting recon. Batch-check: `for slug in ...; do curl -sL -o /dev/null -w "%{http_code}" "https://immunefi.com/bug-bounty/${slug}/information/"; done`
- **Rate limits submissions** — new accounts limited to 1 report/day. Plan submission order: strongest first, weakest last.
- **Cloudflare blocks curl on program pages** — use `curl -sL -o /dev/null -w "%{http_code}"` for status checks. Full page content requires browser.
- **Bounty table uses virtual scrolling** — only 10 rows render at a time, URL filter params ignored. Navigate directly to `/bug-bounty/<slug>/scope/` for specific programs. Scope page has combobox to switch between "Smart Contract" and "Web & App" views.
- **Cloudflare blocks automated browsing** — aggressive bot detection. Manual scope verification may be needed. Use combobox interaction (click dropdown → select option) not button clicks.

## HackenProof

- **No submission rate limit** (unlike Immunefi's 1/day). Submit findings as soon as ready.
- **Programs page is Cloudflare-blocked** — can't access programmatically. Need user to browse manually and share target details.
- **Web3-focused** with generally smaller payouts but less competition than Immunefi.

## HackerOne

- **Triager trust issue (2026-05)** — suspected bug theft via duplicate marking (WalletOnTelegram finding). H1 activity postponed indefinitely. Prefer Intigriti/Immunefi/YesWeHack for new submissions.
- **Weakness field: pick ROOT CAUSE CWE** — only allows one CWE. For chained bugs, pick root cause (e.g., CWE-306) not enabler (e.g., CWE-307). Mention secondary CWEs in report body.
- **Shared-infrastructure bugs — DON'T split into N reports** — submit ONE report targeting highest-value asset. List all affected domains in body. Triagers hate spam.

## Intigriti

- **Login triggers reCAPTCHA for automated browsers** — bot detection blocks headless login. Workaround: use `arkadiyt/bounty-targets-data` GitHub repo (`data/intigriti_data.json`) for full program data. Google/DuckDuckGo also block from same IP — go straight to the repo.

## General Platform Rules

- **PoC required for ALL web/app bugs** — Write PoCs EXCLUSIVELY in Python (`requests` + `eth_account`), NEVER curl. Single self-contained script with actual output in comments.
- **Fix suggestion required** — many programs reject without remediation advice.
- **Don't exfiltrate data to prove SSRF impact** — Session endpoint + API map + tenant config is sufficient proof. Extracting actual user data risks policy violation.
