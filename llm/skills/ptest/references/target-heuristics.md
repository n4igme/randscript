# Target Assessment Heuristics

Decision rules for when to continue testing vs. move on. Apply during Phases 3-6.

## Fast-Exit Rules

- **Hardened Target Fast-Exit** — if first 3 vectors fail cleanly, mark as "hardened" and move on (15-20 min max). **Exception:** Always check pre-auth flows (OTP, login, registration, password reset).
- **Zero-Finding Close-Out Path** — if Phase 5 concludes with 0 exploitable vectors, fast-track Phases 6-8 with a close-out report.
- **RBAC Mesh Fast-Exit** — 50+ subdomains all returning identical 403 = mesh-blocked. Confirm on 10-15 hosts, then move on (30 min cap).

## Blocker Handling

- **Captcha-Gated Assessment** — assess within 10 minutes: server-validated? bypass paths? non-prod enforcement? If no bypass, document as blocker.
- **Account Creation Blockers** — document limitation, offer user options (manual signup, OAuth, API registration). Never bypass KYC.

## False Positive Detection

- **SPA Catch-All Detection** — compare response size of target path vs random nonexistent path. Same size = false positive.
- **False Positive Verification** — check for SPA catch-alls, CORS crashes, 302-to-login. See `references/false-positive-detection.md`.
