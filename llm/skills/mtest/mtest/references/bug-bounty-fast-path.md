# Bug Bounty Fast-Path

Optimized workflow for finding one Critical/High fast. Use this instead of the full 10-phase framework when hunting bounties.

---

## Bug Bounty Fast-Path

When hunting for bounties (not doing comprehensive internal pentest), optimize for finding one Critical/High fast:

**Speed run order:**
1. **Phase 2 (Static)** — 30 min max. Extract: deep links, exported components, WebView + JS bridge, hardcoded secrets, API endpoints. Stop when you have targets.
2. **Phase 3 (Bypass)** — only if needed for traffic capture. If no pinning → skip entirely.
3. **Phase 4 (Traffic)** — 15 min. Capture login + one financial flow. Note sequential IDs.
4. **Skip Phase 5** — you already know what to hit from Phase 2.
5. **Phase 7 (Vuln Analysis)** — go straight to highest-value features:
   - Deep link + WebView + JS bridge → RCE chain (Critical)
   - IDOR on financial/PII endpoints (High-Critical)
   - Race condition on transfers (High)
   - Auth bypass / OTP bypass (Critical)
6. **Phase 9 (Exploit)** — prove it, write PoC, submit.

**What to skip in bug bounty:**
- Phase 1 formality (just note the package name and go)
- Phase 5 formal attack surface map (mental model is enough)
- Phase 6 exhaustive runtime testing (only test what Phase 2 flagged)
- Phase 8 comprehensive API testing (only test IDOR + auth bypass)
- Phase 10 formal report (use program's submission template)

**Time budget:** 4-8 hours per app. If no High+ finding by hour 6, move to next target.

---

## When to Bail: Hardened App Indicators

Some apps (Meta, banking with server-side sig validation) are not viable for unauthenticated mobile-only testing. Bail early if ALL of these are true:

1. **Server-side APK signature validation** — repackaged APK can't login
2. **No exploitable deep link → WebView → JS bridge chain** — deep links route to native UI or sanitize URLs
3. **Content providers signature-protected at runtime** — even if `exported=true`
4. **No IDOR testable** — can't intercept authenticated traffic

**Decision point:** After Phase 2 static + Phase 6 deep link testing (max 4 hours), if no High+ vector found, pivot to:
- Web scope of the same program (*.domain.com)
- Different target app in the same program
- Different bug bounty program entirely

**Meta/Instagram specifically:** Server-side sig validation + native UI deep links + signature-protected providers = mobile app is a dead end without insider access or novel bypass. Web targets are more productive.

---