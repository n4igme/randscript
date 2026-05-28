# Dropbox Infrastructure & Program Intel

> **⚠️ HISTORICAL CONTEXT — NOT CURRENT STATE**
> This file documents observations from 2026-05-27. Infrastructure changes constantly.
> Always run fresh recon and compare against this baseline. Differences from what's
> documented here are investigation-worthy — they indicate changes worth exploring.
> Do NOT skip recon steps because "we already know the stack."

## Program Details
- **Platform:** Intigriti
- **URL:** https://app.intigriti.com/researcher/programs/dropbox/dropbox/detail
- **Type:** Public, Open
- **Bounty range:** $100–$15,000 (3 tiers)
- **Acceptance rate:** ~10% (143/1405 submissions)
- **Avg response:** <5 days first response, <1 week triage, <2 weeks decision

## Tier Structure
| Tier | Low | Medium | High | Critical | Exceptional |
|------|-----|--------|------|----------|-------------|
| Tier 1 | $100-500 | $500-1K | $1K-5K | $5K-10K | $10K-15K |
| Tier 2 | $100-250 | $250-750 | $750-2.5K | $2.5K-7.5K | $7.5K-10K |
| Tier 3 | $100 | $100-500 | $500-2K | $2K-5K | $5K-7.5K |

## Rules of Engagement
- **Email:** @intigriti.me required
- **User-Agent:** `Intigriti - <username> - <user agent>`
- **Header:** `X-Intigriti-Username: {Username}`
- **Rate limit:** max 5 requests/sec
- **RCE reports:** must include timestamp, IP address

## Scope (Partial — full list requires login)
- **In scope:** Any report demonstrating security impact to Dropbox assets/domains
- **Out of scope:** FormSwift, Dropbox Passwords, Capture Desktop Apps (Win/Mac), com.dropbox.paper (Android), 1126623662 (iOS)
- **Out of scope domains:** Any not listed in the Domains section
- **AI exclusions:** Third-party AI model abuse → report to AI developer; leaked AI API keys → report to AI developer; verification tokens in ./well-known/ai-plugin.json

## CDN / WAF / Load Balancing
- **Primary CDN:** Cloudflare (community, sign, dash, fax, events)
- **Secondary CDN:** Amazon CloudFront (most subdomains)
- **Load Balancer:** TLB (TikTok Load Balancer) on www.dropbox.com, Envoy on core services
- **WAF behavior:** Cloudflare blocks nuclei/automated scanners silently (hangs forever)
- **Anti-bot:** Custom `dropboxcaptcha.com` iframe on signup/login forms
- **Fingerprinting:** `fp.dropbox.com` = FingerprintJS Pro (v2 API, `requestId` in responses)

## Tech Stack by Product

### Core (www.dropbox.com)
- Server: Envoy
- Features: HSTS, HTTP/3, PayPal integration
- API: `api.dropboxapi.com` (v2, all endpoints require Bearer token)
- Content: `content.dropboxapi.com` (file upload/download)
- Notify: `notify.dropboxapi.com` (longpoll, validates cursor format without auth)
- Client: `client-web.dropbox.com` (same as www)

### Internal Portal (app.dropboxer.net)
- Server: nginx 1.26.3
- Backend: Django (admin panel at /admin/)
- Auth: Okta SSO (org: `dropbox.okta.com`, client_id: `0oab3gdwm3DUBIR0e4x7`)
- Health: `/health`, `/health/live`, `/health/ready`, `/healthz` (200 without auth)
- Paths found (all auth-gated): `/dig`, `/docs`, `/donate`, `/events`, `/flows`, `/foundation`, `/friends`, `/glossary`, `/opensource`, `/records`, `/snippets`, `/updates`
- Internal docs: `/binder/`, `/binder/eng-career`

### Community Forum (community.dropbox.com)
- Platform: Vanilla Forums v2026.008 (Higher Logic)
- Hosted at: `dropbox.vanilladevelopment.com`
- Cookie: `vf_dropbox-tr_GFLRI`
- Site ID: 6038715
- Registration: OAuth Connect (Dropbox SSO)
- **API is PUBLIC (no auth required for read operations)**
- Users: 10,000+ (pagination capped at 10,000)
- Employees: 1,659 with "Dropboxer" role (roleID: 1019)
- Dev instance: `community-dev.dropbox.com` (46 users, PHP errors exposed, OAuth client_id: `alez4x93nx2u1h6`)

### Dropbox Sign (HelloSign)
- App: `app.hellosign.com`
- Server: Envoy
- API: `api.hellosign.com/v3/` (requires auth, returns clean JSON errors)
- Marketing: `sign.dropbox.com`, `sign-staging.dropbox.com` (Webflow)
- Cookie: `hf_ref` (domain: hellosign.com)

### DocSend
- App: `app.docsend.com` (redirects to docsend.com)
- Server: Heroku
- Protection: Cloudflare challenge page on www.docsend.com
- Document format: `/view/XXXXXX` (6-char, returns 404 for invalid)
- GraphQL: exists (401 without auth)

### Dropbox Fax (HelloFax)
- App: `app.hellofax.com`
- Server: Envoy
- Redirects to `/account/logIn` without session
- Marketing: `fax.dropbox.com` (Cloudflare + Webflow)

### Dropbox Capture
- URL: `capture.dropbox.com`
- Hosting: Amazon S3 + CloudFront
- Frontend: React SPA (catches all routes with 200)
- JS bundles: `/captureWebInit.js`, `/main.*.js`, `/runtime.*.js`
- Sharing URLs: `/c/XXXXX`, `/watch/XXXXX` (all return SPA shell)

### Dropbox Paper
- URL: `paper.dropbox.com` (redirects to dropbox.com/paper)
- Numbered subdomains: `1-99.paper.dropbox.com` (all 200, Envoy)
- API: `/ep/api/v1/docs` (404)

### Dropbox Dash
- URL: `dash.dropbox.com`
- Staging: `dash-staging.dropbox.com` (same Webflow content)
- Stack: Cloudflare + jQuery + jsDelivr

### Investors
- URL: `investors.dropbox.com`
- Stack: Drupal 10, Acquia Cloud, PHP
- Locked: `/user/login` → 403, `/admin` → 403, `/jsonapi` → 403

## Internal Services (dropboxer.net — all 403 on ELB)
- `dbx-kratos-{dev,prod}-api[-{use2,usw2}].dropboxer.net` — Identity/auth (Ory Kratos)
- `dbx-ldap-{dev,stage,prod}-api[-{use2,usw2,ew1}].dropboxer.net` — LDAP service
- `dbx-tempo-dev[-use2].dropboxer.net` — Tempo service
- `dcd-mcp-{dev,stage,prod}[-use2,usw2].dropboxer.net` — MCP service
- `echobot-live-dev-api[-usw2].dropboxer.net` — Bot service
- `wallarm-devapi.dropboxer.net` — Wallarm WAF management
- `thedirectory.dropboxer.net` — Employee directory?

## Staging Environments (Basic Auth — Apache behind CloudFront)
- `blog-stg.dropbox.com` (401)
- `brandpartners-stg.dropbox.com` (401)
- `developers-stg.dropbox.com` (401)
- `experience-stg.dropbox.com` (401)
- `help-stg.dropbox.com` (401)
- `safety-stg.dropbox.com` (401)
- Common creds tested (admin:admin, staging:staging, etc.) — all failed

## S3 Buckets (all 403 — exist but locked)
- dropbox, dropbox-uploads, dropbox-backup, dropbox-dev, dropbox-prod, dropbox-assets
- hellosign, hellofax

## Subdomain Stats
- `dropbox.com` — 2,548 subdomains
- `dropboxer.net` — 160 subdomains
- `dropboxpartners.com` — 16 subdomains
- **Total:** 2,724 subdomains, 184 live hosts

## Security Posture Assessment
- **CORS:** No reflection on any tested endpoint
- **Open Redirect:** All properly validated (login cont= doesn't redirect externally)
- **OAuth:** redirect_uri validated server-side (tested on HelloSign)
- **S3:** All buckets deny ListBucket and GetObject
- **Subdomain Takeover:** No dangling CNAMEs found
- **SSRF:** CloudFront WAF blocks metadata requests
- **XSS:** dalfox found nothing on community search
- **GraphQL:** Not exposed on www/client-web (404)
- **DMARC:** `p=reject` (properly enforced)

## Known Weaknesses (Reportable)
1. Vanilla Forums API exposes user data without auth (community.dropbox.com)
2. Employee enumeration via roleID filter (1,659 Dropboxers)
3. Dev instance exposed with PHP errors (community-dev.dropbox.com)

## Authenticated Testing Priorities (TODO)
1. `save_url` API endpoint — potential SSRF (requires auth token)
2. Shared link access controls — IDOR on `/scl/fi/` format links
3. File requests — access control on `/request/` URLs
4. Team/organization privilege escalation
5. Dropbox Sign embedded signing — token prediction/reuse
6. Paper collaboration — unauthorized document access
7. Transfer links — enumeration of active transfers

## Useful Endpoints for Authenticated Phase
- `POST /2/files/save_url` — URL import (SSRF candidate, needs `X-Dropbox-Uid`)
- `POST /2/sharing/get_shared_link_metadata` — shared link info
- `POST /2/files/list_folder/longpoll` — accepts cursor without auth token (notify.dropboxapi.com)
- `GET /api/v2/users?roleID=1019` — employee enumeration (community)
