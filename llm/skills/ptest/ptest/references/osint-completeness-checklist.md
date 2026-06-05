# OSINT Completeness Checklist

## Purpose
Prevents shallow OSINT. Before marking Phase 1 OSINT as DONE, verify ALL applicable techniques were executed — not just the quick wins.

## Mandatory OSINT Techniques (Web Scope)

### DNS & Domain Intelligence
- [ ] WHOIS (registrar, dates, privacy status)
- [ ] DNS records (A, AAAA, MX, TXT, NS, CNAME)
- [ ] TXT record analysis (SPF includes, domain verifications → reveals services)
- [ ] Certificate Transparency (crt.sh)
- [ ] Subfinder / Amass passive enumeration
- [ ] Merge and deduplicate all subdomain sources

### Code & Secret Leaks
- [ ] GitHub code search (`domain.com` in public repos)
- [ ] GitHub org/user search (official repos)
- [ ] Docker Hub organization check
- [ ] Pastebin / paste site search
- [ ] Google dorking (site:, filetype:, inurl:, intitle:)

### Historical & Archived Data
- [ ] Wayback Machine CDX API (full URL dump)
- [ ] Filter Wayback URLs for interesting paths (api, admin, config, env, internal, staging, graphql, actuator, .json, auth, dashboard, test, dev, swagger, docs, health, socket, webhook)

### Infrastructure Intelligence
- [ ] Shodan InternetDB for all non-CDN IPs
- [ ] Censys (if Shodan lacks data)
- [ ] Cloud provider identification (AWS, GCP, Azure)
- [ ] S3 bucket enumeration (from JS bundles, DNS)
- [ ] CloudFront distribution probing

### Application Intelligence
- [ ] JavaScript bundle analysis (download ALL chunks, grep for URLs, secrets, API endpoints)
- [ ] Next.js `_buildManifest.js` → full route map
- [ ] Angular/React chunk analysis for hardcoded configs
- [ ] Firebase config extraction (`/__/firebase/init.json`)
- [ ] `.well-known/assetlinks.json` (Android app packages)
- [ ] `apple-app-site-association` (iOS app config)
- [ ] API documentation scraping (official docs site)
- [ ] Statuspage component enumeration (reveals service architecture)

### Mobile App Intelligence
- [ ] Identify app package names (assetlinks.json, App Store lookup)
- [ ] APK download and decompilation (jadx) — extract endpoints, secrets, cert pinning config
- [ ] iOS IPA analysis if accessible

### Third-Party Service Mapping
- [ ] Email provider (MX records → Mimecast, Google, O365)
- [ ] Analytics (Mixpanel, Amplitude, Segment from JS)
- [ ] Error tracking (Sentry, Datadog, TrackJS from JS)
- [ ] Push notifications (Firebase, MoEngage from JS)
- [ ] Support/helpdesk (Zendesk, Freshdesk, ManageEngine)
- [ ] CI/CD (GitHub Actions, Jenkins, ArgoCD from subdomains)

### Employee & Organization
- [ ] LinkedIn job postings (reveals tech stack, internal tools)
- [ ] Employee email pattern discovery

### Dark Web & Breach Data (see `dark-web-breach-osint.md` for full methodology)
- [ ] Breach database search — HIBP domain check (free, mandatory)
- [ ] Breach database search — DeHashed/IntelX/LeakCheck (paid, if available)
- [ ] Paste site search (IntelX, Google dorks for pastebin/paste.ee/justpaste.it)
- [ ] Dark web search via clearnet gateways (Ahmia.fi, IntelX media:24)
- [ ] Ransomware leak site check (ransomware.live API)
- [ ] Threat intel feeds (DeepDarkCTI repo grep for target)
- [ ] GitHub/GitLab/Postman public search for leaked secrets

## Bug Bounty Specific
- [ ] Check program scope page for exact in/out scope definitions
- [ ] Identify staging/dev domains from JS bundles (may be out of scope but useful for intelligence)
- [ ] Check for `security.txt` / responsible disclosure policy
- [ ] Note any VDP/bounty-specific exclusions

## Key Lesson (CoinDCX Session, 2026-05-21)
Initial OSINT missed: GitHub search, Google dorking, Wayback Machine, mobile APK analysis, full JS bundle scanning, API docs scraping, and staging domain discovery. The staging domain (dcxstage.com) was only found by downloading and analyzing Next.js chunks — not from DNS/CT sources. Always analyze JS bundles early — they contain the real endpoint map.
