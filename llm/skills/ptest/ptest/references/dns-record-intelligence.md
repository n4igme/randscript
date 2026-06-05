# DNS Record Intelligence Analysis

Extract third-party services, email security posture, and org structure from DNS records alone.

## 1. SPF Record Parsing

SPF (`v=spf1`) in TXT records reveals authorized email senders.

**Common include mappings:**
- `_spf.google.com` → Google Workspace
- `sendgrid.net` → SendGrid
- `spf.sendinblue.com` → Brevo (Sendinblue)
- `servers.mcsv.net` → Mailchimp
- `spf.protection.outlook.com` → Microsoft 365
- `amazonses.com` → AWS SES
- `mailgun.org` → Mailgun

**Bank Jago example:**
```
v=spf1 include:_spf.google.com include:spf.sendinblue.com ~all
```
→ Google Workspace for corporate email, Brevo for marketing/transactional email.

**Note:** `~all` (softfail) is weaker than `-all` (hardfail). Combined with DMARC p=none, spoofing is trivial.

## 2. DMARC Policy Analysis

DMARC record at `_dmarc.domain.com` TXT.

**Policy values:**
- `p=none` — **monitoring only, spoofing fully possible**
- `p=quarantine` — spoofed mail goes to spam
- `p=reject` — spoofed mail blocked

**Intelligence from DMARC:**
- `rua=mailto:` — aggregate report recipient, often leaks internal email addresses or reveals third-party DMARC monitoring (Valimail, Agari, dmarcian)
- `ruf=mailto:` — forensic reports, same leak potential
- `sp=` — subdomain policy (often weaker than parent)

**Bank Jago:** `p=none` = domain is **spoofable** for phishing campaigns targeting employees/customers.

## 3. MX Record Intelligence

MX records reveal email provider and organizational structure.

**Provider fingerprints:**
- `*.google.com` / `*.googlemail.com` → Google Workspace
- `*.mail.protection.outlook.com` → Microsoft 365
- `*.pphosted.com` → Proofpoint (enterprise email security)
- `*.mimecast.com` → Mimecast
- Custom hostnames → self-hosted

**Subdomain MX enumeration:**
Query MX on discovered subdomains. Active MX = active team/environment.

**Bank Jago:** MX on 6 subdomains all point to Google:
- `agent.jago.com` — agent/support team
- `dev.jago.com` — development
- `dev2.jago.com` — secondary dev environment
- `service.jago.com` — service accounts
- `tech.jago.com` — engineering
- `test.jago.com` — testing/QA

→ Reveals internal team structure and environment naming. All on Google Workspace.

## 4. TXT Record Mining

TXT records contain domain verification tokens for SaaS platforms.

**Verification patterns:**
| Pattern | Service |
|---------|---------|
| `atlassian-domain-verification=` | Atlassian (Jira/Confluence) |
| `miro-verification=` | Miro (whiteboarding) |
| `mixpanel-domain-verify=` | Mixpanel (analytics) |
| `wiz-domain-verification=` | Wiz (cloud security) |
| `aiven-domain-verification=` | Aiven (managed databases) |
| `brevo-code:` | Brevo (email marketing) |
| `google-site-verification=` | Google services |
| `MS=` | Microsoft 365 |
| `docusign=` | DocuSign |
| `facebook-domain-verification=` | Meta/Facebook |
| `hubspot-developer-verification=` | HubSpot |
| `stripe-verification=` | Stripe |

**Bank Jago TXT reveals:** Atlassian, Miro, Mixpanel, Wiz, Aiven, Brevo
→ Uses Jira/Confluence for project management, Miro for collaboration, Mixpanel for product analytics, Wiz for cloud security posture, Aiven for managed DB (Kafka/Postgres/Redis), Brevo for email campaigns.

## 5. CNAME Target Mapping

CNAMEs reveal third-party integrations and subdomain takeover candidates.

**Common CNAME targets:**
- `*.cloudfront.net` → AWS CloudFront
- `*.azurewebsites.net` → Azure App Service
- `*.herokuapp.com` → Heroku
- `*.ghost.io` → Ghost CMS
- `*.zendesk.com` → Zendesk
- `*.freshdesk.com` → Freshdesk
- `*.statuspage.io` → Atlassian Statuspage

**Subdomain takeover:** If CNAME points to a service where the resource no longer exists (dangling CNAME), attacker can claim it. High-risk targets: Heroku, GitHub Pages, AWS S3, Shopify, Fastly.

**Check:** Resolve the CNAME target. If it returns NXDOMAIN or a service "not found" page → potential takeover.

## 6. Third-Party Service Inventory (Bank Jago)

Built entirely from DNS records:

**Email & Communications:**
- Google Workspace (SPF + MX on 6 subdomains)
- Brevo/Sendinblue (SPF include + TXT verification)

**Collaboration & PM:**
- Atlassian Jira/Confluence (TXT verification)
- Miro (TXT verification)

**Analytics & Monitoring:**
- Mixpanel (TXT verification)

**Cloud & Infrastructure:**
- Wiz cloud security (TXT verification)
- Aiven managed databases (TXT verification)

**Org Structure (from subdomain MX):**
- agent, dev, dev2, service, tech, test environments

**Security Posture:**
- DMARC p=none → spoofable domain
- SPF softfail (~all) → weak enforcement
- No evidence of email gateway (Proofpoint/Mimecast)

## Quick Commands

```bash
# Full TXT dump
dig +short TXT domain.com

# DMARC
dig +short TXT _dmarc.domain.com

# SPF (in TXT)
dig +short TXT domain.com | grep spf

# MX
dig +short MX domain.com

# Subdomain MX check
for sub in agent dev dev2 service tech test; do
  echo "=== $sub ===" && dig +short MX $sub.domain.com
done

# CNAME check
dig +short CNAME subdomain.domain.com
```
