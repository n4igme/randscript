# Meta Bug Bounty — Auth Attack Surface

## Program Overview
- URL: https://bugbounty.meta.com
- Payouts: $300K (Mobile RCE), $130K (ATO), $20K (2FA bypass), $10K (contact deanonymisation), $500 min
- Scope: Facebook, Instagram, WhatsApp, Messenger, Meta Quest, Ray-Ban, Meta AI, open source
- Hacker Plus: up to 30% bonus
- Total paid to date: $28M+

## Auth Architecture

Meta uses unified auth across properties:
- **Graph API** (graph.facebook.com) — primary API gateway
- **Account Center** (accountscenter.facebook.com / accountscenter.meta.com) — unified account mgmt
- **Checkpoint** — 2FA/verification challenge system
- **OAuth 2.0** — third-party app authorization

## Key Auth Endpoints

### Instagram (Mobile API — i.instagram.com)
| Endpoint | Purpose | Test For |
|----------|---------|----------|
| /api/v1/accounts/login/ | Mobile login | Encrypted password |
| /api/v1/accounts/two_factor_login/ | 2FA verification | Rate limit, oracle |
| /api/v1/accounts/send_two_factor_login_sms/ | 2FA SMS trigger | Unauth trigger, rate limit |
| /api/v1/accounts/check_email/ | Email validation | Oracle (valid vs invalid) |
| /api/v1/accounts/send_recovery_flow_email/ | Recovery trigger | Unauth, rate limit |
| /api/v1/accounts/account_recovery_code_verify/ | Recovery code check | Oracle, rate limit |
| /api/v1/bloks/apps/ | Bloks framework | UI actions via API |
| /accounts/login/ajax/ | Web login | AJAX endpoint |

### Facebook
| Endpoint | Purpose | Test For |
|----------|---------|----------|
| /login.php | Web login | CSRF + encrypted pw |
| /login/device-based/regular/login/ | Device login | POST credentials |
| /ajax/login/help/identify.php | Account recovery | Email/phone lookup oracle |
| /recover/initiate | Password reset | Trigger flow |
| /checkpoint/ | 2FA challenge | Code validation oracle |
| /api/graphql | GraphQL mutations | Auth operations |
| /dialog/oauth | OAuth authorization | redirect_uri manipulation |
| /v20.0/oauth/access_token | Token exchange | Code → token |
| /v20.0/debug_token | Token debug | Token validity oracle |

### WhatsApp
| Endpoint | Purpose | Test For |
|----------|---------|----------|
| /v1/register | Phone registration | SMS code verification |
| /v1/verify | Code verification | 6-digit SMS oracle |
| /v1/exist | Account check | Phone number oracle |

## Protections to Expect
- Encrypted passwords (client-side RSA)
- CSRF tokens (fb_dtsg, jazoest)
- Machine ID / device fingerprinting
- Checkpoint system (behavioral triggers)
- Per-IP, per-account, per-endpoint rate limiting
- Arkose Labs CAPTCHA (FunCaptcha)

## Strategy (matching researcher skills)

### Priority 1: Instagram 2FA/Recovery ($20K-$130K)
Apply TikTok oracle pattern:
- Test `/api/v1/accounts/two_factor_login/` authenticated vs unauthenticated
- Compare rate limits between `send_two_factor_login_sms` vs `two_factor_login`
- Test recovery code verification for oracle behavior

### Priority 2: Facebook Checkpoint ($20K)
- Test `/checkpoint/` code validation with authenticated session
- Look for response differentiation on correct vs incorrect codes

### Priority 3: OAuth Logic ($5K-$20K)
- redirect_uri manipulation on `/dialog/oauth`
- Token scope escalation via Graph API
- Cross-platform token reuse (FB token on IG?)

## Resolved Auth Subdomains (2026-05-29)
All resolve to Meta's c10r infrastructure:
- graph.facebook.com, api.facebook.com, accountscenter.facebook.com
- i.instagram.com, api.instagram.com, graph.instagram.com
- web.whatsapp.com, api.whatsapp.com
- auth.meta.com, accountscenter.meta.com
- developers.facebook.com, business.facebook.com

## Tools
- Meta test accounts: https://bugbounty.meta.com (Tools section)
- Graph API Explorer
- Access Token Debugger
- FBDL (Facebook Data Lookup)
