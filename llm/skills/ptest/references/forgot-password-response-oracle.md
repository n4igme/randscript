# Forgot Password Response Oracle — User Enumeration

## Pattern

When login and signup endpoints don't reveal user existence (generic error messages, domain blocks), the forgot-password endpoint may still leak via subtle response differences:

1. **Whitespace differences** — extra space in the response message for non-existing users
2. **Timing differences** — existing users trigger email send (slower), non-existing return immediately (faster)
3. **Content-length differences** — response body size varies by 1-2 bytes

## Case Study: SecOps Group Mock (June 2026)

- Login: same "Login Failed. User not Found." for both existing and non-existing users
- Signup: blocks @secops.group domain ("Invalid email domain.")
- Forgot password:
  - **Existing user:** `"Check your inbox for the link to reset your password."` (~2.7s)
  - **Non-existing:** `"Check your inbox for the link to reset  your password."` (~1.1s, note DOUBLE SPACE before "your")

### Detection Method

```bash
# Compare responses character-by-character
curl -sk -X POST target/login -d 'forgot_email=known_existing@domain' > resp_exists.txt
curl -sk -X POST target/login -d 'forgot_email=definitely_fake@nowhere.xyz' > resp_fake.txt
diff <(xxd resp_exists.txt) <(xxd resp_fake.txt)

# Or grep for the pattern
curl -sk -X POST target/login -d 'forgot_email=TARGET@domain' 2>/dev/null | grep -P 'reset\s{2,}your'
# Double space = non-existing, single space = existing
```

### Verification Protocol

1. Establish ground truth with a KNOWN existing account (register one via signup first)
2. Establish negative baseline with a clearly fake email
3. Compare response body byte-for-byte (not just status/message at a glance)
4. Also measure timing (existing users often 2-3x slower due to actual email dispatch)
5. Run 3+ iterations to confirm consistency

## Trigger Conditions

- Login endpoint returns generic/identical errors for valid vs invalid users
- Signup blocks certain email domains
- Forgot password returns "success" regardless of email existence
- Look HARDER at the "success" response — subtle byte-level differences often exist

## Severity

- User enumeration via forgot-password: Low-Medium
- Combined with password spray or credential stuffing: escalates to Medium-High
