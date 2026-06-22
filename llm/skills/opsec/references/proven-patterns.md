# Proven Patterns — opsec

## High-ROI Assessment Patterns

### 1. Email Exposure Cascade

**Pattern:** Single email address → breach correlation → password reuse → account takeover path

**Steps:**
1. Enumerate all services using target email (HIBP, credential stuffing DBs)
2. Cross-reference breach dates with password rotation history
3. Identify services where old passwords may still be active
4. Priority: financial > email > social > misc

**Typical yield:** 2-5 accounts with stale credentials per personal email

### 2. Domain Squatting Detection

**Pattern:** Lookalike domains registered targeting your organization

**Steps:**
1. Generate permutations (dnstwist, URLCrazy)
2. Check registration status of each variant
3. Verify if any serve phishing content
4. Check MX records (email interception setup)

**Remediation:** Register defensive variants, monitor new registrations

### 3. Git History Exposure

**Pattern:** Secrets committed and "removed" but still in git history

**Steps:**
1. Clone all public repos
2. Run trufflehog/gitleaks on full history
3. Check if found secrets are still valid
4. Map secrets to services they unlock

**Typical yield:** 1-3 valid secrets per active developer

### 4. Social Media OSINT Surface

**Pattern:** Personal info leakage across platforms enables social engineering

**Steps:**
1. Map all accounts (sherlock/maigret)
2. Extract: location patterns, work schedule, travel, relationships
3. Identify information sufficient for targeted phishing
4. Score: could someone impersonate you with this data?

### 5. Cloud Storage Misconfiguration

**Pattern:** Public S3/GCS/Azure blobs with sensitive data

**Steps:**
1. Enumerate bucket names from DNS/source code
2. Test public list/read permissions
3. Check for sensitive file types (.env, .sql, backups)
4. Verify if bucket policy allows write (defacement risk)

## Anti-Patterns (time wasters)

- Running automated scanners without understanding the target
- Checking breach databases without follow-up validation
- Reporting theoretical exposure without proving access
- Spending >1h on a single vector without findings
