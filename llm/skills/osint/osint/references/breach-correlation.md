# Breach Data Correlation — Deep Methodology

## Data Sources

| Source | Access | Coverage | Notes |
|--------|--------|----------|-------|
| HaveIBeenPwned | API key ($3.50/mo) | Email → breaches list | No passwords, just breach names |
| DeHashed | Paid subscription | Email/username/name/phone → full records | Passwords, hashes, IPs |
| IntelX | Paid (academic free tier) | Pastes, leaks, darknet | Full-text search across dumps |
| Snusbase | Paid | Email/username → credentials | Fast, recent breaches |
| LeakCheck | Paid | Email → breach + partial password | Shows first/last chars |
| BreachDirectory | Free (limited) | Email → breach names + hash type | |

## Query Patterns

### Email-Based Lookup
```bash
# HIBP — which breaches contain this email
curl -s -H "hibp-api-key: {key}" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false" | \
  jq '.[] | {Name, BreachDate, DataClasses}'

# HIBP paste search
curl -s -H "hibp-api-key: {key}" \
  "https://haveibeenpwned.com/api/v3/pasteaccount/{email}" | \
  jq '.[] | {Source, Title, Date}'
```

### Domain-Wide Lookup
```bash
# HIBP domain search (shows all breached emails for a domain)
curl -s -H "hibp-api-key: {key}" \
  "https://haveibeenpwned.com/api/v3/breacheddomain/{domain}" | jq 'keys | length'
# Returns: {"email1": ["breach1","breach2"], "email2": [...]}
```

### Username/Handle Lookup
- DeHashed: search by username field across all dumps
- Check if same handle was used on breached services
- Cross-reference with platform enumeration from Phase 2

## Credential Analysis

### Password Pattern Extraction
When breach data includes passwords/hashes:

1. **Pattern identification:**
   - Base word + number suffix: `Company2023!`
   - Keyboard walk: `qwerty123`, `1qaz2wsx`
   - Personal info: `{pet}{year}`, `{name}{birthyear}`
   - Leet substitutions: `p@ssw0rd`, `s3cur1ty`

2. **Password reuse scoring:**
   - Same password across multiple breaches → HIGH reuse risk
   - Same base word with different suffixes → predictable rotation
   - Different passwords everywhere → low reuse risk

3. **Hash cracking priority:**
   - MD5/SHA1 unsalted → crack immediately (hashcat/john)
   - bcrypt/scrypt → skip unless high-value target
   - Check against known rainbow tables first

### Credential Stuffing Risk Assessment
```
Risk = (password_reuse_count × recency × target_value)

HIGH: Same password in 3+ breaches, breach <2 years old, target has no MFA
MED:  Pattern reuse (base+rotation), breach 2-5 years old
LOW:  Unique passwords, breach >5 years old, target enforces MFA
```

## Cross-Breach Correlation

### Email Linkage
```
Email A (personal) → Breach X → same password → Email B (corporate)
                                                    ↓
                                          Corporate account access
```

### Identity Confirmation via Breach Data
- Breach includes name + email + phone → confirms identity
- IP address in breach data → geolocation correlation
- Registration dates across services → timeline building
- Recovery email in breach → discovers additional email addresses

### Multi-Breach Triangulation
1. Find email in Breach A (2019): reveals password hash
2. Same email in Breach B (2021): reveals phone number
3. Phone number in Breach C (2022): reveals alternate email
4. Alternate email → repeat process → expand graph

## Operational Integration

### Feed to Other Skills
| Discovery | Trigger |
|-----------|---------|
| Valid credentials for cloud service | → ctest: cloud access enumeration |
| Corporate email with password pattern | → ptest: credential stuffing on login panels |
| API key in paste/breach | → atest: API access testing |
| Internal service URL in breach data | → ptest: attack surface expansion |
| Employee personal email compromised | → Social engineering vector (report only, don't exploit) |

### OPSEC for Breach Queries
- Use VPN/Tor for breach database queries
- Don't query from corporate network
- Some services log who queries what — assume your queries are recorded
- Never attempt to use found credentials without explicit authorization

## Output Format

```markdown
## Breach Exposure: {target_identifier}

### Breach Summary
| Email | Breaches | Most Recent | Data Exposed | Risk |

### Credential Analysis
- Password pattern: {description}
- Reuse risk: HIGH/MED/LOW
- Rotation pattern: {if detected}
- MFA likelihood: {based on service types}

### Cross-Reference Discoveries
| Source Breach | Data Found | Links To | Confidence |

### Actionable Intelligence
- {numbered list of what can be done with this data, within scope}
```
