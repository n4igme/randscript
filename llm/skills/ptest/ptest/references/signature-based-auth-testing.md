# Signature-Based Authentication Testing

Testing wallet/crypto signature authentication mechanisms.

---

### Signature-Based Authentication Testing (when wallet/crypto signatures used)

**Detection:** Look for mutations/endpoints requiring `signature`, `message`, `nonce` parameters. Common in Web3 but also in fintech (document signing, API key auth).

**Checklist:**

1. **Timestamp expiry** — sign with old timestamp (years ago) → still accepted?
   ```bash
   # If message format is "Timestamp: <unix>", try timestamp from 2020
   # Accepted = no expiry enforcement → replay window is infinite
   ```

2. **Replay protection** — reuse same signature with different action params:
   ```bash
   # Call 1: signature X + email "legit@user.com" → success
   # Call 2: signature X + email "attacker@evil.com" → success?
   # If yes: no nonce/one-time-use enforcement
   ```

3. **Parameter binding** — is the action (email, amount, recipient) included in the signed message?
   ```
   # If signed message is just "Timestamp: 1716000000" but the mutation
   # also accepts emailAddress as a SEPARATE parameter → email is unbound
   # One signature can set ANY email = blank check
   ```

4. **Message format strictness** — does it require exact format or just "contains keyword"?
   ```bash
   # Try: "Random text Timestamp: 1716000000 more text" → accepted?
   # If yes: cross-protocol signature reuse possible
   ```

5. **Future timestamps** — sign with far-future timestamp → accepted?

6. **Wrong signer** — confirm crypto validation actually works (sanity check):
   ```bash
   # Use invalid/zero signature → should get "invalid signature" error
   # This proves the server DOES verify — it just lacks temporal/replay checks
   ```

**Severity mapping:**
- No expiry alone → Medium (bounded replay if signature intercepted)
- No replay + no expiry → High (unlimited reuse forever)
- No binding + no replay + no expiry → High (permanent irrevocable takeover, victim cannot self-remediate)

**Compare against EIP-4361 (SIWE) standard:** domain binding, nonce, expiration, statement, chain ID. Any missing element is a finding.