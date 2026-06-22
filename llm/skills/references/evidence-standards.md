# Evidence Standards for Security Findings

## Required Evidence

All skills must capture these for every finding:

| Field | Description | Example |
|-------|-------------|---------|
| request_response | HTTP req/res OR tool stdout | Full Burp request + 200 response |
| command | Exact command run | `python3 poc.py --target api.example.com` |
| timestamp | ISO 8601 when evidence captured | `2026-06-22T14:30:00+07:00` |
| tool | Tool used | Burp Suite, nuclei, sqlmap, Frida |

## Optional Evidence

| Field | When to Include |
|-------|-----------------|
| screenshot | UI-based findings (XSS, CSRF, clickjacking) |
| video | Multi-step exploit chains |
| pcap | Network-layer findings (MITM, DNS rebinding) |
| binary_diff | Patch analysis / DLL hijack |
| heap_trace | Heap exploitation / UAF proof |
| token_sample | Auth bypass proof (redacted, not full token) |

## Storage Convention

Save evidence under `{output_dir}/evidence/{finding-id}/`:
```
atest-output/evidence/ATEST-001/
├── request.txt
├── response.txt
├── screenshot.png
└── poc.py
```

## Redaction Rules

- Never store full plaintext passwords, API keys, or private keys
- Store prefixes only: `AKIA...XXXX`, `sk_live...XXXX`
- Redact PII in screenshots: mask names, emails, phone numbers
- Keep original unredacted evidence in private report only

## Cross-Skill Chaining

When passing evidence between skills, include:
- Source finding ID
- Relevant request/response snippet (not full)
- Confirmed impact statement
- Suggested next skill action
