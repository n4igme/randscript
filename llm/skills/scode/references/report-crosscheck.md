---
name: ref-report-crosscheck
description: "Checklist to verify report accuracy before submission. Use during sc5 report generation."
---

# Security Report Crosscheck Methodology

Technique for verifying existing security scan reports against actual file contents.
Use when: handed a pre-existing report and asked to validate its accuracy.

## Approach

1. Enumerate all target files (os.walk, filter by extension)
2. Define regex patterns per finding category
3. Scan every file, count matches per pattern
4. Compare file counts + instance counts vs report claims
5. Identify: false positives (report claims, not found), false negatives (found, report missed)

## Pattern Library (UiPath/RPA XAML + VBA)

| Finding | Regex Pattern | Notes |
|---------|--------------|-------|
| DPAPI | `AQAAANCMnd8BFdERjHoAwE` | DPAPI blob prefix, reliable |
| P12 default key | `notasecret` (case-insensitive) | Google P12 default password |
| Internal URLs | `https?://` excluding `schemas.(microsoft\|openxmlformats\|uipath)` | Filter XML namespace URIs |
| Drive folder IDs | `drive\.google\.com\|folders/[A-Za-z0-9_-]{20,}` | May over-count vs report |
| GCS buckets | `gs://\|storage\.googleapis\.com\|_production(?=["\s/])` | Anchor _production to avoid FPs |
| Service emails | `svc\.[a-z0-9_.]+@[a-z0-9.-]+` | Bank Jago pattern: svc.ops_rpa1@ |
| VPN | `vpn` (case-insensitive) | Broad — catches FortiClient selectors |
| Employee paths | `C:\\Users\\[A-Za-z0-9._-]+` excluding Public/Default/All | Include name-based AND numeric IDs |

## Pitfalls

- URL pattern MUST exclude XML schema namespaces (microsoft.com, openxmlformats.org, uipath.com) — these inflate counts massively
- PATH pattern: `C:\Users\RPA` and `C:\Users\UiPath2` are employee paths too (bot service accounts on named machines) — don't filter on numeric-only
- VPN: don't assume VPN refs exist in files just because they connect via VPN — check the actual XAML selector content
- Drive folder regex can double-count if both `drive.google.com/drive/folders/ID` and standalone `folders/ID` match — deduplicate or use one pattern
- XLSM (binary Excel): cannot grep content directly — need `oletools`/`olevba` to extract VBA source for scanning

## Execution Template (python3)

```python
import os, re

base = "/path/to/repo"
patterns = {
    'DPAPI': re.compile(r'AQAAANCMnd8BFdERjHoAwE'),
    'P12': re.compile(r'notasecret', re.I),
    'URL': re.compile(r'https?://(?!schemas\.(microsoft|openxmlformats|uipath))[^\s"<>&;]+', re.I),
    'EMAIL': re.compile(r'svc\.[a-z0-9_.]+@[a-z0-9.-]+', re.I),
    'VPN': re.compile(r'vpn', re.I),
    'PATH': re.compile(r'C:\\\\?Users\\\\?[A-Za-z0-9._-]+', re.I),
}

results = {}
for root, dirs, files in os.walk(base):
    dirs[:] = [d for d in dirs if not d.startswith('.')]
    for f in files:
        if f.endswith('.xaml'):
            # scan and accumulate
            pass

# Compare: {pattern: {files_found, instances}} vs report claims
```

## Corrected Report Generation

After crosscheck, generate a corrected report if discrepancies found:

1. **Write in chunks** (header → per-project tables → summary → recommendations) to avoid timeouts
2. Per-file table format: `| # | File | Issues | Recommendation |`
3. Issues use format: `DPAPI(x10), P12, URL(x5)` — code + count if >1
4. Recommendations are actionable: "Remove N DPAPI blob(s); use GetCredential" not just "fix credentials"
5. Include a **Corrections vs Original Report** diff table showing what changed
6. Include **Clean Files** section listing files with no findings
7. Group by project, sort by project number

## Output Format

```
CROSSCHECK SUMMARY
Finding          My Files  Report  My Inst  Report Inst  Match?
DPAPI            26        26      93       93           ✓
P12              57        57      61       61           ✓
...
DISCREPANCIES:
- VPN: Report overclaimed (tagged files without actual VPN refs)
- PATH: False positives + false negatives identified
```

## Common False-Positive Patterns (Learned)

| Pattern | False Positive Reason | Fix |
|---------|----------------------|-----|
| VPN tagged on files that merely connect via VPN | Report author assumed VPN usage = VPN selector in code | Only tag VPN if XAML contains literal VPN selector strings |
| PATH tagged based on report author knowledge, not file content | Employee paths reported from memory, not grep | Always verify PATH claims against actual file bytes |
| URL count inflated by XML namespace URIs | `http://schemas.microsoft.com/*` counted as internal URL | Exclude schema namespaces in regex |
| DRIVE count inflated by dual-matching | Both full URL and bare folder ID matched | Use single pattern or deduplicate |

## Workflow Order

1. Enumerate all files (os.walk, skip `.git`/`.local`/`.settings`)
2. Run patterns against each file → build `{file: {finding: count}}` dict
3. Aggregate totals per finding type
4. Compare aggregates to report claims (file count + instance count)
5. For any mismatch: investigate individual files to identify FPs/FNs
6. Produce corrected report with per-file tables + corrections diff

## Report Structure (CRITICAL — user expectation)

The report MUST NOT jump from a summary dashboard directly into a flat per-file table.
Between summary and the file-level detail, include a **Finding Details** section that explains EACH category:

```markdown
## Finding Details

### 3.1 DPAPI-Encrypted Passwords (CRITICAL)
**What it is:** [1-2 sentences explaining the technology]
**Why it's critical:** [exploitability — how easy to abuse]
**Impact:** [N files, M instances + what's at stake]
**Affected files:** [table sorted by instance count descending]
**Recommendation:** [specific fix]

### 3.2 P12 Default Password (CRITICAL)
... same structure ...
```

Each subsection needs: what / why / impact / affected files / recommendation.
Only AFTER all categories are explained, include the full per-file table (Section 5).

## Report Export (Markdown → Google Docs)

When user needs the report in Google Docs:

1. Generate a single comprehensive `.md` file with proper structure:
   - Executive Summary (scope, impact statement)
   - Summary Dashboard (table of all findings)
   - Finding Details (per-category: what/why/impact/files/recommendation)
   - Full file-level detail table (all files, severity, issues, recommendations)
   - Top 10 highest-risk files
   - Regulatory impact (if applicable)
   - Recommendations (P0-P3 priority matrix with owners)
   - Remediation tracking dashboard (baseline 0%)
   - Appendix (scope, tools, definitions)

2. Convert with pandoc:
   ```bash
   pandoc REPORT.md -o REPORT.docx --toc
   ```
   Upload .docx to Google Drive — auto-converts with tables intact.

3. For large reports (>300 lines): write in chunks via `python3` using file append:
   ```python
   with open(outfile, "w") as f: f.write(header)      # chunk 1
   with open(outfile, "a") as f: f.write(section2)    # chunk 2...
   ```

4. Clean up intermediate files after — deliver ONE .docx (or .md if user prefers).

## DPAPI Decryption PoC (for management proof)

When management needs proof that DPAPI credentials are recoverable, provide `dpapi_decrypt_poc.py`:

- Uses `win32crypt.CryptUnprotectData` (pywin32)
- Must run on the SAME Windows machine + SAME user that encrypted the blobs
- UiPath stores passwords as UTF-16LE after DPAPI encryption
- Modes: `--dir` (scan all XAML), `--file` (single file), `--blob` (single base64 blob)
- Output: CSV with file path, truncated blob, plaintext password
- Template in `templates/dpapi_decrypt_poc.py`

Key context for the PoC explanation:
- DPAPI is machine-bound (cannot decrypt from repo alone)
- BUT: anyone with RPA machine access decrypts all 93 blobs in seconds
- Domain admin can also decrypt via DPAPI backup key
- The existence of blobs in git confirms credentials exist + identifies target accounts

---

## Consolidation Pattern

When multiple security review files accumulate in a repo (scan results, posture reviews, findings, skills), consolidate:
- Keep ONE findings report (source of truth)
- Keep ONE coding guidelines doc (if distinct from findings)
- Convert inventory/comparison docs to .csv for checklist use
- Delete superseded/redundant files
