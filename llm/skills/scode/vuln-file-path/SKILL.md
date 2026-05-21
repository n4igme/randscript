---
name: vuln-file-path
description: "Step 3j of bug bounty workflow. Scan for file upload & path traversal vulnerabilities (unrestricted upload, directory traversal). Appends to vulnerabilities.md."
allowed-tools: Read Bash(find *) Bash(grep *) Bash(head *) Bash(wc *) Bash(cat *) Bash(ls *) Write
argument-hint: <path to threat-model.md, defaults to ./assessment/threat-model.md>
---

# Bug Bounty — Step 3j: File Upload & Path Traversal Vulnerabilities

Scan for unsafe file handling that allows arbitrary file upload/write or reading files outside intended directories.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Applicability

Skip if the codebase has no file upload handlers, file read/write operations with user-controlled paths, or dynamic file serving. Report "Not applicable" and skip.

## Vulnerability Patterns

### Unrestricted File Upload
- No file type validation (or client-side only)
- MIME type check without magic byte verification
- Uploaded files stored in web-accessible directories
- Executable extensions allowed (.php, .jsp, .aspx, .sh)
- Double extension bypass (.php.jpg)
- Null byte injection in filenames

**Grep patterns**: `upload`, `multer`, `multipart`, `formidable`, `busboy`, `file.name`, `originalname`, `mimetype`, `content-type`, `extension`, `writeFile`, `createWriteStream`

### Path Traversal (Directory Traversal)
- User input in file paths without sanitization
- `../` sequences not stripped or validated
- Absolute path injection
- Null byte truncation in file paths
- URL-encoded traversal (`%2e%2e%2f`)

**Grep patterns**: `path.join(`, `path.resolve(`, `readFile(`, `readFileSync(`, `fs.`, `open(`, `sendFile(`, `download(`, `attachment(`, `req.params`, `req.query` near file ops

### Arbitrary File Write
- User-controlled filenames in write operations
- Zip slip (traversal in archive extraction)
- Template/config file overwrite via upload

**Grep patterns**: `writeFile(`, `writeFileSync(`, `createWriteStream(`, `extract(`, `unzip`, `tar`, `archiver`, `rename(`, `mv(`

### Local File Inclusion (LFI)
- User input in `require()`, `include()`, `import()` paths
- Dynamic template loading with user-controlled names
- Configuration file path from user input

**Grep patterns**: `require(`, `include(`, `include_once(`, `require_once(`, `import(`, `loadTemplate`, `render(`

## Process

For each priority target from threat-model.md:

1. **Find file operations** — identify all upload handlers, file read/write calls, and path construction
2. **Trace user input** — can user-controlled data reach the filename or path?
3. **Check validation** — allowlist vs denylist, path canonicalization, chroot/jail
4. **Test bypass** — double encoding, null bytes, double extensions, case variations
5. **Assess impact** — RCE via webshell, sensitive file read, arbitrary overwrite

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — File Upload & Path Traversal

**Date**: {date}
**Scanner**: vuln-file-path

## Findings

### VULN-FILE-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Unrestricted Upload / Path Traversal / Arbitrary Write / LFI}
**Location**: `{file}:{line}`
**CWE**: CWE-{434|22|73|98}

**Description**:
{What the vulnerability is}

**Vulnerable Code**:
```{lang}
{code snippet}
`` `

**Attack Scenario**:
1. {Step-by-step exploitation}

**Proof of Concept**:
{Malicious filename/path payload}

**Impact**:
{RCE, sensitive file disclosure, data overwrite}

**Remediation**:
```{lang}
{fixed code}
`` `

---
```

## Rules

- **Only report confirmed file/path flaws** — user input must actually reach file operations unsanitized.
- **Check framework protections** — static file serving configs, upload middleware defaults.
- **Include the exact payload** (traversal sequence, malicious filename) that exploits the flaw.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — File Upload & Path Traversal` section, replace it entirely. See `sc3-vuln-scan` idempotency rule.
- **Save to `./assessment/vulnerabilities.md`** and confirm.
