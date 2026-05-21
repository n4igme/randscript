# Bug Bounty — Step 3l: Dependency & Supply Chain Vulnerabilities

Scan for known vulnerable dependencies, dependency confusion risks, and supply chain attack vectors.

## Input

$ARGUMENTS

- Read `./assessment/threat-model.md` (or provided path) for priority targets
- Read `./assessment/recon.md` for entry points and data flows
- If either is missing, tell the user which step to run first

## Vulnerability Patterns

### Known Vulnerable Dependencies (CVEs)
- Outdated packages with published CVEs
- Dependencies with known RCE, XSS, or deserialization vulns
- Transitive dependencies pulling in vulnerable versions

**Detection**:
- `npm audit` / `yarn audit` / `pnpm audit` for Node.js
- `pip audit` / `safety check` for Python
- Check `package.json`, `package-lock.json`, `requirements.txt`, `Pipfile.lock`, `pom.xml`, `Gemfile.lock`, `go.sum`
- Look for pinned versions that are known-vulnerable

### Dependency Confusion
- Internal/private package names that could be claimed on public registries
- Missing `.npmrc` / `pip.conf` scoping to private registry
- No namespace/scope prefix on internal packages
- `registry` configuration allowing fallback to public

**Grep patterns**: `.npmrc`, `registry=`, `@scope`, `--registry`, `pip.conf`, `index-url`, `extra-index-url`, `artifactory`, `nexus`, `verdaccio`

### Typosquatting Risk
- Dependencies with names similar to popular packages
- Single-character variations of well-known libraries
- Packages with very low download counts for critical functionality

**Detection**: Review `package.json`/`requirements.txt` dependency names manually for suspicious entries.

### Lockfile Integrity
- Missing lockfiles (allows version drift)
- Lockfile not committed to version control
- Integrity hash mismatches
- `postinstall` scripts in dependencies that execute arbitrary code

**Grep patterns**: `postinstall`, `preinstall`, `install` in dependency package.json scripts, `integrity`, `resolved`

### Pinning & Version Ranges
- Overly broad version ranges (`*`, `>=`, `latest`)
- Missing lockfile enforcement in CI
- No `--frozen-lockfile` / `--ci` in build scripts

**Grep patterns**: `"*"`, `"latest"`, `">=`, `"^0.`, `npm install` without `--ci`, `yarn install` without `--frozen-lockfile`

## Process

1. **Identify package managers** — find all manifest files (package.json, requirements.txt, pom.xml, etc.)
2. **Run audit commands** — use available audit tools to find known CVEs
3. **Check registry config** — verify private packages are scoped and registries are pinned
4. **Review lockfiles** — ensure they exist, are committed, and enforced in CI
5. **Assess exploitability** — is the vulnerable code path actually reachable in this application?

## Output

Append to `./assessment/vulnerabilities.md`:

```markdown
# Vulnerability Findings — Dependency & Supply Chain

**Date**: {date}
**Scanner**: vuln-dependency

## Findings

### VULN-DEP-001: {Title}

**Severity**: {Critical/High/Medium/Low}
**Confidence**: {High/Medium/Low}
**Category**: {Known CVE / Dependency Confusion / Typosquatting / Lockfile Issue / Version Pinning}
**Location**: `{file}`
**CVE**: {CVE-XXXX-XXXXX if applicable}
**CWE**: CWE-{1395|427|829}

**Description**:
{What the vulnerability is}

**Affected Package**:
- Name: {package name}
- Installed Version: {version}
- Fixed Version: {patched version}
- Vulnerability: {brief CVE description}

**Reachability**:
{Is the vulnerable function/code path actually used by this application?}

**Impact**:
{What attacker gains — RCE, data theft, supply chain compromise}

**Remediation**:
{Upgrade command or configuration fix}

---
```

## Rules

- **Prioritize reachable vulnerabilities** — a CVE in an unused transitive dep is lower priority.
- **Check if the vulnerable code path is exercised** — not all CVEs are exploitable in every context.
- **For dependency confusion, verify the private package is actually claimable** on the public registry.
- **Idempotent output** — if `vulnerabilities.md` already has a `# Vulnerability Findings — Dependency & Supply Chain` section, replace it entirely. See `sc3-vuln-scan` idempotency rule.
- **Save to `./assessment/vulnerabilities.md`** and confirm.