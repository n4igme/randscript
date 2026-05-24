# YesWeHack Dojo Challenge Interaction

## Overview

YesWeHack Dojo challenges are browser-based CTF-style exercises at `dojo-yeswehack.com`. They require authentication and use a visual pipeline UI.

## URL Patterns

- Challenge info: `https://dojo-yeswehack.com/challenge-of-the-month/dojo-{N}`
- Challenge play: `https://dojo-yeswehack.com/challenge/play/{uuid}`
- Login redirect: `https://yeswehack.com/auth/login` (OAuth with YWH account)

## UI Structure

The play page has tabbed panels:

| Tab | Purpose |
|-----|---------|
| INFO | Challenge description, rules, goal |
| INPUTS | Text fields for exploit parameters + SUBMIT button |
| INSPECT | Request/response inspection |
| WAF | Visual pipeline showing input → URL encode → output flow |
| CODE | Server-side source code (Monaco editor, read-only) |
| RESULT | Execution output after submission |

## Key Facts

- **Login required** to submit — SUBMIT button is disabled when unauthenticated
- The INPUTS tab contains one textbox per input parameter (e.g., key, plugin, zipbase64)
- Tabs are custom Vue/Nuxt components (class: `v-drag-target v-drop-target`), not standard HTML tabs
- The inner clickable div has `cursor: pointer` — use that to identify it in DOM
- Challenge source code is also available via API: `GET /api/challenge-of-the-month/dojo-{N}` (returns JSON with code, runner type, etc.)
- Nuxt SSR state available at `window.__NUXT__` with challenge data

## Programmatic Interaction

Finding the INPUTS tab in DOM:
```javascript
// Tabs render as divs with innerText "drag_indicator\nINPUTS"
const allEls = document.querySelectorAll('*');
for (let el of allEls) {
    const text = el.innerText || '';
    if (text === 'drag_indicator\nINPUTS' && 
        window.getComputedStyle(el).cursor === 'pointer') {
        el.click();
        break;
    }
}
```

After clicking INPUTS tab, textboxes appear in the accessibility tree as `textbox [ref=eN]` elements, followed by a `button "SUBMIT"`.

## API-First Approach (Recommended)

The challenge source code is accessible via API **without authentication**. This is the fastest path — solve the challenge from source, then only use the UI to submit inputs.

```bash
# Fetch challenge metadata + source code
curl -sk "https://dojo-yeswehack.com/api/challenges/{uuid}" | python3 -m json.tool

# Alternative (by challenge number):
curl -sk "https://dojo-yeswehack.com/api/challenge-of-the-month/dojo-{N}" | python3 -m json.tool

# Response includes:
# - .id (UUID for play URL)
# - .template (full server-side source code — this is the key field)
# - .outputLanguage (e.g., "html")
# - .nodes[] (WAF pipeline nodes: input, output, filter)
# - .links[] (connections between nodes)
# - .description (challenge rules in markdown)
# - .flag ("redacted" in API response)
# - .hints[] (may be empty)
```

**Important:** The source code is in the `.template` field (not `.code`). Inputs are substituted as `$output_key`, `$output_plugin`, etc. (matching the output node labels). All inputs pass through `decodeURIComponent()` before use.

**Workflow:**
1. Fetch source via API (no login needed)
2. Reverse-engineer the logic locally
3. Generate exploit inputs
4. **Validate locally** — simulate the challenge environment with the actual libraries (install deps, run the code)
5. Save to `ptest-output/exploit/` for documentation
6. Log in to UI only for final submission (INPUTS tab → paste → SUBMIT)

This avoids fighting with the Vue/Nuxt DOM for source code extraction (Monaco editor is virtualized and hard to scrape).

## Local Validation (MANDATORY before submission)

Always simulate the challenge locally before submitting. This catches interface mismatches that aren't obvious from reading code:

```bash
# 1. Install challenge dependencies locally
npm install yauzl  # or whatever the challenge uses

# 2. Write a simulation script that:
#    - Sets up the filesystem structure the challenge expects
#    - Runs the exact validation/execution logic from .template
#    - Uses YOUR exploit inputs
#    - Verifies the full chain produces output

# 3. Confirm: key validates, zip extracts correctly, plugin loads, flag reads
```

**Common pitfalls (Dojo #51 DEADBOLT, May 2026):**
- Plugin interface requirements hidden in `loadPlugin()` — must export specific methods (e.g., `get()` as a function) to pass validation, PLUS `getName()` and `run()` for the execution loop
- `validateKey()` constraints differ from description — always read the ACTUAL code, not the challenge description
- `path.join(dest, "../file.js")` resolves traversal — yauzl `strictFileNames:true` does NOT block `../`
- Inputs go through `decodeURIComponent()` — base64 with `+` chars may need attention (though standard base64 survives URL encoding in this case since the WAF only does partial encode)

## Brute Force Warning

Most Dojo challenges explicitly state: "BRUTE FORCE IS NOT ALLOWED! (Applies only to the Dojo challenge page itself.)" — solve the logic, don't spray inputs.

## Submission Flow

1. Navigate to `/challenge/play/{uuid}`
2. Log in via YWH OAuth
3. Click INPUTS tab
4. Fill textboxes with exploit values
5. Click SUBMIT
6. Check RESULT tab for flag/output
7. Submit report via YWH program page (separate from Dojo UI)

## Dojo Report Submission Format (YesWeHack Program)

After solving the challenge on the Dojo UI, submit a report via the YWH Dojo program. The report must include these metadata fields plus a writeup body.

### Required Metadata Fields

| Field | Description | Example (Dojo #51) |
|-------|-------------|---------------------|
| Endpoint | Challenge play URL | `https://dojo-yeswehack.com/challenge/play/{uuid}` |
| Vulnerable Part | The specific function/component with the flaw | `unzip()` — `path.join(dest, filenameStr)` with no traversal check |
| Part Name | The input parameter that carries the payload | `zipbase64` input → yauzl extraction |
| Payload | The actual exploit value(s) | Zip with entry `../pwned.js` (base64-encoded) |
| Vulnerability Type | CWE classification | Path Traversal (CWE-22) → RCE (CWE-94) |
| Technical Environment | Runtime, libraries, versions | Node.js, yauzl, `strictFileNames: true` |

### Writeup Body Structure (from published Dojo blog writeups)

Based on official YWH Dojo solution posts (e.g., Dojo #50 Bucket Vault):

```markdown
## Description
{What the application does — 2-3 sentences}

## PoC

### Description
{Deeper technical analysis — how the app works, what the goal is,
 where the vulnerability arises. Include numbered flow of the app logic.}

### Exploitation
{Annotated code snippets from the challenge source showing:
 - The security check (and why it fails)
 - The vulnerable function
 - The execution path}

### PoC
{Step-by-step reproduction:
 Step 1: [action] — with exact input values
 Step 2: [action] — with exact input values
 Result: flag output}

## Risk
{Impact statement — what an attacker achieves}

## Remediation
{How to fix — specific code changes}
```

### Key Differences from Bug Bounty Reports

- No CVSS scoring needed (it's a CTF)
- Flag MUST be included in the report
- Focus on the exploitation chain logic, not business impact
- Code snippets from the challenge source are expected (it's open-source by design)
- The "PoC" section should have the EXACT input values ready to paste into the Dojo UI

## ptest-output Structure for Dojo Challenges

Dojo challenges are CTF-style, not full pentest engagements. Use a streamlined ptest-output:

```
ptest-output/
  state.yaml              # scope_type: "web", type: "ctf-challenge"
  scope.md                # Challenge URL, description, goal, requirements
  findings-log.md         # Usually 1 finding (the solve)
  recon-passive/
    source-code-analysis.md   # Reverse-engineered challenge logic
  enumeration/
    attack-surface.md         # Vulnerability chain mapping
  exploit/
    finding-1-*.md            # Full exploit writeup with PoC
  report/
    dojo{N}-{name}-writeup.md # Complete writeup with attack flow diagram
```

Skip phases that don't apply (active recon, post-exploit). Mark as `N/A (CTF challenge)` in state.yaml.
