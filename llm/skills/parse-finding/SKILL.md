---
name: parse-finding
description: "Parse security finding docs from ./finding/ and produce a structured HTML finding report. Copy text from browser into Jira, then drag-drop the numbered image files."
allowed-tools: Read Write Bash(ls *) Bash(find *) Bash(grep *) Bash(open *) Bash(python3 *) Bash(head *) Bash(wc *)
argument-hint: <folder or filename in ./finding/ directory, e.g. "close-pocket">
---

# Parse Jira Finding

Take raw security finding data (Jira XML/RSS export or Markdown with screenshots) and produce a structured finding report. Generates:
1. **HTML file** — for copy-paste into Jira (text + formatting). Opens in browser.
2. **Renamed image files** — numbered descriptively (e.g. `01_ui_screenshot.png`) for drag-drop into Jira.
3. Opens the Finder folder so images are ready to drag.

NOTE: Jira Cloud strips images from pasted HTML (known limitation JRACLOUD-71695). Text + formatting paste perfectly; images must be dragged in separately from Finder.

## Input

$ARGUMENTS

If an argument is provided, look for it in `./finding/`:
- If it's a directory, look for `.xml`, `.md`, or `.txt` files inside it
- If it's a file, read it directly

If no argument is given, list contents of `./finding/` and ask the user which one to process.

## Step 1: Detect Input Format

Read the first few lines to determine format:
- **XML mode**: file starts with `<?xml`, `<rss`, or contains `<item>` / `<channel>` tags
- **Markdown mode**: anything else (`.md`, `.txt`, or unstructured text, possibly with embedded base64 images)

## Step 2: Check for Context File

Look for a file matching `context*` (e.g. `context.md`, `context.txt`, `context-notes.md`) in the finding directory. If found, read it — it contains additional context from the user such as severity, SLA, due date, scope notes, or other metadata to incorporate into the report. Use these values to fill in the Info Panel and enrich other sections.

## Step 3: Extract Content

### XML Mode
Extract from XML tags: `<key>`, `<summary>`, `<priority>`, `<status>`, `<assignee>`, `<reporter>`, `<created>`, `<description>`, `<comment>` entries, `Epic Link`. Clean the description: decode HTML entities, convert `<br/>` to newlines, strip `{panel}` wrappers, collapse excessive blank lines.

### Markdown Mode
Markdown files may be very large (100K+) due to embedded base64 images. **Do NOT read the entire file with Read.** Use `head` to read the text portion. If images are embedded, use a Python script to extract them to separate files, then use Read to view each image for visual context.

Also check for an HTML export (`.html` file with an `images/` subfolder). If present, read the HTML for text content and use the separate image files (higher quality than base64-embedded images).

## Step 4: Understand the Finding

From the extracted content and screenshots, identify:
- What the vulnerability is
- Which endpoints/APIs are affected
- The attack flow / proof of concept steps
- What each screenshot proves
- The root cause
- The impact
- What the fix should be

## Step 4: Generate the Finding Report

Produce the output in the **exact template format below**. Use the extracted content to populate each section. Preserve all technical details faithfully (endpoints, parameters, account numbers, HTTP methods, response details). Write clear, professional security finding language.

## Step 5: Build HTML and Open

For markdown input with base64 images, write a Python script that:
1. Reads the markdown file
2. Extracts image definitions
3. Inserts the pre-written HTML body (which you provide as a string in the script)
4. Places `<img>` tags at the positions you specify
5. Wraps everything in the HTML shell (see HTML Wrapper below)
6. Writes to `./finding/{name}/{name}.html`

Run the script, then: `open ./finding/{name}/{name}.html`

Tell user: "Opened — Cmd+A, Cmd+C, paste into Jira."

---

## Finding Template

The output MUST follow this exact section structure. Every finding uses this template.

```
{Title}

{Info Panel}

{Description}

{Affected API}

{Root Cause}

{Proof Of Concept}

{Impact}

{Remediation}
```

### Title

A single-line title summarizing the finding. Concise but specific — include the vuln type and the affected feature/component. Rendered as `<h1>`.

Example: `Improper Business Logic — Close Pocket Allows Deletion of Non-Deletable Pockets`

### Info Panel

Always starts the finding. Contains metadata fields. If a value is unknown from the source material, write `[TBD]` so the user can fill it in.

```
Issue Severity - {Low / Medium / High / Critical, or [TBD]}

Criticality: {Low / Medium / High / Critical, or [TBD]}

Exploitability: {Low / Medium / High, or [TBD]}

Presence of Remedial Control: {Yes / No — does any partial mitigation exist?}

Resolution SLA - {e.g. "180 days post acknowledgement", or [TBD]}
Due Date - {e.g. "24 October 2026", or [TBD]}
```

### Description

2-4 paragraphs explaining:
- What the vulnerability is
- Which endpoint/flow is affected (include the full endpoint path)
- What an attacker can do
- What data or functionality is exposed
- Any observed limits to the exposure

### Affected API

List each affected endpoint on its own line with HTTP method:

```
GET /path/to/endpoint?params
POST /another/endpoint
DELETE /yet/another
```

### Root Cause

Explain WHY the vulnerability exists. Focus on:
- What validation or authorization check is missing
- Why the current control fails
- The specific trust assumption that is violated

Use bullet points for multiple contributing factors.

### Proof Of Concept

Include:
- **Test accounts** — list test user details (customerId, accountId, cardId, etc.)
- **Steps** — numbered steps with the exact HTTP requests or actions
- **Expected vs Observed behavior** for each step
- **Screenshots** — insert images inline where they provide evidence. Caption each image.

### Impact

What this allows an attacker to do. Include:
- Bullet points for each specific impact
- Mention the scope (authenticated users, any user, etc.)
- Note if the exposure is limited vs full

### Remediation

Three sub-sections:

**Required fix** — the minimum change needed to close the vulnerability.

**Recommended defense in depth** — additional hardening beyond the minimum fix.

**Additional notes** — related flows to review, general observations.

---

## HTML Wrapper

Wrap the finding content in this HTML shell:

```html
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; line-height: 1.6; color: #172B4D; }
h2 { color: #172B4D; border-bottom: 2px solid #DFE1E6; padding-bottom: 8px; }
h3 { color: #172B4D; margin-top: 32px; }
table { border-collapse: collapse; margin: 16px 0; }
th, td { border: 1px solid #DFE1E6; padding: 8px 12px; text-align: left; }
th { background: #F4F5F7; font-weight: 600; }
img { max-width: 100%; margin: 16px 0; border: 1px solid #DFE1E6; border-radius: 4px; display: block; }
pre { background: #F4F5F7; padding: 12px; border-radius: 3px; overflow-x: auto; font-size: 0.9em; }
code { background: #F4F5F7; padding: 2px 4px; border-radius: 3px; font-size: 0.9em; }
pre code { background: none; padding: 0; }
hr { border: none; border-top: 2px solid #DFE1E6; margin: 24px 0; }
blockquote { border-left: 3px solid #DFE1E6; margin: 16px 0; padding: 8px 16px; color: #6B778C; }
ul, ol { margin: 8px 0; padding-left: 24px; }
li { margin: 4px 0; }
</style>
</head>
<body>
{finding content as HTML}
</body>
</html>
```

## Section-to-HTML Mapping

- Title → `<h1>`
- Info Panel fields → plain `<p>` with `<strong>` for labels
- Section headings (Description, Affected API, etc.) → `<h2>`
- Sub-headings within sections → `<h3>`
- Endpoint paths → `<code>` inline or `<pre>` for full requests
- Bullet lists → `<ul><li>`
- Numbered steps → `<ol><li>`
- Bold labels → `<strong>`
- Images → `<img>` with base64 data URI, followed by `<em>` caption

## Rules

- **Preserve all technical details faithfully.** Endpoints, parameters, account numbers, HTTP methods, response values — these must be exact from the source.
- **Write professional security finding language.** The output is a formal finding report, not raw notes.
- **Rename images descriptively** with numbered prefix (e.g. `01_ui_no_close_option.png`, `02_api_response.png`) so the user knows which image goes where when dragging into Jira.
- **Open both the HTML and the Finder folder** so the user can paste text and drag images side by side.
- **Do NOT print the full output to the terminal.** Just confirm files saved and opened.
- **For large files with base64 images, always use a Python script** to build the HTML. Do not load 100K+ tokens into context.
- Strip `[Appsec]`, `[Jaguard]`, `[Jago]` tags from titles.
- Clean up convert scripts after successful conversion.
