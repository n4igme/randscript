# parse-finding skill for Claude Code

Converts raw security finding docs (Markdown, HTML, or Jira XML exports with screenshots) into a structured finding report ready for Jira Cloud.

## Install

Copy the `SKILL.md` file into your Claude Code skills directory:

```bash
mkdir -p ~/.claude/skills/parse-finding
cp SKILL.md ~/.claude/skills/parse-finding/SKILL.md
```

## Setup

Create a `finding` directory in your working folder:

```bash
mkdir -p ./finding
```

## Usage

1. Create a subfolder in `./finding/` for your finding (e.g. `./finding/close-pocket/`)
2. Drop your raw docs inside: `.md`, `.html` (Google Docs export), `.xml` (Jira export), screenshots
3. Optionally add a `context.md` file with severity, SLA, due date info
4. Run the skill:

```
/parse-finding close-pocket
```

5. The skill generates:
   - An HTML file with the formatted finding (opens in browser)
   - Numbered, descriptively-named image files (Finder opens alongside)

6. In Jira:
   - **Cmd+A → Cmd+C** the HTML page → paste into Jira description (text + formatting comes through)
   - Drag image files from Finder into the Jira description where the placeholders are

## Finding Template

The output follows this structure:

1. **Title**
2. **Info Panel** — Severity, Criticality, Exploitability, Remedial Control, SLA, Due Date
3. **Description** — What the vulnerability is
4. **Affected API** — List of endpoints
5. **Root Cause** — Why it exists
6. **Proof Of Concept** — Test accounts, steps, expected vs observed, screenshots
7. **Impact** — What an attacker can do
8. **Remediation** — Required fix, defense in depth, additional notes

## Why images must be dragged manually

Jira Cloud's editor strips images from pasted HTML (known bug JRACLOUD-71695, open since 2016). Text formatting pastes perfectly; images must be added separately via drag-drop.

## Requirements

- Claude Code CLI
- Python 3 (for processing large files with embedded images)
