#!/usr/bin/env bash
# =====================================================================
# install.sh — Install claude-hunter skill bundle
#
# Copies all bundled content into ~/.claude/:
#   - skills/*       → ~/.claude/skills/
#   - commands/*.md  → ~/.claude/commands/
#   - rules/*.md     → ~/.claude/rules/
#   - scripts/hunt.sh → ~/.claude/scripts/hunt.sh + sourced from shell rc
#
# Idempotent: safe to re-run. Existing skills/commands with the same
# name are backed up before overwrite.
# =====================================================================

set -e

REPO_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SKILLS_DEST="$HOME/.claude/skills"
COMMANDS_DEST="$HOME/.claude/commands"
RULES_DEST="$HOME/.claude/rules"
SCRIPTS_DEST="$HOME/.claude/scripts"

mkdir -p "$SKILLS_DEST" "$COMMANDS_DEST" "$RULES_DEST" "$SCRIPTS_DEST"

SKILL_COUNT=0
CMD_COUNT=0

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║       claude-hunter — installer              ║"
echo "║  Bug Bounty · Red Team · Pentest             ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "Installing from $REPO_DIR"
echo ""

# === Install skills ===
echo "Skills → $SKILLS_DEST"
for skill_dir in "$REPO_DIR/skills"/*/; do
  [ -d "$skill_dir" ] || continue
  skill_name="$(basename "$skill_dir")"
  if [ -d "$SKILLS_DEST/$skill_name" ] && [ ! -L "$SKILLS_DEST/$skill_name" ]; then
    backup_name="${skill_name}.backup-$(date +%Y%m%d-%H%M%S)"
    mv "$SKILLS_DEST/$skill_name" "$SKILLS_DEST/$backup_name"
  fi
  cp -r "$skill_dir" "$SKILLS_DEST/$skill_name"
  SKILL_COUNT=$((SKILL_COUNT + 1))
done
echo "  ✓ $SKILL_COUNT skills installed"
echo ""

# === Install commands ===
echo "Commands → $COMMANDS_DEST"
for cmd_file in "$REPO_DIR/commands"/*.md; do
  [ -e "$cmd_file" ] || continue
  cmd_name="$(basename "$cmd_file")"
  if [ -f "$COMMANDS_DEST/$cmd_name" ] && [ ! -L "$COMMANDS_DEST/$cmd_name" ]; then
    backup_name="${cmd_name%.md}.backup-$(date +%Y%m%d-%H%M%S).md"
    mv "$COMMANDS_DEST/$cmd_name" "$COMMANDS_DEST/$backup_name"
  fi
  cp "$cmd_file" "$COMMANDS_DEST/$cmd_name"
  CMD_COUNT=$((CMD_COUNT + 1))
done
echo "  ✓ $CMD_COUNT commands installed"
echo ""

# === Install rules ===
if [ -d "$REPO_DIR/rules" ]; then
  echo "Rules → $RULES_DEST"
  for rule_file in "$REPO_DIR/rules"/*.md; do
    [ -e "$rule_file" ] || continue
    cp "$rule_file" "$RULES_DEST/$(basename "$rule_file")"
  done
  echo "  ✓ Rules installed"
  echo ""
fi

# === Install hunt shell command ===
cp "$REPO_DIR/scripts/hunt.sh" "$SCRIPTS_DEST/hunt.sh"
chmod +x "$SCRIPTS_DEST/hunt.sh"

# Detect shell rc file
SHELL_RC=""
if [ -n "${ZDOTDIR:-}" ] && [ -f "$ZDOTDIR/.zshrc" ]; then
  SHELL_RC="$ZDOTDIR/.zshrc"
elif [ -f "$HOME/.zshrc" ]; then
  SHELL_RC="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
  SHELL_RC="$HOME/.bashrc"
fi

if [ -n "$SHELL_RC" ]; then
  if grep -q "claude/scripts/hunt.sh" "$SHELL_RC" 2>/dev/null; then
    echo "  ✓ hunt.sh already sourced from $SHELL_RC"
  else
    echo "" >> "$SHELL_RC"
    echo "# claude-hunter engagement scaffolding" >> "$SHELL_RC"
    echo "source ~/.claude/scripts/hunt.sh" >> "$SHELL_RC"
    echo "  ✓ Added 'source ~/.claude/scripts/hunt.sh' to $SHELL_RC"
  fi
else
  echo "  ⚠ Could not detect shell rc file. Manually add:"
  echo "       source ~/.claude/scripts/hunt.sh"
fi

# Source it for current session
source "$SCRIPTS_DEST/hunt.sh" 2>/dev/null || true

echo ""
echo "════════════════════════════════════════════════"
echo "  ✓ Install complete"
echo ""
echo "  Skills:   $SKILL_COUNT"
echo "  Commands: $CMD_COUNT"
echo "  Rules:    hunting.md, reporting.md"
echo "  Shell:    hunt <target-name>"
echo "════════════════════════════════════════════════"
echo ""
echo "Next steps:"
echo "  1. Open a new terminal (or 'source $SHELL_RC')"
echo "  2. Run: hunt my-target"
echo "  3. Open Claude Code in the engagement folder"
echo "  4. Type: /recon target.com"
echo ""
echo "Optional — Burp MCP integration:"
echo "  See mcp/burp-mcp-client/README.md"
echo ""
echo "Optional — HackerOne MCP integration:"
echo "  See mcp/hackerone-mcp/config.json"
echo ""
