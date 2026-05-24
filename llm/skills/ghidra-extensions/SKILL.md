---
name: ghidra-extensions
description: Build, install, debug, and manage Ghidra extensions/plugins — version mismatches, manifest fixes, and MCP integration.
tags: [ghidra, reverse-engineering, extensions, plugins, mcp]
triggers:
  - Ghidra extension not loading or crashing on startup
  - Version mismatch between Ghidra and an extension
  - Building Ghidra extensions from source
  - GhidraMCP setup and bridge configuration
  - Module.manifest or extension.properties errors
---

# Ghidra Extensions

## Environment (macOS Homebrew)

- Ghidra binary: /opt/homebrew/bin/ghidraRun
- Ghidra install: /opt/homebrew/Cellar/ghidra/<version>/libexec/
- System extensions: /opt/homebrew/Cellar/ghidra/<version>/libexec/Ghidra/Extensions/
- User extensions: ~/Library/ghidra/ghidra_<version>_PUBLIC/Extensions/
- Logs: ~/Library/ghidra/ghidra_<version>_PUBLIC/application.log
- Java: /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home

## Debugging Ghidra Startup Failures

1. Run in foreground mode to see errors:
   ```
   JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
     /opt/homebrew/Cellar/ghidra/<ver>/libexec/support/launch.sh fg jdk Ghidra "" "" ghidra.GhidraRun 2>&1
   ```
2. Common errors:
   - "Multiple modules collided with same name" — extension installed in BOTH system and user dirs. Remove one.
   - "Invalid line encountered" in Module.manifest — Ghidra 12+ only accepts `MODULE FILE LICENSE:` lines or empty manifest.
   - "ghidraVersion" mismatch — extension.properties must match installed Ghidra version exactly.

## Building Extensions from Source (Maven-based)

Steps for version-mismatch rebuilds:

1. Clone the extension source
2. Locate required JARs from your Ghidra install:
   ```
   find /opt/homebrew/Cellar/ghidra/<ver>/libexec -name "Generic.jar" -o -name "SoftwareModeling.jar" \
     -o -name "Base.jar" -o -name "Docking.jar" -o -name "Decompiler.jar" \
     -o -name "Utility.jar" -o -name "Project.jar" -o -name "Gui.jar"
   ```
3. Copy JARs into the extension's `lib/` directory (replacing old ones)
4. Update `src/main/resources/extension.properties` — set `version` and `ghidraVersion` to match your Ghidra
5. Build: `mvn clean package -q`
6. Output ZIP in `target/`

## Installing Extensions

- Preferred location: ~/Library/ghidra/ghidra_<version>_PUBLIC/Extensions/
- Unzip the extension ZIP there
- Fix Module.manifest if needed (empty file is safe for simple extensions)
- Ensure extension.properties ghidraVersion matches exactly
- NEVER install same extension in both system and user dirs

## Pitfalls

- Nested clone trap: When rebuilding an extension for a new Ghidra version, avoid cloning the repo inside the existing checkout (e.g. a `source/` subfolder with its own `.git/`). This creates a nested repo that git treats as untracked files and can't be pushed. Fix: remove the nested clone (`rm -rf source/`) after confirming no unique changes exist in it (use `diff` to verify).
- Ghidra is a GUI app — running `ghidraRun` normally gives no error output. Always use `launch.sh fg` mode for debugging.
- Module.manifest format changed across Ghidra versions. Old extensions may have `GHIDRA_MODULE_NAME=` lines that are invalid in newer Ghidra. Clear the file.
- Homebrew Ghidra upgrades change the Cellar path — extensions in the system dir get wiped. User dir (~Library/ghidra/) persists across upgrades.
- The extension JAR is compiled against specific Ghidra API JARs. Even if extension.properties version is patched, the JAR must be recompiled against the new version's JARs to avoid runtime errors.

## Native Binary Analysis Workflows

> SSL pinning analysis: references/native-ssl-pinning-analysis.md

## GitHub Push with Workflow Files

When pushing a repo containing `.github/workflows/` and the OAuth token lacks `workflow` scope:
1. `gh auth refresh -h github.com -s workflow` — interactive, needs browser
2. If that's not feasible, workaround: remove workflow from tracking, push, then re-add later:
   ```
   git rm --cached .github/workflows/build.yml
   git commit -m "Remove workflow from tracking to allow push"
   git -c credential.helper='!gh auth git-credential' push -u <remote> main
   ```
3. To restore later (once scope is added): `git add .github/workflows/ && git commit && git push`

## GhidraMCP Specifics

> Full API reference: references/ghidramcp-api.md

- Source: https://github.com/LaurieWired/GhidraMCP
- Build system: Maven (pom.xml with system-scoped Ghidra JAR deps)
- Plugin starts HTTP server on port 8080 when enabled in CodeBrowser
- Bridge script: `bridge_mcp_ghidra.py` — connects MCP (SSE on :8081) to Ghidra HTTP (:8080)
- Enable in Ghidra: File > Configure > Miscellaneous > GhidraMCP
- Bridge command: `python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/`
- Bridge deps: `requests>=2,<3` and `mcp>=1.2.0,<2`
- API pitfall: "Function not found" means the function address doesn't exist in the currently-loaded binary. Always verify with `curl http://localhost:8080/methods` first to confirm what's loaded. Address ranges vary per binary — a function from one project won't resolve in another.
- The `gh auth setup-git` + `git -c credential.helper='!gh auth git-credential' push` pattern is needed when gh is configured but git credential helper isn't wired up globally.

## Verification

After install/fix, confirm with foreground launch — look for "Ghidra startup complete" in output.
