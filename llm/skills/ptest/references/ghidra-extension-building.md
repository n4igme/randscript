# Building Ghidra Extensions for Mismatched Versions

## Problem

Ghidra extensions are version-locked via `extension.properties` (`ghidraVersion=X.Y.Z`).
If the released extension binary targets a different Ghidra version than what's installed,
Ghidra silently refuses to load it.

## Diagnosis

1. Check installed Ghidra version: look at the install path or `ghidraRun` wrapper
2. Check extension's target version: `unzip -p Extension.zip */extension.properties`
3. If `ghidraVersion` doesn't match your install → must rebuild from source

## Environment (macOS Homebrew)

- Ghidra install: `/opt/homebrew/Cellar/ghidra/{VERSION}/libexec/`
- Extension dirs:
  - `/opt/homebrew/Cellar/ghidra/{VERSION}/libexec/Ghidra/Extensions/` (user extensions go here)
  - `/opt/homebrew/Cellar/ghidra/{VERSION}/libexec/Extensions/` (bundled IDE extensions)
- ghidraRun wrapper: `/opt/homebrew/bin/ghidraRun`
- JDK: `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`

## Build Procedure (Maven-based extensions like GhidraMCP)

```bash
# 1. Clone the extension source
git clone https://github.com/{author}/{extension}.git source
cd source

# 2. Find required JARs from your Ghidra install
GHIDRA_HOME="/opt/homebrew/Cellar/ghidra/{VERSION}/libexec"
find $GHIDRA_HOME -name "Generic.jar" -o -name "SoftwareModeling.jar" \
  -o -name "Base.jar" -o -name "Docking.jar" -o -name "Decompiler.jar" \
  -o -name "Utility.jar" -o -name "Project.jar" -o -name "Gui.jar"

# 3. Copy JARs to the project's lib/ directory
rm -f lib/*.jar
cp $GHIDRA_HOME/Ghidra/Framework/Generic/lib/Generic.jar lib/
cp $GHIDRA_HOME/Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar lib/
cp $GHIDRA_HOME/Ghidra/Framework/Project/lib/Project.jar lib/
cp $GHIDRA_HOME/Ghidra/Framework/Docking/lib/Docking.jar lib/
cp $GHIDRA_HOME/Ghidra/Features/Decompiler/lib/Decompiler.jar lib/
cp $GHIDRA_HOME/Ghidra/Framework/Utility/lib/Utility.jar lib/
cp $GHIDRA_HOME/Ghidra/Features/Base/lib/Base.jar lib/
cp $GHIDRA_HOME/Ghidra/Framework/Gui/lib/Gui.jar lib/

# 4. Patch extension.properties to match your Ghidra version
sed -i '' 's/version=.*/version={YOUR_VERSION}/' src/main/resources/extension.properties
sed -i '' 's/ghidraVersion=.*/ghidraVersion={YOUR_VERSION}/' src/main/resources/extension.properties

# 5. Build (install maven first: brew install maven)
mvn clean package -q

# 6. Install the extension
unzip -o target/{ExtensionName}*.zip -d "$GHIDRA_HOME/Ghidra/Extensions/"
```

## Post-Install

1. Restart Ghidra (if running)
2. Open CodeBrowser with a binary
3. File > Configure > Miscellaneous → enable the extension
4. Extension starts its service (e.g., HTTP server for MCP bridge)

## GhidraMCP Specific

- Source: https://github.com/LaurieWired/GhidraMCP
- Build system: Maven (pom.xml with system-scoped Ghidra JARs)
- Extension starts HTTP server on port 8080
- MCP bridge: `python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/`
- Bridge dependencies: `requests>=2,<3` and `mcp>=1.2.0,<2`
- As of 2026-05: latest release (1.4) targets Ghidra 11.3.2, no release for 12.x yet

## Pitfalls

- Ghidra installed via Homebrew puts extensions in a versioned Cellar path — upgrades may wipe custom extensions
- The pom.xml uses `<scope>system</scope>` with `<systemPath>` — JARs MUST be in lib/ (not resolved from Maven Central)
- No compilation errors doesn't guarantee runtime compatibility — major Ghidra API changes between versions may cause ClassNotFoundException at load time
- After `brew upgrade ghidra`, you'll need to rebuild and reinstall all custom extensions
